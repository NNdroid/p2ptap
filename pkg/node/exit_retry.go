package node

import (
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// exitRetryMinInterval and exitRetryMaxInterval bound the exponential backoff
// used by the Exit Node re-apply loop while waiting for a disconnected peer to
// come back.
const (
	exitRetryMinInterval = 1 * time.Second
	exitRetryMaxInterval = 30 * time.Second
)

// retryExitNodeAfterDisconnect remembers pid as the Exit Node peer that was
// cleared because it disconnected, and launches a background loop that
// re-applies the Exit Node for the SAME peer as soon as it is reachable again.
//
// The disconnect handler tears the Exit Node default route down on purpose so a
// peer that is gone for good does not leave the host black-holing egress. The
// cost of that safety is that a TRANSIENT disconnect (Android network churn, a
// brief transport reset, a relay hop hiccup) previously left the Exit Node dead
// until the operator re-selected it by hand — exactly the "works a few seconds,
// then stalls until the app restarts" symptom. This loop closes that gap.
//
// ip4 / ip6 are the gateway TAP IPs captured before ClearExitNode wiped the
// bookkeeping (the peer's self-reported metadata is deleted on disconnect, so
// they cannot be re-resolved later). A later operator action — selecting a
// different Exit Node, or explicitly clearing the Exit Node — bumps
// GatewayManager.ExitChangeSeq and cancels the loop.
func (n *Node) retryExitNodeAfterDisconnect(pid peer.ID, ip4, ip6 string) {
	if pid == "" {
		return
	}
	n.exitRetryMu.Lock()
	if n.exitRetryDesired == pid {
		// Already retrying this peer — refresh the captured gateway IPs (they may
		// have been learned more precisely since the first disconnect).
		n.exitRetryIP4 = ip4
		n.exitRetryIP6 = ip6
		n.exitRetryMu.Unlock()
		return
	}
	n.exitRetryDesired = pid
	n.exitRetryIP4 = ip4
	n.exitRetryIP6 = ip6
	gen := n.exitRetryGen + 1
	n.exitRetryGen = gen
	n.exitRetryMu.Unlock()
	go n.exitNodeRetryLoop(pid, ip4, ip6, gen)
}

// exitNodeRetryLoop polls until pid is reachable again, then re-applies the
// Exit Node for it. It stops when:
//   - the node shuts down (n.ctx is cancelled),
//   - a newer generation supersedes it (a fresh retry was scheduled), or
//   - any Exit Node state transition happened since it started (an operator
//     action, or some other path already re-activated an Exit Node).
//
// On a re-apply failure (e.g. the peer's TAP IP is not resolvable yet) it backs
// off and retries rather than giving up on a peer that is coming back up.
func (n *Node) exitNodeRetryLoop(pid peer.ID, ip4, ip6 string, gen uint64) {
	startSeq := n.Gateway.ExitChangeSeq()
	interval := exitRetryMinInterval
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-time.After(interval):
		}

		n.exitRetryMu.Lock()
		if n.exitRetryGen != gen || n.exitRetryDesired != pid {
			n.exitRetryMu.Unlock()
			return // superseded by a newer retry
		}
		n.exitRetryMu.Unlock()

		// An Exit Node state transition (operator set a different peer, operator
		// cleared, or a concurrent path re-activated one) invalidates this retry.
		if n.Gateway.ExitChangeSeq() != startSeq {
			n.clearExitNodeRetryDesired(pid, gen)
			return
		}
		if n.isExitNodeActive() {
			n.clearExitNodeRetryDesired(pid, gen)
			return
		}
		if n.peerReachable(pid) {
			if err := n.reapplyExitNode(pid, ip4, ip6); err == nil {
				n.clearExitNodeRetryDesired(pid, gen)
				return
			}
		}

		if interval < exitRetryMaxInterval {
			interval *= 2
			if interval > exitRetryMaxInterval {
				interval = exitRetryMaxInterval
			}
		}
	}
}

// clearExitNodeRetryDesired forgets a pending re-apply, but only for the exact
// (pid, gen) the caller owns, so a newer retry or an operator action is never
// erased by a stale loop.
func (n *Node) clearExitNodeRetryDesired(pid peer.ID, gen uint64) {
	n.exitRetryMu.Lock()
	if n.exitRetryGen == gen && n.exitRetryDesired == pid {
		n.exitRetryDesired = ""
		n.exitRetryIP4 = ""
		n.exitRetryIP6 = ""
	}
	n.exitRetryMu.Unlock()
}

// peerReachable reports whether pid currently has at least one live connection
// (direct or relay). The disconnect handler's debounce uses the same test, so a
// peer that reconnected within the debounce window is treated as reachable.
func (n *Node) peerReachable(pid peer.ID) bool {
	if n.Host == nil {
		return false
	}
	if n.Host.Network().Connectedness(pid) == network.Connected {
		return true
	}
	return len(n.Host.Network().ConnsToPeer(pid)) > 0
}

// reapplyExitNode re-installs the Exit Node default route for pid, mirroring the
// WebUI /api/exit_node "set" handler: the peer's TAP gateway IPs are the ones
// captured at disconnect time (metadata is gone by now), and physical endpoints
// are re-resolved from the peerstore so bypass host routes stay correct.
func (n *Node) reapplyExitNode(pid peer.ID, ip4, ip6 string) error {
	if ip4 == "" && ip6 == "" {
		return fmt.Errorf("exit node re-apply for %s: no gateway TAP IP available", pid.String())
	}
	endpoints := n.peerEndpoints(pid)
	if err := n.Gateway.SetExitNode(pid.String(), ip4, ip6, endpoints); err != nil {
		return err
	}
	log.Info("Exit Node re-applied for peer %s after reconnect (ip4=%s ip6=%s)", pid.String(), ip4, ip6)
	return nil
}

// peerEndpoints returns every physical (non-circuit, non-loopback) IP the
// peerstore currently knows for pid, used to install bypass host routes so the
// tunnel's own P2P traffic is not pulled into the TAP.
func (n *Node) peerEndpoints(pid peer.ID) []string {
	if n.Host == nil {
		return nil
	}
	var ips []string
	for _, a := range filterUndialableAddrs(n.Host.Peerstore().Addrs(pid)) {
		multiaddr.ForEach(a, func(c multiaddr.Component) bool {
			if c.Protocol().Code == multiaddr.P_IP4 || c.Protocol().Code == multiaddr.P_IP6 {
				ips = append(ips, c.Value())
			}
			return true
		})
	}
	return ips
}
