package node

import (
	"fmt"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

const (
	relayFailureResetWindow      = 5 * time.Minute
	relayPermissionDenyThreshold = 3
	relayPermissionDenyCooldown  = 2 * time.Minute
	relayFailureDedupWindow      = time.Second
)

type relayControlFailureState struct {
	consecutiveFailures int
	permissionDenials   int
	lastFailure         time.Time
	lastError           string
	cooldownUntil       time.Time
	authRefreshIssued   bool
	rediscoveryIssued   bool
}

// isRelayPermissionDenied distinguishes a hard Circuit Relay ACL rejection
// from the genuinely transient 203/CONNECTION_FAILED case. In p2ptap-boot a
// 202 means source/destination authentication or PSK-network isolation failed;
// retrying it immediately cannot repair the policy decision.
func isRelayPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	return isRelayPermissionDeniedText(err.Error())
}

func isRelayPermissionDeniedText(text string) bool {
	s := strings.ToLower(text)
	return strings.Contains(s, "permission_denied") ||
		strings.Contains(s, "permission denied") ||
		strings.Contains(s, "(202)")
}

// recordRelayControlFailure updates the target-level circuit breaker. Repeated
// observations of the same propagated error within one second are one failure:
// openStreamViaRelay, RelayCtrl and SeqSync can all see the same failed stream.
func (n *Node) recordRelayControlFailure(target peer.ID, err error) {
	if n == nil || target == "" || err == nil {
		return
	}
	now := time.Now()
	errText := err.Error()

	n.relayControlHealthMu.Lock()
	if n.relayControlHealth == nil {
		n.relayControlHealth = make(map[peer.ID]relayControlFailureState)
	}
	st := n.relayControlHealth[target]
	if !st.lastFailure.IsZero() && now.Sub(st.lastFailure) > relayFailureResetWindow {
		st = relayControlFailureState{}
	}
	permissionDenied := isRelayPermissionDenied(err)
	duplicate := !st.lastFailure.IsZero() && now.Sub(st.lastFailure) < relayFailureDedupWindow &&
		st.lastError == errText
	if !duplicate {
		st.consecutiveFailures++
		if permissionDenied {
			st.permissionDenials++
		}
	}
	st.lastFailure = now
	st.lastError = errText

	refreshAuth := permissionDenied && !st.authRefreshIssued
	if refreshAuth {
		st.authRefreshIssued = true
	}
	enterCooldown := st.permissionDenials >= relayPermissionDenyThreshold && !now.Before(st.cooldownUntil)
	if enterCooldown {
		st.cooldownUntil = now.Add(relayPermissionDenyCooldown)
	}
	rediscover := st.consecutiveFailures >= relayPermissionDenyThreshold && !st.rediscoveryIssued
	if rediscover {
		st.rediscoveryIssued = true
	}
	n.relayControlHealth[target] = st
	n.relayControlHealthMu.Unlock()

	if refreshAuth {
		go n.refreshConnectedRelayAuthentication()
	}
	if rediscover {
		n.peerReady.Delete(target)
		go n.rediscoverPeer(target)
	}
	if enterCooldown {
		// A previously negotiated cipher/ready bit is not proof that the current
		// relay path still works. Clear readiness so the data plane and WebUI do
		// not present a stale healthy session during the ACL cooldown.
		n.peerReady.Delete(target)
		log.Warn("Relay circuit to %s was denied %d consecutive times; refreshing authentication/routes and cooling down for %s",
			target.String(), st.permissionDenials, relayPermissionDenyCooldown)
	}
}

func (n *Node) clearRelayControlFailure(target peer.ID) {
	if n == nil || target == "" {
		return
	}
	n.relayControlHealthMu.Lock()
	delete(n.relayControlHealth, target)
	n.relayControlHealthMu.Unlock()
}

func (n *Node) relayPermissionCooldownRemaining(target peer.ID) time.Duration {
	if n == nil || target == "" {
		return 0
	}
	n.relayControlHealthMu.Lock()
	defer n.relayControlHealthMu.Unlock()
	st, ok := n.relayControlHealth[target]
	if !ok || st.cooldownUntil.IsZero() {
		return 0
	}
	remaining := time.Until(st.cooldownUntil)
	if remaining <= 0 {
		st.cooldownUntil = time.Time{}
		st.permissionDenials = 0
		st.authRefreshIssued = false
		st.rediscoveryIssued = false
		n.relayControlHealth[target] = st
		return 0
	}
	return remaining
}

func (n *Node) relayPermissionCooldownError(target peer.ID) error {
	if remaining := n.relayPermissionCooldownRemaining(target); remaining > 0 {
		return fmt.Errorf("relay circuit to %s is cooling down after repeated permission denial; retry in %s",
			target, remaining.Round(time.Second))
	}
	return nil
}

// recentRelayControlFailure is consumed by the WebUI verdict. A route-table
// entry is only a candidate path; a recent failed control handshake overrides
// it until an echo/rekey success clears the failure.
func (n *Node) recentRelayControlFailure(target peer.ID, maxAge time.Duration) (string, bool) {
	if n == nil || target == "" {
		return "", false
	}
	n.relayControlHealthMu.Lock()
	defer n.relayControlHealthMu.Unlock()
	st, ok := n.relayControlHealth[target]
	if !ok || st.lastFailure.IsZero() || time.Since(st.lastFailure) > maxAge {
		return "", false
	}
	detail := strings.TrimSpace(st.lastError)
	if len(detail) > 180 {
		detail = detail[:177] + "..."
	}
	if remaining := time.Until(st.cooldownUntil); remaining > 0 {
		return fmt.Sprintf("relay permission denied; retry after %s: %s", remaining.Round(time.Second), detail), true
	}
	return detail, true
}

// refreshConnectedRelayAuthentication re-runs the PSK handshake with every
// connected configured/discovered boot. It is single-flighted per boot by
// ensureRelayAuth, so simultaneous target failures cannot create an auth storm.
func (n *Node) refreshConnectedRelayAuthentication() {
	if n == nil || n.Host == nil || n.Config == nil {
		return
	}
	seen := make(map[peer.ID]struct{})
	refresh := func(info peer.AddrInfo) {
		if info.ID == "" {
			return
		}
		if _, ok := seen[info.ID]; ok {
			return
		}
		seen[info.ID] = struct{}{}
		if n.Host.Network().Connectedness(info.ID) == network.Connected {
			n.ensureRelayAuth(info)
		}
	}
	for _, raw := range n.Config.BootstrapPeers {
		addr, err := multiaddr.NewMultiaddr(raw)
		if err != nil {
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(addr)
		if err == nil {
			refresh(*info)
		}
	}
	n.discoveredBoots.Range(func(k, _ any) bool {
		if id, ok := k.(peer.ID); ok {
			refresh(peer.AddrInfo{ID: id})
		}
		return true
	})
}
