package node

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/multiformats/go-multiaddr"
)

func (n *Node) discoveryLoop() {
	defer n.wg.Done()

	// Hash the PSK using SHA256 to generate a secure rendezvous string
	hash := sha256.Sum256([]byte(n.Config.PSK))
	rendezvousString := "p2ptap-" + hex.EncodeToString(hash[:])
	log.Debug("Generated secure rendezvous string for DHT discovery")

	// Initialize routing discovery
	routingDiscovery := drouting.NewRoutingDiscovery(n.DHT)

	// Advertise the hashed string as the rendezvous point
	util.Advertise(n.ctx, routingDiscovery, rendezvousString)

	// Helper for single discovery round
	runFind := func() {
		peerChan, err := routingDiscovery.FindPeers(n.ctx, rendezvousString)
		if err != nil {
			log.Debug("Error finding peers in DHT: %v", err)
			return
		}
		for p := range peerChan {
			if p.ID == n.Host.ID() || len(p.Addrs) == 0 {
				continue
			}

			// Feed newly discovered addresses to Peerstore for DCUtR hole punching
			n.Host.Peerstore().AddAddrs(p.ID, p.Addrs, 10*time.Minute)

			// Check if already connected; if not, initiate CONCURRENT connection with parallel race
			if n.Host.Network().Connectedness(p.ID) != network.Connected {
				log.Debug("DHT discovered new peer %s with addrs %v, connecting...", p.ID.String(), p.Addrs)
				go func(pi peer.AddrInfo) {
					if err := n.dialInParallel(n.ctx, pi, "discovered"); err != nil {
						log.Debug("All connection methods to discovered peer %s failed: %v", pi.ID.String(), err)
					}
				}(p)
			}
		}
	}

	// Initial fast discovery burst on startup (1s, 4s, 10s)
	burstIntervals := []time.Duration{1 * time.Second, 4 * time.Second, 10 * time.Second}
	for _, delay := range burstIntervals {
		select {
		case <-n.ctx.Done():
			return
		case <-time.After(delay):
			runFind()
		}
	}

	// Regular background discovery loop (every 20 seconds)
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			runFind()
		}
	}
}

func (n *Node) isBootstrapPeer(pID peer.ID) bool {
	if _, ok := n.discoveredBoots.Load(pID); ok {
		return true
	}
	for _, bStr := range n.Config.BootstrapPeers {
		ma, err := multiaddr.NewMultiaddr(bStr)
		if err != nil {
			continue
		}
		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			continue
		}
		if info.ID == pID {
			return true
		}
	}
	return false
}

// markRelayOnlyPeer records that pID is only reachable through a circuit relay
// (its direct addresses are private/unreachable). Used to force relay-priority
// dialing and keepalive for that peer.
func (n *Node) markRelayOnlyPeer(pID peer.ID) {
	n.relayOnlyMu.Lock()
	if n.relayOnlyPeers == nil {
		n.relayOnlyPeers = make(map[peer.ID]bool)
	}
	n.relayOnlyPeers[pID] = true
	n.relayOnlyMu.Unlock()
}

// clearRelayOnlyPeer removes the relay-only classification (e.g. once a direct
// transport to the peer is established).
func (n *Node) clearRelayOnlyPeer(pID peer.ID) {
	n.relayOnlyMu.Lock()
	delete(n.relayOnlyPeers, pID)
	n.relayOnlyMu.Unlock()
}

// isRelayOnlyPeer reports whether pID is known to be only reachable via relay.
func (n *Node) isRelayOnlyPeer(pID peer.ID) bool {
	n.relayOnlyMu.RLock()
	defer n.relayOnlyMu.RUnlock()
	return n.relayOnlyPeers[pID]
}

func (n *Node) getPeerLatency(pID peer.ID) int64 {
	ewma := n.Host.Peerstore().LatencyEWMA(pID)
	if ewma > 0 {
		return ewma.Milliseconds()
	}
	return 10
}

// realPeerLatencyMs returns the cached EWMA latency for pID in milliseconds,
// or -1 when no measurement is available. Unlike getPeerLatency this never
// fabricates a placeholder value, so callers in the multiaddr probe path can
// distinguish "we don't actually know" from "we measured X ms" — the UI then
// renders -1 as "unverified / —" instead of misleadingly claiming a 0 ms RTT.
func (n *Node) realPeerLatencyMs(pID peer.ID) int64 {
	if ewma := n.Host.Peerstore().LatencyEWMA(pID); ewma > 0 {
		return ewma.Milliseconds()
	}
	return -1
}

// SynthesizeRelayCircuitAddrs returns the circuit-relay multiaddrs that can be
// used to reach targetPeer through every bootstrap relay we are currently
// Connected to.
//
// This is the SINGLE SOURCE OF TRUTH for circuit-addr composition. Both the
// initial parallel dial race (dialInParallel) and the relay-priority control
// path (openStreamViaRelay / reconnectPeer / LSA-meta sync / reachability
// probe) call it, so the old "dialInParallel can establish a circuit link but
// SynthesizeRelayCircuitAddrs returns empty / a different shape" divergence can
// never recur.
//
// For each connected relay it emits the peer-ID-only form
// "/p2p/<relay>/p2p-circuit/p2p/<target>". This is the most robust shape:
// because the relay peer is already in the peerstore as Connected, libp2p
// resolves the relay's live transport address from the existing connection, so
// no loopback/transport filter is needed and a same-host (loopback) relay works
// exactly like a public one. The returned slice is ordered by ascending relay
// RTT (unknown RTT sorted last) so callers that try addrs in order prefer the
// fastest bridge.
func (n *Node) SynthesizeRelayCircuitAddrs(targetPeer peer.ID) []multiaddr.Multiaddr {
	type relayEntry struct {
		addr    multiaddr.Multiaddr
		latency time.Duration // 0 means unknown
	}

	n.relayLatencyMu.RLock()
	defer n.relayLatencyMu.RUnlock()

	var entries []relayEntry
	for _, bStr := range n.Config.BootstrapPeers {
		bMa, err := multiaddr.NewMultiaddr(bStr)
		if err != nil {
			continue
		}
		bInfo, err := peer.AddrInfoFromP2pAddr(bMa)
		if err != nil {
			continue
		}
		// A relay that is also the destination makes no sense as a circuit
		// relay — emitting "/p2p/<boot>/p2p-circuit/p2p/<boot>" would be a
		// self-circuit that can never resolve. Skip it up front so callers never
		// get a useless address (this kills the teardown-race
		// "circuit dial to <boot itself>" case at the source).
		if bInfo.ID == targetPeer {
			continue
		}
		// Only relays we are actually Connected to can forward a circuit — and
		// only then is the peer-ID-only circuit addr below resolvable by libp2p
		// (it looks the relay peer up in the peerstore and reuses the live
		// connection). If a relay dropped, we simply omit it rather than emit an
		// unusable address.
		if n.Host.Network().Connectedness(bInfo.ID) != network.Connected {
			continue
		}
		circuitMA, cerr := multiaddr.NewMultiaddr(
			fmt.Sprintf("/p2p/%s/p2p-circuit/p2p/%s", bInfo.ID.String(), targetPeer.String()))
		if cerr != nil {
			continue
		}
		entries = append(entries, relayEntry{addr: circuitMA, latency: n.relayLatency[bInfo.ID]})
	}

	// Sort: prefer lower-latency relay paths; unknown latency at end.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].latency == 0 && entries[j].latency == 0 {
			return false
		}
		if entries[i].latency == 0 {
			return false
		}
		if entries[j].latency == 0 {
			return true
		}
		return entries[i].latency < entries[j].latency
	})

	result := make([]multiaddr.Multiaddr, len(entries))
	for i, e := range entries {
		result[i] = e.addr
	}
	return result
}

// recordRelayLatency records the RTT to a relay bootstrap peer for path quality tracking.
func (n *Node) recordRelayLatency(relayID peer.ID, rtt time.Duration) {
	n.relayLatencyMu.Lock()
	if n.relayLatency == nil {
		n.relayLatency = make(map[peer.ID]time.Duration)
	}
	if existing, ok := n.relayLatency[relayID]; ok {
		// EWMA smoothing: 70% existing + 30% new
		n.relayLatency[relayID] = (existing*7 + rtt*3) / 10
	} else {
		n.relayLatency[relayID] = rtt
	}
	n.relayLatencyMu.Unlock()
}

func PrintBanner(n *Node) {
	log.Info("=========================================================")
	log.Info("             P2P TAP VPN (go-libp2p) Started             ")
	log.Info("=========================================================")
	log.Info(" Node Name     : %s", n.nodeName)
	log.Info(" Local Peer ID : %s", n.Host.ID())
	log.Info(" TAP Interface : %s (IPv4: %s | IPv6: %s)", n.TAP.Name(), n.Config.TapIP, n.Config.TapIPv6)
	log.Info(" P2P Strategy  : %s (Obfuscation: %s)", n.Config.TransportStrategy, n.Config.Obfuscation.Mode)
	log.Info(" Log Level     : %s", n.Config.LogLevel)
	if n.Config.WebUI.Enable {
		webIP := n.Config.WebUI.ListenIP
		if webIP == "0.0.0.0" || webIP == "" || webIP == "auto" {
			if tapIPv4, _, err := net.ParseCIDR(n.Config.TapIP); err == nil && tapIPv4 != nil {
				log.Info(" Web UI        : http://%s:%d (or http://127.0.0.1:%d)", tapIPv4.String(), n.Config.WebUI.Port, n.Config.WebUI.Port)
			} else {
				log.Info(" Web UI        : http://127.0.0.1:%d", n.Config.WebUI.Port)
			}
		} else {
			log.Info(" Web UI        : http://%s:%d", webIP, n.Config.WebUI.Port)
		}
	}
	log.Info(" Listen Addrs  :")
	for _, a := range n.Host.Addrs() {
		log.Info("   - %s/p2p/%s", a, n.Host.ID())
	}
	log.Info("=========================================================")
}
