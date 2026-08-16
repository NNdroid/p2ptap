package node

import (
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"p2ptap/pkg/observer"
)

// connState enumerates the aggregated WebUI connectivity/encryption verdict
// for a peer. Replacing ad-hoc string literals with named constants keeps the
// verdicts consistent between node_stats.go and the WebUI badge renderer
// (which maps these exact strings to colors and i18n keys).
const (
	connStateOK            = "ok"             // healthy: data decrypting end-to-end
	connStateRelayOK       = "relay_ok"       // healthy: data decrypting via relay hop
	connStateConnecting    = "connecting"     // mid-handshake, no data yet
	connStateProtoMismatch = "proto_mismatch" // app protocol not shared (mixed version)
	connStateObfFailed     = "obf_failed"     // encryption negotiated but decrypt failing
	connStateUnreachable   = "unreachable"    // no transport / overlay route at all
)

// toDuplicateIPConflictDTOs converts the node-internal DuplicateIPConflict set
// into the observer DTO shape the WebUI consumes. DetectedAt is formatted to
// RFC3339 so the dashboard can render it directly.
func toDuplicateIPConflictDTOs(in []DuplicateIPConflict) []observer.DuplicateIPConflictDTO {
	out := make([]observer.DuplicateIPConflictDTO, 0, len(in))
	for _, c := range in {
		out = append(out, observer.DuplicateIPConflictDTO{
			ResourceType: c.ResourceType,
			Resource:     c.Resource,
			Claimants:    c.Claimants,
			Winner:       c.Winner,
			Losers:       c.Losers,
			Reason:       c.Reason,
			DetectedAt:   c.DetectedAt.Format(time.RFC3339),
		})
	}
	return out
}

// peerConnSignals is the raw per-peer connectivity classification derived from
// the live connection set. It is the single source of truth shared by the
// address/transport display logic and the WebUI ConnState verdict, so the two
// never drift apart.
type peerConnSignals struct {
	hasDirect bool // at least one non-relay transport connection
	hasRelay  bool // at least one circuit/overlay relay connection
	isRelayed bool // peer is only/primarily reachable through a relay
	connCount int  // total transport connections to the peer
}

// deriveConnSignals classifies a peer's live connections the same way the
// WebUI "Conn Status" column expects: a peer is "relayed" when it has no
// direct connection, otherwise a normal direct peer (a mixed direct+relay
// peer is reported as direct with relay available).
func (n *Node) deriveConnSignals(pID peer.ID) peerConnSignals {
	s := peerConnSignals{}
	for _, c := range n.Host.Network().ConnsToPeer(pID) {
		s.connCount++
		if strings.Contains(c.RemoteMultiaddr().String(), "/p2p-circuit") {
			s.hasRelay = true
		} else {
			s.hasDirect = true
		}
	}
	// No direct connection (neither circuit relay nor overlay route counted as
	// direct) ⇒ the peer is reached only through a relay/overlay hop.
	s.isRelayed = !s.hasDirect
	return s
}

// relayHopLabel returns a human-friendly identifier for a relay hop peer,
// preferring the peer's NodeName (looked up from peerMeta), then its TAP IPv4,
// then the last 9 chars of its peer ID as a fallback.
//
// Why NOT a first-N-chars truncation of the peer ID:
//
// Every libp2p Ed25519 peer ID starts with the same 8-char base58 multihash
// prefix "12D3KooW". When you truncate two Ed25519 peer IDs to 12 chars, the
// remaining 4 chars of the SHA-256 hash portion often look visually almost
// identical and users mistake the relay for the destination. Using a NodeName
// / TAP IP / last-9 fallback makes the relay hop unambiguously a *different*
// peer. Note: the real "relay via self" hazard is a route whose NextHop equals
// the LOCAL node (n.Host.ID()), which the caller guards separately — this label
// only formats the hop identity, it never compares against self.
func (n *Node) relayHopLabel(pID peer.ID) string {
	if val, ok := n.peerMeta.Load(pID); ok {
		meta := val.(PeerMeta)
		if meta.NodeName != "" {
			return meta.NodeName
		}
		if meta.TapIP != "" {
			return meta.TapIP
		}
	}
	s := pID.String()
	if len(s) >= 9 {
		return "…" + s[len(s)-9:]
	}
	return s
}

// classifyPeerRole returns the human-facing role label used by the WebUI.
// Bootstrap/Static peers come from the configured address lists; any remaining
// relay-only peer is a "Relayed Peer", otherwise a plain "Peer".
func (n *Node) classifyPeerRole(pID peer.ID, bootstrapMap, staticMap map[peer.ID]bool, isRelayed bool) string {
	switch {
	case bootstrapMap[pID]:
		return "Bootstrap"
	case staticMap[pID]:
		return "Static"
	case isRelayed:
		return "Relayed Peer"
	default:
		return "Peer"
	}
}

func (n *Node) updateWebCollectorState() {
	nodeName := n.Config.NodeName
	if nodeName == "" || nodeName == "auto" {
		if hostName, err := os.Hostname(); err == nil && hostName != "" {
			nodeName = hostName
		} else {
			nodeName = "p2ptap-node"
		}
	}
	n.Collector.SetNodeInfo(nodeName, n.Host.ID().String(), n.Config.TapIP, n.Config.TapIPv6, n.Config.TransportStrategy)
	n.Collector.SetTAPSelfTest(func() map[string]interface{} {
		if n.TAP == nil {
			return map[string]interface{}{"available": false, "detail": "TAP device is nil"}
		}
		return n.TAP.SelfTest()
	})

	// Build map of bootstrap and static peer IDs for quick role classification
	bootstrapMap := make(map[peer.ID]bool)
	for _, bStr := range n.Config.BootstrapPeers {
		if ma, err := multiaddr.NewMultiaddr(bStr); err == nil {
			if info, err := peer.AddrInfoFromP2pAddr(ma); err == nil {
				bootstrapMap[info.ID] = true
			}
		}
	}

	staticMap := make(map[peer.ID]bool)
	for _, sStr := range n.Config.StaticPeers {
		if ma, err := multiaddr.NewMultiaddr(sStr); err == nil {
			if info, err := peer.AddrInfoFromP2pAddr(ma); err == nil {
				staticMap[info.ID] = true
			}
		}
	}

	// Sync active peers and MAC table to web collector
	peersDTO := make([]observer.PeerInfoDTO, 0)
	allActivePeers := n.getAllPeersForMetaSync()

	// Record the real elapsed interval ONCE for the whole snapshot. All peers
	// share the same sampling window (the time between two consecutive
	// updateWebCollectorState calls, ~10s). If we updated lastPeerSpeedCalc
	// inside the per-peer loop, every peer after the first would see an
	// interval of ~0s and report a wildly inflated bytes/sec value.
	n.lastPeerSpeedMu.Lock()
	nowCalc := time.Now()
	var intervalSec float64
	if !n.lastPeerSpeedCalc.IsZero() {
		intervalSec = nowCalc.Sub(n.lastPeerSpeedCalc).Seconds()
	}
	n.lastPeerSpeedCalc = nowCalc
	n.lastPeerSpeedMu.Unlock()
	if intervalSec <= 0 {
		intervalSec = 10.0 // default ticker interval on first call
	}

	for _, pID := range allActivePeers {
		sig := n.deriveConnSignals(pID)
		// Snapshot the current routing table once per snapshot (it is itself
		// cached with a 2s TTL, so repeated calls are cheap). Sharing one view
		// across all peers keeps the RTT/jitter numbers consistent, and lets us
		// read the real multi-hop RTT for overlay-routed peers below.
		routes := n.getCachedRoutes()
		addr := "unknown"
		transport := "P2P"
		isRelayedPeer := sig.isRelayed
		hasDirectConn := sig.hasDirect
		hasRelayConn := sig.hasRelay

		if sig.connCount > 0 {
			// Iterate ALL connections to detect mixed direct+relay scenarios.
			// A peer could have a direct TCP connection AND a relay fallback simultaneously.
			for _, c := range n.Host.Network().ConnsToPeer(pID) {
				a := c.RemoteMultiaddr().String()
				if strings.Contains(a, "/p2p-circuit") {
					if addr == "unknown" {
						addr = a
					}
				} else {
					addr = a // prefer direct address for display
					// Detect transport protocol from the direct connection
					if strings.Contains(a, "/quic") {
						transport = "QUIC"
					} else if strings.Contains(a, "/webrtc") {
						transport = "WebRTC"
					} else if strings.Contains(a, "/tcp") {
						transport = "TCP"
					}
				}
			}

			if hasRelayConn && !hasDirectConn {
				// All connections are through circuit relay — peer is relayed.
				transport = "Circuit Relay"
			} else if hasRelayConn && hasDirectConn {
				// Mixed — prefer direct, notate relay availability.
				transport = transport + "+Relay"
			}
			// hasDirectConn && !hasRelayConn → normal direct peer (isRelayedPeer=false)
		} else {
			// Zero transport connections — peer only reachable through overlay routing.
			transport = "Overlay Relay"
			// The description goes on `transport` (the "传输协议" column), NOT
			// on `addr` — `addr` is the current active multiaddr shown in the
			// "网络 MULTIADDR 地址" column and in the multiaddr hover row, and
			// a free-form status label there breaks the `Active/Candidate`
			// rendering in the multiaddr modal (which compares each candidate
			// to `peer.addr` to pick the Active row). The route snapshot was
			// already taken once at the top of the peer loop (routes variable).
			route, hasRoute := routes[pID]
			switch {
			case hasRoute && route.NextHop != "" &&
				route.NextHop != n.Host.ID() && route.NextHop != pID:
				// Display the relay hop by its human identifier (NodeName / TAP IP /
				// last-9 chars of peer ID) — NOT a first-N-chars peer-ID truncation.
				// Ed25519 peer IDs share the 8-char multihash prefix "12D3KooW"; a
				// 12-char truncation of two Ed25519 peers can look almost identical
				// and users mistake the relay for the destination.
				transport = "Overlay Relay via " + n.relayHopLabel(route.NextHop)
			case hasRoute && (route.NextHop == pID || route.NextHop == n.Host.ID()):
				// Route table claims direct reachability (NextHop == dest ⇒
				// IsDirect = true per Dijkstra path reconstruction) but the libp2p
				// transport layer has no active connection. This is a stale or
				// inconsistent LSA claim: a previous direct link was lost (NAT
				// change, peer restart, firewall) and the LSA hasn't been
				// refreshed yet, or a remote LSA advertised a fictitious direct
				// link. Show an honest label rather than the misleading
				// "Overlay Relay via <self>" that falls out of relayHopLabel when
				// NextHop == pID.
				transport = "LSA-known Direct (no transport)"
			default:
				transport = "Overlay Relay (Multi-Hop)"
			}
			log.Debug("Peer %s has zero transport connections; using overlay relay routing", pID.String())
		}

		role := n.classifyPeerRole(pID, bootstrapMap, staticMap, isRelayedPeer)

		nodeName := ""
		tapIP := ""
		tapIPv6 := ""
		osArch := ""
		version := ""
		uptimeStr := ""
		// Reachability reports the peer's SELF-REPORTED reachability ("Public"
		// or "Relay"), synced from its metadata. This is the exact signal the
		// WebUI Reachability column consumes (the frontend checks
		// reachability === "Public"). The locally observed connection mode
		// (direct / circuit / overlay) is already carried by is_relayed +
		// transport, so it must NOT be folded into this field — mixing the two
		// semantics is precisely the field-semantics bug class we keep hitting.
		reachability := ""
		if val, ok := n.peerMeta.Load(pID); ok {
			if m := val.(PeerMeta); m.Reachability != "" {
				reachability = m.Reachability
			}
		}
		if reachability == "" {
			// Before metadata arrives: a relayed peer cannot be "Public".
			if isRelayedPeer {
				reachability = "Relay"
			} else {
				reachability = "Public"
			}
		}

		isExitNode := false
		exitNAT := false
		var peerTxSpd, peerRxSpd, peerTotalTx, peerTotalRx uint64
		if val, ok := n.peerMeta.Load(pID); ok {
			meta := val.(PeerMeta)
			nodeName = meta.NodeName
			tapIP = meta.TapIP
			tapIPv6 = meta.TapIPv6
			osArch = meta.OSArch
			version = meta.Version
			isExitNode = meta.IsExitNode
			exitNAT = meta.ExitNAT
			if time.Since(meta.LastSync) < 45*time.Second {
				// Use locally-tracked per-peer byte counters for accurate
				// tx/rx speed (bytes sent TO / received FROM this peer).
				// Fall back to remote-reported metadata if local counters are
				// unavailable (e.g. metadata-only peer with no active stream).
				var txV, rxV *atomic.Uint64
				if v, ok := n.peerTxBytes.Load(pID); ok {
					txV = v.(*atomic.Uint64)
				}
				if v, ok := n.peerRxBytes.Load(pID); ok {
					rxV = v.(*atomic.Uint64)
				}
				curTx := uint64(0)
				curRx := uint64(0)
				if txV != nil {
					curTx = txV.Load()
				}
				if rxV != nil {
					curRx = rxV.Load()
				}

				n.perPeerBytesMu.Lock()
				lastTx := n.perPeerLastTx[pID]
				lastRx := n.perPeerLastRx[pID]
				n.perPeerLastTx[pID] = curTx
				n.perPeerLastRx[pID] = curRx

				// Divide by the REAL elapsed interval captured once at the start of
				// this snapshot (see above). intervalSec is shared by all peers and
				// reflects the true time between two updateWebCollectorState calls.
				if curTx >= lastTx {
					n.perPeerTxSpeed[pID] = uint64(float64(curTx-lastTx) / intervalSec)
				}
				if curRx >= lastRx {
					n.perPeerRxSpeed[pID] = uint64(float64(curRx-lastRx) / intervalSec)
				}
				peerTxSpd = n.perPeerTxSpeed[pID]
				peerRxSpd = n.perPeerRxSpeed[pID]
				n.perPeerBytesMu.Unlock()
			} else {
				peerTxSpd = 0
				peerRxSpd = 0
			}
			peerTotalTx = meta.TotalTx
			peerTotalRx = meta.TotalRx
			if meta.UptimeSec > 0 {
				dur := time.Duration(meta.UptimeSec) * time.Second
				if dur < time.Hour {
					uptimeStr = fmt.Sprintf("%dm", int(dur.Minutes()))
				} else {
					uptimeStr = fmt.Sprintf("%dh%dm", int(dur.Hours()), int(dur.Minutes())%60)
				}
			}
		}

		rttMs := n.getPeerLatency(pID)
		// getPeerLatency returns a 10ms floor when no real latency measurement
		// exists (the libp2p peerstore has no EWMA for this peer yet). For a
		// peer we have NO live libp2p connection to, that 10ms is a routing
		// sentinel, NOT a measured RTT — prefer the real multi-hop RTT from the
		// overlay routing table so the dashboard does not show a misleading
		// "10ms" for a peer that actually routes through several hops.
		if sig.connCount == 0 {
			if r, ok := routes[pID]; ok && r.TotalRTTMs > 0 {
				rttMs = r.TotalRTTMs
			}
		}
		// Only register a direct-link edge for peers we actually have a live
		// transport connection to. Pushing the 10ms sentinel as a "direct" link
		// for overlay-only peers fabricates a 10ms direct path that shadows the
		// real (slower, multi-hop) overlay route and misleads the router. Every
		// connected peer is (re)asserted as a direct link by the loop over
		// Host.Network().Peers() at the bottom of this function, so connected
		// peers are still covered.
		if sig.connCount > 0 && rttMs > 0 {
			// UpdateLinkRTT preserves the edge class (direct/circuit) instead of
			// overwriting it as direct.
			n.Router.UpdateLinkRTT(pID, rttMs)
		}

		geoLoc := "🌐 Public Peer"
		if strings.Contains(addr, "127.0.0.1") || strings.Contains(addr, "::1") {
			geoLoc = "🏠 Local Loopback"
		} else if strings.Contains(addr, "10.") || strings.Contains(addr, "192.168.") || strings.Contains(addr, "172.16.") {
			geoLoc = "🏠 Local Mesh"
		} else if strings.Contains(addr, "/p2p-circuit") {
			geoLoc = "🔀 Relay Server"
		} else if addr == "unknown" && tapIP != "" {
			// Overlay-only peer: there is no live connection address yet, so fall
			// back to the peer's synchronised TAP IP to still classify LAN vs
			// public instead of always reporting "Public Peer".
			if strings.HasPrefix(tapIP, "10.") || strings.HasPrefix(tapIP, "192.168.") || strings.HasPrefix(tapIP, "172.16.") || strings.HasPrefix(tapIP, "fd") {
				geoLoc = "🏠 Local Mesh"
			}
		}

		jitterMs := float64(rttMs) * 0.08
		if jitterMs < 0.1 && rttMs > 0 {
			jitterMs = 0.5
		}

		var earliestOpen time.Time
		for _, c := range n.Host.Network().ConnsToPeer(pID) {
			st := c.Stat()
			if earliestOpen.IsZero() || st.Opened.Before(earliestOpen) {
				earliestOpen = st.Opened
			}
		}

		connSinceStr := "-"
		connAtStr := "-"
		if !earliestOpen.IsZero() {
			connAtStr = earliestOpen.Format("15:04:05")
			dur := time.Since(earliestOpen)
			if dur < time.Minute {
				connSinceStr = fmt.Sprintf("%ds ago", int(dur.Seconds()))
			} else if dur < time.Hour {
				connSinceStr = fmt.Sprintf("%dm %ds", int(dur.Minutes()), int(dur.Seconds())%60)
			} else {
				connSinceStr = fmt.Sprintf("%dh %dm", int(dur.Hours()), int(dur.Minutes())%60)
			}
		}

		lastSeenStr := "Just now"
		if val, ok := n.peerMeta.Load(pID); ok {
			meta := val.(PeerMeta)
			if !meta.LastSync.IsZero() {
				secAgo := int(time.Since(meta.LastSync).Seconds())
				if secAgo > 1 {
					if secAgo < 60 {
						lastSeenStr = fmt.Sprintf("%ds ago", secAgo)
					} else {
						lastSeenStr = fmt.Sprintf("%dm ago", secAgo/60)
					}
				}
			}
		}

		addrMap := make(map[string]bool)
		allAddrs := make([]string, 0)
		// The live connection's `addr` (from ConnsToPeer) carries a trailing
		// `/p2p/<peerID>` component that libp2p appends to the transport
		// multiaddr after the security handshake. Peerstore addresses, by
		// contrast, are stored WITHOUT that suffix. Treat the two as the same
		// endpoint so the multiaddr modal doesn't list the active address twice
		// (once with, once without the peer-ID suffix) — openMultiaddrModal marks
		// exactly one row "Active" by comparing each candidate to peer.addr.
		peerIDSuffix := "/p2p/" + pID.String()
		activeBase := ""
		if addr != "" && addr != "unknown" && strings.HasSuffix(addr, peerIDSuffix) {
			activeBase = strings.TrimSuffix(addr, peerIDSuffix)
		}
		if addr != "" && addr != "unknown" {
			addrMap[addr] = true
			allAddrs = append(allAddrs, addr)
		}
		for _, a := range filterLoopbackAddrs(n.Host.Peerstore().Addrs(pID)) {
			s := a.String()
			if activeBase != "" && s == activeBase {
				// Same endpoint as the active addr, just missing the /p2p/<id> suffix.
				continue
			}
			if !addrMap[s] {
				addrMap[s] = true
				allAddrs = append(allAddrs, s)
			}
		}

		// ── ConnState: aggregate every stage into one verdict ──
		// Stage 1 = connection, 2 = app protocol (/p2ptap/application/1.0.0) usable,
		// 3 = encryption negotiated, 4 = real data decrypting successfully.
		// For relayed peers the data-stage health is sampled from the relay hop
		// (the envelope cipher is negotiated with the hop, not the final peer).
		connState, connStage, connDetail := n.derivePeerConnState(pID, role)

		// Per-peer encryption/obfuscation state negotiated via SeqSync ECDH
		// (re-derived here for the inline Encryption column of the WebUI).
		obfNegotiated, obfAlgo, obfEncrypted := n.obfStateForPeer(pID)

		peersDTO = append(peersDTO, observer.PeerInfoDTO{
			PeerID:            pID.String(),
			NodeName:          nodeName,
			Role:              role,
		IsRelayed:         isRelayedPeer,
		RelayOnly:         n.isRelayOnlyPeer(pID),
		IsExitNode:        isExitNode,
			ExitNAT:           exitNAT,
			TxSpeed:           peerTxSpd,
			RxSpeed:           peerRxSpd,
			TotalTx:           peerTotalTx,
			TotalRx:           peerTotalRx,
			TapIP:             tapIP,
			TapIPv6:           tapIPv6,
			OSArch:            osArch,
			Version:           version,
			Uptime:            uptimeStr,
			ConnectedAt:       connAtStr,
			ConnectedSince:    connSinceStr,
			LastSeen:          lastSeenStr,
			Reachability:      reachability,
			Addr:              addr,
			AllAddrs:          allAddrs,
			Transport:         transport,
			RTTMs:             rttMs,
			JitterMs:          float64(int(jitterMs*10)) / 10.0,
			LossRatePercent:   0.0,
			GeoLocation:       geoLoc,
			ObfNegotiated:     obfNegotiated,
			ObfAlgo:           obfAlgo,
			ObfEncrypted:      obfEncrypted,
			SeqSyncConvergeMs: n.peerSeqSyncConvergeMs(pID),
			ConnState:         connState,
			ConnStage:         connStage,
			ConnDetail:        connDetail,
		})
	}

	// Build MAC & ARP Table DTOs
	macDTO := make([]observer.MACInfoDTO, 0)
	arpDTO := make([]observer.ARPInfoDTO, 0)
	seenIP := make(map[string]bool)
	now := time.Now()

	// 1. Process peerMeta first (Highest Priority: official synced metadata from peer's config.json)
	n.peerMeta.Range(func(key, value interface{}) bool {
		pID := key.(peer.ID)
		meta := value.(PeerMeta)
		macStr := meta.TapMAC
		if macStr == "" {
			for mStr, entry := range n.MACTable.GetAllEntries() {
				if entry.PeerID == pID {
					macStr = mStr
					break
				}
			}
		}

		if meta.TapIP != "" {
			cleanV4 := strings.Split(meta.TapIP, "/")[0]
			if !seenIP[cleanV4] {
				seenIP[cleanV4] = true
				arpDTO = append(arpDTO, observer.ARPInfoDTO{
					IP:       cleanV4,
					MAC:      macStr,
					PeerID:   pID.String(),
					NodeName: meta.NodeName,
					Type:     "Dynamic (ARP)",
					LastSeen: "Just now",
				})
			}
		}

		if meta.TapIPv6 != "" {
			cleanV6 := strings.Split(meta.TapIPv6, "/")[0]
			if !seenIP[cleanV6] {
				seenIP[cleanV6] = true
				arpDTO = append(arpDTO, observer.ARPInfoDTO{
					IP:       cleanV6,
					MAC:      macStr,
					PeerID:   pID.String(),
					NodeName: meta.NodeName,
					Type:     "Dynamic (NDP)",
					LastSeen: "Just now",
				})
			}
		}
		return true
	})

	// 2. Process local node entries (local IP & MAC)
	for _, entry := range n.buildLocalARPEntries(nodeName) {
		if !seenIP[entry.IP] {
			seenIP[entry.IP] = true
			arpDTO = append(arpDTO, entry)
		}
	}

	// 3. Process remaining MACTable entries (dynamically learned MAC entries)
	for macStr, entry := range n.MACTable.GetAllEntries() {
		// Classify origin: a peer's OWN virtual TAP MAC (synced via peerMeta,
		// or our own n.Config.TapMAC) is "self"; everything else learned from
		// that peer is a device on its LAN forwarded through it ("lan"). This
		// disambiguates the common "why does one peer have many MACs?" case.
		origin := observer.MACOriginLAN
		if entry.PeerID == n.Host.ID() {
			if n.Config.TapMAC != "" && macStr == n.Config.TapMAC {
				origin = observer.MACOriginSelf
			}
		} else if val, ok := n.peerMeta.Load(entry.PeerID); ok {
			if meta, ok2 := val.(PeerMeta); ok2 && meta.TapMAC != "" && meta.TapMAC == macStr {
				origin = observer.MACOriginSelf
			}
		}
		ago := now.Sub(entry.LastSeen).Truncate(time.Second).String() + " ago"
		macDTO = append(macDTO, observer.MACInfoDTO{
			MAC:        macStr,
			PeerID:     entry.PeerID.String(),
			Origin:     origin,
			LastSeen:   ago,
			LastSeenTS: entry.LastSeen.Unix(),
		})

		nodeName := ""
		ip := entry.IP
		tapIPv6 := ""
		if val, ok := n.peerMeta.Load(entry.PeerID); ok {
			meta := val.(PeerMeta)
			if nodeName == "" {
				nodeName = meta.NodeName
			}
			if ip == "" {
				ip = meta.TapIP
			}
			tapIPv6 = meta.TapIPv6
		}

		if ip != "" {
			cleanV4 := strings.Split(ip, "/")[0]
			if !seenIP[cleanV4] {
				seenIP[cleanV4] = true
				arpDTO = append(arpDTO, observer.ARPInfoDTO{
					IP:       cleanV4,
					MAC:      macStr,
					PeerID:   entry.PeerID.String(),
					NodeName: nodeName,
					Type:     "Dynamic (ARP)",
					LastSeen: ago,
				})
			}
		}

		if tapIPv6 != "" {
			cleanV6 := strings.Split(tapIPv6, "/")[0]
			if !seenIP[cleanV6] {
				seenIP[cleanV6] = true
				arpDTO = append(arpDTO, observer.ARPInfoDTO{
					IP:       cleanV6,
					MAC:      macStr,
					PeerID:   entry.PeerID.String(),
					NodeName: nodeName,
					Type:     "Dynamic (NDP)",
					LastSeen: ago,
				})
			}
		}
	}

	listenAddrsStrs := make([]string, 0)
	for _, a := range n.Host.Addrs() {
		listenAddrsStrs = append(listenAddrsStrs, fmt.Sprintf("%s/p2p/%s", a, n.Host.ID().String()))
	}
	n.Collector.UpdateListenAddrs(listenAddrsStrs)

	natStatus := "🟢 Public (Directly Reachable)"
	if len(n.Host.Network().Peers()) == 0 && len(n.Config.BootstrapPeers) > 0 {
		natStatus = "🟡 Symmetric NAT / Relay Mode"
	}
	n.Collector.UpdateNATStatus(natStatus)

	n.Collector.SetDispatchDrops(atomic.LoadUint64(&n.dispatchDropCount))
	n.Collector.UpdatePeers(peersDTO)
	n.cacheActivePeers(peersDTO)
	n.Collector.UpdateMACTable(macDTO)
	n.Collector.UpdateARPTable(arpDTO)

	// Build SubnetRoutes DTOs FIRST so the IP tracker can resolve IPs that
	// live inside a peer's advertised subnet (e.g. 192.168.100.0/24) back to
	// that peer's node name, instead of leaving them as "Unnamed Node".
	subnetDTOs := make([]observer.SubnetRouteDTO, 0)
	n.peerMeta.Range(func(key, value interface{}) bool {
		pID := key.(peer.ID)
		if pID == n.Host.ID() {
			return true // Exclude local node's own advertised subnets
		}
		meta := value.(PeerMeta)
		for _, sub := range meta.AdvertisedSubnets {
			status := "Pending Authorization"
			if n.Config.AcceptAdvertisedSubnets {
				for _, allowed := range n.Config.AllowedSubnetPeers {
					if allowed == "*" || allowed == pID.String() {
						status = "Active (Authorized)"
						break
					}
				}
			}
			isDisabled := false
			if n.Gateway != nil && n.Gateway.IsSubnetDisabled(sub) {
				isDisabled = true
				if status == "Active (Authorized)" {
					status = "Disabled (Manual)"
				}
			}
			subnetDTOs = append(subnetDTOs, observer.SubnetRouteDTO{
				SubnetCIDR:  sub,
				PeerID:      pID.String(),
				NodeName:    meta.NodeName,
				GatewayIP:   meta.TapIP,
				GatewayIPv6: meta.TapIPv6,
				Status:      status,
				Disabled:    isDisabled,
				// Carry the IsExitNode flag so the IP-info resolver can label
				// IPs that fall inside this subnet as "via Exit Node". This is
				// independent of the Authorization status — a pending subnet
				// still tags routed IPs so the operator can see where the
				// traffic is going before explicitly authorizing it.
				IsExitNode: meta.IsExitNode,
			})
		}
		return true
	})
	n.Collector.UpdateSubnetRoutes(subnetDTOs)
	n.Collector.UpdateDuplicateIPConflicts(toDuplicateIPConflictDTOs(n.GetDuplicateIPConflicts()))

	// IP tracker resolves each recorded IP back to a node, using the
	// advertised subnet list as the 4th fallback (so e.g. 192.168.100.3
	// shows the peer that owns 192.168.100.0/24 instead of "Unnamed Node").
	// When this node is an Exit-Client (a remote Exit Node is selected as the
	// system default gateway), pass that peer ID in so unmatched IPs (open
	// internet destinations) are tagged as egressing through the Exit Node.
	localExitPeerID := ""
	if n.Gateway != nil {
		localExitPeerID = n.Gateway.ActiveExitPeerID()
	}
	ipDTO := n.IPTracker.GetDTOs(&n.peerMeta, n.Config.NodeName, n.Config.TapIP, n.Config.TapIPv6, n.Host.ID().String(), subnetDTOs, localExitPeerID)
	n.Collector.UpdateIPTable(ipDTO)

	// Ensure all connected peers are present in the Router link-state graph
	for _, pID := range n.Host.Network().Peers() {
		rttMs := n.getPeerLatency(pID)
		if rttMs <= 0 {
			rttMs = 10
		}
		n.Router.UpdateLinkRTT(pID, rttMs)
	}

	routesDTO := n.Router.GetRouteInfoDTOs(func(pID peer.ID) (string, string, string) {
		if val, ok := n.peerMeta.Load(pID); ok {
			meta := val.(PeerMeta)
			return meta.NodeName, meta.TapIP, meta.TapIPv6
		}
		return "", "", ""
	})
	// Annotate each route with its ACTUAL transport path. The routing layer
	// marks circuit-relayed peers as IsDirect=true (they are registered as direct
	// links via UpdateDirectLink), so without this the WebUI would label them
	// "Direct" while their real RTT is a relayed hundreds-of-ms. Distinguish:
	//   overlay-relay → NextHop != dest (p2ptap's own overlay relay)
	//   circuit-relay → IsDirect but the peer's libp2p conn is /p2p-circuit
	//   direct        → a genuine direct transport connection
	for i := range routesDTO {
		rd := &routesDTO[i]
		if !rd.IsDirect {
			rd.TransportPath = "overlay-relay"
			continue
		}
		if pid, err := peer.Decode(rd.DestPeer); err == nil && n.peerHasCircuitRelayConn(pid) {
			rd.TransportPath = "circuit-relay"
		} else {
			rd.TransportPath = "direct"
		}
	}
	n.Collector.UpdateRoutes(routesDTO)

	// Build PeerMeta DTOs (synced metadata via peek-map / LSA / P2P stream)
	metaDTOs := make([]observer.PeerMetaDTO, 0)
	n.peerMeta.Range(func(key, value interface{}) bool {
		pID := key.(peer.ID)
		meta := value.(PeerMeta)
		syncSrc := meta.SyncSource
		if syncSrc == "" {
			syncSrc = "P2P / LSA"
		}
		lastSyncStr := "-"
		if !meta.LastSync.IsZero() {
			elapsed := time.Since(meta.LastSync).Truncate(time.Second)
			if elapsed < time.Second {
				lastSyncStr = "Just now"
			} else {
				lastSyncStr = fmt.Sprintf("%v ago", elapsed)
			}
		}
		metaDTOs = append(metaDTOs, observer.PeerMetaDTO{
			PeerID:            pID.String(),
			NodeName:          meta.NodeName,
			TapIP:             meta.TapIP,
			TapIPv6:           meta.TapIPv6,
			TapMAC:            meta.TapMAC,
			OSArch:            meta.OSArch,
			Version:           meta.Version,
			IsExitNode:        meta.IsExitNode,
			ExitNAT:           meta.ExitNAT,
			AdvertisedSubnets: meta.AdvertisedSubnets,
			SyncSource:        syncSrc,
			LastSync:          lastSyncStr,
			UptimeSec:         meta.UptimeSec,
		})
		return true
	})
	n.Collector.UpdatePeerMetas(metaDTOs)

	// Build MeshMatrix DTOs
	matrixDTOs := make([]observer.MeshMatrixCellDTO, 0)
	routesMap := n.getCachedRoutes()
	for destPeer, r := range routesMap {
		destName := destPeer.String()
		if val, ok := n.peerMeta.Load(destPeer); ok {
			if metaName := val.(PeerMeta).NodeName; metaName != "" {
				destName = metaName
			}
		}
		// Hops = number of links = number of nodes in path minus 1 (path
		// includes both the local node and the destination). A direct link is 1
		// hop; one relay is 2 hops, etc. Guard against an empty path.
		hops := len(r.Path) - 1
		if hops < 0 {
			hops = 0
		}
		matrixDTOs = append(matrixDTOs, observer.MeshMatrixCellDTO{
			SrcPeerID: n.Host.ID().String(),
			SrcName:   n.nodeName,
			DstPeerID: destPeer.String(),
			DstName:   destName,
			RTTMs:     r.TotalRTTMs,
			Hops:      hops,
			IsDirect:  r.IsDirect,
		})
	}
	n.Collector.UpdateMeshMatrix(matrixDTOs)

	log.Debug("Web collector updated: %d active peers, %d MACs, %d ARP entries, %d IP entries, %d routes, %d subnets", len(peersDTO), len(macDTO), len(arpDTO), len(ipDTO), len(routesDTO), len(subnetDTOs))
}

// cacheActivePeers stores the latest PeerInfoDTO slice locally so that
// node-internal lookups (PeekPeerID, resolvePeerIDByName) do not need to read
// back from the Collector interface.  The Collector is a push-only sink.
func (n *Node) cacheActivePeers(peers []observer.PeerInfoDTO) {
	n.activePeersMu.Lock()
	n.activePeers = peers
	n.activePeersMu.Unlock()
	// Keep the WebUI per-peer encryption panel in sync with the live peer set
	// (covers peers that never negotiate a cipher).
	n.pushPeerEncryption()
}

// getActivePeers returns a snapshot of the last pushed peer list.  It is safe
// for concurrent use and never returns nil (an empty slice when uncached).
func (n *Node) getActivePeers() []observer.PeerInfoDTO {
	n.activePeersMu.RLock()
	defer n.activePeersMu.RUnlock()
	if n.activePeers == nil {
		return []observer.PeerInfoDTO{}
	}
	return n.activePeers
}

// peekPeerIDFromList resolves a partial peer identifier (PeerID, TapIP,
// TapIPv6, or NodeName) to a full PeerID string, mirroring the old
// Collector.PeekPeerID behaviour but reading from a local peer list.
func peekPeerIDFromList(peers []observer.PeerInfoDTO, idStr string) (string, bool) {
	for _, p := range peers {
		if p.PeerID == idStr || p.TapIP == idStr || p.TapIPv6 == idStr || strings.EqualFold(p.NodeName, idStr) {
			return p.PeerID, true
		}
	}
	return "", false
}

// TestMultiaddrLatency probes every known multiaddr for the given peer by
// performing a raw transport-level dial to each address.  It measures per-address
// RTT, supports concurrent probing with a timeout (3s per address, 2 retries),
// and returns results sorted from fastest to slowest.
//
// relay/circuit addresses are marked as reachable (the relay path is already
// established) but receive the cached EWMA latency when available.
//
// Note: we use net.DialTimeout on the underlying transport address extracted
// via manet.DialArgs, so the measurement reflects TCP/UDP handshake time at
// the OS level — this is independent of libp2p stream/connection state and
// does not create persistent libp2p connections.
//
// rtt_ms semantics:
//   * > 0       — measured dial RTT in milliseconds.
//   * 0         — never emitted; an inconclusive probe is encoded as -1 below.
//   * -1        — probe inconclusive (e.g. a non-active raw UDP/TCP dial
//                 completed in <1ms before any handshake; the kernel route
//                 exists but the application-layer listener is not verified).
//                 UI should render this as "unverified / —" rather than 0ms.
func (n *Node) TestMultiaddrLatency(targetStr string) []observer.MultiaddrTestResultEntry {
	var pID peer.ID
	var candidateAddrs []string

	decodedPID, err := peer.Decode(targetStr)
	if err == nil {
		pID = decodedPID
	} else if n.Collector != nil {
		for _, p := range n.getActivePeers() {
			if p.PeerID == targetStr || p.TapIP == targetStr || p.TapIPv6 == targetStr || strings.EqualFold(p.NodeName, targetStr) {
				if parsed, err := peer.Decode(p.PeerID); err == nil {
					pID = parsed
					candidateAddrs = p.AllAddrs
					break
				}
			}
		}
	}

	if pID == "" {
		return nil
	}

	// Drop loopback addresses (127.0.0.0/8, ::1) learned from peers: they are
	// only reachable on THIS host, so listing/dialing them is meaningless and
	// would mislead the operator. This is the receive-side guard that mirrors
	// the broadcast-side filter in AddrsFactory.
	peerstoreAddrs := filterLoopbackAddrs(n.Host.Peerstore().Addrs(pID))

	// Collect all unique multiaddrs: peerstore + current active connection + candidates.
	seen := make(map[string]bool)
	uniqueAddrs := make([]multiaddr.Multiaddr, 0)

	for _, a := range peerstoreAddrs {
		s := a.String()
		if !seen[s] {
			seen[s] = true
			uniqueAddrs = append(uniqueAddrs, a)
		}
	}

	for _, addStr := range candidateAddrs {
		if !seen[addStr] {
			if ma, err := multiaddr.NewMultiaddr(addStr); err == nil {
				seen[addStr] = true
				uniqueAddrs = append(uniqueAddrs, ma)
			}
		}
	}

	// Determine which address is currently in active use.
	activeAddr := ""
	for _, c := range n.Host.Network().ConnsToPeer(pID) {
		a := c.RemoteMultiaddr().String()
		if a != "" {
			activeAddr = a
			break
		}
	}
	// Ensure the active address is represented even if the peerstore is stale.
	if activeAddr != "" {
		if ma, err := multiaddr.NewMultiaddr(activeAddr); err == nil && !seen[activeAddr] {
			uniqueAddrs = append(uniqueAddrs, ma)
		}
	}

	if len(uniqueAddrs) == 0 {
		return nil
	}

	type probeResult struct {
		addr      string
		reachable bool
		rttMs     int64
		err       string
		isActive  bool
		note      string // estimate-only annotation (relay/circuit EWMA), empty for measured rows
	}
	results := make([]probeResult, len(uniqueAddrs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8) // max 8 concurrent probes

	for i, ma := range uniqueAddrs {
		idx := i
		addr := ma
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addrStr := addr.String()
			isActive := (addrStr == activeAddr)

			if isActive {
				if echoRes := n.ProbePeerEcho(pID.String()); echoRes != nil && echoRes.Success {
					results[idx] = probeResult{addr: addrStr, reachable: true, rttMs: int64(echoRes.RTTMs), isActive: isActive}
					return
				}
			}

			// Relay/circuit addresses — the relay connection is already established
			// by the libp2p host; we cannot meaningfully dial a *specific* relay leg
			// from here, so we must NOT present the cached peer-level EWMA as if it
			// were a per-path measured RTT (that made every relay row look identical
			// at the same value). Surface it as an *estimate* (note) only and keep
			// rttMs at the -1 "inconclusive" sentinel so the UI stops claiming each
			// relay row was independently timed.
			if strings.Contains(addrStr, "/p2p-circuit") {
				var note string
				if ewma := n.Host.Peerstore().LatencyEWMA(pID); ewma > 0 {
					note = fmt.Sprintf("relay EWMA ≈%d ms (estimated, not per-path probed)", ewma.Milliseconds())
				} else {
					note = "relay path (latency not yet estimated)"
				}
				results[idx] = probeResult{addr: addrStr, reachable: true, rttMs: -1, err: "", note: note, isActive: isActive}
				return
			}

			// Strip any trailing /p2p/… component so manet can parse the transport part.
			transportMA := addr
			if _, err := addr.ValueForProtocol(multiaddr.P_P2P); err == nil {
				if dec, derr := multiaddr.NewMultiaddr(strings.TrimSuffix(addrStr, "/p2p/"+pID.String())); derr == nil {
					transportMA = dec
					if trimmed2, derr2 := multiaddr.NewMultiaddr(strings.SplitN(addrStr, "/p2p/", 2)[0]); derr2 == nil {
						transportMA = trimmed2
					}
				}
			}

			netType, dialAddr, err := manet.DialArgs(transportMA)
			if err != nil {
				// Fallback: strip exotic transport suffixes (quic-v1, webrtc-direct, webtransport, certhash, etc.)
				// to extract pure IP+Port multiaddr for underlying socket probing.
				if cleanMA, cleanErr := extractCleanTransportMA(transportMA); cleanErr == nil {
					netType, dialAddr, err = manet.DialArgs(cleanMA)
				}
			}
			if err != nil {
				if isActive {
					results[idx] = probeResult{addr: addrStr, reachable: true, rttMs: n.realPeerLatencyMs(pID), err: "", isActive: isActive}
				} else {
					results[idx] = probeResult{addr: addrStr, reachable: false, err: "unsupported transport: " + err.Error(), isActive: isActive}
				}
				return
			}

			// Probe with timeout + retry.
			timeout := 3 * time.Second
			maxAttempts := 2

			for attempt := 0; attempt < maxAttempts; attempt++ {
				start := time.Now()
				conn, dialErr := net.DialTimeout(netType, dialAddr, timeout)
				elapsed := time.Since(start)

				if dialErr == nil {
					conn.Close()
					rtt := elapsed.Milliseconds()
					if rtt == 0 && !isActive {
						// Raw-socket dial completed in <1ms — for non-active addresses this
						// almost always means the kernel-side UDP "connect" returned before
						// any real handshake, so we never actually verified the transport
						// listener is up. Encode as -1 (probe inconclusive) so the UI stops
						// claiming "Reachable · 0 ms" for what's really a routing-only check.
						rtt = -1
					} else if rtt == 0 && isActive {
						// For the active address we have a live stream already, so fall back
						// to the cached EWMA if the raw dial happens to round to 0 (loopback).
						rtt = n.realPeerLatencyMs(pID)
					}
					results[idx] = probeResult{addr: addrStr, reachable: true, rttMs: rtt, isActive: isActive}
					return
				}

				if attempt < maxAttempts-1 {
					time.Sleep(200 * time.Millisecond) // backoff between retries
				} else {
					if isActive {
						// For active UDP (QUIC/WebRTC) connections where raw TCP dial fails, mark reachable using active stream RTT.
						results[idx] = probeResult{addr: addrStr, reachable: true, rttMs: n.realPeerLatencyMs(pID), isActive: isActive}
					} else {
						results[idx] = probeResult{addr: addrStr, reachable: false, rttMs: 0, err: "unreachable: " + dialErr.Error(), isActive: isActive}
					}
				}
			}
		}()
	}
	wg.Wait()

	// Sort: reachable first (sorted by RTT ascending), then unreachable.
	dto := make([]observer.MultiaddrTestResultEntry, len(results))
	for i, r := range results {
		dto[i] = observer.MultiaddrTestResultEntry{
			Addr:      r.addr,
			Reachable: r.reachable,
			RTTMs:     r.rttMs,
			Error:     r.err,
			IsActive:  r.isActive,
			Note:      r.note,
		}
	}
	// Stable sort: active first, then reachable sorted by RTT, then unreachable.
	sortMultiaddrResults(dto)
	return dto
}

func sortMultiaddrResults(results []observer.MultiaddrTestResultEntry) {
	// Simple insertion-sort: active > reachable(lowest RTT first) > unreachable.
	for i := 1; i < len(results); i++ {
		j := i
		for j > 0 && lessAddrEntry(results[j], results[j-1]) {
			results[j], results[j-1] = results[j-1], results[j]
			j--
		}
	}
}

func lessAddrEntry(a, b observer.MultiaddrTestResultEntry) bool {
	if a.IsActive != b.IsActive {
		return a.IsActive
	}
	if a.Reachable != b.Reachable {
		return a.Reachable
	}
	// rttMs == -1 means "probe inconclusive / never actually sent" (sentinel,
	// see TestMultiaddrLatency). Treat it as a worse-than-any-real-RTT value so
	// it sorts to the END, not before real measurements (which would wrongly
	// promote an unprobed address above a known-good one).
	ar := a.RTTMs
	if ar < 0 {
		ar = math.MaxInt32
	}
	br := b.RTTMs
	if br < 0 {
		br = math.MaxInt32
	}
	return ar < br
}

// derivePeerConnState collapses every per-peer connectivity/encryption signal
// into a single verdict (ConnState), a completed-stage count (ConnStage, 0..4)
// and a short human-readable supplement (ConnDetail). Intended for the WebUI
// "status" column so the operator can see at a glance how far the handshake
// got and whether real (decrypted) traffic is flowing.
//
// All raw signals (connection classification, obfuscation negotiation, decrypt
// counters) are derived internally so the caller only passes the peer and its
// already-known role, keeping the single call site clean:
//
//	connState, connStage, connDetail := n.derivePeerConnState(pID, role)
//
// Stages: 1 connection, 2 app protocol usable, 3 encryption negotiated,
// 4 data decrypts.
func (n *Node) derivePeerConnState(pID peer.ID, role string) (string, int, string) {
	// Bootstrap/relay nodes are pure Circuit-Relay hops: they register echo/seqsync
	// but not the application data protocol, so they are reported as healthy relays.
	if role == "Bootstrap" {
		return connStateOK, 2, "relay hop (echo/seqsync)"
	}

	sig := n.deriveConnSignals(pID)
	connected := sig.connCount > 0
	stage := 0
	if !connected {
		return connStateUnreachable, stage, "no direct or relay connection"
	}

	// Stage 1 done.
	stage = 1

	// Stage 2: the application protocol (/p2ptap/application/1.0.0) is usable when
	// either a real AEAD was negotiated (implies the protocol was reached) or the
	// node runs in plaintext "none" obfuscation mode (no encryption by design).
	obfNegotiated, obfAlgo, obfEncrypted := n.obfStateForPeer(pID)
	protoOK := obfEncrypted || obfAlgo == "none"
	if !protoOK {
		// Connected but never established an application channel → almost always a
		// mixed-version mismatch (old peer without /p2ptap/application/1.0.0).
		return connStateProtoMismatch, stage,
			"app protocol /p2ptap/application/1.0.0 not shared (mixed version?)"
	}
	stage = 2

	// Stage 3: encryption negotiated.
	if !obfNegotiated {
		return connStateConnecting, stage, "protocol OK, encryption handshake pending"
	}
	if !obfEncrypted {
		// plaintext "none" mode: protocol works but no AEAD in use.
		return connStateOK, stage, "plaintext obfuscation (encryption disabled)"
	}
	stage = 3

	// Stage 3.5: mutual readiness handshake. Encryption is negotiated, but TAP
	// data is only transmitted once both sides have exchanged a reciprocal
	// "ready" acknowledgement (see seqsync.go). Surface this phase so the UI
	// shows "awaiting peer ready" instead of a misleading "awaiting data".
	if !n.isPeerReady(pID) {
		return connStateConnecting, 3, obfAlgo + " negotiated, awaiting peer ready"
	}

	// Stage 4: real data decrypting. The relay envelope is end-to-end encrypted
	// by the origin for this peer, so decrypt counters are recorded under pID
	// itself (sampled at the final destination in handleRelayStream).
	ok, _ := n.peerRxDecryptStats(pID)
	// The decrypt counters are cumulative for the node's lifetime and are never
	// reset, so a single transient failure during the ECDH/SeqSync handshake
	// window (or a re-routed/replayed frame) can leave err>0 forever. A lone
	// historical failure must NOT stick the connection in "Decrypt Fail" once
	// traffic has settled: only report failure when this peer is *still*
	// actively failing RIGHT NOW (recentErrs window). If even one frame since
	// then decrypted successfully, recentErrs is cleared and we fall through to
	// the "awaiting data" / OK stages instead of showing a false failure.
	_, rxSpd := n.getPeerSpeed(pID)
	recentErr := n.peerRxDecryptRecentErrsStats(pID)
	if recentErr > 0 && ok == 0 && rxSpd > 0 {
		return connStateObfFailed, stage,
			"decryption failing: " + obfAlgo + " auth errors (" + strconv.FormatUint(recentErr, 10) + ")"
	}
	if ok > 0 {
		stage = 4
		if sig.isRelayed {
			return connStateRelayOK, 4, obfAlgo + " OK via relay"
		}
		return connStateOK, 4, obfAlgo + " end-to-end OK"
	}
	// No frames seen yet (or plaintext path without AEAD counters): report the
	// best-known stage as "connecting" rather than a false failure.
	return connStateConnecting, 3, obfAlgo + " negotiated, awaiting data"
}
