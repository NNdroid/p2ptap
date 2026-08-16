package node

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"p2ptap/pkg/meta"
	"p2ptap/pkg/observer"
	"p2ptap/pkg/routing"
	"p2ptap/pkg/tap"
	"p2ptap/pkg/version"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/multiformats/go-multiaddr"
)

func (n *Node) registerMetaStreamHandler() {
	n.Host.SetStreamHandler(meta.MetaProtocolID, func(s network.Stream) {
		n.handleMetaStream(s)
	})
	log.Debug("Stream handler registered for metadata protocol: %s", meta.MetaProtocolID)
}

// handleMetaStream processes a metadata sync exchange on s. It is the shared
// body used both for the direct MetaProtocolID stream handler and for the
// relay-ctrl tunnel's inner dispatch (logicalPeerStream makes s.Conn().RemotePeer()
// report the true origin so identity is stored under the real counterpart).
func (n *Node) handleMetaStream(s network.Stream) {
	startTime := time.Now()
	defer s.Close()
	remotePeer := s.Conn().RemotePeer()

	// Length-prefixed frame loop (B). The peer reuses a persistent meta
	// stream across ticks, so we answer each incoming request frame with a
	// response frame instead of closing after one exchange.
	buf := make([]byte, 64*1024)
	for {
		rn, err := ReadFrame(s, buf)
		if err != nil {
			if err != io.EOF {
				log.Debug("Meta stream read error from %s: %v", remotePeer.String(), err)
			}
			return
		}
		if rn == 0 {
			continue
		}
		data := buf[:rn]

		var payload meta.NodeMetaPayload
		if err := json.Unmarshal(data, &payload); err == nil {
			n.storePeerMeta(remotePeer, PeerMeta{
				NodeName:          payload.NodeName,
				TapIP:             payload.TapIP,
				TapIPv6:           payload.TapIPv6,
				TapMAC:            payload.TapMAC,
				OSArch:            fmt.Sprintf("%s/%s", payload.OS, payload.Arch),
				Version:           payload.Version,
				UptimeSec:         payload.UptimeSec,
				Reachability:      payload.Reachability,
				IsExitNode:        payload.IsExitNode,
				ExitNAT:           payload.ExitNAT,
				TxSpeed:           payload.TxSpeed,
				RxSpeed:           payload.RxSpeed,
				TotalTx:           payload.TotalTx,
				TotalRx:           payload.TotalRx,
				AdvertisedSubnets: payload.AdvertisedSubnets,
				SyncSource:        "P2P Stream Direct",
				LastSync:          time.Now(),
			})
			n.processSubnetRoutes(remotePeer, payload.TapIP, payload.TapIPv6, payload.AdvertisedSubnets)
			if payload.TapMAC != "" {
				if hw, err := net.ParseMAC(payload.TapMAC); err == nil && len(hw) == 6 {
					n.MACTable.Learn(hw, remotePeer)
					cleanIP := strings.Split(payload.TapIP, "/")[0]
					cleanv6 := strings.Split(payload.TapIPv6, "/")[0]
					if setter, ok := n.TAP.(interface{ RegisterIPMAC(string, string) }); ok {
						if cleanIP != "" {
							setter.RegisterIPMAC(cleanIP, payload.TapMAC)
						}
						if cleanv6 != "" {
							setter.RegisterIPMAC(cleanv6, payload.TapMAC)
						}
					}
					if ip := net.ParseIP(cleanIP); ip != nil && len(ip.To4()) == 4 && n.TAP != nil {
						garpFrame := tap.BuildARPReplyFrame(hw, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ip, ip)
						_, _ = n.TAP.Write(garpFrame)
					}
					if ip6 := net.ParseIP(cleanv6); ip6 != nil && ip6.To16() != nil && n.TAP != nil {
						naFrame := tap.BuildIPv6NeighborAdvertisementFrame(hw, ip6)
						if len(naFrame) > 0 {
							_, _ = n.TAP.Write(naFrame)
						}
					}
				}
			}
			log.Debug("Received metadata sync from peer %s: name=%s os=%s/%s tap_ip=%s mac=%s ver=%s exit_node=%v tx_speed=%d rx_speed=%d",
				remotePeer.String(), payload.NodeName, payload.OS, payload.Arch, payload.TapIP, payload.TapMAC, payload.Version, payload.IsExitNode, payload.TxSpeed, payload.RxSpeed)
		}

		// Respond with local node's metadata (length-prefixed frame).
		localTxRx := observer.TxRxStats{}
		if n.Collector != nil {
			localTxRx = n.Collector.GetTxRxStats()
		}
		respPayload := meta.NodeMetaPayload{
			NodeName:          n.Config.NodeName,
			TapIP:             n.Config.TapIP,
			TapIPv6:           n.Config.TapIPv6,
			TapMAC:            n.Config.TapMAC,
			OS:                runtime.GOOS,
			Arch:              runtime.GOARCH,
			Version:           version.Version,
			UptimeSec:         int64(time.Since(startTime).Seconds()),
			Reachability:      "P2P Node",
			IsExitNode:        n.Config.ExitNode.Enable,
			ExitNAT:           n.Config.ExitNode.NATMasquerade,
			TxSpeed:           localTxRx.TxSpeed,
			RxSpeed:           localTxRx.RxSpeed,
			TotalTx:           localTxRx.TotalTx,
			TotalRx:           localTxRx.TotalRx,
			AdvertisedSubnets: n.Config.AdvertisedSubnets,
		}
		if respBytes, err := json.Marshal(respPayload); err == nil {
			_ = WriteFrame(s, respBytes)
		}
	}
}

func (n *Node) metaSyncLoop() {
	defer n.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Initial sync immediately after startup
	time.Sleep(2 * time.Second)
	n.broadcastMetadata()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.broadcastMetadata()
		}
	}
}

func (n *Node) getAllPeersForMetaSync() []peer.ID {
	seen := make(map[peer.ID]bool)
	list := make([]peer.ID, 0)
	for _, p := range n.Host.Network().Peers() {
		if !seen[p] {
			seen[p] = true
			list = append(list, p)
		}
	}
	for _, entry := range n.MACTable.GetAllEntries() {
		if entry.PeerID != "" && entry.PeerID != n.Host.ID() && !seen[entry.PeerID] {
			seen[entry.PeerID] = true
			list = append(list, entry.PeerID)
		}
	}
	for targetPeer := range n.Router.ComputeRoutes() {
		if targetPeer != "" && targetPeer != n.Host.ID() && !seen[targetPeer] {
			seen[targetPeer] = true
			list = append(list, targetPeer)
		}
	}
	return list
}

// syncMetadataToPeer performs a single-peer metadata exchange (meta protocol).
// It opens a libp2p stream to targetPeer, sends our NodeMetaPayload, reads the
// remote response, and updates peerMeta / MAC table / ARP-ND cache accordingly.
// This is safe for circuit-relay peers because libp2p transparently routes the
// stream via p2p-circuit when no direct transport exists.
//
// NOTE: this per-peer meta stream is a BEST-EFFORT enhancement channel. Node
// identity (name/IP/MAC) is primarily carried piggyback on the periodic LSA
// broadcast (see applyPeerMetaFromLSA) which is far more resilient on circuit
// relay paths. That is why failures here are logged at debug level and only
// retried a couple of times: a timeout is expected when the peer is only
// reachable over an unreachable direct address, and it is not fatal.
func (n *Node) syncMetadataToPeer(targetPeer peer.ID) {
	// Relay-only peers may need a few more attempts because the circuit is
	// established lazily; identity must still propagate so the peer is not
	// shown as "unknown" in the WebUI. The relay-priority dial path
	// (openStreamViaRelay) is used automatically by the meta pool.
	maxAttempts := 2
	if n.isRelayOnlyPeer(targetPeer) {
		maxAttempts = 4
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Reuse a persistent per-peer meta stream (A) instead of opening a fresh
		// NewStream on every 15s tick. WithStream runs write+read inside the
		// peer's lock so no other goroutine can interleave on the same stream.
		ok := n.metaPool.WithStream(targetPeer, func(s network.Stream) error {
			_ = s.SetWriteDeadline(time.Now().Add(5 * time.Second))
			payload := n.buildLocalMetaPayload()
			data, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			// Length-prefixed frame (B); do NOT CloseWrite — the persistent stream
			// is reused, and the receiver answers on the same stream.
			if err := WriteFrame(s, data); err != nil {
				return err
			}
			// Read the peer's response frame on the same stream.
			respBuf := make([]byte, 8192)
			rn, err := ReadFrame(s, respBuf)
			if err == nil && rn > 0 {
				n.handleMetaResponse(targetPeer, respBuf[:rn])
			}
			return nil
		})
		if ok {
			return
		}
		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
			continue
		}
		if n.isRelayOnlyPeer(targetPeer) {
			// For relay-only peers the meta stream IS the identity fallback
			// (the LSA sub-stream uses the same relay path), so keep retrying
			// on the next 15s cycle instead of declaring it permanently dead.
			log.Debug("Meta sync to relay-only peer %s failed after %d attempts (will retry next cycle)",
				targetPeer.ShortString(), maxAttempts)
		} else {
			log.Debug("Meta sync stream to %s skipped (using LSA identity channel instead)",
				targetPeer.ShortString())
		}
		return
	}
}

// buildLocalMetaPayload constructs the current node's metadata for exchange.
//
// Identity fields (NodeName/IP/MAC/OS/arch/version/exit flag/subnets) are
// included so the bootstrap node — which does NOT participate in the LSA mesh —
// and peers that only establish a meta stream (e.g. circuit-relay paths where
// the periodic LSA sub-stream cannot be dialed) can still learn each other's
// name/IP/MAC. The LSA broadcast remains the source of truth for identity and
// is merged with this on the receiver side (only-empty-fields overwritten), so
// sending identity here does not cause duplication — it only fills gaps. Peers
// that still send a full payload (older builds) are handled the same way.
func (n *Node) buildLocalMetaPayload() meta.NodeMetaPayload {
	reachability := n.computeReachability()
	localTxRx := observer.TxRxStats{}
	if n.Collector != nil {
		localTxRx = n.Collector.GetTxRxStats()
	}
	exitSubnets := make([]string, 0)
	if n.Config.ExitNode.Enable && len(n.Config.AdvertisedSubnets) > 0 {
		exitSubnets = n.Config.AdvertisedSubnets
	}
	return meta.NodeMetaPayload{
		// Identity fields — required for boot nodes and relay-only peers that
		// cannot rely on the LSA channel to learn who we are.
		NodeName:          n.nodeName,
		TapIP:             n.Config.TapIP,
		TapIPv6:           n.Config.TapIPv6,
		TapMAC:            n.Config.TapMAC,
		OS:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		Version:           version.Version,
		IsExitNode:        n.Config.ExitNode.Enable,
		AdvertisedSubnets: exitSubnets,
		// Dynamic liveness fields.
		UptimeSec:    int64(time.Since(n.startTime).Seconds()),
		Reachability: reachability,
		ExitNAT:      n.Config.ExitNode.NATMasquerade,
		TxSpeed:      localTxRx.TxSpeed,
		RxSpeed:      localTxRx.RxSpeed,
		TotalTx:      localTxRx.TotalTx,
		TotalRx:      localTxRx.TotalRx,
	}
}

// computeReachability returns "Public" if ANY peer has a direct (non-circuit)
// transport link; otherwise "Relay".
func (n *Node) computeReachability() string {
	for _, p := range n.Host.Network().Peers() {
		conns := n.Host.Network().ConnsToPeer(p)
		for _, conn := range conns {
			if !strings.Contains(conn.RemoteMultiaddr().String(), "/p2p-circuit") {
				return "Public"
			}
		}
	}
	return "Relay"
}

// handleMetaResponse processes an inbound meta response payload from a peer:
// stores PeerMeta, learns MAC, registers IP↔MAC mappings, and sends GARP/NA.
func (n *Node) handleMetaResponse(remotePeer peer.ID, respData []byte) {
	var respPayload meta.NodeMetaPayload
	if err := json.Unmarshal(respData, &respPayload); err != nil {
		return
	}

	// Merge-only: a peer may send a payload that carries only the dynamic
	// liveness fields (older/no-identity builds) or only identity fields.
	// Never discard the whole record when one subset is missing — fill the
	// empty slots and keep whatever was already known from LSA or a prior sync.
	prev, _ := n.peerMeta.Load(remotePeer)
	updated := PeerMeta{}
	if prev != nil {
		if pm, ok := prev.(PeerMeta); ok {
			updated = pm
		}
	}
	updated.NodeName = firstNonEmpty(updated.NodeName, respPayload.NodeName)
	updated.TapIP = firstNonEmpty(updated.TapIP, respPayload.TapIP)
	updated.TapIPv6 = firstNonEmpty(updated.TapIPv6, respPayload.TapIPv6)
	updated.TapMAC = firstNonEmpty(updated.TapMAC, respPayload.TapMAC)
	updated.OSArch = firstNonEmpty(updated.OSArch, fmt.Sprintf("%s/%s", respPayload.OS, respPayload.Arch))
	updated.Version = firstNonEmpty(updated.Version, respPayload.Version)
	updated.Reachability = firstNonEmpty(updated.Reachability, respPayload.Reachability)
	if respPayload.UptimeSec != 0 {
		updated.UptimeSec = respPayload.UptimeSec
	}
	updated.IsExitNode = updated.IsExitNode || respPayload.IsExitNode
	updated.ExitNAT = updated.ExitNAT || respPayload.ExitNAT
	if respPayload.TxSpeed != 0 {
		updated.TxSpeed = respPayload.TxSpeed
	}
	if respPayload.RxSpeed != 0 {
		updated.RxSpeed = respPayload.RxSpeed
	}
	if respPayload.TotalTx != 0 {
		updated.TotalTx = respPayload.TotalTx
	}
	if respPayload.TotalRx != 0 {
		updated.TotalRx = respPayload.TotalRx
	}
	if len(respPayload.AdvertisedSubnets) > 0 {
		updated.AdvertisedSubnets = respPayload.AdvertisedSubnets
	}
	updated.SyncSource = "P2P Stream Direct"
	updated.LastSync = time.Now()
	n.storePeerMeta(remotePeer, updated)
	n.processSubnetRoutes(remotePeer, respPayload.TapIP, respPayload.TapIPv6, respPayload.AdvertisedSubnets)

	// A peer with no known TapMAC (e.g. learned via circuit-relay before its
	// dedicated meta stream came up) must not abort here: subnet routes were
	// already installed above. We only skip the MAC-dependent steps below so
	// that the peer's advertised LANs still route even before its L2 MAC is
	// discovered. The proxy-ARP fallback in handleIncomingFrame resolves the
	// missing MAC on demand.
	if respPayload.TapMAC == "" {
		n.registerPeerIPMACFallback(remotePeer, respPayload.TapIP, respPayload.TapIPv6)
		return
	}
	hw, err := net.ParseMAC(respPayload.TapMAC)
	if err != nil || len(hw) != 6 {
		n.registerPeerIPMACFallback(remotePeer, respPayload.TapIP, respPayload.TapIPv6)
		return
	}

	n.MACTable.Learn(hw, remotePeer)

	cleanIP := strings.Split(respPayload.TapIP, "/")[0]
	cleanv6 := strings.Split(respPayload.TapIPv6, "/")[0]

	if setter, ok := n.TAP.(interface{ RegisterIPMAC(string, string) }); ok {
		if cleanIP != "" {
			setter.RegisterIPMAC(cleanIP, respPayload.TapMAC)
		}
		if cleanv6 != "" {
			setter.RegisterIPMAC(cleanv6, respPayload.TapMAC)
		}
	}

	if n.TAP == nil {
		return
	}
	if ip := net.ParseIP(cleanIP); ip != nil && len(ip.To4()) == 4 {
		garpFrame := tap.BuildARPReplyFrame(hw, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ip, ip)
		_, _ = n.TAP.Write(garpFrame)
	}
	if ip6 := net.ParseIP(cleanv6); ip6 != nil && ip6.To16() != nil {
		naFrame := tap.BuildIPv6NeighborAdvertisementFrame(hw, ip6)
		if len(naFrame) > 0 {
			_, _ = n.TAP.Write(naFrame)
		}
	}
}

// applyPeerMetaFromLSA ingests node identity carried piggyback on an LSA.
// This is the resilient path: even when the dedicated per-peer meta stream
// cannot be established (e.g. circuit-relay sub-stream dials timing out), the
// periodic LSA broadcast still delivers name/IP/MAC so the peer is identifiable
// in the WebUI and ARP/ND can resolve it.
func (n *Node) applyPeerMetaFromLSA(remotePeer peer.ID, lsa routing.LinkStatePayload) {
	if lsa.NodeName == "" && lsa.TapIP == "" && lsa.TapMAC == "" {
		return
	}

	existing, _ := n.peerMeta.Load(remotePeer)
	prev, _ := existing.(PeerMeta)

	// Only fill fields that are empty, so a later rich meta-stream response can
	// upgrade (e.g. add TxSpeed/RxSpeed/UptimeSec) without being downgraded.
	updated := prev
	if updated.NodeName == "" {
		updated.NodeName = lsa.NodeName
	}
	if updated.TapIP == "" {
		updated.TapIP = lsa.TapIP
	}
	if updated.TapIPv6 == "" {
		updated.TapIPv6 = lsa.TapIPv6
	}
	if updated.TapMAC == "" {
		updated.TapMAC = lsa.TapMAC
	}
	if updated.OSArch == "" && (lsa.OS != "" || lsa.Arch != "") {
		updated.OSArch = fmt.Sprintf("%s/%s", lsa.OS, lsa.Arch)
	}
	if updated.Version == "" {
		updated.Version = lsa.Version
	}
	if len(lsa.AdvertisedSubnets) > 0 {
		updated.AdvertisedSubnets = lsa.AdvertisedSubnets
	}
	updated.IsExitNode = lsa.IsExitNode
	updated.SyncSource = "LSA / Peek-Map"
	updated.LastSync = time.Now()

	n.storePeerMeta(remotePeer, updated)
	n.processSubnetRoutes(remotePeer, lsa.TapIP, lsa.TapIPv6, updated.AdvertisedSubnets)

	// Same as handleMetaResponse: an empty/invalid TapMAC must not abort the
	// whole update — keep subnet routes and only skip MAC-dependent steps.
	if lsa.TapMAC == "" {
		n.registerPeerIPMACFallback(remotePeer, lsa.TapIP, lsa.TapIPv6)
		return
	}
	hw, err := net.ParseMAC(lsa.TapMAC)
	if err != nil || len(hw) != 6 {
		n.registerPeerIPMACFallback(remotePeer, lsa.TapIP, lsa.TapIPv6)
		return
	}
	n.MACTable.Learn(hw, remotePeer)

	cleanIP := strings.Split(lsa.TapIP, "/")[0]
	cleanv6 := strings.Split(lsa.TapIPv6, "/")[0]
	if setter, ok := n.TAP.(interface{ RegisterIPMAC(string, string) }); ok {
		if cleanIP != "" {
			setter.RegisterIPMAC(cleanIP, lsa.TapMAC)
		}
		if cleanv6 != "" {
			setter.RegisterIPMAC(cleanv6, lsa.TapMAC)
		}
	}
	if n.TAP == nil {
		return
	}
	if ip := net.ParseIP(cleanIP); ip != nil && len(ip.To4()) == 4 {
		garpFrame := tap.BuildARPReplyFrame(hw, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ip, ip)
		_, _ = n.TAP.Write(garpFrame)
	}
	if ip6 := net.ParseIP(cleanv6); ip6 != nil && ip6.To16() != nil {
		naFrame := tap.BuildIPv6NeighborAdvertisementFrame(hw, ip6)
		if len(naFrame) > 0 {
			_, _ = n.TAP.Write(naFrame)
		}
	}
}

// registerPeerIPMACFallback records a peer's TAP IP when its MAC is not yet
// known (e.g. learned via circuit-relay before the meta stream established the
// MAC). It keeps the peer resolvable by peer ID so that handleIncomingFrame's
// proxy-ARP fallback can answer ARP/ND for the peer's own TAP IP and
// drainTapBatch can deliver the frame by peer ID once a MAC is learned.
func (n *Node) registerPeerIPMACFallback(remotePeer peer.ID, tapIP, tapIPv6 string) {
	cleanIP := strings.Split(tapIP, "/")[0]
	cleanv6 := strings.Split(tapIPv6, "/")[0]
	if setter, ok := n.TAP.(interface{ RegisterIPMAC(string, string) }); ok {
		if cleanIP != "" {
			setter.RegisterIPMAC(cleanIP, "")
		}
		if cleanv6 != "" {
			setter.RegisterIPMAC(cleanv6, "")
		}
	}
}

// firstNonEmpty returns the first non-empty string, preferring cur (the value
// already cached from a prior sync/LSA) so a partial update never clobbers a
// known identity field with an empty one.
func firstNonEmpty(cur, next string) string {
	if cur != "" {
		return cur
	}
	return next
}

func (n *Node) broadcastMetadata() {
	peers := n.getAllPeersForMetaSync()
	if len(peers) == 0 {
		return
	}

	const maxConcurrentSync = 8
	sem := make(chan struct{}, maxConcurrentSync)

	for _, pID := range peers {
		targetPeer := pID
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			n.syncMetadataToPeer(targetPeer)
		}()
	}
}

// ─── Bootstrap Network Map (peek-map) broadcast protocol ─────────────────────
//
// The p2ptap-boot node acts as a stateless pub/sub hub. Every client opens a
// long-lived listener stream to the boot node. Frames sent by any client are
// routed by the boot node to the appropriate recipients:
//
//   QUERY   → boot broadcasts to all OTHER clients; each replies with REPLY
//   REPLY   → boot forwards to the original requester (query_id = requester ID)
//   PUBLISH → boot broadcasts to all OTHER clients (unsolicited update)
//
// This makes peek-map a universal broadcast pipe for node-info / subnet / route
// exchange, used as a supplement to direct P2P meta/LSA streams. It works even
// when two clients cannot establish a direct P2P connection — they only need
// to each reach the boot node (possibly via circuit relay).

const PeekMapProtocolID = "/p2ptap/peek-map/1.0.0"

// PeekMap message types exchanged over the bootstrap pub/sub channel.
const PeekMapUpdate = "update" // a node's identity/subnets; hub rebroadcasts to all others

// PeekMapNodeInfo is the payload carried inside UPDATE frames. It mirrors
// routing.LinkStatePayload so the receiver can ingest it directly.
type PeekMapNodeInfo struct {
	PeerID     string `json:"peer_id"`
	NodeName   string `json:"node_name,omitempty"`
	TapIP      string `json:"tap_ip,omitempty"`
	TapIPv6    string `json:"tap_ipv6,omitempty"`
	TapMAC     string `json:"tap_mac,omitempty"`
	OS         string `json:"os,omitempty"`
	Arch       string `json:"arch,omitempty"`
	Version    string `json:"version,omitempty"`
	IsExitNode bool   `json:"is_exit_node,omitempty"`
	// AdvertisedSubnets carries this node's LAN subnets to be routed across the
	// mesh. Distributed over the peek-map broadcast channel so every peer learns
	// which subnets we advertise (and re-learns on change).
	AdvertisedSubnets []string `json:"advertised_subnets,omitempty"`
	// HopDistance is the number of bootstrap relays between this node and the
	// boot it published through. A node publishes 0 (it is directly attached to
	// its publishing boot); each intermediate boot increments the value by 1 as
	// it forwards the frame, so a receiver's value equals the boot-hop distance
	// from the receiver's *own* immediate boot to this node. The receiver uses it
	// to backfill a weighted edge boot<->peer into the topology graph, so a peer
	// learned purely via peek-map still appears nested under its boot node with
	// an estimated latency derived from the accumulated hop distance (see
	// ingestPeekMapNodeInfo). This lets a sub-boot hanging under another boot
	// build a deeper multi-level interconnect tree.
	HopDistance int `json:"hop_distance,omitempty"`
	// Addrs are the publisher's dialable multiaddrs (without the /p2p/<id>
	// suffix). Identity alone is not enough to REACH a peer: a peer learned
	// across a federated boot backbone has no entry in our peerstore and no
	// usable circuit address either (a circuit requires both ends to be attached
	// to the SAME boot, which is exactly what is not true across clusters). By
	// carrying endpoints here, a peer in cluster B can dial a peer in cluster A
	// directly (or hole-punch to it) instead of being permanently unreachable.
	Addrs []string `json:"addrs,omitempty"`
	// IsBoot marks the publisher as a bootstrap/relay node rather than a mesh
	// member. Receivers use it to optionally attach to boots they discovered
	// through the backbone, which merges the two clusters into one
	// circuit-relay domain (see considerDiscoveredBoot).
	IsBoot bool `json:"is_boot,omitempty"`
}

// PeekMapMessage is the envelope for all peek-map broadcast traffic. The boot
// hub only rewrites From and rebroadcasts; it never inspects Payload.
type PeekMapMessage struct {
	Type    string          `json:"type"`
	From    string          `json:"from"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// registerPeekMapHandler registers the client-side listener. The boot hub
// rebroadcasts every UPDATE here. We ingest it, and — to achieve self-discovery
// without a separate query/reply round-trip — we reply with our own UPDATE when
// the sender is a *new* peer. Because we only reply to new peers, the exchange
// converges (no storm): a newly joined node receives one UPDATE from each old
// peer and replies once; old peers already know it, so they stay silent.
func (n *Node) registerPeekMapHandler() {
	n.Host.SetStreamHandler(PeekMapProtocolID, func(s network.Stream) {
		defer s.Close()
		remotePeer := s.Conn().RemotePeer()
		// Streaming JSON decoder. The sender (boot hub or peer) emits
		// newline-delimited PeekMapMessage values via json.NewEncoder(s).Encode.
		// A bare s.Read + json.Unmarshal would only parse the first value in a
		// coalesced read and drop split/concatenated values, silently losing
		// peer-discovery updates. json.NewDecoder reads one value at a time
		// correctly across read and value boundaries.
		dec := json.NewDecoder(s)
		for {
			var msg PeekMapMessage
			if err := dec.Decode(&msg); err != nil {
				if err != io.EOF {
					log.Debug("Peek-map listener from %s closed: %v", remotePeer.ShortString(), err)
				}
				return
			}
			if msg.Type != PeekMapUpdate {
				continue
			}
			var info PeekMapNodeInfo
			if err := json.Unmarshal(msg.Payload, &info); err != nil {
				log.Debug("Peek-map listener could not parse payload from %s: %v", remotePeer.ShortString(), err)
				continue
			}
			// Was this peer previously unknown? Reply once to announce ourselves.
			isNew := !n.peerKnownPeer(info.PeerID)
			n.ingestPeekMapNodeInfo(info, remotePeer)
			if isNew {
				go n.publishPeekMapSelf()
			}
		}
	})
	log.Debug("Stream handler registered for peek-map protocol: %s", PeekMapProtocolID)
}

// peerKnownPeer reports whether we already hold node info for the given peer.
// It tolerates undecodable peer IDs (treated as unknown).
func (n *Node) peerKnownPeer(peerID string) bool {
	pID, err := peer.Decode(peerID)
	if err != nil {
		return false
	}
	_, ok := n.peerMeta.Load(pID)
	return ok
}

// ingestPeekMapNodeInfo applies a received node-info frame. viaPeer is the
// bootstrap/relay node the frame arrived from; we use it to backfill a weighted
// topology edge viaPeer<->pID so a peer learned purely over the peek-map channel
// still appears nested under its boot node with an estimated latency derived from
// its advertised hop distance.
func (n *Node) ingestPeekMapNodeInfo(info PeekMapNodeInfo, viaPeer peer.ID) {
	pID, err := peer.Decode(info.PeerID)
	if err != nil || pID == n.Host.ID() {
		log.Debug("Peek-map ingested node info ignored (peer=%s, self=%v, decode_err=%v)", info.PeerID, pID == n.Host.ID(), err)
		return
	}
	log.Debug("Peek-map ingesting node info: peer=%s via=%s name=%q tapIP=%s tapIPv6=%s mac=%s os=%s arch=%s ver=%s exit=%v subnets=%v hop=%d",
		pID.ShortString(), viaPeer.ShortString(), info.NodeName, info.TapIP, info.TapIPv6, info.TapMAC, info.OS, info.Arch, info.Version, info.IsExitNode, info.AdvertisedSubnets, info.HopDistance)
	n.applyPeerMetaFromLSA(pID, routing.LinkStatePayload{
		NodeName:          info.NodeName,
		TapIP:             info.TapIP,
		TapIPv6:           info.TapIPv6,
		TapMAC:            info.TapMAC,
		OS:                info.OS,
		Arch:              info.Arch,
		Version:           info.Version,
		IsExitNode:        info.IsExitNode,
		AdvertisedSubnets: info.AdvertisedSubnets,
	})
	// Backfill the indirect link into the topology graph. The weight estimates
	// the boot<->peer latency as a base relay cost scaled by the advertised hop
	// distance (1 hop = single relay hop, 2 = two cascaded hops, ...). This lets
	// the hierarchical topology tree attach the peer under its boot node instead
	// of leaving it as a floating child of the local root with a 0 RTT.
	hop := info.HopDistance
	if hop < 1 {
		hop = 1
	}
	estimatedRTT := int64(hop) * 25
	// The peek-map learns this peer indirectly, through the relay/boot node
	// (viaPeer). Mark the backfilled edge as circuit class so the cost model
	// penalises it and prefers any real direct/overlay path when one exists.
	n.Router.SetEdge(viaPeer, pID, estimatedRTT, routing.LinkCircuit)
	log.Debug("Peek-map recorded indirect edge %s<->%s (hop=%d, est_rtt=%dms)", viaPeer.ShortString(), pID.ShortString(), hop, estimatedRTT)

	// Remember WHICH boot carried this announcement and how many boot-to-boot
	// backbone hops it crossed. The link-state graph can only express "there is
	// an edge"; it cannot say "this node lives in a different boot cluster and is
	// N federation hops away", which is precisely what a multi-cluster topology
	// view has to show. Kept separate from PeerMeta because it describes the
	// DISCOVERY path, not the peer's own identity.
	n.recordPeekMapOrigin(pID, viaPeer, info.HopDistance, info.IsBoot)

	// Record the publisher's endpoints so it becomes DIALABLE, not merely
	// visible. Without this a peer discovered across a federated boot backbone
	// has no address and no circuit (a circuit needs both ends on the same
	// boot), so it would show up in the UI and stay permanently unreachable.
	n.registerPeekMapAddrs(pID, info.Addrs)

	// A boot learned through the backbone can be attached to, which merges the
	// two clusters into a single circuit-relay domain.
	if info.IsBoot {
		go n.considerDiscoveredBoot(pID)
	}
}

// peekMapOrigin records how a peer became visible over the peek-map channel.
// It answers "which boot cluster does this node belong to, and how far across
// the boot backbone did its announcement travel" — questions the link-state
// graph cannot answer, because there an inter-cluster hop and an intra-cluster
// relay hop look identical.
type peekMapOrigin struct {
	// Via is the boot node whose hub rebroadcast the announcement to us. It is
	// the cluster anchor the peer is grouped under in the topology view.
	Via peer.ID
	// Hops is the boot-to-boot backbone distance carried in the announcement:
	// 0 means the publisher is attached to the boot we heard it from (same
	// cluster as that boot), 1+ means it was federated across that many peer
	// boots before reaching us.
	Hops int
	// IsBoot marks the publisher itself as a bootstrap node.
	IsBoot bool
	// At is the last time we heard this announcement, so a stale cluster
	// assignment can be aged out by the reader if it ever matters.
	At time.Time
}

// recordPeekMapOrigin stores/refreshes the discovery provenance for a peer.
//
// Later announcements win, but a CLOSER one is never overwritten by a farther
// one within the same refresh window: with a federated backbone the same node is
// announced by several boots (its own, plus every boot that relayed it), and
// whichever arrived last would otherwise decide the displayed cluster. Preferring
// the smallest hop count keeps a node grouped under the boot that is genuinely
// closest to it.
func (n *Node) recordPeekMapOrigin(pID, via peer.ID, hops int, isBoot bool) {
	if hops < 0 {
		hops = 0
	}
	next := peekMapOrigin{Via: via, Hops: hops, IsBoot: isBoot, At: time.Now()}
	if prev, ok := n.peekMapOrigin.Load(pID); ok {
		p := prev.(peekMapOrigin)
		// A boot flag, once observed, is sticky: a relayed re-announcement that
		// happens to omit it must not demote a known boot to a plain member.
		next.IsBoot = next.IsBoot || p.IsBoot
		if p.Via != via && p.Hops < hops && time.Since(p.At) < peekMapOriginStickyFor {
			next.Via = p.Via
			next.Hops = p.Hops
		}
	}
	n.peekMapOrigin.Store(pID, next)
}

// peekMapOriginStickyFor is how long a closer cluster assignment resists being
// replaced by a farther one. Sized above the peek-map republish cadence so all
// announcements of one refresh round are compared against each other, yet short
// enough that a node that genuinely moved clusters is re-homed promptly.
const peekMapOriginStickyFor = 90 * time.Second

// lookupPeekMapOrigin returns the recorded discovery provenance for a peer.
func (n *Node) lookupPeekMapOrigin(pID peer.ID) (peekMapOrigin, bool) {
	v, ok := n.peekMapOrigin.Load(pID)
	if !ok {
		return peekMapOrigin{}, false
	}
	return v.(peekMapOrigin), true
}

// registerPeekMapAddrs stores endpoints advertised over the peek-map channel.
//
// AddressTTL (not PermanentAddrTTL) is deliberate: these are third-party claims
// relayed through a boot, so they must expire if the peer stops republishing.
// The peek-map republishes on every change and on every new peer, which keeps
// live entries fresh.
func (n *Node) registerPeekMapAddrs(pID peer.ID, addrs []string) {
	if len(addrs) == 0 {
		return
	}
	parsed := make([]multiaddr.Multiaddr, 0, len(addrs))
	for _, s := range addrs {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			log.Debug("Peek-map addr %q from %s is invalid, skipped: %v", s, pID.ShortString(), err)
			continue
		}
		// A /p2p/<id> suffix would make the peerstore entry unusable for
		// dialling; strip it and verify it matches the claimed publisher.
		if info, err := peer.AddrInfoFromP2pAddr(ma); err == nil {
			if info.ID != pID {
				log.Debug("Peek-map addr %q claims peer %s but was published by %s, skipped",
					s, info.ID.ShortString(), pID.ShortString())
				continue
			}
			parsed = append(parsed, info.Addrs...)
			continue
		}
		parsed = append(parsed, ma)
	}
	if len(parsed) == 0 {
		return
	}
	n.Host.Peerstore().AddAddrs(pID, parsed, peerstore.AddressTTL)
	log.Debug("Peek-map registered %d dialable addr(s) for %s", len(parsed), pID.ShortString())
}

// maxDiscoveredBoots caps how many boots we will attach to beyond the ones in
// our own config. A federated backbone can announce many boots; attaching to
// all of them would turn every client into a full-mesh boot client and defeat
// the point of having separate clusters.
const maxDiscoveredBoots = 8

// considerDiscoveredBoot attaches to a boot we learned about through the boot
// backbone, so peers in the remote cluster become reachable.
//
// Why attach at all: p2ptap's two relay mechanisms both need a shared anchor.
// Circuit Relay v2 requires BOTH endpoints to be connected to the same boot, and
// the boot process does not implement overlay-relay forwarding, so it cannot be
// an overlay hop either. Attaching to the remote cluster's boot supplies exactly
// that shared anchor and makes both mechanisms work across clusters without the
// boot having to forward data frames.
func (n *Node) considerDiscoveredBoot(pID peer.ID) {
	if pID == n.Host.ID() || !n.Config.DiscoverBootMesh {
		return
	}
	// Already ours (configured) — the normal bootstrap path owns it.
	if n.isBootstrapPeer(pID) {
		return
	}
	if _, seen := n.discoveredBoots.Load(pID); seen {
		return
	}
	count := 0
	n.discoveredBoots.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count >= maxDiscoveredBoots {
		log.Debug("Peek-map discovered boot %s ignored: already attached to %d discovered boot(s) (cap %d)",
			pID.ShortString(), count, maxDiscoveredBoots)
		return
	}
	if _, loaded := n.discoveredBoots.LoadOrStore(pID, struct{}{}); loaded {
		return
	}

	if n.Host.Network().Connectedness(pID) != network.Connected {
		addrs := filterLoopbackAddrs(n.Host.Peerstore().Addrs(pID))
		if len(addrs) == 0 {
			// No usable endpoint yet; drop the marker so a later announcement
			// carrying addresses can retry.
			n.discoveredBoots.Delete(pID)
			log.Debug("Peek-map discovered boot %s has no dialable addr yet, will retry on next announcement",
				pID.ShortString())
			return
		}
		ctx, cancel := context.WithTimeout(n.ctx, 20*time.Second)
		defer cancel()
		if err := n.Host.Connect(ctx, peer.AddrInfo{ID: pID, Addrs: addrs}); err != nil {
			n.discoveredBoots.Delete(pID)
			log.Debug("Peek-map discovered boot %s connect failed: %v", pID.ShortString(), err)
			return
		}
		log.Info("Attached to boot %s discovered through the boot backbone — remote cluster peers are now reachable",
			pID.ShortString())
	}
	// Authenticate with discovered boot before opening peek-map stream
	if !n.authenticateWithRelay(pID, false) {
		log.Warn("PSK auth with discovered boot %s failed — peek-map not opened", pID.ShortString())
		return
	}
	// Subscribe to its peek-map so we also see ITS cluster's clients directly.
	n.ensurePeekMapListener(pID)
}

// localPeekMapNodeInfo builds our own node-info payload.
func (n *Node) localPeekMapNodeInfo() PeekMapNodeInfo {
	return PeekMapNodeInfo{
		PeerID:     n.Host.ID().String(),
		NodeName:   n.nodeName,
		TapIP:      n.Config.TapIP,
		TapIPv6:    n.Config.TapIPv6,
		TapMAC:     n.Config.TapMAC,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Version:    version.Version,
		IsExitNode: n.Config.ExitNode.Enable,
		// LAN subnets we advertise into the mesh — sent over the peek-map
		// broadcast channel so every peer learns/updates our routed subnets.
		AdvertisedSubnets: n.Config.AdvertisedSubnets,
		// We publish through a boot node we are directly connected to. The
		// immediate boot increments this to 1 as it forwards, so a direct
		// receiver records a weighted boot<->us edge of one relay hop. Cascaded
		// boots further down the tree increment again, accumulating depth.
		HopDistance: 0,
		// Publish our endpoints so peers that learn about us indirectly (through
		// a boot, or across a federated boot backbone) can actually dial us.
		// Loopback is not stripped here: the peerstore is a knowledge base and
		// the dial paths already drop loopback (filterLoopbackAddrs), so
		// filtering twice would only make single-machine setups untestable.
		Addrs: multiaddrsToStrings(n.Host.Addrs()),
	}
}

// multiaddrsToStrings renders multiaddrs for the peek-map wire format.
func multiaddrsToStrings(addrs []multiaddr.Multiaddr) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a == nil {
			continue
		}
		out = append(out, a.String())
	}
	return out
}

type peekMapStreamWrapper struct {
	mu sync.Mutex
	s  network.Stream
}

// peekMapListeners tracks which bootstrap peers we already have a long-lived
// listener stream open to, so we never open the channel twice for the same peer.
var peekMapListeners sync.Map // peer.ID -> *peekMapStreamWrapper

// peekMapOpening dedups concurrent ensurePeekMapListener calls during multi-transport
// connection events so only ONE stream is opened to a bootstrap peer at a time.
var peekMapOpening sync.Map // peer.ID -> struct{}

// ensurePeekMapListener opens (if not already open) a long-lived peek-map
// listener stream to the given bootstrap peer and announces our node info to the
// broadcast channel. It is idempotent per bootstrap peer and safe to call from
// both the startup loop and the connection event handler.
func (n *Node) ensurePeekMapListener(bsPeer peer.ID) {
	if _, loaded := peekMapListeners.Load(bsPeer); loaded {
		log.Debug("Peek-map listener for %s already open, skipping duplicate", bsPeer.ShortString())
		return
	}
	if _, inFlight := peekMapOpening.LoadOrStore(bsPeer, struct{}{}); inFlight {
		log.Debug("Peek-map listener for %s opening in-flight, skipping duplicate trigger", bsPeer.ShortString())
		return
	}

	go func() {
		defer peekMapOpening.Delete(bsPeer)

		if _, loaded := peekMapListeners.Load(bsPeer); loaded {
			return
		}

		s, err := n.openPeekMapStream(bsPeer)
		if err != nil {
			return
		}
		wrapper := &peekMapStreamWrapper{s: s}
		if _, loaded := peekMapListeners.LoadOrStore(bsPeer, wrapper); loaded {
			_ = s.Close()
			return
		}

		go func() {
			defer func() {
				_ = s.Close()
				peekMapListeners.Delete(bsPeer)
				log.Info("Peek-map listener stream to %s closed", bsPeer.ShortString())
				// Auto-reconnect: if the underlying libp2p connection is still alive
				// (e.g. stream timed out or was reset) but we never fully disconnected,
				// ConnectedF will NOT fire again — so we must reopen the stream here.
				// Wait 2 s before retrying to avoid a tight loop if the stream keeps
				// failing (e.g. boot is temporarily overloaded).
				select {
				case <-n.ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
				if n.Host.Network().Connectedness(bsPeer) == network.Connected {
					log.Debug("Peek-map listener to %s: auto-reconnecting stream", bsPeer.ShortString())
					n.ensurePeekMapListener(bsPeer)
				}
			}()
			dec := json.NewDecoder(s)
			for {
				var msg PeekMapMessage
				if err := dec.Decode(&msg); err != nil {
					return
				}
				if msg.Type != PeekMapUpdate {
					continue
				}
				var info PeekMapNodeInfo
				if err := json.Unmarshal(msg.Payload, &info); err != nil {
					log.Debug("Peek-map client stream to %s could not parse payload: %v", bsPeer.ShortString(), err)
					continue
				}
				// Drop our own UPDATE echoed back through the hub. The hub
				// rebroadcasts every received UPDATE to all other listeners
				// (registerPeekMapHandler -> publishPeekMapSelf), so without
				// this filter we would re-ingest our own node info, bump
				// our peerMeta counter, and double-count ourselves in
				// statistics. Only the hub's view of us is authoritative.
				if info.PeerID == n.Host.ID().String() {
					log.Debug("Peek-map ignoring own UPDATE echoed back via bootstrap %s", bsPeer.ShortString())
					continue
				}
				// Was this peer previously unknown? Reply once to announce ourselves.
				isNew := !n.peerKnownPeer(info.PeerID)
				n.ingestPeekMapNodeInfo(info, bsPeer)
				if isNew {
					go n.publishPeekMapSelf()
				}
			}
		}()
	}()
}

// openPeekMapStream opens a long-lived stream to a bootstrap peer so that
// broadcast frames (QUERY/REPLY/PUBLISH) are delivered to us. On connect it
// immediately PUBLISHes our own node info (announcing we're online) and also
// sends a QUERY so we learn everyone else's node info right away.
func (n *Node) openPeekMapStream(bsPeer peer.ID) (network.Stream, error) {
	log.Debug("Peek-map opening listener stream to bootstrap %s", bsPeer.ShortString())
	s, err := n.Host.NewStream(n.ctx, bsPeer, PeekMapProtocolID)
	if err != nil {
		log.Debug("Peek-map listener to %s failed: %v", bsPeer.ShortString(), err)
		return nil, err
	}
	log.Debug("Peek-map listener stream to bootstrap %s opened", bsPeer.ShortString())

	// Announce ourselves: every other client on the channel learns we are
	// online (and our current state). The hub rebroadcasts it; existing peers
	// reply with their own UPDATE, so we learn them without a query round-trip.
	if err := n.publishPeekMapNodeInfo(s); err != nil {
		log.Debug("Peek-map initial UPDATE to %s failed: %v", bsPeer.ShortString(), err)
	} else {
		log.Debug("Peek-map initial UPDATE sent to bootstrap %s (announced online)", bsPeer.ShortString())
	}
	// Leave stream open for the boot node to push other peers' updates through
	// the reverse direction. We don't close it here.
	return s, nil
}

// publishPeekMapNodeInfo writes an UPDATE frame (our node info) to the stream.
func (n *Node) publishPeekMapNodeInfo(s network.Stream) error {
	info := n.localPeekMapNodeInfo()
	payload, err := json.Marshal(info)
	if err != nil {
		return err
	}
	msg := PeekMapMessage{
		Type:    PeekMapUpdate,
		From:    n.Host.ID().String(),
		Payload: payload,
	}
	_ = s.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return json.NewEncoder(s).Encode(msg)
}

// publishPeekMapSelf broadcasts our node info to ALL open peek-map listeners.
// Used for unsolicited state updates (e.g. name/IP/MAC change) at runtime.
func (n *Node) publishPeekMapSelf() {
	peekMapListeners.Range(func(k, v interface{}) bool {
		bsPeer := k.(peer.ID)
		wrapper := v.(*peekMapStreamWrapper)
		wrapper.mu.Lock()
		defer wrapper.mu.Unlock()
		if err := n.publishPeekMapNodeInfo(wrapper.s); err != nil {
			log.Debug("Peek-map publish-self to %s failed: %v", bsPeer.ShortString(), err)
		} else {
			log.Debug("Peek-map published self update to bootstrap %s", bsPeer.ShortString())
		}
		return true
	})
}

func (n *Node) processSubnetRoutes(remotePeer peer.ID, tapIPv4, tapIPv6 string, subnets []string) {
	if remotePeer == n.Host.ID() || len(subnets) == 0 || !n.Config.AcceptAdvertisedSubnets {
		return
	}

	isAllowed := false
	for _, p := range n.Config.AllowedSubnetPeers {
		if p == "*" || p == remotePeer.String() {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		log.Debug("🔒 Subnet route from peer %s ignored (not in allowed_subnet_peers)", remotePeer.String())
		return
	}

	cleanGWv4 := strings.Split(tapIPv4, "/")[0]
	cleanGWv6 := strings.Split(tapIPv6, "/")[0]

	for _, sub := range subnets {
		if sub == "" {
			continue
		}

		// Pick correct gateway based on subnet address family.
		var gw string
		if _, subnetNet, err := net.ParseCIDR(sub); err == nil {
			if subnetNet.IP.To4() != nil {
				gw = cleanGWv4
			} else {
				gw = cleanGWv6
			}
		} else {
			continue
		}

		if gw == "" {
			log.Warn("No gateway available for subnet %s: remote peer %s has no matching IP on the overlay",
				sub, remotePeer.String())
			continue
		}

		// Skip OS route installation for a subnet that lost the duplicate/overlap
		// arbitration to a higher-priority peer; the ARP index already suppressed
		// its L2/L3 resolution, so installing the route would create a conflicting
		// or blackhole entry in the OS routing table.
		if n.isSubnetRouteSuppressed(remotePeer, sub) {
			log.Warn("🌐 Subnet route %s from peer %s suppressed: arbitrated as lower-priority duplicate/overlap; OS route not installed",
				sub, remotePeer.String())
			continue
		}

		installed, err := n.Gateway.AddSubnetRoute(sub, gw)
		if err != nil {
			log.Warn("Failed to install subnet route %s via %s: %v", sub, gw, err)
		} else if installed {
			log.Info("🌐 Successfully installed authorized subnet route %s via peer %s (%s)", sub, remotePeer.String(), gw)
		}
	}
}

// reconcileSubnetRoutes recalculates all active subnets from surviving peers in peerMeta
// and removes only stale routes whose peer/gateway is no longer active.
func (n *Node) reconcileSubnetRoutes() {
	if n.Gateway == nil {
		return
	}
	validSubnets := make(map[string]string)
	if n.Config.AcceptAdvertisedSubnets {
		n.peerMeta.Range(func(key, value interface{}) bool {
			pID := key.(peer.ID)
			if pID == n.Host.ID() {
				return true
			}
			meta := value.(PeerMeta)

			isAllowed := false
			for _, p := range n.Config.AllowedSubnetPeers {
				if p == "*" || p == pID.String() {
					isAllowed = true
					break
				}
			}
			if !isAllowed {
				return true
			}

			cleanGWv4 := strings.Split(meta.TapIP, "/")[0]
			cleanGWv6 := strings.Split(meta.TapIPv6, "/")[0]

			for _, sub := range meta.AdvertisedSubnets {
				if sub == "" {
					continue
				}
				// Exclude subnets that lost the duplicate/overlap arbitration to a
				// higher-priority peer, so their OS route is reconciled away.
				if n.isSubnetRouteSuppressed(pID, sub) {
					continue
				}
				if _, subnetNet, err := net.ParseCIDR(sub); err == nil {
					if subnetNet.IP.To4() != nil {
						if cleanGWv4 != "" {
							validSubnets[sub] = cleanGWv4
						}
					} else {
						if cleanGWv6 != "" {
							validSubnets[sub] = cleanGWv6
						}
					}
				}
			}
			return true
		})
	}

	n.Gateway.ReconcileSubnetRoutes(validSubnets)
}
