package node

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	manet "github.com/multiformats/go-multiaddr/net"

	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/routing"
)

const ProtocolID protocol.ID = "/p2ptap/application/1.0.0"

// PeerStreams manages all active P2P streams to a single remote peer
type PeerStreams struct {
	mu      sync.RWMutex
	writeMu sync.Mutex // serializes WriteFrame calls to prevent interleaving across concurrent goroutines
	peerID  peer.ID
	streams map[string]network.Stream // TransportName -> Stream

	// sorted is the transport-priority-ordered snapshot of streams, rebuilt
	// under mu on EVERY streams-map mutation. Readers get the published slice
	// without copying or sorting: the hot path (GetAllStreams once or twice per
	// TAP frame) used to pay one slice allocation + a sort PER CALL, which is
	// pure GC pressure at wire rate. A published snapshot is immutable — the
	// rebuild always allocates a fresh slice — so readers may iterate it after
	// releasing the lock. Re-fetch to observe later add/remove.
	sorted []network.Stream

	// nextWriteDeadlineRenew tracks when the write deadline must be refreshed.
	// All writes to this field happen under writeMu, so no atomic is needed.
	// Zero value means "renew immediately".
	nextWriteDeadlineRenew time.Time
}

func NewPeerStreams(pID peer.ID) *PeerStreams {
	return &PeerStreams{
		peerID:  pID,
		streams: make(map[string]network.Stream),
	}
}

// rebuildLocked re-sorts the streams snapshot. Caller MUST hold ps.mu (write).
func (ps *PeerStreams) rebuildLocked() {
	next := make([]network.Stream, 0, len(ps.streams))
	for _, s := range ps.streams {
		next = append(next, s)
	}
	if len(next) > 1 {
		sort.SliceStable(next, func(i, j int) bool {
			return scoreStreamTransport(next[i]) < scoreStreamTransport(next[j])
		})
	}
	ps.sorted = next
}

func (ps *PeerStreams) AddStream(transportName string, s network.Stream) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.streams[transportName] = s
	ps.rebuildLocked()
	log.Debug("Stream registered for peer %s via %s (total: %d streams)", ps.peerID.String(), transportName, len(ps.streams))
}

func (ps *PeerStreams) RemoveStream(transportName string, stream network.Stream) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if current, ok := ps.streams[transportName]; ok && current == stream {
		delete(ps.streams, transportName)
		ps.rebuildLocked()
	}
}

// GetAllStreams returns the transport-priority-ordered stream snapshot. Hot
// path: one RWMutex read-lock and no allocation — the snapshot is prebuilt by
// AddStream/RemoveStream. Callers may iterate the returned slice freely (it is
// never mutated after publish) but must re-call to observe later changes.
func (ps *PeerStreams) GetAllStreams() []network.Stream {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.sorted
}

// scoreStreamTransport ranks streams for transport strategy selection:
// 0: Local loopback (fastest)
// 10: Private LAN IP (192.168.x, 10.x, 172.16-31.x, ULA fd00::/8) - LAN direct pass-through
// 20: Direct Public WAN IP (QUIC / TCP / WebRTC direct)
// 100: Relayed connection (/p2p-circuit) - slowest, rate-limited
func scoreStreamTransport(s network.Stream) int {
	if s == nil || s.Conn() == nil {
		return 999
	}
	rMA := s.Conn().RemoteMultiaddr()
	if rMA == nil {
		return 999
	}
	rStr := rMA.String()
	if strings.Contains(rStr, "/p2p-circuit") {
		return 100 // Relay stream: lowest priority
	}
	if manet.IsIPLoopback(rMA) {
		return 0 // Local loopback: top priority
	}
	if manet.IsPrivateAddr(rMA) {
		return 10 // Private LAN direct: high priority
	}
	return 20 // Public WAN direct: medium priority
}

// prefersTCPFragPayload reports whether ALL active streams for this peer are
// carried over TCP (identified by "/tcp" in the multiaddr key). When true, the
// caller may use a much larger fragment payload threshold because TCP/yamux is a
// reliable byte-stream with no UDP path-MTU constraint — unlike QUIC/WebRTC
// where every UDP datagram must fit under the ~1200-byte IP MTU. This check
// avoids needless fragmentation on the common TCP-direct-connect path, cutting
// double-AEAD overhead by ~50% for bulk transfers.
// Returns false when any stream is non-TCP or when no streams are registered.
func (ps *PeerStreams) prefersTCPFragPayload() bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if len(ps.streams) == 0 {
		return false
	}
	for key := range ps.streams {
		// Transport keys are full multiaddr strings, e.g.
		// "/ip4/1.2.3.4/tcp/12345" or "/ip6/.../quic-v1/...".
		// A TCP stream always contains "/tcp/" in its path.
		if !strings.Contains(key, "/tcp/") {
			return false
		}
	}
	return true
}

// StrategyDispatcher implements 'best_path', 'redundant', and 'fallback' transport strategies
type StrategyDispatcher struct {
	h                     host.Host
	node                  *Node  // back-reference for per-peer byte tracking
	mode                  string // "best_path", "redundant", "fallback"
	peersMu               sync.RWMutex
	peerMap               map[peer.ID]*PeerStreams
	outgoingStreamHandler func(network.Stream)
	// knownPeersFn returns all VPN peers known to the node, INCLUDING peers
	// that are only reachable via a circuit relay (and therefore NOT present in
	// h.Network().Peers(), which only lists directly-connected peers such as
	// the relay hop itself). Broadcast fan-out relies on this to reach relay-only
	// peers, otherwise ARP/NDP requests never reach them and unicast frames
	// (e.g. pings) stay unresolved.
	knownPeersFn func() []peer.ID
}

// SetKnownPeersProvider installs a callback that returns every known VPN peer
// (direct + relay-reachable). Optional; when unset, broadcast falls back to the
// connected-peer-only view.
func (sd *StrategyDispatcher) SetKnownPeersProvider(fn func() []peer.ID) {
	sd.knownPeersFn = fn
}

// SetOutgoingStreamHandler installs the reader used for locally opened
// streams. libp2p only calls the host stream handler for streams opened by a
// remote peer, so locally opened streams need this explicit reader as well.
func (sd *StrategyDispatcher) SetOutgoingStreamHandler(handler func(network.Stream)) {
	sd.outgoingStreamHandler = handler
}

func NewStrategyDispatcher(h host.Host, mode string) *StrategyDispatcher {
	return &StrategyDispatcher{
		h:       h,
		mode:    mode,
		peerMap: make(map[peer.ID]*PeerStreams),
	}
}

// SetNode sets the node back-reference (called after Node construction completes).
func (sd *StrategyDispatcher) SetNode(n *Node) { sd.node = n }

func (sd *StrategyDispatcher) GetPeerStreams(pID peer.ID) *PeerStreams {
	sd.peersMu.RLock()
	defer sd.peersMu.RUnlock()
	return sd.peerMap[pID]
}

func (sd *StrategyDispatcher) GetOrCreatePeerStreams(pID peer.ID) *PeerStreams {
	sd.peersMu.Lock()
	defer sd.peersMu.Unlock()

	ps, exists := sd.peerMap[pID]
	if !exists {
		ps = NewPeerStreams(pID)
		sd.peerMap[pID] = ps
	}
	return ps
}

func (sd *StrategyDispatcher) RegisterStream(pID peer.ID, transportName string, s network.Stream) {
	ps := sd.GetOrCreatePeerStreams(pID)
	ps.AddStream(transportName, s)
}

func (sd *StrategyDispatcher) UnregisterStream(pID peer.ID, transportName string, s network.Stream) {
	sd.peersMu.RLock()
	ps := sd.peerMap[pID]
	sd.peersMu.RUnlock()
	if ps != nil {
		ps.RemoveStream(transportName, s)
	}
}

func (sd *StrategyDispatcher) RemovePeer(pID peer.ID) {
	sd.peersMu.Lock()
	defer sd.peersMu.Unlock()
	delete(sd.peerMap, pID)
	log.Debug("Removed peer %s from strategy dispatcher map", pID.String())
}

func (sd *StrategyDispatcher) openStream(parentCtx context.Context, targetPeer peer.ID) (*PeerStreams, network.Stream, error) {
	// Double-check if stream was opened while caller was waiting
	sd.peersMu.RLock()
	ps, exists := sd.peerMap[targetPeer]
	sd.peersMu.RUnlock()
	if exists && ps != nil {
		streams := ps.GetAllStreams()
		if len(streams) > 0 {
			return ps, streams[0], nil
		}
	}

	log.Debug("No active streams to peer %s, opening new stream...", targetPeer.String())

	// If the peer is already transport-connected, yamux can open a sub-stream in
	// milliseconds — no TCP handshake needed. Use a tight timeout so a stuck TCP
	// send buffer (common cause of the 3-second+ spikes) fails fast and falls
	// through to relay fallback rather than blocking this dispatch worker.
	// If the peer is NOT connected, we need a full dial timeout (8s) for NAT
	// traversal + relay setup.
	streamTimeout := 3 * time.Second
	if sd.node != nil && sd.node.Host.Network().Connectedness(targetPeer) == network.Connected {
		streamTimeout = 1500 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(parentCtx, streamTimeout)
	defer cancel()

	// Allow stream creation over transient / relayed connections
	streamCtx := network.WithAllowLimitedConn(ctx, "p2ptap-data")
	s, err := sd.h.NewStream(streamCtx, targetPeer, ProtocolID)
	if err != nil {
		return nil, nil, fmt.Errorf("open stream to peer %s: %w", targetPeer, err)
	}

	// Best-effort: disable Nagle/delay on the underlying connection for low-latency forwarding.
	if conn := s.Conn(); conn != nil {
		if tcpConn, ok := extractUnderlyingTCPConn(conn); ok {
			_ = tcpConn.SetNoDelay(true)
		}
	}

	transportName := s.Conn().RemoteMultiaddr().String()
	ps = sd.GetOrCreatePeerStreams(targetPeer)
	ps.AddStream(transportName, s)
	log.Debug("Opened new outgoing stream to peer %s via %s", targetPeer.String(), transportName)

	if sd.outgoingStreamHandler != nil {
		go sd.outgoingStreamHandler(s)
	}

	return ps, s, nil
}

// extractUnderlyingTCPConn unwraps libp2p transport layers to find a *net.TCPConn for NoDelay tuning.
func extractUnderlyingTCPConn(conn interface{}) (interface{ SetNoDelay(bool) error }, bool) {
	// Direct match (fast path, rare in libp2p).
	if tc, ok := conn.(interface{ SetNoDelay(bool) error }); ok {
		return tc, true
	}
	// Walk common libp2p wrapper chains via reflection-free interface probing.
	type connAccessor interface{ Conn() interface{} }
	type rawAccessor interface{ RawConn() interface{} }
	if accessor, ok := conn.(connAccessor); ok {
		inner := accessor.Conn()
		if tc, ok := inner.(interface{ SetNoDelay(bool) error }); ok {
			return tc, true
		}
		if ra, ok := inner.(rawAccessor); ok {
			if tc, ok := ra.RawConn().(interface{ SetNoDelay(bool) error }); ok {
				return tc, true
			}
		}
	}
	if accessor, ok := conn.(rawAccessor); ok {
		if tc, ok := accessor.RawConn().(interface{ SetNoDelay(bool) error }); ok {
			return tc, true
		}
	}
	return nil, false
}

// SendToPeer dispatches packed frame bytes according to the configured strategy.
// On write failure, dead streams are removed, a new stream is opened, and the write is retried once.
func (sd *StrategyDispatcher) SendToPeer(ctx context.Context, targetPeer peer.ID, packedData []byte) error {
	// Relay-only / circuit-only peers (no active direct application stream) are
	// routed through the SAME PackRelayFrame overlay wrapper used for normal
	// relay routing, instead of libp2p's transparent /p2p-circuit L3 stream.
	// This unifies both relay paths under one hop-by-hop encrypted envelope (see
	// the overlay relay fix) and avoids sealing the frame with targetPeer's cipher
	// while only the relay hop can decrypt it. Matches BroadcastBatchToAllPeers'
	// !hasDirectStream predicate.
	if sd.node != nil && !sd.hasDirectStream(targetPeer) {
		// Hard guard: if the target is a libp2p DIRECT peer (Connected at the
		// transport layer), never route it through the overlay relay. The
		// application-level peerMap may lag the transport connection during the
		// SeqSync handshake window, so hasDirectStream can briefly report false
		// for a peer we are in fact directly connected to. Routing such a peer
		// through PackRelayFrame would wrap its frames in a relay envelope, send
		// them to itself-as-hopper, and silently drop the ICMP payload (exactly
		// the "ping peer fails but link ping-pong OK" symptom). This guard keeps
		// directly-connected peers on the direct path unconditionally.
		if !sd.node.isDirectlyConnected(targetPeer) {
			if hop := sd.node.relayHopForTarget(targetPeer); hop != "" {
				// A boot hop means the target is only reachable THROUGH a boot
				// (same boot, or another boot in the same PSK network across the
				// backbone). The boot does not speak the overlay relay protocol, so
				// it must go via the boot-relay (relay-over-backbone) uplink.
				if sd.node.isBootstrapPeer(hop) {
					return sd.sendToPeerViaBootRelay(targetPeer, hop, packedData)
				}
				return sd.sendToPeerViaOverlayRelay(targetPeer, hop, packedData)
			}
		}
	}

	sd.peersMu.RLock()
	ps, exists := sd.peerMap[targetPeer]
	sd.peersMu.RUnlock()

	if !exists {
		var err error
		ps, _, err = sd.openStream(ctx, targetPeer)
		if err != nil {
			log.Debug("Failed to open stream to peer %s: %v", targetPeer.String(), err)
			if rfErr := sd.relayFallbackIfPossible(targetPeer, packedData); rfErr == nil {
				return nil
			}
			return err
		}
	}

	// Resolve the per-peer cipher ONCE and seal + fragment the frame ONCE
	// (non-blocking CPU work). The plaintext frame is preserved in rawData for
	// relay fallback; the direct-write helpers below may drop & reopen streams
	// without re-encrypting. Crucially, we do NOT hold ps.writeMu while calling
	// openStream (an up-to-8s NewStream): every per-mode helper releases the
	// lock before (re)opening a stream, so a stalled direct link never
	// serialises the other dispatch goroutines sending to the same peer behind
	// that blocking call — which used to peg the CPU at idle.
	rawData := packedData
	var cipher obfuscate.ObfCipher
	if sd.node != nil {
		cipher = sd.node.obfCipherForPeer(targetPeer)
	}
	// Use a transport-aware fragment-payload threshold: TCP/yamux streams have
	// no UDP path-MTU constraint, so we use a much larger limit to avoid
	// pointless fragmentation and the associated double-AEAD overhead.
	var fragMaxPayload int
	if sd.node != nil {
		fragMaxPayload = sd.node.maxFragPayloadForPS(ps)
	}
	frags, origLen, encErr := sd.encryptAndFragment(targetPeer, cipher, packedData, fragMaxPayload)
	if encErr != nil {
		// Never fall through to the wire with an unsealed frame: the peer would
		// drop it and the operator would see only an unexplained packet loss.
		log.Warn("Tx to peer %s aborted: %v", targetPeer.String(), encErr)
		return encErr
	}

	switch sd.mode {
	case "redundant":
		// Send duplicate copies over ALL active transport streams.
		return sd.sendRedundant(ctx, targetPeer, ps, frags, origLen, rawData)

	case "fallback":
		// Try streams sequentially until one succeeds, then reopen + relay fallback.
		return sd.sendFallback(ctx, targetPeer, ps, frags, origLen, rawData)

	case "best_path":
		fallthrough
	default:
		// Default: best_path — first stream, cleanup + retry, then relay fallback.
		return sd.sendBestPath(ctx, targetPeer, ps, frags, origLen, rawData)
	}
}

// encryptAndFragment seals rawData with the per-peer cipher and splits it into
// length-prefixed frames. It is non-blocking and safe to call under ps.writeMu
// or on a hot path. Returns the frames and the post-inner-encrypt payload length
// used for TX byte accounting. cipher may be nil (plaintext obfuscation only).
// SendToPeer and writeFrameLocked both route through it so the two paths can
// never drift apart.
//
// maxPayload controls the per-fragment inner-payload threshold. Pass 0 to use
// the node-default (QUIC-safe). Callers with an active TCP PeerStreams should
// use maxFragPayloadForPS(ps) to avoid needless fragmentation on byte-streams.
func (sd *StrategyDispatcher) encryptAndFragment(targetPeer peer.ID, cipher obfuscate.ObfCipher, rawData []byte, maxPayload int) ([][]byte, int, error) {
	if sd.node == nil {
		return [][]byte{rawData}, len(rawData), nil
	}
	data := rawData
	if cipher != nil {
		enc, err := sd.node.sealPeerFrame(targetPeer, cipher, data)
		if err != nil {
			// A cipher IS negotiated for this peer, which means its RX path
			// AEAD-opens every frame it receives. The previous code merely logged
			// at Debug level and then sent the PLAINTEXT frame anyway — so the
			// receiver's AEAD gate silently dropped it while the true cause stayed
			// invisible, and the payload leaked onto the wire unencrypted. Both are
			// unacceptable: surface the error and let the caller decide.
			return nil, 0, fmt.Errorf("seal frame for peer %s: %w", targetPeer.String(), err)
		}
		data = enc
	} else {
		log.Debug("Tx: SENDING FRAME TO %s IN PLAINTEXT — no per-peer cipher negotiated (encryption disabled or handshake incomplete)",
			targetPeer.String())
	}
	// Fragment envelopes are Packed with a FRESH per-fragment seqID (see
	// fragmentFrame): the AEAD nonce is derived from the frame header, so reusing
	// one seqID for every fragment would reuse one nonce for every fragment.
	frags := sd.node.fragmentFrame(data, sd.node.fragRX, sd.node.txEpochForPeer(targetPeer), maxPayload)
	// When fragmentation occurred, re-encrypt each outer envelope with the SAME
	// per-peer cipher so the receiver's AEAD open gate accepts the fragments.
	// Non-fragmented frames are already per-peer encrypted above and must NOT be
	// double-encrypted.
	if len(frags) > 1 && cipher != nil {
		for i, f := range frags {
			enc, err := sd.node.sealPeerFrame(targetPeer, cipher, f)
			if err != nil {
				// Skipping a failed fragment (the old `continue`) shipped it
				// unsealed; the receiver dropped it and the reassembly of the
				// WHOLE frame failed anyway. Fail fast with a precise error.
				return nil, 0, fmt.Errorf("seal fragment %d/%d for peer %s: %w",
					i+1, len(frags), targetPeer.String(), err)
			}
			frags[i] = enc
		}
	}
	return frags, len(data), nil
}

// removeStreamUnderLock drops a stream from ps while the caller holds
// ps.writeMu. It takes ps.mu (a separate lock) to mutate the map, so there is no
// deadlock with the held writeMu. A nil Conn() is handled safely.
func (sd *StrategyDispatcher) removeStreamUnderLock(ps *PeerStreams, s network.Stream) {
	if s == nil {
		return
	}
	var tName string
	if conn := s.Conn(); conn != nil {
		tName = conn.RemoteMultiaddr().String()
	} else {
		tName = "(disconnected)"
	}
	ps.RemoveStream(tName, s)
}

// writeOverStreams tries each currently-registered stream in order; the first
// success wins and returns nil. Every failed stream is removed from ps (dead
// cleanup). The caller MUST hold ps.writeMu. Returns the last write error (nil
// only when at least one stream succeeded).
func (sd *StrategyDispatcher) writeOverStreams(ps *PeerStreams, targetPeer peer.ID, frags [][]byte, origLen int) error {
	var lastErr error
	for _, s := range ps.GetAllStreams() {
		if s == nil {
			continue
		}
		if err := sd.writeFragsToStreams(ps, targetPeer, []network.Stream{s}, origLen, frags); err == nil {
			return nil
		} else {
			lastErr = err
		}
		sd.removeStreamUnderLock(ps, s)
	}
	return lastErr
}

// retryWithFreshStream opens a new stream OUTSIDE any writeMu lock and retries
// the write once. On total failure it falls back to an overlay relay. origErr,
// when non-nil, is the error from the first (dead) write, preserved for the
// returned message.
func (sd *StrategyDispatcher) retryWithFreshStream(ctx context.Context, targetPeer peer.ID, ps *PeerStreams, frags [][]byte, origLen int, rawData []byte, origErr error) error {
	ps2, _, openErr := sd.openStream(ctx, targetPeer)
	if openErr != nil {
		if rfErr := sd.relayFallbackIfPossible(targetPeer, rawData); rfErr == nil {
			return nil
		}
		if origErr != nil {
			return fmt.Errorf("best_path retry failed: %w (original: %v)", openErr, origErr)
		}
		return fmt.Errorf("best_path: %w", openErr)
	}
	ps2.writeMu.Lock()
	remaining := ps2.GetAllStreams()
	if len(remaining) > 0 {
		err := sd.writeFragsToStreams(ps2, targetPeer, remaining, origLen, frags)
		ps2.writeMu.Unlock()
		if err == nil {
			return nil
		}
		if rfErr := sd.relayFallbackIfPossible(targetPeer, rawData); rfErr == nil {
			return nil
		}
		return fmt.Errorf("best_path: no streams after retry for peer %s: %w", targetPeer.String(), err)
	}
	ps2.writeMu.Unlock()
	if rfErr := sd.relayFallbackIfPossible(targetPeer, rawData); rfErr == nil {
		return nil
	}
	return fmt.Errorf("best_path: no streams after retry for peer %s", targetPeer.String())
}

// sendBestPath is the default strategy: write to the first available stream.
// On a write failure it removes the dead stream and reopens a fresh one WITHOUT
// holding writeMu (so a stalled/blocked direct link never serialises other
// senders behind the up-to-8s NewStream). Falls back to an overlay relay when
// the direct path is unrecoverable — closing the silent-drop hole.
func (sd *StrategyDispatcher) sendBestPath(ctx context.Context, targetPeer peer.ID, ps *PeerStreams, frags [][]byte, origLen int, rawData []byte) error {
	ps.writeMu.Lock()
	streams := ps.GetAllStreams()
	if len(streams) == 0 {
		ps.writeMu.Unlock()
		return sd.retryWithFreshStream(ctx, targetPeer, ps, frags, origLen, rawData, nil)
	}
	err := sd.writeFragsToStreams(ps, targetPeer, streams, origLen, frags)
	if err == nil {
		ps.writeMu.Unlock()
		return nil
	}
	// Dead stream: drop it under lock, then release BEFORE reopening so we never
	// hold writeMu across the (up-to-8s) NewStream call.
	sd.removeStreamUnderLock(ps, streams[0])
	ps.writeMu.Unlock()
	log.Debug("Removed dead best_path stream for peer %s (%v), retrying with fresh stream", targetPeer.String(), err)
	return sd.retryWithFreshStream(ctx, targetPeer, ps, frags, origLen, rawData, err)
}

// sendFallback tries every active stream in turn (first success wins) and
// removes any dead ones. When no stream survives it reopens a fresh one WITHOUT
// holding writeMu and retries; if the direct path is truly dead it falls back
// to an overlay relay — closing the silent-drop hole that previously existed
// for this mode.
func (sd *StrategyDispatcher) sendFallback(ctx context.Context, targetPeer peer.ID, ps *PeerStreams, frags [][]byte, origLen int, rawData []byte) error {
	ps.writeMu.Lock()
	lastErr := sd.writeOverStreams(ps, targetPeer, frags, origLen)
	ps.writeMu.Unlock()
	if lastErr == nil {
		return nil
	}
	// No stream survived; reopen a fresh one OUTSIDE writeMu, then retry.
	ps2, _, openErr := sd.openStream(ctx, targetPeer)
	if openErr != nil {
		if rfErr := sd.relayFallbackIfPossible(targetPeer, rawData); rfErr == nil {
			return nil
		}
		return fmt.Errorf("fallback: %w (after stream failures, open failed)", openErr)
	}
	ps2.writeMu.Lock()
	remaining := ps2.GetAllStreams()
	if len(remaining) > 0 {
		err := sd.writeFragsToStreams(ps2, targetPeer, remaining, origLen, frags)
		ps2.writeMu.Unlock()
		if err == nil {
			return nil
		}
		if rfErr := sd.relayFallbackIfPossible(targetPeer, rawData); rfErr == nil {
			return nil
		}
		return fmt.Errorf("fallback: no streams after reopen for peer %s: %w", targetPeer.String(), err)
	}
	ps2.writeMu.Unlock()
	if rfErr := sd.relayFallbackIfPossible(targetPeer, rawData); rfErr == nil {
		return nil
	}
	return fmt.Errorf("fallback: no streams available for peer %s", targetPeer.String())
}

// sendRedundant writes a duplicate copy over EVERY active transport stream (the
// real meaning of "redundant"), so a frame is delivered along all healthy paths
// simultaneously. Dead streams are dropped. If every stream fails (or none
// exist) it reopens a fresh one WITHOUT holding writeMu and falls back to an
// overlay relay when the direct path is unrecoverable — closing the silent-drop
// hole that previously existed for this mode.
func (sd *StrategyDispatcher) sendRedundant(ctx context.Context, targetPeer peer.ID, ps *PeerStreams, frags [][]byte, origLen int, rawData []byte) error {
	ps.writeMu.Lock()
	streams := ps.GetAllStreams()
	sentAny := false
	for _, s := range streams {
		if s == nil {
			continue
		}
		if err := sd.writeFragsToStreams(ps, targetPeer, []network.Stream{s}, origLen, frags); err == nil {
			sentAny = true
		} else {
			sd.removeStreamUnderLock(ps, s)
		}
	}
	ps.writeMu.Unlock()
	if sentAny {
		return nil
	}
	// All streams failed (or none existed): try a fresh stream, then relay fallback.
	ps2, _, openErr := sd.openStream(ctx, targetPeer)
	if openErr != nil {
		if rfErr := sd.relayFallbackIfPossible(targetPeer, rawData); rfErr == nil {
			return nil
		}
		return fmt.Errorf("redundant: %w", openErr)
	}
	ps2.writeMu.Lock()
	remaining := ps2.GetAllStreams()
	if len(remaining) > 0 {
		err := sd.writeFragsToStreams(ps2, targetPeer, remaining, origLen, frags)
		ps2.writeMu.Unlock()
		if err == nil {
			return nil
		}
		if rfErr := sd.relayFallbackIfPossible(targetPeer, rawData); rfErr == nil {
			return nil
		}
		return fmt.Errorf("redundant: no streams after reopen for peer %s: %w", targetPeer.String(), err)
	}
	ps2.writeMu.Unlock()
	if rfErr := sd.relayFallbackIfPossible(targetPeer, rawData); rfErr == nil {
		return nil
	}
	return fmt.Errorf("redundant: no streams available for peer %s", targetPeer.String())
}

// sendToPeerViaOverlayRelay delivers packedData to a relay-only / circuit-only
// peer using the PackRelayFrame overlay wrapper — identical to the normal relay
// path used by the TAP dispatch layer. This is the unified code path that lets
// circuit-only peers benefit from the same hop-by-hop encrypted envelope:
//
//  1. END-TO-END seal the inner payload for targetPeer (relay cannot read it).
//  2. Wrap in PackRelayFrame(targetPeer, self, TTL, inner).
//  3. HOP-BY-HOP seal the outer relay frame with the relay hop's cipher.
//  4. Submit to relayPool, which opens/uses the OverlayRelayProtocolID stream to hop.
//
// Forwards to relayPool.Submit so the existing persistent-connection machinery
// (reconnect-on-idle, single-flight) is reused.
func (sd *StrategyDispatcher) sendToPeerViaOverlayRelay(targetPeer, relayHop peer.ID, packedData []byte) error {
	n := sd.node
	if n == nil {
		return fmt.Errorf("overlay relay send to %s requires node", targetPeer.String())
	}

	// Capture the on-wire payload length up-front. The frame buffer may be a
	// pooled buffer (acquireFrameBuf) that the dispatch worker releases and
	// reuses the instant SendToPeer returns; onSent runs asynchronously inside
	// the relay pool's write loop, so reading len(packedData) there would race
	// with reuse and report a wrong (often zero) TX byte count.
	txBytes := len(packedData)

	// 1. END-TO-END seal for the final destination. packedData IS an obfuscate
	//    frame, so sealing it in place is structurally valid. The error is NOT
	//    swallowed: forwarding an unsealed inner payload would be rejected by the
	//    destination's AEAD gate, losing the frame with no diagnostic.
	inner := packedData
	if cipher := n.obfCipherForPeer(targetPeer); cipher != nil {
		enc, eerr := n.sealPeerFrame(targetPeer, cipher, inner)
		if eerr != nil {
			return fmt.Errorf("overlay relay end-to-end seal for %s failed: %w", targetPeer.String(), eerr)
		}
		inner = enc
	}

	// 2. Wrap in an overlay relay frame.
	relayBuf, err := routing.PackRelayFrame(targetPeer, n.Host.ID(), routing.MaxRelayTTL, inner)
	if err != nil {
		return fmt.Errorf("overlay relay pack for %s failed: %w", targetPeer.String(), err)
	}

	// 3. HOP-BY-HOP: wrap the envelope in an obfuscate frame, then seal THAT for
	//    the hop. The wrap is mandatory — sealing a bare relay envelope always
	//    failed with ErrFrameCorrupted and shipped it in plaintext, which the hop
	//    then dropped. See sealRelayEnvelopeForHop for the full analysis.
	relayBuf, err = n.sealRelayEnvelopeForHop(relayHop, relayBuf)
	if err != nil {
		return fmt.Errorf("overlay relay hop seal via %s failed: %w", relayHop.String(), err)
	}

	// 4. Submit via the persistent relay connection pool.
	if !n.relayPool.Submit(relayHop, relayBuf,
		func() {
			n.recordPeerTxBytes(targetPeer, txBytes)
			if n.protoTracker != nil {
				n.protoTracker.RelayData.RecordTx(1, uint64(len(relayBuf)))
			}
		}, // onSent
		func() { // onFail
			log.Debug("Overlay relay send to peer %s via %s permanently failed",
				targetPeer.String(), relayHop.String())
		},
	) {
		return fmt.Errorf("overlay relay send to %s via %s: pool queue full",
			targetPeer.String(), relayHop.String())
	}
	return nil
}

// relayFallbackIfPossible re-routes rawData to targetPeer through an overlay
// relay hop when every direct stream write has failed. It returns nil on a
// successful relay hand-off (frame queued for delivery) and an error when no
// usable relay path exists, so callers can fall through to their original error.
//
// It is the unified safety net behind SendToPeer's best_path/fallback modes and
// SendBatchToPeer: a peer with an existing-but-stalled direct stream keeps TAP
// traffic flowing instead of silently dropping frames during a transient
// UDP/QUIC stall (e.g. the "write frame header: i/o deadline reached" symptom).
//
// relayHopForTarget already excludes the target itself and any directly
// connected peer as a hop, so this never wraps a frame in a relay envelope
// addressed to self (which would drop the payload). When no relay is
// configured/available the call returns an error and behaviour is unchanged.
func (sd *StrategyDispatcher) relayFallbackIfPossible(targetPeer peer.ID, rawData []byte) error {
	if sd.node == nil {
		return fmt.Errorf("relay fallback unavailable: node is nil")
	}
	hop := sd.node.relayHopForTarget(targetPeer)
	if hop == "" {
		return fmt.Errorf("relay fallback unavailable: no relay hop for %s", targetPeer.String())
	}
	// A boot hop routes through boot-relay (relay-over-backbone); a real
	// overlay-relay peer routes through the overlay relay pool.
	if sd.node.isBootstrapPeer(hop) {
		log.Debug("Direct send to %s failed; falling back to boot-relay via %s", targetPeer.String(), hop.String())
		return sd.sendToPeerViaBootRelay(targetPeer, hop, rawData)
	}
	log.Debug("Direct send to %s failed; falling back to overlay relay via %s", targetPeer.String(), hop.String())
	return sd.sendToPeerViaOverlayRelay(targetPeer, hop, rawData)
}

// SendBatchToPeer sends multiple packed frames to the same target peer.  When
// the peer has a live direct stream it takes ONE writeMu lock and resolves the
// per-peer ObfCipher ONCE for the whole batch, then encrypts + fragments +
// writes each frame back-to-back under that single lock (writeFrameLocked).
// This removes the per-frame obfCipherForPeer lookup and the per-frame
// lock/unlock churn that the previous per-frame SendToPeer loop paid, capturing
// most of the batching benefit WITHOUT touching the wire protocol, the RX path,
// or introducing any Nagle-style latency (frames are still written the moment
// they are dequeued).
//
// Each frame remains an independent length-prefixed, per-peer-encrypted tunnel
// frame, so the receiver needs no changes.  On any direct write failure the
// shared lock is released and the REMAINING frames (including the failed one)
// are routed through the robust per-frame SendToPeer path, which performs
// dead-stream removal, stream re-open and overlay-relay fallback — so a stalled
// direct link never silently drops a frame.  Relay-only peers (no direct
// stream) also defer to SendToPeer, which makes the relay-vs-direct decision
// per frame.
func (sd *StrategyDispatcher) SendBatchToPeer(ctx context.Context, targetPeer peer.ID, packedFrames [][]byte) error {
	if len(packedFrames) == 0 {
		return nil
	}

	// Relay-only / circuit-only peers have no direct application stream, so the
	// shared-lock optimisation below does not apply.  Route each frame through
	// SendToPeer, which makes the relay-vs-direct decision per frame.
	if sd.node != nil && !sd.hasDirectStream(targetPeer) && !sd.node.isDirectlyConnected(targetPeer) {
		return sd.sendFramesViaSendToPeer(ctx, targetPeer, packedFrames)
	}

	// ---- Direct-stream batch: ONE writeMu lock + ONE cipher lookup ----
	sd.peersMu.RLock()
	ps, exists := sd.peerMap[targetPeer]
	sd.peersMu.RUnlock()
	if !exists {
		var err error
		ps, _, err = sd.openStream(ctx, targetPeer)
		if err != nil {
			log.Debug("Failed to open stream to peer %s for batch: %v", targetPeer.String(), err)
			return sd.sendFramesViaSendToPeer(ctx, targetPeer, packedFrames)
		}
	}

	ps.writeMu.Lock()

	var cipher obfuscate.ObfCipher
	if sd.node != nil {
		cipher = sd.node.obfCipherForPeer(targetPeer)
	}

	for i, data := range packedFrames {
		if err := sd.writeFrameLocked(targetPeer, ps, cipher, data); err != nil {
			// A direct write failed (stalled/dead stream).  Release the shared
			// lock and route the REMAINING frames (this one included) through the
			// robust per-frame path.  Frames already written stay sent.
			log.Debug("Tx batch frame %d/%d to peer %s failed under shared lock: %v; routing remainder via SendToPeer",
				i+1, len(packedFrames), targetPeer.String(), err)
			// SendToPeer eventually acquires ps.writeMu itself.  Do not defer this
			// unlock: returning through the fallback while still holding the lock
			// self-deadlocks this peer's entire transmit path.
			ps.writeMu.Unlock()
			return sd.sendFramesViaSendToPeer(ctx, targetPeer, packedFrames[i:])
		}
	}
	ps.writeMu.Unlock()
	return nil
}

// writeFrameLocked encrypts and writes a single packed frame to targetPeer's
// direct streams while the caller holds ps.writeMu.  cipher is the per-peer
// ObfCipher resolved ONCE by the caller (once per SendToPeer call, or once per
// whole SendBatchToPeer batch), eliminating the per-frame obfCipherForPeer
// lookup.  The wire format is unchanged: each frame is an independent
// length-prefixed, per-peer-encrypted tunnel frame.
//
// On a write error it returns the error WITHOUT performing dead-stream removal,
// stream re-open or relay fallback — the caller decides how to recover (e.g.
// SendBatchToPeer routes the remainder via SendToPeer).
// writeFrameLocked encrypts + fragments + writes a single packed frame to
// targetPeer's direct streams while the caller holds ps.writeMu. cipher is the
// per-peer ObfCipher resolved ONCE by the caller (once per SendToPeer call, or
// once per whole SendBatchToPeer batch), eliminating the per-frame
// obfCipherForPeer lookup. The wire format is unchanged: each frame is an
// independent length-prefixed, per-peer-encrypted tunnel frame. The shared
// encryptAndFragment helper is reused so SendToPeer and the batch path cannot
// drift apart.
//
// On a write error it returns the error WITHOUT performing dead-stream removal,
// stream re-open or relay fallback — the caller decides how to recover (e.g.
// SendBatchToPeer routes the remainder via SendToPeer).
func (sd *StrategyDispatcher) writeFrameLocked(targetPeer peer.ID, ps *PeerStreams, cipher obfuscate.ObfCipher, packedData []byte) error {
	streams := ps.GetAllStreams()
	if len(streams) == 0 {
		return fmt.Errorf("no direct streams for peer %s", targetPeer.String())
	}
	var fragMaxPayload int
	if sd.node != nil {
		fragMaxPayload = sd.node.maxFragPayloadForPS(ps)
	}
	frags, origLen, err := sd.encryptAndFragment(targetPeer, cipher, packedData, fragMaxPayload)
	if err != nil {
		return err
	}
	return sd.writeFragsToStreams(ps, targetPeer, streams, origLen, frags)
}

// writeFragsToStreams writes the (already encrypted + fragmented) frags to
// targetPeer's direct streams according to the active strategy.  It records TX
// bytes once on success and returns the first write error, if any.
//
// ps must not be nil. Callers must hold ps.writeMu. The write deadline is
// refreshed at most once per second (throttled via ps.nextWriteDeadlineRenew)
// to avoid the per-frame SetWriteDeadline syscall cost under high PPS.
func (sd *StrategyDispatcher) writeFragsToStreams(ps *PeerStreams, targetPeer peer.ID, streams []network.Stream, origLen int, frags [][]byte) error {
	// Throttle SetWriteDeadline: only call it when the existing deadline is
	// within writeDeadlineRenewThreshold of expiry. All callers hold
	// ps.writeMu, so ps.nextWriteDeadlineRenew is safe to read/write here.
	const writeDeadlineWindow = 2500 * time.Millisecond
	const writeDeadlineRenewThreshold = 1000 * time.Millisecond
	needsDeadline := ps == nil || time.Now().After(ps.nextWriteDeadlineRenew)
	writeOne := func(s network.Stream) error {
		if needsDeadline {
			_ = s.SetWriteDeadline(time.Now().Add(writeDeadlineWindow))
		}
		for _, f := range frags {
			if err := WriteFrame(s, f); err != nil {
				return err
			}
		}
		return nil
	}
	if needsDeadline && ps != nil {
		ps.nextWriteDeadlineRenew = time.Now().Add(writeDeadlineWindow - writeDeadlineRenewThreshold)
	}

	record := func() {
		if sd.node != nil {
			sd.node.recordPeerTxBytes(targetPeer, origLen)
			if sd.node.protoTracker != nil {
				sd.node.protoTracker.Data.RecordTx(uint64(len(frags)), uint64(origLen))
			}
		}
	}

	switch sd.mode {
	case "redundant", "fallback":
		// Try each stream in order; first success wins.  (Dead-stream cleanup
		// and relay fallback are handled by the caller's outer retry logic.)
		var lastErr error
		for _, s := range streams {
			if s == nil {
				continue
			}
			writeErr := writeOne(s)
			if writeErr == nil {
				record()
				return nil
			}
			lastErr = writeErr
		}
		return lastErr
	default: // best_path
		if len(streams) == 0 {
			return fmt.Errorf("no streams for peer %s", targetPeer.String())
		}
		if err := writeOne(streams[0]); err != nil {
			return err
		}
		record()
		return nil
	}
}

// sendFramesViaSendToPeer delivers each frame through the full per-frame path.
// It is the relay-only and post-failure fallback for SendBatchToPeer, so
// batching never drops or mis-routes a frame when the optimised direct path
// cannot guarantee delivery.
func (sd *StrategyDispatcher) sendFramesViaSendToPeer(ctx context.Context, targetPeer peer.ID, packedFrames [][]byte) error {
	var firstErr error
	for i, data := range packedFrames {
		if err := sd.SendToPeer(ctx, targetPeer, data); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			log.Debug("Tx batched unicast frame %d/%d to peer %s failed: %v",
				i+1, len(packedFrames), targetPeer.String(), err)
		}
	}
	if firstErr != nil {
		return fmt.Errorf("batch send to %s: %w", targetPeer.String(), firstErr)
	}
	return nil
}

// BroadcastToAllPeers floods packed frame bytes to all connected VPN peers
// (ignores Bootstrap nodes) using parallel fan-out. Frames are packed in-memory
// synchronously so the source buffer can be released immediately, and network
// sends run asynchronously in background tasks without blocking dispatch workers.
func (sd *StrategyDispatcher) BroadcastToAllPeers(ctx context.Context, data []byte) {
	peerIDs := collectBroadcastPeers(sd)

	if len(peerIDs) == 0 {
		return
	}

	log.Debug("Broadcasting to %d active P2P peers (parallel fan-out)", len(peerIDs))

	// Bump the shared frame counter ONCE for this logical broadcast frame; every
	// peer's SeqID reuses the same counter but folds in its OWN anti-replay epoch
	// (so rotating one peer's epoch never touches another). Pack happens per-peer
	// here (not at the TAP read site) so each peer gets its epoch baked into the
	// SeqID.
	cnt := sd.node.Packer.BumpCounter()
	for pID := range peerIDs {
		p := pID
		if sd.node != nil && (!sd.node.canEgressToPeer(p) || sd.node.peerStalled(p)) {
			continue
		}
		localEpoch := uint64(0)
		if po := sd.node.peerObf(p); po != nil {
			localEpoch = po.localEpoch
		}
		seqID := sd.node.Packer.MakeSeqID(cnt, localEpoch)
		sd.node.Collector.RecordTxSeq(sd.node.peerIDString(p), seqID)
		maxPacked := sd.node.Packer.MaxPackedLen(len(data))
		outBuf := acquireFrameBuf(maxPacked)
		n, perr := sd.node.Packer.Pack(seqID, data, outBuf)
		if perr != nil {
			releaseFrameBuf(outBuf)
			log.Debug("P2P broadcast pack for peer %s failed: %v", p.String(), perr)
			continue
		}
		packed := outBuf[:n]
		go func(target peer.ID, pkt []byte, rawBuf []byte) {
			defer releaseFrameBuf(rawBuf)
			perPeerCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()
			if err := sd.SendToPeer(perPeerCtx, target, pkt); err != nil {
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					if sd.node != nil {
						sd.node.markPeerStalled(target)
					}
				}
				log.Debug("P2P broadcast write to peer %s failed: %v", target.String(), err)
			}
		}(p, packed, outBuf)
	}
}

// BroadcastBatchToAllPeers floods multiple packed frames to all connected
// VPN peers in a single fan-out pass. Frames are packed synchronously in-memory
// and sent asynchronously, never blocking dispatch workers on slow or wedged peers.
func (sd *StrategyDispatcher) BroadcastBatchToAllPeers(ctx context.Context, frames [][]byte) {
	if len(frames) == 0 {
		return
	}
	peerIDs := collectBroadcastPeers(sd)
	if len(peerIDs) == 0 {
		return
	}

	log.Debug("Broadcasting batch (%d frames) to %d active P2P peers", len(frames), len(peerIDs))

	for pID := range peerIDs {
		p := pID
		if sd.node != nil && (!sd.node.canEgressToPeer(p) || sd.node.peerStalled(p)) {
			continue
		}
		localEpoch := uint64(0)
		if po := sd.node.peerObf(p); po != nil {
			localEpoch = po.localEpoch
		}

		type packedItem struct {
			data   []byte
			rawBuf []byte
		}
		packedList := make([]packedItem, 0, len(frames))
		for _, frame := range frames {
			seqID := sd.node.Packer.MakeSeqID(sd.node.Packer.BumpCounter(), localEpoch)
			sd.node.Collector.RecordTxSeq(sd.node.peerIDString(p), seqID)
			maxPacked := sd.node.Packer.MaxPackedLen(len(frame))
			outBuf := acquireFrameBuf(maxPacked)
			n, perr := sd.node.Packer.Pack(seqID, frame, outBuf)
			if perr != nil {
				releaseFrameBuf(outBuf)
				log.Debug("P2P broadcast batch pack for peer %s failed: %v", p.String(), perr)
				continue
			}
			packedList = append(packedList, packedItem{data: outBuf[:n], rawBuf: outBuf})
		}
		if len(packedList) == 0 {
			continue
		}

		go func(target peer.ID, items []packedItem) {
			defer func() {
				for _, it := range items {
					releaseFrameBuf(it.rawBuf)
				}
			}()
			perPeerCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()

			batch := make([][]byte, 0, len(items))
			for _, it := range items {
				batch = append(batch, it.data)
			}
			if err := sd.SendBatchToPeer(perPeerCtx, target, batch); err != nil {
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					if sd.node != nil {
						sd.node.markPeerStalled(target)
					}
				}
				log.Debug("P2P broadcast batch write to peer %s failed: %v", target.String(), err)
			}
		}(p, packedList)
	}
}

// collectBroadcastPeers returns the set of peers to which broadcast frames
// should be delivered.  Peers that are not currently connected (or do not
// advertise the P2P TAP protocol) are excluded.
func collectBroadcastPeers(sd *StrategyDispatcher) map[peer.ID]bool {
	peerIDs := make(map[peer.ID]bool)

	// Never broadcast to our own peer ID. The known-peers provider may include
	// self (e.g. when self appears in the routing table), and doing so makes us
	// dial ourselves — "dial to self attempted" — on every single broadcast wave.
	// Filter it once up front so all three collection phases stay clean.
	self := sd.h.ID()

	// Phase 1: peers that already have active P2P streams.
	sd.peersMu.Lock()
	for pID := range sd.peerMap {
		if sd.h.Network().Connectedness(pID) == network.Connected {
			peerIDs[pID] = true
		} else {
			delete(sd.peerMap, pID)
		}
	}
	sd.peersMu.Unlock()

	// Phase 2: peers that are connected but haven't opened a stream yet,
	// provided they support the P2P TAP protocol (excludes bootstrap/crawlers).
	for _, pID := range sd.h.Network().Peers() {
		if pID == self {
			continue
		}
		if peerIDs[pID] {
			continue
		}
		if sd.h.Network().Connectedness(pID) != network.Connected {
			continue
		}
		protocols, err := sd.h.Peerstore().GetProtocols(pID)
		if err != nil {
			continue
		}
		for _, p := range protocols {
			if p == ProtocolID {
				peerIDs[pID] = true
				break
			}
		}
	}

	// Phase 3: peers known to the node but ONLY reachable via a circuit relay.
	// libp2p's Network().Peers() does not include them (it lists the relay hop,
	// not the indirect target), so broadcast ARP/NDP would never reach them and
	// their MACs would never be learned — breaking unicast traffic like ping.
	// These are delivered through SendToPeer, which opens a relay-routed stream.
	// Bootstrap/relay nodes are excluded: they are pure Circuit-Relay hops that
	// do NOT register the application data protocol, so opening a /p2ptap/
	// application/1.0.0 stream to them always fails with "protocols not supported".
	if sd.knownPeersFn != nil {
		for _, pID := range sd.knownPeersFn() {
			if pID == self {
				continue
			}
			if sd.node != nil && sd.node.isBootstrapPeer(pID) {
				continue
			}
			peerIDs[pID] = true
		}
	}
	return peerIDs
}

// PurgeCircuitStreams drops all circuit-routed (/p2p-circuit) data streams for
// a peer from the dispatcher map. Called when a DIRECT transport connection to
// the peer comes up: without this, an existing healthy circuit stream keeps
// winning best_path selection forever (its writes succeed, so nothing ever
// reopens it over the now-preferred direct connection) and Tx stays pinned to
// relay. The next SendToPeer finds no streams and opens a fresh one via
// NewStream, which the swarm routes over the direct conn (bestConnToPeer
// prefers direct over relayed). Streams are deregistered but not closed, so any
// in-flight write completes normally; the underlying circuit conn stays alive
// as a failover path.
func (sd *StrategyDispatcher) PurgeCircuitStreams(pID peer.ID) int {
	sd.peersMu.RLock()
	ps := sd.peerMap[pID]
	sd.peersMu.RUnlock()
	if ps == nil {
		return 0
	}
	purged := 0
	ps.mu.Lock()
	for name, s := range ps.streams {
		if s != nil && s.Conn() != nil && strings.Contains(s.Conn().RemoteMultiaddr().String(), "/p2p-circuit") {
			delete(ps.streams, name)
			purged++
		}
	}
	if purged > 0 {
		ps.rebuildLocked()
	}
	ps.mu.Unlock()
	if purged > 0 {
		log.Info("Purged %d circuit-routed stream(s) for peer %s after direct connect; next Tx re-opens over direct",
			purged, pID.ShortString())
	}
	return purged
}

// hasDirectStream reports whether the peer currently has an active direct
// (non-relay) stream in the peer map. Relay-only peers do not, and must be
// reached via SendToPeer (which dials through the relay).
func (sd *StrategyDispatcher) hasDirectStream(p peer.ID) bool {
	sd.peersMu.RLock()
	ps, exists := sd.peerMap[p]
	sd.peersMu.RUnlock()
	if !exists || ps == nil {
		return false
	}
	return len(ps.GetAllStreams()) > 0
}
