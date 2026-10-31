package node

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	manet "github.com/multiformats/go-multiaddr/net"
	msmux "github.com/multiformats/go-multistream"

	"p2ptap/pkg/maddrutil"
	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/routing"
)

const ProtocolID protocol.ID = "/p2ptap/application/1.0.0"

// PeerStreams manages all active P2P streams to a single remote peer
type PeerStreams struct {
	mu      sync.RWMutex
	writeMu sync.Mutex // serializes WriteFrame calls to prevent interleaving across concurrent goroutines
	// ensureMu serializes per-connection stream repair (EnsureStreamsOnAllConns)
	// for this peer. It is separate from writeMu because opening a stream can
	// block for seconds and must never hold the packet-path lock.
	ensureMu sync.Mutex
	peerID   peer.ID
	streams  map[string]network.Stream // streamRegistryKey -> Stream

	// sorted is the transport-priority-ordered snapshot of streams, rebuilt
	// under mu on EVERY streams-map mutation. Readers get the published slice
	// without copying or sorting: the hot path (GetAllStreams once or twice per
	// TAP frame) used to pay one slice allocation + a sort PER CALL, which is
	// pure GC pressure at wire rate. A published snapshot is immutable — the
	// rebuild always allocates a fresh slice — so readers may iterate it after
	// releasing the lock. Re-fetch to observe later add/remove.
	sorted []network.Stream

	// snapshot publishes the immutable read-side topology. Writers rebuild it
	// under mu whenever streams changes; packet-path readers only perform one
	// atomic load and never contend with stream registration/removal.
	snapshot atomic.Pointer[peerStreamsSnapshot]

	// Deadlines belong to streams, not peers. Protected by writeMu; topology
	// changes are reconciled from the immutable snapshot before the next write.
	writeDeadlineRenew    map[network.Stream]time.Time
	writeDeadlineSnapshot *peerStreamsSnapshot
	// Most batches stay on one stream. Cache that stream's map entry so the
	// steady path avoids interface-key hashing without sharing its deadline.
	writeDeadlineStream    network.Stream
	nextWriteDeadlineRenew time.Time
	// Adaptive transport selection is confined to multi-stream writers.
	// writeQuality is guarded by qualityMu — NOT by writeMu: the multipath
	// per-stream writer goroutines record samples from their own goroutines
	// (they never take writeMu), while the schedulers read it under writeMu.
	// qualityMu holders never acquire writeMu, so the two orders cannot cycle.
	qualityMu           sync.Mutex
	writeQuality        map[network.Stream]streamWriteQuality
	preferredStream     network.Stream
	streamSelectedAt    time.Time
	nextStreamSelection time.Time
	streamProbeCursor   int
	selectionSnapshot   *peerStreamsSnapshot
	// mpDeficit holds the DWRR deficit for the "multipath" strategy, keyed by
	// stream. Protected by writeMu (all pickMultipathStreamIndex callers hold
	// it). Pruned against the live topology inside pickMultipathStreamIndex and
	// removeStreamUnderLock.
	mpDeficit map[network.Stream]float64
	// mpWeights is the scratch weight buffer reused by the scheduler so the
	// packet path does not allocate per frame. Guarded by writeMu.
	mpWeights []float64
	// mpWriters holds the per-stream async writer for the multipath strategy
	// (see stream_writer.go). Guarded by writeMu; entries are stopped and
	// removed in removeStreamUnderLock, and pruned on topology changes in the
	// writeFragsToStreams reconciliation. Writer goroutines never take writeMu.
	mpWriters map[network.Stream]*streamWriter
	// mpPruneSnapshot is the topology snapshot the deficit map was last pruned
	// against, so pruning runs on topology changes instead of every frame.
	mpPruneSnapshot *peerStreamsSnapshot
	// pathKeys caches each stream's physical path key (remote multiaddr) so the
	// scheduler never re-renders the multiaddr on the packet path. Protected by
	// writeMu.
	pathKeys map[network.Stream]string
	// pathBackoff is the per-PATH circuit breaker for the "multipath" strategy,
	// keyed by path key rather than by stream: a failing path is usually
	// re-opened as a new stream, and keying by stream would reset the counter on
	// every rebuild and walk straight back into the same dead path. Protected by
	// writeMu.
	pathBackoff map[string]*pathBackoff
}

type peerStreamsSnapshot struct {
	streams []network.Stream
}

func NewPeerStreams(pID peer.ID) *PeerStreams {
	ps := &PeerStreams{
		peerID:  pID,
		streams: make(map[string]network.Stream),
	}
	ps.snapshot.Store(&peerStreamsSnapshot{})
	return ps
}

// rebuildLocked re-sorts the streams snapshot. Caller MUST hold ps.mu (write).
func (ps *PeerStreams) rebuildLocked() {
	names := make([]string, 0, len(ps.streams))
	for name := range ps.streams {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := scoreStreamTransport(ps.streams[names[i]]), scoreStreamTransport(ps.streams[names[j]])
		if a != b {
			return a < b
		}
		// Same transport tier: prefer OUR outbound stream over the peer's
		// inbound one. Both reach the same peer over the same connection, but
		// an outbound stream's lifetime is ours to manage — if the peer stops
		// reading, resets, or halves it, we are the side that has to notice and
		// re-open, whereas an inbound stream can be closed by the peer at any
		// time with no local signal until a write fails. best_path/fallback use
		// this ordering to pick their single stream.
		da, db := streamDirectionRank(ps.streams[names[i]]), streamDirectionRank(ps.streams[names[j]])
		if da != db {
			return da < db
		}
		return names[i] < names[j]
	})
	next := make([]network.Stream, 0, len(names))
	for _, name := range names {
		next = append(next, ps.streams[name])
	}
	ps.sorted = next
	ps.snapshot.Store(&peerStreamsSnapshot{streams: next})
}

// streamDirection reports the stream's direction, tolerating test doubles that
// embed a nil network.Stream (see strategyPipeStream): calling the promoted
// Stat() then panics on the nil interface. Direction is only a registry/ranking
// hint here, so a failed probe falls back to outbound instead of taking the
// whole stream table down.
func streamDirection(s network.Stream) (dir network.Direction) {
	if s == nil {
		return network.DirOutbound
	}
	defer func() {
		if recover() != nil {
			dir = network.DirOutbound
		}
	}()
	return s.Stat().Direction
}

// streamRegistryKey is the slot a stream occupies in PeerStreams.streams.
//
// The key used to be the stream's remote multiaddr, which collapses every
// stream that shares one connection into a single slot. An inbound stream
// opened by the peer and an outbound stream we opened ourselves report the SAME
// RemoteMultiaddr() (it is a property of the connection, not the stream), so
// the second registration CLOSED the first via AddStream's replacement path.
// With both sides priming a stream on connect — the normal case — each side
// tore down the stream the other had just registered, the peer's reader exited,
// and the data path rebuilt itself from scratch. That is a connect-then-stall
// cycle on every reconnect, and under the multipath strategy it also pins the
// peer to a SINGLE path forever, because whichever direction registers last is
// the only survivor.
//
// Keying on (direction, connection ID) gives one inbound and one outbound slot
// per physical connection and never evicts a healthy stream. Using the
// connection ID rather than the multiaddr also means a re-dial of the same
// address cannot collide with a stream still open on the previous connection.
func streamRegistryKey(s network.Stream) string {
	if s == nil {
		return ""
	}
	dir := "out"
	if streamDirection(s) == network.DirInbound {
		dir = "in"
	}
	if c := s.Conn(); c != nil {
		if id := c.ID(); id != "" {
			return dir + "|" + id
		}
	}
	// No usable connection identity: fall back to the stream's own address so
	// distinct streams still occupy distinct slots. Production streams always
	// have a connection ID; this branch exists for test doubles that implement
	// network.Stream without a real transport underneath.
	return fmt.Sprintf("%s|%p", dir, s)
}

// outboundKeyForConn is streamRegistryKey for an outbound stream we are about to
// open on c, so EnsureStreamsOnAllConns can test for an existing slot without
// holding a stream yet.
func outboundKeyForConn(c network.Conn) string {
	if c == nil {
		return ""
	}
	return "out|" + c.ID()
}

// AddStream registers s under key. It is derived from the stream itself by every
// caller (see streamRegistryKey) so there is exactly one notion of a slot.
func (ps *PeerStreams) AddStream(key string, s network.Stream) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	// A concurrent openStream may produce a new stream for the same slot while
	// the old one is still open (and still has a read goroutine). Closing the
	// old stream here prevents leaked streams and goroutines that accumulate
	// during connection churn. Because the slot is (direction, conn ID), this
	// can only ever replace OUR stream on the SAME connection in the SAME
	// direction — never the peer's inbound stream (see streamRegistryKey).
	if old, ok := ps.streams[key]; ok && old != s {
		old.Close()
	}
	ps.streams[key] = s
	ps.rebuildLocked()
	log.Debug("Stream registered for peer %s as %s (total: %d streams)", ps.peerID.String(), key, len(ps.streams))
}

// RemoveStream drops stream from the table by IDENTITY, not by key. An inbound
// stream handler unregisters while returning, possibly after its connection was
// torn down — at which point the key (which embeds the connection ID) can no
// longer be reproduced. The table holds at most a handful of streams per peer,
// so matching the value costs nothing.
func (ps *PeerStreams) RemoveStream(stream network.Stream) {
	if stream == nil {
		return
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	removed := false
	for key, current := range ps.streams {
		if current == stream {
			delete(ps.streams, key)
			removed = true
		}
	}
	if removed {
		ps.rebuildLocked()
	}
}

// HasStreamKey reports whether key currently holds a stream. Used by the
// per-connection stream repair to stay idempotent.
func (ps *PeerStreams) HasStreamKey(key string) bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	_, ok := ps.streams[key]
	return ok
}

// GetAllStreams returns the transport-priority-ordered immutable snapshot.
// Steady-state packet reads are lock-free: stream mutations publish a fresh
// slice through snapshot, and published slices are never changed in place.
func (ps *PeerStreams) GetAllStreams() []network.Stream {
	if snap := ps.snapshot.Load(); snap != nil {
		return snap.streams
	}
	// Compatibility slow path for a zero-value/struct-literal PeerStreams.
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.sorted
}

// scoreStreamTransport ranks streams for transport strategy selection:
// 0: Local loopback (fastest)
// 10: Private LAN IP (192.168.x, 10.x, 172.16-31.x, ULA fd00::/8) - LAN direct pass-through
// 20: Direct Public WAN IP (QUIC / TCP / WebRTC direct)
// 100: Relayed connection (/p2p-circuit) - slowest, rate-limited
// streamDirectionRank orders streams within one transport tier: our own
// outbound stream first (0), a peer-opened inbound stream second (1).
func streamDirectionRank(s network.Stream) int {
	if s == nil {
		return 2
	}
	if streamDirection(s) == network.DirInbound {
		return 1
	}
	return 0
}

func scoreStreamTransport(s network.Stream) int {
	if s == nil || s.Conn() == nil {
		return 999
	}
	rMA := s.Conn().RemoteMultiaddr()
	if rMA == nil {
		return 999
	}
	if maddrutil.IsCircuitRelay(rMA) {
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

// isRelayStream reports whether s rides a circuit-relay connection.
func isRelayStream(s network.Stream) bool {
	if s == nil || s.Conn() == nil || s.Conn().RemoteMultiaddr() == nil {
		return false
	}
	return maddrutil.IsCircuitRelay(s.Conn().RemoteMultiaddr())
}

// nonRelayStreams drops circuit-relay streams from the candidate set while at
// least one direct (non-relay) stream exists. A relay path is rate-limited and
// adds a slow high-latency hop, so scheduling it alongside a direct path taxes
// every frame it carries — under multipath the DWRR min-share gives it ~5% of
// the budget, and under redundant it would carry a full duplicate of EVERY
// frame. The relay stream is left REGISTERED (not closed) so the post-failure
// fallbacks (sendFramesViaSendToPeer / relayFallbackIfPossible) can still use it
// once every direct path drops; this filter only stops it being scheduled while
// a direct path is healthy.
//
// The caller's slice is the published PeerStreams snapshot and is shared by
// every reader, so a filtered result is always a fresh slice, never a
// zero-length view into the shared backing array.
func nonRelayStreams(streams []network.Stream) []network.Stream {
	if len(streams) <= 1 {
		return streams
	}
	hasDirect := false
	for _, s := range streams {
		if !isRelayStream(s) {
			hasDirect = true
			break
		}
	}
	if !hasDirect {
		return streams // relay-only peer: the relay path IS the only path
	}
	out := make([]network.Stream, 0, len(streams))
	for _, s := range streams {
		if !isRelayStream(s) {
			out = append(out, s)
		}
	}
	return out
}

// StrategyDispatcher implements 'best_path', 'multipath', 'redundant', and 'fallback' transport strategies
type StrategyDispatcher struct {
	h    host.Host
	node *Node // back-reference for per-peer byte tracking
	// mode is the active transport strategy. It is an atomic because hot reload
	// can switch strategies at runtime: every send path reads it, so a plain
	// string field written by SetConfig would be a data race.
	mode                  atomic.Value // string
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
	sd := &StrategyDispatcher{
		h:       h,
		peerMap: make(map[peer.ID]*PeerStreams),
	}
	sd.SetMode(mode)
	return sd
}

// Mode returns the active transport strategy. Safe to call on the packet path.
func (sd *StrategyDispatcher) Mode() string {
	if v := sd.mode.Load(); v != nil {
		return v.(string)
	}
	return "best_path"
}

// SetMode switches the transport strategy at runtime (config hot reload). The
// switch is visible to in-flight sends on their next frame; no stream is torn
// down, because every strategy shares the same per-peer stream set.
func (sd *StrategyDispatcher) SetMode(mode string) {
	if mode == "" {
		mode = "best_path"
	}
	sd.mode.Store(mode)
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

// PrimeStream opens a ProtocolID stream to a peer in the background so the
// first TAP frame never waits on a lazy NewStream. Called from ConnectedF.
// If a stream is already open, this is a no-op. The stream is read by
// outgoingStreamHandler (handleStream), which processes inbound frames.
func (sd *StrategyDispatcher) PrimeStream(pID peer.ID) {
	// One entry point for "give this peer its data streams". Going through
	// EnsureStreamsOnAllConns (rather than a bare openStream) means a peer that
	// is reachable over QUIC AND TCP gets a stream on each path, and the
	// per-peer ensureMu keeps a concurrent ConnF for the second transport from
	// opening a duplicate on the same connection (which AddStream would
	// immediately close).
	go func() {
		if opened := sd.EnsureStreamsOnAllConns(pID); opened == 0 {
			log.Debug("PrimeStream to peer %s left no direct stream (will open lazily on first frame)", pID.ShortString())
		}
	}()
}

// RegisterStream publishes an inbound stream under its slot key. transportName
// is accepted for call-site compatibility but no longer identifies the slot:
// keying by remote multiaddr made an inbound and an outbound stream on the same
// connection collide and close each other (see streamRegistryKey).
func (sd *StrategyDispatcher) RegisterStream(pID peer.ID, key string, s network.Stream) {
	ps := sd.GetOrCreatePeerStreams(pID)
	ps.AddStream(key, s)
}

func (sd *StrategyDispatcher) UnregisterStream(pID peer.ID, transportName string, s network.Stream) {
	sd.peersMu.RLock()
	ps := sd.peerMap[pID]
	sd.peersMu.RUnlock()
	if ps != nil {
		ps.RemoveStream(s)
	}
}

func (sd *StrategyDispatcher) RemovePeer(pID peer.ID) {
	sd.peersMu.Lock()
	defer sd.peersMu.Unlock()
	if ps, exists := sd.peerMap[pID]; exists {
		for _, s := range ps.GetAllStreams() {
			_ = s.Close()
		}
	}
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
	if sd.h == nil {
		return nil, nil, fmt.Errorf("open stream to peer %s: host unavailable", targetPeer)
	}

	log.Debug("No active streams to peer %s, opening new stream...", targetPeer.String())

	// If the peer is already transport-connected, yamux can open a sub-stream in
	// milliseconds — no TCP handshake needed. Use a tight timeout so a stuck TCP
	// send buffer (common cause of the 3-second+ spikes) fails fast and falls
	// through to relay fallback rather than blocking this dispatch worker.
	// If the peer is NOT connected, we need a full dial timeout (8s) for NAT
	// traversal + relay setup.
	streamTimeout := 3 * time.Second
	if sd.node != nil && sd.node.Host.Network().Connectedness(targetPeer) != network.NotConnected {
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
	ps.AddStream(streamRegistryKey(s), s)
	log.Debug("Opened new outgoing stream to peer %s via %s", targetPeer.String(), transportName)

	if sd.outgoingStreamHandler != nil {
		go sd.outgoingStreamHandler(s)
	}

	return ps, s, nil
}

// openStreamOnConn opens a ProtocolID data stream PINNED to one physical
// connection.
//
// swarm.NewStream always picks the connection it considers best, so no amount of
// calling it can place a second stream on the second-best path. That is why a
// peer with both QUIC and TCP up still carried every byte on one of them, and
// why the multipath strategy only ever had a single path to schedule over.
//
// Conn.NewStream returns a bare muxed stream with no protocol negotiation, so we
// run multistream-select ourselves — exactly what BasicHost.NewStream does right
// after asking the swarm for a stream. The remote dispatches it to the ordinary
// ProtocolID handler, so nothing changes on the receiving side.
func (sd *StrategyDispatcher) openStreamOnConn(ctx context.Context, target peer.ID, c network.Conn) (network.Stream, error) {
	if c == nil {
		return nil, fmt.Errorf("open stream to peer %s: nil connection", target.String())
	}
	streamCtx := network.WithAllowLimitedConn(ctx, "p2ptap-data")
	s, err := c.NewStream(streamCtx)
	if err != nil {
		return nil, fmt.Errorf("open stream on conn %s: %w", c.ID(), err)
	}
	selected, err := msmux.SelectOneOf([]protocol.ID{ProtocolID}, s)
	if err != nil {
		_ = s.ResetWithError(network.StreamProtocolNegotiationFailed)
		return nil, fmt.Errorf("negotiate %s on conn %s: %w", ProtocolID, c.ID(), err)
	}
	if err := s.SetProtocol(selected); err != nil {
		_ = s.Reset()
		return nil, fmt.Errorf("set protocol on conn %s: %w", c.ID(), err)
	}
	if tcpConn, ok := extractUnderlyingTCPConn(s.Conn()); ok {
		_ = tcpConn.SetNoDelay(true)
	}
	return s, nil
}

// EnsureStreamsOnAllConns opens one data stream on EVERY direct (non-relayed)
// connection to target, so each physical path carries its own stream.
//
// It exists because of two separate problems:
//
//  1. No multi-path to schedule. Every other stream is created through
//     Host.NewStream -> swarm.bestConnToPeer, so a peer with QUIC and TCP up
//     gets all of its streams on the single connection the swarm likes best.
//     Multipath then had exactly one path and behaved like best_path.
//  2. Permanent degradation. When a path's stream is retired (write failure, or
//     a full writer queue — see writeMultipathLocked), nothing re-opens it:
//     openStream reuses any surviving stream and only dials when the peer has
//     NONE left. A peer that lost one of two paths stayed single-path for the
//     rest of the session, so multipath's benefit decayed to zero after the
//     first transient failure. Called on connect and, under multipath, on the
//     health-probe tick, so a lost path returns within one tick.
//
// Idempotent (it checks the (direction, conn) slot first) and serialized per
// peer, because two concurrent opens against the same conn would register two
// streams on one slot and the second would close the first.
func (sd *StrategyDispatcher) EnsureStreamsOnAllConns(target peer.ID) (opened int) {
	if sd.h == nil || target == "" {
		return 0
	}
	conns := sd.h.Network().ConnsToPeer(target)
	if len(conns) == 0 {
		// No transport connection at all: nothing to pin a stream to, and
		// NewStream would just dial. Leave it to the lazy path.
		return 0
	}
	// Skip relayed connections whenever a direct one exists: a circuit stream
	// scores 100 and would be scheduled as a real "path", quietly shifting
	// traffic onto the slowest hop.
	direct := make([]network.Conn, 0, len(conns))
	for _, c := range conns {
		if c == nil || c.RemoteMultiaddr() == nil {
			continue
		}
		if maddrutil.IsCircuitRelay(c.RemoteMultiaddr()) {
			continue
		}
		direct = append(direct, c)
	}

	ps := sd.GetOrCreatePeerStreams(target)
	ps.ensureMu.Lock()
	defer ps.ensureMu.Unlock()

	baseCtx := context.Background()
	if sd.node != nil && sd.node.ctx != nil {
		baseCtx = sd.node.ctx
	}

	if len(direct) == 0 {
		// Relay-only / circuit peer. The lazy path would create exactly one
		// stream here, so create it now to keep the "first frame never waits on
		// a NewStream" guarantee that PrimeStream exists for. openStream reuses
		// any existing stream, so a repeat call is a no-op.
		if len(ps.GetAllStreams()) > 0 {
			return 0
		}
		openCtx, cancel := context.WithTimeout(baseCtx, 3*time.Second)
		defer cancel()
		if _, _, err := sd.openStream(openCtx, target); err != nil {
			log.Debug("Relay-path prime for peer %s failed (will open lazily): %v", target.ShortString(), err)
			return 0
		}
		return 1
	}

	for _, c := range direct {
		key := outboundKeyForConn(c)
		if key == "" || ps.HasStreamKey(key) {
			continue
		}
		openCtx, cancel := context.WithTimeout(baseCtx, 3*time.Second)
		s, err := sd.openStreamOnConn(openCtx, target, c)
		cancel()
		if err != nil {
			log.Debug("Per-connection stream to peer %s on conn %s failed: %v", target.ShortString(), c.ID(), err)
			continue
		}
		ps.AddStream(streamRegistryKey(s), s)
		if sd.outgoingStreamHandler != nil {
			go sd.outgoingStreamHandler(s)
		}
		log.Debug("Per-connection data stream opened to peer %s on conn %s (%s)",
			target.ShortString(), c.ID(), c.RemoteMultiaddr().String())
		opened++
	}
	return opened
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
		// A live circuit also reaches the final peer; keep its data encrypted
		// for that endpoint rather than diverting it into a speculative hop.
		if !sd.node.hasPeerConnection(targetPeer) {
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
	// Reliable streams segment below the application. Respect an explicit
	// fragment limit, otherwise avoid the extra fragment and AEAD layers.
	var fragMaxPayload int
	if sd.node != nil {
		fragMaxPayload = sd.node.maxFragPayloadForPS(ps)
	}
	frags, stat, releaseFrags, encErr := sd.encryptAndFragment(targetPeer, cipher, packedData, fragMaxPayload)
	if encErr != nil {
		// Never fall through to the wire with an unsealed frame: the peer would
		// drop it and the operator would see only an unexplained packet loss.
		log.Warn("Tx to peer %s aborted: %v", targetPeer.String(), encErr)
		return encErr
	}
	if releaseFrags {
		defer releaseFragmentBuffers(frags)
	}

	switch sd.Mode() {
	case "redundant":
		// Send duplicate copies over ALL active transport streams.
		return sd.sendRedundant(ctx, targetPeer, ps, frags, stat, rawData)

	case "fallback":
		// Try streams sequentially until one succeeds, then reopen + relay fallback.
		return sd.sendFallback(ctx, targetPeer, ps, frags, stat, rawData)

	case "best_path":
		fallthrough
	default:
		// Default: best_path — first stream, cleanup + retry, then relay fallback.
		return sd.sendBestPath(ctx, targetPeer, ps, frags, stat, rawData)
	}
}

// encryptAndFragment seals rawData with the per-peer cipher and splits it into
// length-prefixed frames. It is non-blocking and safe to call under ps.writeMu
// or on a hot path. Returns the frames and the original TAP Ethernet-frame
// length used for WebUI throughput accounting. cipher may be nil (plaintext
// obfuscation only).
// SendToPeer and writePackedBatchLocked both route through it so the paths can
// never drift apart.
//
// maxPayload controls the per-fragment inner-payload threshold. Callers with
// active streams use maxFragPayloadForPS(ps); 0 selects the overlay default.
func (sd *StrategyDispatcher) encryptAndFragment(targetPeer peer.ID, cipher obfuscate.ObfCipher, rawData []byte, maxPayload int) ([][]byte, tapPayloadStat, bool, error) {
	if sd.node == nil {
		stat := framePayloadStats(rawData)
		return [][]byte{rawData}, stat, false, nil
	}
	if maxPayload <= 0 {
		maxPayload = sd.node.maxFragPayload()
	}
	stat := framePayloadStats(rawData)
	data := rawData
	innerPooled := false
	if cipher != nil {
		// Keep ciphertext owned until every synchronous write/retry returns.
		// Reuse the destination for both single frames and fragmented frames.
		innerBuf := acquireFrameBuf(len(rawData) + cipher.Overhead())
		enc, err := sd.node.sealPeerFrameInto(targetPeer, cipher, rawData, innerBuf[:0])
		if err != nil {
			releaseFrameBuf(innerBuf)
			return nil, tapPayloadStat{}, false, fmt.Errorf("seal frame for peer %s: %w", targetPeer.String(), err)
		}
		data = enc
		innerPooled = true
	} else if log.IsDebug() {
		// Guarded: arguments are evaluated at the call site regardless of level,
		// and this branch runs on EVERY frame in plaintext mode (no negotiated
		// cipher) — an unguarded String() here is ~0.9µs + 2 allocs per frame.
		log.Debug("Tx: SENDING FRAME TO %s IN PLAINTEXT — no per-peer cipher negotiated (encryption disabled or handshake incomplete)",
			targetPeer.String())
	}

	frags, pooled := sd.node.fragmentFrame(data, sd.node.fragRX, targetPeer, maxPayload)
	if innerPooled {
		if pooled {
			// fragmentFrame has copied every chunk out of the logical sealed frame.
			releaseFrameBuf(data)
		} else {
			// Defensive ownership fallback: if fragmentation did not happen after
			// all, the single returned frame is the pooled logical frame itself.
			pooled = true
		}
	}

	if len(frags) > 1 && cipher != nil {
		for i, f := range frags {
			encBuf := acquireFrameBuf(len(f) + cipher.Overhead())
			enc, err := sd.node.sealPeerFrameInto(targetPeer, cipher, f, encBuf[:0])
			if err != nil {
				releaseFrameBuf(encBuf)
				if pooled {
					releaseFragmentBuffers(frags)
				}
				return nil, tapPayloadStat{}, false, fmt.Errorf("seal fragment %d/%d for peer %s: %w",
					i+1, len(frags), targetPeer.String(), err)
			}
			if pooled {
				releaseFrameBuf(f)
			}
			frags[i] = enc
		}
		// Every encrypted outer frame was written into a pooled destination.
		pooled = true
	}
	return frags, stat, pooled, nil
}

// removeStreamUnderLock drops a stream from ps while the caller holds
// ps.writeMu. It takes ps.mu (a separate lock) to mutate the map, so there is no
// deadlock with the held writeMu. A nil Conn() is handled safely.
func (sd *StrategyDispatcher) removeStreamUnderLock(ps *PeerStreams, s network.Stream) {
	if s == nil {
		return
	}
	ps.mu.Lock()
	removed := false
	for name, current := range ps.streams {
		if current == s {
			delete(ps.streams, name)
			removed = true
		}
	}
	if removed {
		ps.rebuildLocked()
	}
	ps.mu.Unlock()
	delete(ps.writeDeadlineRenew, s)
	ps.stopMpWriterLocked(s)
	ps.qualityMu.Lock()
	delete(ps.writeQuality, s)
	ps.qualityMu.Unlock()
	delete(ps.mpDeficit, s)
	// pathKeys is per-stream bookkeeping only; pathBackoff is deliberately NOT
	// cleared here — it is keyed by path and must outlive the stream so the
	// scheduler keeps avoiding a path that was just re-opened.
	delete(ps.pathKeys, s)
	if ps.preferredStream == s {
		ps.preferredStream = nil
	}
	if ps.writeDeadlineStream == s {
		ps.writeDeadlineStream = nil
		ps.nextWriteDeadlineRenew = time.Time{}
	}
	// A failed write may have sent a partial length prefix or body. Never
	// reuse that stream for another frame, and release its blocked reader.
	_ = s.Reset()
}

// writeOverStreams tries each currently-registered stream in order; the first
// success wins and returns nil. Every failed stream is removed from ps (dead
// cleanup). The caller MUST hold ps.writeMu. Returns the last write error (nil
// only when at least one stream succeeded).
func (sd *StrategyDispatcher) writeOverStreams(ps *PeerStreams, targetPeer peer.ID, frags [][]byte, stat tapPayloadStat) error {
	return sd.writeFragsToStreams(ps, targetPeer, ps.GetAllStreams(), stat, frags, true)
}

// retryWithFreshStream opens a new stream OUTSIDE any writeMu lock and retries
// the write once. On total failure it falls back to an overlay relay. origErr,
// when non-nil, is the error from the first (dead) write, preserved for the
// returned message.
func (sd *StrategyDispatcher) retryWithFreshStream(ctx context.Context, targetPeer peer.ID, ps *PeerStreams, frags [][]byte, stat tapPayloadStat, rawData []byte, origErr error) error {
	ps2, _, openErr := sd.openStream(ctx, targetPeer)
	if openErr != nil {
		if rfErr := sd.relayFallbackIfPossible(targetPeer, rawData); rfErr == nil {
			return nil
		}
		if origErr != nil {
			return fmt.Errorf("best_path retry failed: %w; reopen: %w", origErr, openErr)
		}
		return fmt.Errorf("best_path: %w", openErr)
	}
	ps2.writeMu.Lock()
	remaining := ps2.GetAllStreams()
	if len(remaining) > 0 {
		err := sd.writeFragsToStreams(ps2, targetPeer, remaining, stat, frags, true)
		ps2.writeMu.Unlock()
		if err == nil {
			return nil
		}
		if rfErr := sd.relayFallbackIfPossible(targetPeer, rawData); rfErr == nil {
			return nil
		}
		if origErr != nil {
			return fmt.Errorf("best_path retry failed: %w; retry: %w", origErr, err)
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
func (sd *StrategyDispatcher) sendBestPath(ctx context.Context, targetPeer peer.ID, ps *PeerStreams, frags [][]byte, stat tapPayloadStat, rawData []byte) error {
	ps.writeMu.Lock()
	streams := ps.GetAllStreams()
	if len(streams) == 0 {
		ps.writeMu.Unlock()
		return sd.retryWithFreshStream(ctx, targetPeer, ps, frags, stat, rawData, nil)
	}
	err := sd.writeFragsToStreams(ps, targetPeer, streams, stat, frags, true)
	if err == nil {
		ps.writeMu.Unlock()
		return nil
	}
	// The writer retired the failed stream. Release BEFORE reopening so we
	// never hold writeMu across the NewStream call.
	ps.writeMu.Unlock()
	log.Debug("Removed dead best_path stream for peer %s (%v), retrying with fresh stream", targetPeer.String(), err)
	return sd.retryWithFreshStream(ctx, targetPeer, ps, frags, stat, rawData, err)
}

// sendFallback tries every active stream in turn (first success wins) and
// removes any dead ones. When no stream survives it reopens a fresh one WITHOUT
// holding writeMu and retries; if the direct path is truly dead it falls back
// to an overlay relay — closing the silent-drop hole that previously existed
// for this mode.
func (sd *StrategyDispatcher) sendFallback(ctx context.Context, targetPeer peer.ID, ps *PeerStreams, frags [][]byte, stat tapPayloadStat, rawData []byte) error {
	ps.writeMu.Lock()
	lastErr := sd.writeOverStreams(ps, targetPeer, frags, stat)
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
		return fmt.Errorf("fallback: %w; reopen: %w", lastErr, openErr)
	}
	ps2.writeMu.Lock()
	remaining := ps2.GetAllStreams()
	if len(remaining) > 0 {
		err := sd.writeFragsToStreams(ps2, targetPeer, remaining, stat, frags, true)
		ps2.writeMu.Unlock()
		if err == nil {
			return nil
		}
		if rfErr := sd.relayFallbackIfPossible(targetPeer, rawData); rfErr == nil {
			return nil
		}
		return fmt.Errorf("fallback: %w; retry: %w", lastErr, err)
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
func (sd *StrategyDispatcher) sendRedundant(ctx context.Context, targetPeer peer.ID, ps *PeerStreams, frags [][]byte, stat tapPayloadStat, rawData []byte) error {
	ps.writeMu.Lock()
	writeErr := sd.writeFragsToStreams(ps, targetPeer, ps.GetAllStreams(), stat, frags, true)
	ps.writeMu.Unlock()
	if writeErr == nil {
		return nil
	}
	// All streams failed (or none existed): try a fresh stream, then relay fallback.
	ps2, _, openErr := sd.openStream(ctx, targetPeer)
	if openErr != nil {
		if rfErr := sd.relayFallbackIfPossible(targetPeer, rawData); rfErr == nil {
			return nil
		}
		return fmt.Errorf("redundant: %w; reopen: %w", writeErr, openErr)
	}
	ps2.writeMu.Lock()
	remaining := ps2.GetAllStreams()
	if len(remaining) > 0 {
		err := sd.writeFragsToStreams(ps2, targetPeer, remaining, stat, frags, true)
		ps2.writeMu.Unlock()
		if err == nil {
			return nil
		}
		if rfErr := sd.relayFallbackIfPossible(targetPeer, rawData); rfErr == nil {
			return nil
		}
		return fmt.Errorf("redundant: %w; retry: %w", writeErr, err)
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

	// Capture the original TAP payload accounting up-front. The frame buffer may
	// be a pooled buffer (acquireFrameBuf) that the dispatch worker releases and
	// reuses the instant SendToPeer returns; onSent runs asynchronously inside
	// the relay pool's write loop, so parsing packedData there would race with
	// reuse and report a wrong TX byte count.
	stat := framePayloadStats(packedData)

	// 1. END-TO-END seal for the final destination. packedData IS an obfuscate
	//    frame, so sealing it in place is structurally valid. The error is NOT
	//    swallowed: forwarding an unsealed inner payload would be rejected by the
	//    destination's AEAD gate, losing the frame with no diagnostic.
	//
	//    All three buffers are pooled: encScratch and relayScratch are released
	//    once the next stage copies them out; sealedDst becomes the Submitted
	//    buffer, released exactly once by the pool's onSent/onFail.
	inner := packedData
	var encScratch []byte
	if cipher := n.obfCipherForPeer(targetPeer); cipher != nil {
		encScratch = acquireFrameBuf(len(inner) + cipher.Overhead())
		enc, eerr := n.sealPeerFrameInto(targetPeer, cipher, inner, encScratch)
		if eerr != nil {
			releaseFrameBuf(encScratch)
			return fmt.Errorf("overlay relay end-to-end seal for %s failed: %w", targetPeer.String(), eerr)
		}
		inner = enc
	}

	// 2. Wrap in an overlay relay frame.
	relayScratch := acquireFrameBuf(n.relayEnvelopeSize(targetPeer, n.Host.ID(), len(inner)))
	relayBuf, err := n.packRelayFrameInto(relayScratch, targetPeer, n.Host.ID(), routing.MaxRelayTTL, inner)
	if encScratch != nil {
		releaseFrameBuf(encScratch)
	}
	if err != nil {
		releaseFrameBuf(relayScratch)
		return fmt.Errorf("overlay relay pack for %s failed: %w", targetPeer.String(), err)
	}

	// 3. HOP-BY-HOP: wrap the envelope in an obfuscate frame, then seal THAT for
	//    the hop. The wrap is mandatory — sealing a bare relay envelope always
	//    failed with ErrFrameCorrupted and shipped it in plaintext, which the hop
	//    then dropped. See sealRelayEnvelopeForHop for the full analysis.
	sealedDst := acquireFrameBuf(n.sealRelayEnvelopeMaxLen(len(relayBuf)))
	sealed, serr := n.sealRelayEnvelopeForHopInto(relayHop, relayBuf, sealedDst)
	releaseFrameBuf(relayScratch)
	if serr != nil {
		releaseFrameBuf(sealedDst)
		return fmt.Errorf("overlay relay hop seal via %s failed: %w", relayHop.String(), serr)
	}
	relayBuf = sealed

	// 4. Submit via the persistent relay connection pool. Exactly one of
	//    onSent / onFail fires per job, so releaseSealed runs exactly once.
	releaseSealed := func() { releaseFrameBuf(sealedDst) }
	if !n.relayPool.Submit(relayHop, relayBuf,
		func() {
			n.recordPeerTxBytes(targetPeer, stat.bytes)
			n.recordPeerTxBytesOnPath(targetPeer, "overlay-relay://"+relayHop.String(), stat.bytes, stat.frames)
			if n.protoTracker != nil {
				n.protoTracker.RelayData.RecordTx(1, uint64(len(relayBuf)))
			}
			releaseSealed()
		}, // onSent
		func() { // onFail
			log.Debug("Overlay relay send to peer %s via %s permanently failed",
				targetPeer.String(), relayHop.String())
			releaseSealed()
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
// writes already queued frames in bounded transport batches under that lock.
// Each independent wire frame is retained, but consecutive prefixes and bodies
// share a transport write. There is no timer or delay to wait for more frames.
//
// Each frame remains an independent length-prefixed, per-peer-encrypted tunnel
// frame, so the receiver needs no changes.  On any direct write failure the
// shared lock is released and the REMAINING frames (including the failed batch)
// are routed through the robust per-frame SendToPeer path, which performs
// dead-stream removal, stream re-open and overlay-relay fallback — so a stalled
// direct link never silently drops a frame.  Relay-only peers (no direct
// stream) also defer to SendToPeer, which makes the relay-vs-direct decision
// per frame.
func (sd *StrategyDispatcher) SendBatchToPeer(ctx context.Context, targetPeer peer.ID, packedFrames [][]byte) error {
	if len(packedFrames) == 0 {
		return nil
	}

	// Peers without an endpoint transport use the per-frame overlay/boot path.
	// A live circuit is an endpoint transport and can use the batch writer.
	if sd.node != nil && !sd.hasDirectStream(targetPeer) && !sd.node.hasPeerConnection(targetPeer) {
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

	const batchFrames = 32
	for i := 0; i < len(packedFrames); i += batchFrames {
		end := min(i+batchFrames, len(packedFrames))
		if err := sd.writePackedBatchLocked(targetPeer, ps, cipher, packedFrames[i:end]); err != nil {
			// A direct write failed (stalled/dead stream).  Release the shared
			// lock and route the remaining batch through the per-frame path.
			// A failed write can have delivered a prefix of the batch: retries
			// retain each original SeqID so receive dedup suppresses that prefix.
			log.Debug("Tx batch frame %d/%d to peer %s failed under shared lock: %v; routing remainder via SendToPeer",
				i+1, len(packedFrames), targetPeer.String(), err)
			// SendToPeer eventually acquires ps.writeMu itself.  Do not defer this
			// unlock: returning through the fallback while still holding the lock
			// self-deadlocks this peer's entire transmit path.
			ps.writeMu.Unlock()
			if retryErr := sd.sendFramesViaSendToPeer(ctx, targetPeer, packedFrames[i:]); retryErr != nil {
				return fmt.Errorf("batch write: %w; recovery: %w", err, retryErr)
			}
			return nil
		}
	}
	ps.writeMu.Unlock()
	return nil
}

// batchFrame is one already-sealed logical frame inside a batch write: its
// fragments and the TAP-payload accounting that belongs to it.
type batchFrame struct {
	frags [][]byte
	stat  tapPayloadStat
}

// writePackedBatchLocked retains encrypted fragments until the bounded batch
// write finishes. Pooled fragment ownership remains separate from the caller's
// packed frames, which may be retried after a partial transport write.
// Callers hold ps.writeMu and pass at most 32 logical frames.
func (sd *StrategyDispatcher) writePackedBatchLocked(targetPeer peer.ID, ps *PeerStreams, cipher obfuscate.ObfCipher, packedFrames [][]byte) error {
	streams := nonRelayStreams(ps.GetAllStreams())
	if len(streams) == 0 {
		return fmt.Errorf("no direct streams for peer %s", targetPeer)
	}
	var fragMaxPayload int
	if sd.node != nil {
		fragMaxPayload = sd.node.maxFragPayloadForPS(ps)
	}
	owned := make([][][]byte, len(packedFrames))
	defer func() {
		for _, frags := range owned {
			releaseFragmentBuffers(frags)
		}
	}()
	frames := make([]batchFrame, 0, len(packedFrames))
	for i, data := range packedFrames {
		frags, stat, pooled, err := sd.encryptAndFragment(targetPeer, cipher, data, fragMaxPayload)
		if err != nil {
			return err
		}
		if pooled {
			owned[i] = frags
		}
		frames = append(frames, batchFrame{frags: frags, stat: stat})
	}

	// multipath spreads the batch over the available paths at FRAME granularity
	// (see writeBatchMultipathLocked). Treating the whole batch as one unit — as
	// the other strategies do — would push 32 consecutive frames onto a single
	// link and skew the path split, which shows up on the receiver as a 32-frame
	// burst of out-of-order traffic hitting the reorder window all at once.
	if sd.Mode() == "multipath" && len(streams) > 1 {
		return sd.writeBatchMultipathLocked(targetPeer, ps, streams, frames)
	}

	wireFrames := make([][]byte, 0, len(frames)*4)
	var logicalStat tapPayloadStat
	for _, f := range frames {
		wireFrames = append(wireFrames, f.frags...)
		logicalStat.bytes += f.stat.bytes
		logicalStat.frames += f.stat.frames
	}
	return sd.writeFragsToStreams(ps, targetPeer, streams, logicalStat, wireFrames, true)
}

// writeBatchMultipathLocked assigns every logical frame in the batch to a path
// with the same DWRR the per-frame path uses, then issues ONE coalesced write
// per path on that path's async writer goroutine. Batching keeps its syscall
// advantage while the path split stays proportional to capacity instead of
// concentrating on one link, and — because every write waits OFF the peer's
// write lock (stream_writer.go) — a slow path's bucket no longer delays the
// other paths' buckets beyond its own queue. Caller holds ps.writeMu (and it
// is re-acquired before return).
func (sd *StrategyDispatcher) writeBatchMultipathLocked(targetPeer peer.ID, ps *PeerStreams, streams []network.Stream, frames []batchFrame) error {
	if len(frames) == 0 {
		return nil
	}
	if len(streams) == 0 {
		return fmt.Errorf("no direct streams for peer %s", targetPeer)
	}

	// Phase 1 — under the write lock: assign frames to paths and hand every
	// bucket to its path's writer without blocking on queue capacity.
	type mpBucket struct {
		s     network.Stream
		frags [][]byte
		stat  tapPayloadStat
		items []batchFrame
		wait  func() mpWriteResult // nil = queue was full
	}
	order := make([]*mpBucket, 0, len(streams))
	byStream := make(map[network.Stream]*mpBucket, len(streams))
	for _, f := range frames {
		idx := ps.pickMultipathStreamIndex(streams, time.Now())
		if idx < 0 {
			idx = 0
		}
		s := streams[idx]
		b := byStream[s]
		if b == nil {
			b = &mpBucket{s: s}
			byStream[s] = b
			order = append(order, b)
		}
		b.frags = append(b.frags, f.frags...)
		b.stat.bytes += f.stat.bytes
		b.stat.frames += f.stat.frames
		b.items = append(b.items, f)
	}
	for _, b := range order {
		wait, err := ps.submitMpWriteLocked(b.s, sd.node, targetPeer, b.frags, b.stat)
		if err != nil {
			continue // queue full: b.wait stays nil, handled as a failure below
		}
		b.wait = wait
	}

	// Phase 2 — wait for every bucket OFF the write lock.
	ps.writeMu.Unlock()
	results := make(map[network.Stream]mpWriteResult, len(order))
	for _, b := range order {
		if b.wait != nil {
			results[b.s] = b.wait()
		}
	}
	ps.writeMu.Lock()

	// Phase 3 — same failure handling as the synchronous version.
	var firstErr error
	var retry []batchFrame
	var sentBytes int
	var sentFrames []batchFrame
	var sentWireBytes int
	for _, b := range order {
		res, ok := results[b.s]
		if !ok {
			res = mpWriteResult{err: errWriterQueueFull}
		}
		if res.err != nil {
			if firstErr == nil {
				firstErr = res.err
			}
			// Frames already handed to this broken path cannot be recovered from
			// it, but they CAN still go out on a surviving path — that is the
			// whole point of having more than one.
			ps.notePathFailureUnderLock(b.s, time.Now())
			log.Debug("Multipath batch: path to peer %s failed (%v); re-queuing %d frame(s) on the remaining paths",
				targetPeer.String(), res.err, len(b.items))
			sd.removeStreamUnderLock(ps, b.s)
			retry = append(retry, b.items...)
			streams = withoutStream(streams, b.s)
			continue
		}
		ps.notePathSuccessUnderLock(b.s)
		sentBytes += b.stat.bytes
		sentFrames = append(sentFrames, b.items...)
		for _, it := range b.items {
			for _, frag := range it.frags {
				sentWireBytes += len(frag)
			}
		}
		// Per-path TX attribution, matching writeFragsOnStream: the peer-level
		// recordPeerTxBytes below covers the aggregate, but without this the
		// per-path table (pathTx) misses every byte a batch went out on, so a
		// multipath peer's path rows read zero while its peer row is full.
		if sd.node != nil {
			if conn := b.s.Conn(); conn != nil {
				sd.node.recordPeerTxBytesOnPath(targetPeer, conn.RemoteMultiaddr().String(), b.stat.bytes, b.stat.frames)
			}
		}
	}

	// Record the successes of THIS pass before the retry branch below can return
	// early. Without this, when some paths failed and their frames were re-queued
	// on the survivors, the bytes that DID go out on the successful paths were
	// never counted (the accounting leak): the recursion records only its own
	// (retry) successes, so the two passes together must cover every sent frame
	// exactly once. This same block also serves the all-success case (no retry),
	// where sentFrames == frames and the old post-branch block is now redundant.
	if sd.node != nil && sentBytes > 0 {
		sd.node.recordPeerTxBytes(targetPeer, sentBytes)
		if sd.node.protoTracker != nil {
			sd.node.protoTracker.Data.RecordTx(uint64(len(sentFrames)), uint64(sentWireBytes))
		}
	}

	if len(retry) > 0 && len(streams) > 0 {
		// Each retry retires at least one more stream, so this terminates.
		if err := sd.writeBatchMultipathLocked(targetPeer, ps, streams, retry); err != nil {
			return err
		}
		if firstErr != nil {
			// Some frames were recovered on a surviving path. Reporting the first
			// error here would make the caller re-send frames that already went
			// out; the receive-side dedup would drop the duplicates, but the extra
			// traffic is pure waste.
			log.Debug("Multipath batch to peer %s: recovered a failed path's frames on a surviving path",
				targetPeer.String())
		}
		return nil
	}
	if len(retry) > 0 {
		return firstErr
	}
	return nil
}

// Write-deadline policy for direct stream writes.
//
// The deadline bounds how long a single frame batch may block the writer. It used
// to be a flat 2500ms, which is far too generous for a path that normally
// services a frame in microseconds: under multipath the DWRR hands every path a
// share of the traffic, so one wedged path pinned the peer's whole transmit lock
// for 2.5 seconds on each of its turns — the classic "throughput collapses in
// sawteeth" symptom. The window is now derived from the path's own measured
// service time, with a cold-start value that a healthy link clears easily and a
// hard cap that keeps the old worst case.
const (
	writeDeadlineWindow        = 2500 * time.Millisecond
	writeDeadlineColdStart     = 600 * time.Millisecond
	writeDeadlineMinWindow     = 150 * time.Millisecond
	writeDeadlineServiceFactor = 8
	// writeDeadlineColdStartNanosPerByte scales the cold-start window with the
	// batch size so a genuinely slow link doesn't blow the deadline mid-write.
	// 20000 ns/byte is ~400kbps, the slowest sustained rate the flat 600ms
	// window was implicitly sized for: below that, a large batch would take
	// longer than the window to drain and be falsely flagged as a stall.
	writeDeadlineColdStartNanosPerByte = 20000
)

// writeDeadlineColdStartFor returns the un-measured fallback window for writing
// wireBytes: the flat cold-start, or (for a batch too large to drain within it
// at a slow link's floor rate) a size-scaled window so the first write on a
// slow link is given enough time to complete instead of being misjudged.
func writeDeadlineColdStartFor(wireBytes int) time.Duration {
	est := time.Duration(wireBytes) * writeDeadlineColdStartNanosPerByte
	if est < writeDeadlineColdStart {
		return writeDeadlineColdStart
	}
	return est
}

// writeDeadlineFor returns the deadline window to use for writing wireBytes on
// this stream. A path with a usable measurement gets a few multiples of the time
// it is known to need (so a genuine stall is detected quickly), clamped between
// the minimum window and the historical cap. No caller lock is required: the
// only shared state read is the per-stream quality sample, which qualityFor
// reads under its own mutex (the runMpWriter goroutine and the writeMu-holding
// batch path both call this).
func (ps *PeerStreams) writeDeadlineFor(s network.Stream, wireBytes int, now time.Time) time.Duration {
	q := ps.qualityFor(s)
	if !q.usable(now) || q.nanosPerByte <= 0 {
		return writeDeadlineColdStartFor(wireBytes)
	}
	est := time.Duration(q.nanosPerByte * float64(wireBytes) * writeDeadlineServiceFactor)
	if est < writeDeadlineMinWindow {
		est = writeDeadlineMinWindow
	}
	if est > writeDeadlineWindow {
		est = writeDeadlineWindow
	}
	return est
}

// writeFragsOnStream writes an encrypted fragment batch to ONE stream,
// refreshing that stream's write deadline lazily and recording both the
// per-path TX attribution and the write-quality sample that feeds multipath
// weighting. Caller MUST hold ps.writeMu.
func (sd *StrategyDispatcher) writeFragsOnStream(ps *PeerStreams, targetPeer peer.ID, s network.Stream, frags [][]byte, stat tapPayloadStat) error {
	start := time.Now()
	wireBytes := 0
	for _, frag := range frags {
		wireBytes += len(frag) + 4
	}
	window := writeDeadlineColdStartFor(wireBytes)
	if ps != nil {
		// Lazy init: the batch path enters here directly, without the topology
		// reconciliation preamble in writeFragsToStreams, and a nil map would
		// panic on the first deadline cache write.
		if ps.writeDeadlineRenew == nil {
			ps.writeDeadlineRenew = make(map[network.Stream]time.Time, 4)
		}
		window = ps.writeDeadlineFor(s, wireBytes, start)
		if ps.writeDeadlineStream != s {
			ps.writeDeadlineStream = s
			ps.nextWriteDeadlineRenew = ps.writeDeadlineRenew[s]
		}
		if !start.Before(ps.nextWriteDeadlineRenew) {
			if err := s.SetWriteDeadline(start.Add(window)); err != nil {
				return fmt.Errorf("set write deadline: %w", err)
			}
			// Renew at the halfway point so a shrinking window takes effect on
			// the next write instead of one full window later.
			ps.nextWriteDeadlineRenew = start.Add(window / 2)
			ps.writeDeadlineRenew[s] = ps.nextWriteDeadlineRenew
		}
	} else if err := s.SetWriteDeadline(start.Add(window)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}

	if err := writeFrames(s, frags); err != nil {
		return err
	}
	// Write-quality measurement AND per-path TX attribution run for EVERY
	// successful write, single-stream peers included: the per-path table
	// enumerates a single-stream peer too, and a permanently-empty writeQuality
	// made its whole TX/quality columns read as zero. The measurement only feeds
	// multi-stream selection/weights; recording it for one stream is harmless and
	// keeps the table honest.
	completed := time.Now()
	if ps != nil {
		ps.recordStreamWrite(s, wireBytes, completed.Sub(start), completed)
	}
	if sd.node != nil && s != nil && s.Conn() != nil {
		// Use the cached path key when we hold ps.writeMu (we do): rendering
		// the multiaddr on every frame is a heap alloc + base58 formatting on
		// the packet path. pathKeyForLocked caches it per stream.
		var pathKey string
		if ps != nil {
			pathKey = ps.pathKeyForLocked(s)
		} else {
			pathKey = s.Conn().RemoteMultiaddr().String()
		}
		sd.node.recordPeerTxBytesOnPath(targetPeer, pathKey, stat.bytes, stat.frames)
	}
	return nil
}

// writeFragsToStreams writes the (already encrypted + fragmented) frags to
// targetPeer's direct streams according to the active strategy.  It records TX
// logical payload bytes once on success, and wire bytes for every physical copy.
//
// ps must not be nil. Callers must hold ps.writeMu.
func (sd *StrategyDispatcher) writeFragsToStreams(ps *PeerStreams, targetPeer peer.ID, streams []network.Stream, stat tapPayloadStat, frags [][]byte, recordPeerPayload bool) error {
	// Never schedule a circuit-relay path alongside a healthy direct path (see
	// nonRelayStreams). This is the fallback/best_path/redundant entry; the
	// multipath batch entry filters in writePackedBatchLocked.
	streams = nonRelayStreams(streams)
	if ps != nil {
		snapshot := ps.snapshot.Load()
		if snapshot != ps.writeDeadlineSnapshot {
			// Prune retired streams without acquiring writeMu from Add/Remove,
			// which would invert the registration and writer lock order.
			activeStreams := ps.GetAllStreams()
			for cached := range ps.writeDeadlineRenew {
				active := false
				for _, s := range activeStreams {
					if s == cached {
						active = true
						break
					}
				}
				if !active {
					delete(ps.writeDeadlineRenew, cached)
					if ps.writeDeadlineStream == cached {
						ps.writeDeadlineStream = nil
						ps.nextWriteDeadlineRenew = time.Time{}
					}
					// A stream replaced in place via AddStream never passes
					// through removeStreamUnderLock, so its async writer is
					// reaped here instead of leaking the goroutine.
					ps.stopMpWriterLocked(cached)
				}
			}
			ps.writeDeadlineSnapshot = snapshot
		}
		if ps.writeDeadlineRenew == nil {
			ps.writeDeadlineRenew = make(map[network.Stream]time.Time, len(streams))
		}
	}
	writeOne := func(s network.Stream) error {
		return sd.writeFragsOnStream(ps, targetPeer, s, frags, stat)
	}
	record := func(recordPayload bool) {
		if sd.node != nil {
			if recordPayload && recordPeerPayload {
				sd.node.recordPeerTxBytes(targetPeer, stat.bytes)
			}
			if sd.node.protoTracker != nil {
				// Protocol telemetry intentionally reports encrypted/fragmented
				// overlay bytes. Keep that wire-oriented metric separate from the
				// TAP-payload rate shown in the topology.
				wireBytes := 0
				for _, frag := range frags {
					wireBytes += len(frag)
				}
				sd.node.protoTracker.Data.RecordTx(uint64(len(frags)), uint64(wireBytes))
			}
		}
	}

	switch sd.Mode() {
	case "redundant", "fallback":
		var lastErr error
		sentAny := false
		for _, s := range streams {
			if s == nil {
				continue
			}
			writeErr := writeOne(s)
			if writeErr == nil {
				record(!sentAny)
				sentAny = true
				if sd.Mode() == "fallback" {
					return nil
				}
				continue
			}
			lastErr = writeErr
			sd.removeStreamUnderLock(ps, s)
		}
		if sentAny {
			return nil
		}
		if lastErr == nil {
			return fmt.Errorf("no streams for peer %s", targetPeer)
		}
		return lastErr
	default: // best_path (and multipath: same skeleton, per-path pick below)
		if len(streams) == 0 || streams[0] == nil {
			return fmt.Errorf("no streams for peer %s", targetPeer.String())
		}
		if sd.Mode() != "multipath" || len(streams) == 1 {
			selected := 0
			if len(streams) > 1 {
				selected = ps.selectStreamIndex(streams, time.Now())
			}
			if err := writeOne(streams[selected]); err != nil {
				sd.removeStreamUnderLock(ps, streams[selected])
				return err
			}
			record(true)
			return nil
		}
		return sd.writeMultipathLocked(ps, targetPeer, streams, stat, frags, record)
	}
}

// writeMultipathLocked sends ONE logical frame (all of its fragments) over the
// path the DWRR scheduler picks, failing over to the remaining paths when that
// write breaks. Caller holds ps.writeMu (and re-acquires it before returning —
// it is dropped while waiting for the write result).
//
// The write itself runs on the path's own writer goroutine (stream_writer.go):
// the lock is released while the frame is in flight, so a slow path delays only
// its own queue while every other path keeps draining. The receiver's reorder
// buffer absorbs the cross-path interleaving this produces; the synchronous
// strategies keep the strictly serialized writeFragsOnStream path because they
// hand a frame to exactly one stream at a time.
//
// Failing over inside the loop is the difference between "redundancy" and
// "redundancy on paper": previously a single broken path aborted the frame,
// which unwound to sendBestPath → a fresh NewStream (up to 8s) or an overlay
// relay hop, even though another healthy path to the same peer was already
// open. That turned one path's stall into a visible multi-second outage on a
// link that had spare capacity sitting idle.
//
// A failed write may have emitted a partial length prefix or body, so the stream
// can never carry another frame: it is retired (and reset) exactly as before.
func (sd *StrategyDispatcher) writeMultipathLocked(ps *PeerStreams, targetPeer peer.ID, streams []network.Stream, stat tapPayloadStat, frags [][]byte, record func(bool)) error {
	remaining := streams
	var firstErr error
	for len(remaining) > 0 {
		idx := ps.pickMultipathStreamIndex(remaining, time.Now())
		if idx < 0 {
			break
		}
		s := remaining[idx]
		wait, err := ps.submitMpWriteLocked(s, sd.node, targetPeer, frags, stat)
		if err != nil {
			// Queue full: the path is a whole window behind live traffic.
			// Treat it exactly like a failed write — open the per-path circuit
			// and retire the stream so the scheduler stops feeding it.
			if firstErr == nil {
				firstErr = err
			}
			ps.notePathFailureUnderLock(s, time.Now())
			log.Debug("Multipath: writer queue full on a path to peer %s; retiring it and retrying the frame on a remaining path",
				targetPeer.String())
			sd.removeStreamUnderLock(ps, s)
			remaining = withoutStream(remaining, s)
			continue
		}
		// Wait OFF the write lock — the whole point of the per-stream writers.
		ps.writeMu.Unlock()
		res := wait()
		ps.writeMu.Lock()
		if res.err == nil {
			ps.notePathSuccessUnderLock(s)
			record(true)
			return nil
		}
		if firstErr == nil {
			firstErr = res.err
		}
		// Open the circuit for this PATH (not just this stream) before retiring
		// it: the replacement stream will be the same physical path, and the
		// scheduler must keep avoiding it until the cooldown expires.
		ps.notePathFailureUnderLock(s, time.Now())
		log.Debug("Multipath: path to peer %s failed (%v); retiring it and retrying the frame on a remaining path",
			targetPeer.String(), res.err)
		sd.removeStreamUnderLock(ps, s)
		remaining = withoutStream(remaining, s)
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("no streams for peer %s", targetPeer)
	}
	return firstErr
}

// withoutStream returns a NEW slice with s removed. It never mutates the input:
// the slice is the published PeerStreams snapshot, which is shared by every
// reader and must stay immutable.
func withoutStream(streams []network.Stream, drop network.Stream) []network.Stream {
	out := make([]network.Stream, 0, len(streams))
	for _, s := range streams {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
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

	// Every peer's SeqID comes from ITS OWN sequence ledger and folds in its own
	// anti-replay epoch (rotating one peer's epoch never touches another). Pack
	// happens per-peer here (not at the TAP read site) so each peer gets its own
	// counter and epoch baked into the SeqID. The counter MUST be per-peer: a
	// single shared counter would make each peer observe a sparse subsequence,
	// which the multipath reorder buffer cannot distinguish from packet loss.
	for pID := range peerIDs {
		p := pID
		// canEgressToPeer only. Deliberately NOT peerStalled: the stall breaker
		// exists to stop one wedged peer's 2.5s write deadline from pinning a
		// dispatch worker, and a broadcast send is not one of those — it is a
		// detached goroutine with its own 1.5s context (below), so skipping it
		// on a timeout buys nothing and costs the peer every group-addressed
		// frame for the whole cooldown. ARP and MLD retry on ~1s intervals, so
		// one write timeout silenced that peer's service discovery for 3+
		// seconds, which reads as "some protocols don't work".
		if sd.node != nil && !sd.node.canEgressToPeer(p) {
			continue
		}
		// Outbound ACL must gate broadcast / unknown-unicast floods too, not
		// just the unicast path (node_tap.go). Without this an operator's
		// outbound deny rule is dead code for every ARP/mDNS/DHCP discovery
		// frame, which floods to ALL peers below.
		if sd.node != nil && !sd.node.checkACL(data, sd.node.peerIDString(p), true) {
			continue
		}
		seqID := sd.node.nextTxSeqID(p)
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
				if sd.node != nil {
					sd.node.notePeerSendError(target, err)
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

		type packedItem struct {
			data   []byte
			rawBuf []byte
		}
		packedList := make([]packedItem, 0, len(frames))
		for _, frame := range frames {
			// Outbound ACL is per-frame (the protocol/port are extracted from
			// the payload); a denied frame is dropped for this peer, the rest
			// of the batch still flows.
			if sd.node != nil && !sd.node.checkACL(frame, sd.node.peerIDString(p), true) {
				continue
			}
			// Per-peer counter: a shared one would leave gaps in every peer's
			// observed sequence (see tx_seq.go).
			seqID := sd.node.nextTxSeqID(p)
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
				if sd.node != nil {
					sd.node.notePeerSendError(target, err)
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
	// Copy the peer set under peersMu, then check Connectedness OUTSIDE the
	// lock — libp2p's Connectedness acquires its own network lock, and holding
	// peersMu across that call creates a peersMu→network lock order that blocks
	// every unicast SendToPeer (GetPeerStreams / GetOrCreatePeerStreams /
	// RemovePeer) during broadcast storms (ARP/NDP floods are common in VPNs).
	sd.peersMu.Lock()
	mapCopy := make([]peer.ID, 0, len(sd.peerMap))
	for pID := range sd.peerMap {
		mapCopy = append(mapCopy, pID)
	}
	sd.peersMu.Unlock()
	var stalePeers []peer.ID
	for _, pID := range mapCopy {
		if sd.h.Network().Connectedness(pID) != network.NotConnected {
			peerIDs[pID] = true
		} else {
			stalePeers = append(stalePeers, pID)
		}
	}
	if len(stalePeers) > 0 {
		sd.peersMu.Lock()
		for _, pID := range stalePeers {
			delete(sd.peerMap, pID)
		}
		sd.peersMu.Unlock()
	}

	// Phase 2: peers that are connected but haven't opened a stream yet,
	// provided they support the P2P TAP protocol (excludes bootstrap/crawlers).
	for _, pID := range sd.h.Network().Peers() {
		if pID == self {
			continue
		}
		if peerIDs[pID] {
			continue
		}
		if sd.h.Network().Connectedness(pID) == network.NotConnected {
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
		if s != nil && s.Conn() != nil && maddrutil.IsCircuitRelay(s.Conn().RemoteMultiaddr()) {
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

// PurgeCircuitStreamsExcept drops the peer's circuit-routed data streams that
// are not pinned to keepConn. ConnectedF calls it when a NEW circuit connection
// comes up: autorelay rotates a peer's reservation, so the old relay's conn
// stays alive while the new one is established, and the lazy stream lifecycle
// would otherwise keep Tx riding the outgoing relay until that conn dies. The
// new conn's own streams are untouched, and the persistent control streams are
// left alone — the superseded relay's conn is still alive, so those writes
// still succeed, and DisconnectedF retires them precisely when it closes.
// Streams are deregistered but not closed, matching PurgeCircuitStreams.
func (sd *StrategyDispatcher) PurgeCircuitStreamsExcept(pID peer.ID, keepConn network.Conn) int {
	if keepConn == nil {
		return 0
	}
	keepMA := keepConn.RemoteMultiaddr().String()
	sd.peersMu.RLock()
	ps := sd.peerMap[pID]
	sd.peersMu.RUnlock()
	if ps == nil {
		return 0
	}
	purged := 0
	ps.mu.Lock()
	for name, s := range ps.streams {
		if c := s.Conn(); c != nil {
			ma := c.RemoteMultiaddr()
			if maddrutil.IsCircuitRelay(ma) && ma.String() != keepMA {
				delete(ps.streams, name)
				purged++
			}
		}
	}
	if purged > 0 {
		ps.rebuildLocked()
	}
	ps.mu.Unlock()
	if purged > 0 {
		log.Info("Purged %d circuit stream(s) for peer %s pinned to a superseded relay; next Tx re-opens over the new relay",
			purged, pID.ShortString())
	}
	return purged
}

// PurgeDeadConnStreams drops the peer's data streams pinned to the transport
// that just closed, so the next Tx re-opens over a surviving path instead of
// stalling until the write deadline expires on a dead conn. DisconnectedF calls
// it when a direct link goes away while a circuit relay survives. Streams are
// deregistered but not closed, matching PurgeCircuitStreams: an in-flight write
// owns the stream and completes normally.
func (sd *StrategyDispatcher) PurgeDeadConnStreams(pID peer.ID, deadConn network.Conn) int {
	if deadConn == nil {
		return 0
	}
	sd.peersMu.RLock()
	ps := sd.peerMap[pID]
	sd.peersMu.RUnlock()
	if ps == nil {
		return 0
	}
	purged := 0
	ps.mu.Lock()
	for name, s := range ps.streams {
		if c := s.Conn(); c != nil && c.RemotePeer() == pID &&
			c.RemoteMultiaddr().String() == deadConn.RemoteMultiaddr().String() {
			delete(ps.streams, name)
			purged++
		}
	}
	if purged > 0 {
		ps.rebuildLocked()
	}
	ps.mu.Unlock()
	if purged > 0 {
		log.Info("Dropped %d data stream(s) for peer %s pinned to the dead transport; next Tx re-opens over the surviving relay",
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
