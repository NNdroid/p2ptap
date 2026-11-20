package node

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"p2ptap/pkg/maddrutil"
	"p2ptap/pkg/observer"
)

// Per-path telemetry for the "multipath" strategy.
//
// Each path to a peer is an application stream (PeerStreams.streams, keyed by
// the remote multiaddr). The write side already tracks per-path cost via
// recordStreamWrite (streamWriteQuality). The receive side is attributed per
// path here: every accepted frame records its TAP-payload bytes against the
// stream's path key, so the operator can see how traffic splits across the
// direct and circuit-relay paths and whether a slow path is being starved.

// pathKey identifies one (peer, path) pair for receive attribution.
type pathKey struct {
	peer peer.ID
	path string
}

// relayPathKeyCacheEntry is the CoW-cache key for a synthetic relay path key:
// the hop plus which kind of relay it is.
type relayPathKeyCacheEntry struct {
	via  peer.ID
	boot bool
}

// relayPathKeyCache caches the synthetic per-path key per hop. The base58
// render inside peer.ID.String() costs ~930ns and 2 allocations, and the key is
// rebuilt once per RELAYED frame on transit nodes (boot-relay downlink alone
// renders it up to three times per frame). Peer IDs are immutable, so entries
// never go stale and need no invalidation; the map grows with the number of
// distinct relay hops ever seen, which is bounded in practice.
// Same CoW shape as peerIDStrings: lock-free reads, mutex only on first sight.
type relayPathKeyCache struct {
	mu sync.Mutex
	m  atomic.Pointer[map[relayPathKeyCacheEntry]string]
}

func (c *relayPathKeyCache) get(n *Node, via peer.ID, boot bool) string {
	k := relayPathKeyCacheEntry{via: via, boot: boot}
	if m := c.m.Load(); m != nil {
		if s, ok := (*m)[k]; ok {
			return s
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if m := c.m.Load(); m != nil {
		if s, ok := (*m)[k]; ok {
			return s
		}
	}
	var s string
	if boot {
		s = "boot-relay://" + via.String()
	} else {
		s = "overlay-relay://" + via.String()
	}
	var next map[relayPathKeyCacheEntry]string
	if m := c.m.Load(); m != nil {
		next = make(map[relayPathKeyCacheEntry]string, len(*m)+1)
		for ek, ev := range *m {
			next[ek] = ev
		}
	} else {
		next = make(map[relayPathKeyCacheEntry]string, 1)
	}
	next[k] = s
	c.m.Store(&next)
	return s
}

// relayPathKeyFor returns the synthetic per-path key for a frame carried by
// viaPeer, distinguishing an overlay relay from a boot (backbone) relay so the
// per-path table can label and aggregate each kind correctly.
func (n *Node) relayPathKeyFor(viaPeer peer.ID) string {
	return n.relayPathKeys.get(n, viaPeer, n.isBootstrapPeer(viaPeer))
}

// pathRxCounters is the per-path inbound TAP-payload accounting.
type pathRxCounters struct {
	bytes  atomic.Uint64
	frames atomic.Uint64
	// last is the unix-nano time of the most recent frame attributed to this
	// path (0 = never). One atomic store per frame on the RX hot path; read by
	// pathReturnStale for blackhole demotion.
	last atomic.Int64
}

// pathTxCounters is the per-path outbound TAP-payload accounting.
type pathTxCounters struct {
	bytes  atomic.Uint64
	frames atomic.Uint64
	// last is the unix-nano time of the most recent successful write on this
	// path (0 = never). See pathRxCounters.last.
	last atomic.Int64
}

// pathReturnStaleFor is how long a path must have received nothing back while
// we are actively writing to it before the scheduler treats it as a suspected
// one-way blackhole. Wide enough to ride out ACK asymmetry and bursty return
// traffic; short enough to demote inside one keepalive interval.
const pathReturnStaleFor = 15 * time.Second

// pathReturnDemotion divides the DWRR weight of a path whose return side looks
// dead. Demote, don't retire: the write side still "succeeds" locally, so the
// only proof of a blackhole is the missing return traffic, and a path that
// starts returning again earns its share back on the next weight read.
const pathReturnDemotion = 4.0

// pathReturnStale reports whether (p, path) looks like a one-way blackhole:
// we have successfully written TAP payload to it within pathReturnStaleFor
// (the path is actively used) but nothing has come back ON IT for at least as
// long. The write-quality signal is local service time — it cannot see a relay
// that accepts bytes and forwards nothing — so the return side is the only
// delivery proof the sender has. An actively-written path with zero return
// traffic loses most of its scheduler share, shifting traffic to sibling
// paths that ARE being acknowledged; a path that resumes returning earns its
// weight back on the next read.
func (n *Node) pathReturnStale(p peer.ID, path string, now time.Time) bool {
	txv, ok := n.pathTx.Load(pathKey{peer: p, path: path})
	if !ok {
		return false
	}
	txLast := txv.(*pathTxCounters).last.Load()
	if txLast == 0 || now.Sub(time.Unix(0, txLast)) > pathReturnStaleFor {
		// Not actively written: the path carries nothing to judge. A dormant
		// path must keep its nominal weight so it is still there when traffic
		// comes back.
		return false
	}
	rxv, ok := n.pathRx.Load(pathKey{peer: p, path: path})
	if !ok {
		return true
	}
	rxLast := rxv.(*pathRxCounters).last.Load()
	if rxLast == 0 {
		return true
	}
	return now.Sub(time.Unix(0, rxLast)) >= pathReturnStaleFor
}

// recordPeerRxBytesOnPath attributes nBytes of accepted TAP payload to the path
// it arrived on. path is the transport key (RemoteMultiaddr for direct/circuit
// paths, a synthetic "overlay-relay://<hop>" / "boot-relay://<hop>" for relayed
// frames). It is the receive-side counterpart of the per-path write quality;
// keep it symmetric with recordPeerRxBytes so the per-path sums can be compared
// to the per-peer total.
func (n *Node) recordPeerRxBytesOnPath(p peer.ID, path string, nBytes int) {
	n.recordPeerRxBytesOnPathAt(p, path, nBytes, time.Now())
}

// recordPeerRxBytesOnPathAt is the At-variant for hot paths that already hold a
// frame timestamp: the receive pipeline used to spend one extra time.Now() per
// frame here on top of its other bookkeeping clocks.
func (n *Node) recordPeerRxBytesOnPathAt(p peer.ID, path string, nBytes int, now time.Time) {
	if nBytes <= 0 || path == "" {
		return
	}
	k := pathKey{peer: p, path: path}
	v, ok := n.pathRx.Load(k)
	if !ok {
		v, _ = n.pathRx.LoadOrStore(k, &pathRxCounters{})
	}
	c := v.(*pathRxCounters)
	c.bytes.Add(uint64(nBytes))
	c.frames.Add(1)
	c.last.Store(now.UnixNano())
}

// pathRxStats returns the accumulated (bytes, frames) received on one path.
func (n *Node) pathRxStats(p peer.ID, path string) (bytes, frames uint64, ok bool) {
	if path == "" {
		return 0, 0, false
	}
	v, ok := n.pathRx.Load(pathKey{peer: p, path: path})
	if !ok {
		return 0, 0, false
	}
	c := v.(*pathRxCounters)
	return c.bytes.Load(), c.frames.Load(), true
}

// recordPeerTxBytesOnPath attributes a successfully-written outbound TAP payload
// to the path it was sent on. path MUST use the same key format as the receive
// side (RemoteMultiaddr for direct/circuit, "overlay-relay://<hop>" /
// "boot-relay://<hop>" for relayed frames) so the two directions line up.
// nFrames is the number of TAP payloads carried (sub-frames for a batch).
func (n *Node) recordPeerTxBytesOnPath(p peer.ID, path string, nBytes, nFrames int) {
	n.recordPeerTxBytesOnPathAt(p, path, nBytes, nFrames, time.Now())
}

// recordPeerTxBytesOnPathAt is the At-variant for writers that already hold the
// completion timestamp (the multipath writer's `completed` clock read).
func (n *Node) recordPeerTxBytesOnPathAt(p peer.ID, path string, nBytes, nFrames int, now time.Time) {
	if nBytes <= 0 || path == "" {
		return
	}
	if nFrames <= 0 {
		nFrames = 1
	}
	k := pathKey{peer: p, path: path}
	v, ok := n.pathTx.Load(k)
	if !ok {
		v, _ = n.pathTx.LoadOrStore(k, &pathTxCounters{})
	}
	c := v.(*pathTxCounters)
	c.bytes.Add(uint64(nBytes))
	c.frames.Add(uint64(nFrames))
	c.last.Store(now.UnixNano())
}

// pathTxStats returns the accumulated (bytes, frames) sent on one path.
func (n *Node) pathTxStats(p peer.ID, path string) (bytes, frames uint64, ok bool) {
	if path == "" {
		return 0, 0, false
	}
	v, ok := n.pathTx.Load(pathKey{peer: p, path: path})
	if !ok {
		return 0, 0, false
	}
	c := v.(*pathTxCounters)
	return c.bytes.Load(), c.frames.Load(), true
}

// forgetPeerTelemetry drops all per-path receive counters and the reorder queue
// for a departed peer. Called from the same sites that purge the peer's streams
// (Dispatcher.RemovePeer), so a churning peer cannot leak path entries forever.
func (n *Node) forgetPeerTelemetry(p peer.ID) {
	// Retire the reorder queue BEFORE dropping the reference: a queue that is
	// simply deleted keeps its buffered frames (and their pooled buffers) alive
	// and leaves a pending release timer running. stop() also returns those
	// buffers, which previously leaked until GC and showed up as buffer-pool
	// churn on peers that flap.
	if v, ok := n.rxReorder.LoadAndDelete(p); ok {
		if q, ok := v.(*rxReorderQueue); ok {
			q.stop()
		}
	}
	n.pathRx.Range(func(k, _ any) bool {
		if pk, ok := k.(pathKey); ok && pk.peer == p {
			n.pathRx.Delete(k)
		}
		return true
	})
	n.pathTx.Range(func(k, _ any) bool {
		if pk, ok := k.(pathKey); ok && pk.peer == p {
			n.pathTx.Delete(k)
		}
		return true
	})
}

// transportPriorityLabel renders a scoreStreamTransport rank the same way
// node_stats.go does for the peer-level TransportPriority column.
func transportPriorityLabel(score int) string {
	switch score {
	case 0:
		return "Loopback (0)"
	case 10:
		return "LAN Direct (10)"
	case 20:
		return "WAN Direct (20)"
	case 100:
		return "Relay (100)"
	default:
		return "Overlay (999)"
	}
}

// attributedPathsIndex builds the peer → attributed-path view in ONE pass over
// the pathRx/pathTx maps. The per-peer buildPathMetrics calls used to Range
// BOTH maps PER PEER — O(peers²) map visits per 10s stats tick (with closure
// allocation per entry): P=200 peers × K=3 paths cost ~240k no-op Range visits
// per tick. The index is built once per tick and shared by every peer row.
func (n *Node) attributedPathsIndex() map[peer.ID][]string {
	idx := make(map[peer.ID][]string)
	seen := make(map[pathKey]struct{})
	collect := func(m *sync.Map) {
		m.Range(func(k, _ any) bool {
			pk, ok := k.(pathKey)
			if !ok || pk.path == "" {
				return true
			}
			if _, dup := seen[pk]; dup {
				return true
			}
			seen[pk] = struct{}{}
			idx[pk.peer] = append(idx[pk.peer], pk.path)
			return true
		})
	}
	collect(&n.pathRx)
	collect(&n.pathTx)
	return idx
}

// buildPathMetrics returns the per-path breakdown for one peer. Every path is
// enumerated that either (a) is a currently-registered application stream
// (direct + circuit-relay — exactly the paths the multipath scheduler
// distributes over) or (b) has a recorded TX/RX attribution (attributed —
// prebuilt per stats tick by attributedPathsIndex), which covers an overlay/boot
// relay path and any stream replaced by a reconnect. Active marks the
// live-stream subset; the cumulative counters are keyed by path, so a path
// keeps its totals across stream churn on the same link.
func (n *Node) buildPathMetrics(pID peer.ID, attributed []string) []observer.PathMetricDTO {
	if n.Dispatcher == nil {
		return nil
	}
	ps := n.Dispatcher.GetPeerStreams(pID)
	var streams []network.Stream
	var wq map[network.Stream]streamWriteQuality
	if ps != nil {
		streams = ps.GetAllStreams()
		// Snapshot the write-quality map under qualityMu (the same lock the
		// writer goroutines and schedulers use); the collector ticker is far
		// too slow for the lock to contend.
		ps.writeMu.Lock()
		ps.qualityMu.Lock()
		if len(ps.writeQuality) > 0 {
			wq = make(map[network.Stream]streamWriteQuality, len(ps.writeQuality))
			for s, q := range ps.writeQuality {
				wq[s] = q
			}
		}
		ps.qualityMu.Unlock()
		ps.writeMu.Unlock()
	}

	// Union of live-stream paths and every path with recorded attribution.
	paths := make([]string, 0, len(streams)+len(attributed))
	seen := make(map[string]bool, len(streams)+len(attributed))
	for _, s := range streams {
		if s == nil || s.Conn() == nil {
			continue
		}
		path := s.Conn().RemoteMultiaddr().String()
		if path != "" && !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	for _, p := range attributed {
		if p != "" && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return nil
	}

	now := time.Now()
	out := make([]observer.PathMetricDTO, 0, len(paths))
	for _, path := range paths {
		var s network.Stream
		var q streamWriteQuality
		// A connection carries one inbound and one outbound data stream, and both
		// report the SAME RemoteMultiaddr (it identifies the connection). Only the
		// outbound one is written by us, so only it accumulates write samples.
		// Taking the first match blindly meant a path could be shown with the
		// nominal capacity estimate and "not usable" while the sibling stream held
		// a real measurement — so prefer whichever stream actually has samples.
		var fallback network.Stream
		for _, cur := range streams {
			if cur == nil || cur.Conn() == nil || cur.Conn().RemoteMultiaddr().String() != path {
				continue
			}
			if fallback == nil {
				fallback = cur
			}
			if cand := wq[cur]; cand.samples > 0 {
				s, q = cur, cand
				break
			}
		}
		if s == nil {
			s = fallback
		}
		out = append(out, n.pathDTOFor(pID, path, s, q, now))
	}
	return out
}

func (n *Node) pathDTOFor(pID peer.ID, path string, s network.Stream, q streamWriteQuality, now time.Time) observer.PathMetricDTO {
	dto := observer.PathMetricDTO{
		PathID: path,
		PeerID: n.peerIDString(pID),
		Active: s != nil,
	}
	if s != nil && s.Conn() != nil {
		dto.Transport = TransportDisplayName(s.Conn())
		dto.RelayKind = "direct"
		if maddrutil.IsCircuitRelay(s.Conn().RemoteMultiaddr()) {
			dto.RelayKind = "circuit-relay"
		} else if s.Conn().RemotePeer() != pID {
			// A relayed path's underlying connection terminates at a hop (the
			// boot-relay uplink), so its connection peer is the hop, not pID.
			dto.RelayKind = "boot-relay"
		}
		dto.Score = scoreStreamTransport(s, pID)
		dto.Priority = transportPriorityLabel(dto.Score)

		if q.samples > 0 {
			dto.Usable = q.usable(now)
			dto.NanosPerByte = q.nanosPerByte
			if q.nanosPerByte > 0 {
				dto.EstBps = 1e9 / q.nanosPerByte
				// Lower-bound per-frame service time for a nominal 1500 B frame; a
				// latency proxy, NOT a true RTT (see PathMetricDTO comment).
				dto.ServiceMs = q.nanosPerByte * 1500 / 1e6
			}
			dto.Updated = q.updated.UTC().Format(time.RFC3339)
		}
		if dto.EstBps <= 0 {
			// No usable measurement yet: fall back to the topology nominal so the
			// WebUI still shows a comparable capacity placeholder.
			dto.EstBps = mpNominalBps(dto.Score)
		}
	} else {
		// Relay / replaced path: no live stream to derive the label from.
		switch {
		case strings.HasPrefix(path, "boot-relay://"):
			dto.Transport, dto.RelayKind = "Boot Relay", "boot-relay"
		case strings.HasPrefix(path, "overlay-relay://"), strings.HasPrefix(path, "relay://"):
			dto.Transport, dto.RelayKind = "Overlay Relay", "overlay-relay"
		default:
			dto.Transport, dto.RelayKind = "Unknown", "direct"
			// A path with no live stream can still be a plain direct link whose
			// stream was replaced (e.g. the QUIC path after a switch to TCP).
			// Name the transport from the address so the row stays identifiable
			// instead of collapsing to "Unknown" for both ends of a multipath
			// peer. Circuit addresses must be classified FIRST: they also carry
			// a /tcp or /quic-v1 component, and TransportOf would name the
			// relay's own listener transport instead of the hop.
			if ma, err := multiaddr.NewMultiaddr(path); err == nil {
				if maddrutil.IsCircuitRelay(ma) {
					dto.Transport, dto.RelayKind = "Circuit Relay", "circuit-relay"
				} else if name := TransportDisplayNameOfMultiaddr(ma); name != "" {
					dto.Transport = name
				}
			}
		}
		dto.Score = 999
		dto.Priority = transportPriorityLabel(999)
		dto.Usable = false
	}
	// Cumulative per-path traffic is keyed by path, not by the (ephemeral) stream
	// object, so both directions survive a stream reconnect on the same path.
	if tb, tf, ok := n.pathTxStats(pID, path); ok {
		dto.TxBytes = tb
		dto.TxFrames = tf
	}
	if rb, rf, ok := n.pathRxStats(pID, path); ok {
		dto.RxBytes = rb
		dto.RxFrames = rf
	}
	return dto
}
