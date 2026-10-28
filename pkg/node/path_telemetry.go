package node

import (
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

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

// pathRxCounters is the per-path inbound TAP-payload accounting.
type pathRxCounters struct {
	bytes  atomic.Uint64
	frames atomic.Uint64
}

// recordPeerRxBytesOnPath attributes nBytes of accepted TAP payload to the path
// it arrived on. path is the transport key (RemoteMultiaddr for direct/circuit
// paths, a synthetic "relay://<hop>" for relayed frames). It is the receive-side
// counterpart of the per-path write quality; keep it symmetric with
// recordPeerRxBytes so the per-path sums can be compared to the per-peer total.
func (n *Node) recordPeerRxBytesOnPath(p peer.ID, path string, nBytes int) {
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

// forgetPeerTelemetry drops all per-path receive counters and the reorder queue
// for a departed peer. Called from the same sites that purge the peer's streams
// (Dispatcher.RemovePeer), so a churning peer cannot leak path entries forever.
func (n *Node) forgetPeerTelemetry(p peer.ID) {
	n.rxReorder.Delete(p)
	n.pathRx.Range(func(k, _ any) bool {
		if pk, ok := k.(pathKey); ok && pk.peer == p {
			n.pathRx.Delete(k)
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

// buildPathMetrics returns the per-path breakdown for one peer. Only the
// application-stream paths (direct + circuit-relay) are enumerated: those are
// exactly the paths the multipath scheduler distributes over. Overlay/boot
// relays are single fallback paths, not multi-path targets, so they are not
// listed here (the per-peer ReturnTransport already reports which relay carried
// the last inbound frame).
func (n *Node) buildPathMetrics(pID peer.ID) []observer.PathMetricDTO {
	if n.Dispatcher == nil {
		return nil
	}
	ps := n.Dispatcher.GetPeerStreams(pID)
	if ps == nil {
		return nil
	}
	streams := ps.GetAllStreams()
	if len(streams) == 0 {
		return nil
	}
	// Snapshot the write-quality map under writeMu (the same lock the writer
	// holds); the collector ticker is far too slow for the lock to contend.
	ps.writeMu.Lock()
	wq := make(map[network.Stream]streamWriteQuality, len(ps.writeQuality))
	for s, q := range ps.writeQuality {
		wq[s] = q
	}
	ps.writeMu.Unlock()

	now := time.Now()
	out := make([]observer.PathMetricDTO, 0, len(streams))
	for _, s := range streams {
		if s == nil || s.Conn() == nil {
			continue
		}
		out = append(out, n.pathDTOFor(pID, s, wq[s], now))
	}
	return out
}

func (n *Node) pathDTOFor(pID peer.ID, s network.Stream, q streamWriteQuality, now time.Time) observer.PathMetricDTO {
	dto := observer.PathMetricDTO{
		PathID:    s.Conn().RemoteMultiaddr().String(),
		PeerID:    n.peerIDString(pID),
		Transport: transportLabelForConn(s.Conn()),
		RelayKind: "direct",
		Active:    true,
	}
	if maddrutil.IsCircuitRelay(s.Conn().RemoteMultiaddr()) {
		dto.RelayKind = "circuit-relay"
	}
	dto.Score = scoreStreamTransport(s)
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
		dto.TxBytes = uint64(q.bytes)
		dto.TxFrames = uint64(q.samples)
		dto.Updated = q.updated.UTC().Format(time.RFC3339)
	}
	if dto.EstBps <= 0 {
		// No usable measurement yet: fall back to the topology nominal so the
		// WebUI still shows a comparable capacity placeholder.
		dto.EstBps = mpNominalBps(dto.Score)
	}
	if rb, rf, ok := n.pathRxStats(pID, dto.PathID); ok {
		dto.RxBytes = rb
		dto.RxFrames = rf
	}
	return dto
}
