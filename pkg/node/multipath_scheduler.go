package node

import (
	"time"

	"github.com/libp2p/go-libp2p/core/network"
)

// Multipath transport strategy.
//
// "multipath" distributes logical TAP frames across every active path to a peer
// using deficit weighted round-robin (DWRR). The weight of a path is its
// estimated capacity, derived from the per-stream write quality already
// measured by recordStreamWrite (nanosPerByte → bytes/sec). Paths without a
// usable measurement fall back to a nominal capacity for their topology score
// (scoreStreamTransport), so a freshly-opened direct link competes fairly
// before its first samples arrive.
//
// Distribution granularity is ONE logical frame (with all its fragments) per
// path: writeFragsToStreams always writes a frame's fragment batch to a single
// stream, so fragments never split across paths and the receive-side
// reassembler keeps working unchanged. The receive-side reorder buffer
// (rx_reorder.go) is what lets the TUN device see an in-order stream despite
// cross-path reordering.
//
// Weights are per-peer (stored on PeerStreams, protected by writeMu). The
// chosen frequency of a path is proportional to its weight, so a fast direct
// link carries most of the load while a slow relay path carries a small share —
// enough to keep its write-quality measurement fresh and the path warm for a
// fast failover when the primary path drops.
const (
	// mpMinShare is the smallest share of the frame budget any path may carry
	// (relative to the fastest path). It guarantees a slow path is never starved
	// entirely, which would both freeze its measurement and leave it cold for a
	// failover. 5% of the fastest path's weight.
	mpMinShare = 0.05
)

// mpNominalBps returns a nominal capacity (bytes/sec) for a path by topology
// score, used until the path accumulates enough measured write samples. The
// values are rough placeholders — loopback and LAN are not rate-limited in
// practice, WAN is, and a circuit-relay hop is heavily rate-limited.
func mpNominalBps(score int) float64 {
	switch score {
	case 0: // loopback
		return 1e9
	case 10: // private LAN
		return 5e8
	case 20: // public WAN direct
		return 1e8
	case 100: // circuit relay
		return 5e6
	default:
		return 1e6
	}
}

// mpWeightFor returns the DWRR weight (bytes/sec capacity) for a single stream.
// A usable measured write quality wins; otherwise the topology-score nominal is
// used. The result is always positive.
func (ps *PeerStreams) mpWeightFor(s network.Stream, now time.Time) float64 {
	if q, ok := ps.writeQuality[s]; ok && q.usable(now) {
		if bps := 1e9 / q.nanosPerByte; bps > 0 {
			return bps
		}
	}
	return mpNominalBps(scoreStreamTransport(s))
}

// pickMultipathStreamIndex returns the index of the stream that should carry
// the current frame under the "multipath" strategy. The caller MUST hold
// ps.writeMu.
//
// DWRR keeps total deficit bounded: each call credits every stream by its
// normalized weight, then debits the chosen stream by one unit. Over N frames a
// stream is chosen about N × weight/sum(weight) times, so load follows capacity
// while the min-share floor keeps slow paths alive.
func (ps *PeerStreams) pickMultipathStreamIndex(streams []network.Stream, now time.Time) int {
	if len(streams) == 0 {
		return -1
	}
	if len(streams) == 1 {
		return 0
	}
	if ps.mpDeficit == nil {
		ps.mpDeficit = make(map[network.Stream]float64)
	}
	// Prune deficit entries for streams retired from this peer's topology.
	for s := range ps.mpDeficit {
		active := false
		for _, cur := range streams {
			if cur == s {
				active = true
				break
			}
		}
		if !active {
			delete(ps.mpDeficit, s)
		}
	}

	weights := make([]float64, len(streams))
	var maxW float64
	for i, s := range streams {
		w := ps.mpWeightFor(s, now)
		weights[i] = w
		if w > maxW {
			maxW = w
		}
	}
	// Floor each weight so no path falls below mpMinShare of the fastest one,
	// then normalize (DWRR requires weights that sum to 1 to keep deficit
	// bounded across rounds).
	floor := maxW * mpMinShare
	var total float64
	for i := range weights {
		if weights[i] < floor {
			weights[i] = floor
		}
		total += weights[i]
	}
	if total <= 0 {
		return 0
	}

	best := 0
	bestDeficit := -1e18
	for i, s := range streams {
		ps.mpDeficit[s] += weights[i] / total
		if ps.mpDeficit[s] > bestDeficit {
			bestDeficit = ps.mpDeficit[s]
			best = i
		}
	}
	ps.mpDeficit[streams[best]] -= 1
	return best
}
