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

	// pathBackoffBase is the cooling period after a path's first write failure.
	// It doubles per consecutive failure up to pathBackoffMax.
	//
	// The point is not to punish the path but to stop paying for it: a write
	// failure means the stream had to be retired, and re-opening the same broken
	// path (a dead NAT mapping, a stalled relay hop) would block the peer's
	// transmit lock up to the write deadline each time. While a path is cooling
	// the scheduler simply routes around it; the path returns automatically once
	// the cooldown expires and its next write succeeds.
	pathBackoffBase = 2 * time.Second
	pathBackoffMax  = 30 * time.Second
)

// pathBackoff is the circuit-breaker state for one PHYSICAL path. It is keyed by
// the remote multiaddr rather than by the stream object, so a path that keeps
// failing survives the stream re-open that a failure triggers — otherwise every
// rebuild would reset the counter and the scheduler would walk straight back into
// the same dead path.
type pathBackoff struct {
	failures int
	until    time.Time
}

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

// pathKeyForLocked returns the physical path key (remote multiaddr) for s,
// caching it so the hot path never re-renders the multiaddr. Caller holds
// ps.writeMu.
func (ps *PeerStreams) pathKeyForLocked(s network.Stream) string {
	if k, ok := ps.pathKeys[s]; ok {
		return k
	}
	if s == nil || s.Conn() == nil {
		return ""
	}
	ma := s.Conn().RemoteMultiaddr()
	if ma == nil {
		return ""
	}
	k := ma.String()
	if ps.pathKeys == nil {
		ps.pathKeys = make(map[network.Stream]string, 4)
	}
	ps.pathKeys[s] = k
	return k
}

// notePathFailureUnderLock opens (or extends) the circuit for the path carrying
// s. Caller holds ps.writeMu.
func (ps *PeerStreams) notePathFailureUnderLock(s network.Stream, now time.Time) {
	k := ps.pathKeyForLocked(s)
	if k == "" {
		return
	}
	if ps.pathBackoff == nil {
		ps.pathBackoff = make(map[string]*pathBackoff, 4)
	}
	b := ps.pathBackoff[k]
	if b == nil {
		b = &pathBackoff{}
		ps.pathBackoff[k] = b
	}
	b.failures++
	cooldown := pathBackoffBase
	for i := 1; i < b.failures && cooldown < pathBackoffMax; i++ {
		cooldown *= 2
	}
	if cooldown > pathBackoffMax {
		cooldown = pathBackoffMax
	}
	b.until = now.Add(cooldown)
}

// notePathCongestedUnderLock opens a SHORT, fixed circuit for a path whose
// writer queue is full. Queue-full means the path is alive but behind live
// traffic: the connection and its measured capacity are fine, so this must not
// feed the exponential backoff a real write failure earns — otherwise a burst
// of congestion exiles a healthy path for up to pathBackoffMax, exactly when
// the peer can least afford to lose it. The stream is still retired (its queue
// is dropped with it); pathBackoffBase later it is eligible again with an empty
// queue, and the first successful submit clears the circuit entirely.
// Caller holds ps.writeMu.
func (ps *PeerStreams) notePathCongestedUnderLock(s network.Stream, now time.Time) {
	k := ps.pathKeyForLocked(s)
	if k == "" {
		return
	}
	if ps.pathBackoff == nil {
		ps.pathBackoff = make(map[string]*pathBackoff, 4)
	}
	b := ps.pathBackoff[k]
	if b == nil {
		b = &pathBackoff{}
		ps.pathBackoff[k] = b
	}
	// Never shorten a real failure's circuit, never grow it: congestion gets
	// exactly pathBackoffBase, whatever the failure counter says.
	if until := now.Add(pathBackoffBase); until.After(b.until) {
		b.until = until
	}
}

// notePathSuccessUnderLock closes the circuit for the path carrying s.
// Caller holds ps.writeMu.
func (ps *PeerStreams) notePathSuccessUnderLock(s network.Stream) {
	if len(ps.pathBackoff) == 0 {
		return
	}
	if k := ps.pathKeyForLocked(s); k != "" {
		delete(ps.pathBackoff, k)
	}
}

// ClearPathBreakers drops every per-path cooldown for this peer. Called from
// the ping-pong keepalive on a successful end-to-end echo: a completed round
// trip proves the peer is reachable, so a breaker armed by a transient write
// failure must not keep exiling a now-healthy path. The old reset condition —
// a successful WRITE on the path — could never fire while the path was cooling,
// making the exponential cooldown self-sustaining even after the link recovered.
// A path that is genuinely still dead re-arms its breaker on the next write
// failure, so the worst case is one write deadline of extra latency, not a
// pathBackoffMax exile.
func (ps *PeerStreams) ClearPathBreakers() {
	ps.writeMu.Lock()
	if len(ps.pathBackoff) > 0 {
		ps.pathBackoff = nil
	}
	ps.writeMu.Unlock()
}

// pathCoolingLocked reports whether the path carrying s is inside its
// post-failure cooldown. Caller holds ps.writeMu.
func (ps *PeerStreams) pathCoolingLocked(s network.Stream, now time.Time) bool {
	if len(ps.pathBackoff) == 0 {
		return false
	}
	b := ps.pathBackoff[ps.pathKeyForLocked(s)]
	return b != nil && now.Before(b.until)
}

// mpWeightFor returns the DWRR weight (bytes/sec capacity) for a single stream.
// A usable measured write quality wins; otherwise the topology-score nominal is
// used. The result is always positive.
//
// On top of capacity, a path whose RETURN side looks dead (actively written,
// nothing received back for pathReturnStaleFor — see pathReturnStale) is
// demoted: local write service time cannot see a relay that accepts bytes and
// forwards nothing, so without this signal a blackhole path kept its full DWRR
// share indefinitely and only the peer-level echo probe would eventually react.
//
// Caller holds ps.writeMu. q must come from the pick's one-shot quality
// snapshot (see pickMultipathStreamIndex); the direct wrapper below is for
// callers outside the pick loop (tests, single-stream paths).
func (ps *PeerStreams) mpWeightFor(s network.Stream, now time.Time) float64 {
	return ps.mpWeightForQ(s, now, ps.qualityFor(s))
}

func (ps *PeerStreams) mpWeightForQ(s network.Stream, now time.Time, q streamWriteQuality) float64 {
	w := 0.0
	if q.usable(now) {
		if bps := 1e9 / q.nanosPerByte; bps > 0 {
			w = bps
		}
	}
	if w <= 0 {
		w = mpNominalBps(ps.streamScoreCached(s))
	}
	if ps.node != nil {
		if k := ps.pathKeyForLocked(s); k != "" && ps.pathStaleMemoLocked(s, k, now) {
			w /= pathReturnDemotion
		}
	}
	return w
}

// pathStaleMemoTTL bounds how long a memoized return-path verdict stays valid.
// The underlying signal has pathReturnStaleFor (15s) granularity, so a 2s
// memo cannot delay a demotion meaningfully — but it removes the two boxed
// sync.Map loads per stream per frame that the uncached verdict cost, all
// inside ps.writeMu.
const pathStaleMemoTTL = 2 * time.Second

type pathStaleVerdict struct {
	stale bool
	at    time.Time
}

// pathStaleMemoLocked returns the cached blackhole verdict for s, refreshing it
// from node.pathReturnStale at most once per pathStaleMemoTTL. Caller holds
// ps.writeMu.
func (ps *PeerStreams) pathStaleMemoLocked(s network.Stream, key string, now time.Time) bool {
	if v, ok := ps.pathStaleCache[s]; ok && now.Sub(v.at) < pathStaleMemoTTL {
		return v.stale
	}
	stale := ps.node.pathReturnStale(ps.peerID, key, now)
	if ps.pathStaleCache == nil {
		ps.pathStaleCache = make(map[network.Stream]pathStaleVerdict, 4)
	}
	ps.pathStaleCache[s] = pathStaleVerdict{stale: stale, at: now}
	return stale
}

// streamScoreCached caches scoreStreamTransport for a stream. The score is
// immutable per connection (it classifies the remote multiaddr), but the
// unmeasured-path fallback used to re-run the multiaddr protocol walk per
// stream per frame during warm-up and on idle paths. Caller holds ps.writeMu.
func (ps *PeerStreams) streamScoreCached(s network.Stream) int {
	if v, ok := ps.streamScores[s]; ok {
		return v
	}
	v := scoreStreamTransport(s, ps.peerID)
	if ps.streamScores == nil {
		ps.streamScores = make(map[network.Stream]int, 4)
	}
	ps.streamScores[s] = v
	return v
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

	// Route around paths that are inside their post-failure cooldown (see
	// pathBackoff). If EVERY path is cooling we keep the full set: a degraded
	// link still beats dropping the frame, and the cooldowns expire on their own.
	// The filter slices are scratch-reused: a cooling path must not cost two
	// fresh allocations per frame.
	active := streams
	var origIdx []int
	if len(ps.pathBackoff) > 0 {
		filtered := ps.mpFilteredScratch[:0]
		idx := ps.mpFilteredIdx[:0]
		for i, s := range streams {
			if !ps.pathCoolingLocked(s, now) {
				filtered = append(filtered, s)
				idx = append(idx, i)
			}
		}
		ps.mpFilteredScratch = filtered
		ps.mpFilteredIdx = idx
		if len(filtered) > 0 && len(filtered) < len(streams) {
			active, origIdx = filtered, idx
		}
	}

	if len(active) == 1 {
		return activeStreamIndex(origIdx, 0)
	}
	if ps.mpDeficit == nil {
		ps.mpDeficit = make(map[network.Stream]float64)
	}
	// Prune deficit entries for streams retired from this peer's topology. This
	// only has to happen when the topology actually changed: scanning the whole
	// map against every candidate on EVERY frame is O(n²) on the packet path.
	// The memoized stale verdicts and stream scores share the same sweep.
	if snap := ps.snapshot.Load(); snap != nil && snap != ps.mpPruneSnapshot {
		ps.mpPruneSnapshot = snap
		for s := range ps.mpDeficit {
			present := false
			for _, cur := range snap.streams {
				if cur == s {
					present = true
					break
				}
			}
			if !present {
				delete(ps.mpDeficit, s)
				delete(ps.pathStaleCache, s)
				delete(ps.streamScores, s)
			}
		}
	}

	// One qualityMu acquisition per pick instead of one per stream: the same
	// lock is taken by every writer goroutine's recordStreamWrite, so the old
	// per-stream acquisition serialised the pick against them once per path per
	// frame, all while holding ps.writeMu. The snapshot is stable for the rest
	// of the pick (writeQuality only changes on completed writes, which take
	// the same lock).
	ps.qualityMu.Lock()
	qual := ps.mpQualScratch[:0]
	for _, s := range active {
		qual = append(qual, ps.writeQuality[s])
	}
	ps.mpQualScratch = qual
	ps.qualityMu.Unlock()

	// Reuse the scratch weight slice: one allocation per frame is pure GC
	// pressure at wire rate.
	if cap(ps.mpWeights) < len(active) {
		ps.mpWeights = make([]float64, len(active))
	} else {
		ps.mpWeights = ps.mpWeights[:len(active)]
	}
	weights := ps.mpWeights
	var maxW float64
	for i, s := range active {
		w := ps.mpWeightForQ(s, now, qual[i])
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
		return activeStreamIndex(origIdx, 0)
	}

	best := 0
	bestDeficit := -1e18
	for i, s := range active {
		ps.mpDeficit[s] += weights[i] / total
		if ps.mpDeficit[s] > bestDeficit {
			bestDeficit = ps.mpDeficit[s]
			best = i
		}
	}
	ps.mpDeficit[active[best]] -= 1
	return activeStreamIndex(origIdx, best)
}

// activeStreamIndex maps an index into the (possibly filtered) candidate slice
// back to the caller's original slice. An empty map means no filtering happened.
func activeStreamIndex(origIdx []int, i int) int {
	if len(origIdx) == 0 {
		return i
	}
	return origIdx[i]
}
