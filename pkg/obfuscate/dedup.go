package obfuscate

import (
	"sync"
	"sync/atomic"
)

// Deduplicator tracks received structured SeqIDs to discard duplicates in
// 'redundant' (multi-path) strategy and to reject cross-session/stale frames.
//
// With structured SeqIDs (ver:4|srcHash:20|connEpoch:24|counter:16) the dedup
// window is keyed on the 16-bit per-source counter rather than the full 64-bit
// value. This gives a natural 65536-slot window per source. A peer's reported
// SeqID is anchored via SyncFrom() on connect, and the expected connEpoch
// (negotiated at handshake) is recorded via SetConnEpoch(). Any frame whose
// epoch does not match is rejected, which is the robust anti-replay guarantee
// against captured frames from a previous session — with no wall-clock
// dependency.
type Deduplicator struct {
	mu                sync.Mutex
	maxSeq            uint64                // highest full structured SeqID seen
	minCounter        uint64                // lowest counter still inside the live window
	recvd             [counterWindow]uint64 // 64-bit bitmask rings (1 bit per counter)
	epochSet          bool                  // whether expectedConnEpoch has been negotiated yet
	expectedConnEpoch uint64                // 24-bit epoch expected on every frame from this peer

	// Diagnostics (atomic, lock-free reads).
	replayDrops uint64
	windowRets  uint64
}

// counterWindow is the number of 64-bit words covering the 16-bit counter
// space: 65536 counters / 64 bits = 1024 words.
const counterWindow = 1024

// NewDeduplicator creates a new Deduplicator.
func NewDeduplicator() *Deduplicator {
	return &Deduplicator{}
}

// MaxSeq returns the current highest full SeqID seen. Safe for concurrent use.
func (d *Deduplicator) MaxSeq() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.maxSeq
}

// ReplayDrops returns the count of frames rejected as stale replays.
func (d *Deduplicator) ReplayDrops() uint64 {
	return atomic.LoadUint64(&d.replayDrops)
}

// WindowResets returns the count of window re-anchors (SyncFrom / large jump).
func (d *Deduplicator) WindowResets() uint64 {
	return atomic.LoadUint64(&d.windowRets)
}

// WindowUtilization reports how full the live dedup window currently is (0..1).
func (d *Deduplicator) WindowUtilization() float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	var bits uint64
	for _, w := range d.recvd {
		bits += uint64(popcount(w))
	}
	return float64(bits) / float64(counterWindow*64)
}

// SetConnEpoch records the per-connection epoch negotiated with this peer
// during the SeqSync handshake. Every subsequently received frame is required
// to carry this exact epoch; a mismatch means the frame originates from a
// different (e.g. previous) session and is rejected as a stale replay.
func (d *Deduplicator) SetConnEpoch(epoch uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expectedConnEpoch = epoch & 0xFFF
	d.epochSet = true
}

// ConnEpoch returns the currently expected connEpoch (0 if not yet negotiated).
func (d *Deduplicator) ConnEpoch() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.expectedConnEpoch
}

// SyncFrom anchors the dedup window to a peer-reported SeqID (sent over the
// seqsync control protocol on connect, or on a forced re-sync). Instead of
// clearing everything, it sets maxSeq/minCounter so the very next frame the
// peer sends is accepted without a 1024-wide blind spot. The connEpoch carried
// by the reported SeqID becomes the expected epoch for this peer.
func (d *Deduplicator) SyncFrom(remoteSeq uint64) {
	if remoteSeq == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	atomic.AddUint64(&d.windowRets, 1)
	d.maxSeq = remoteSeq
	c := CounterFromSeq(remoteSeq)
	d.minCounter = (c - dedupWindow) & 0xFFFF
	// Adopt the epoch from the handshake frame so subsequent frames must match.
	if IsStructuredSeq(remoteSeq) {
		d.expectedConnEpoch = ConnEpochFromSeq(remoteSeq)
		d.epochSet = true
	}
	// Mark the anchor counter as seen so it is not re-accepted.
	d.setBit(c)
	log.Debug("Dedup: SyncFrom remoteSeq=%d counter=%d epoch=%d", remoteSeq, c, d.expectedConnEpoch)
}

// IsDuplicate returns true if seqID is a duplicate or a stale/cross-session
// replay. Otherwise records it and returns false.
func (d *Deduplicator) IsDuplicate(seqID uint64) bool {
	if seqID == 0 || !IsStructuredSeq(seqID) {
		// Unstructured / raw frames: never dedup (handled upstream).
		return false
	}

	// --- Anti-replay via per-connection epoch ---
	// A frame captured in a previous session carries a stale epoch and must be
	// rejected. We compare against the epoch negotiated at handshake, which is
	// refreshed on every (re)connect, so no wall-clock is involved.
	d.mu.Lock()
	epochSet := d.epochSet
	expect := d.expectedConnEpoch
	d.mu.Unlock()
	if epochSet && ConnEpochFromSeq(seqID) != expect {
		atomic.AddUint64(&d.replayDrops, 1)
		log.Debug("Dedup: stale epoch drop seq=%d got=%d expect=%d", seqID, ConnEpochFromSeq(seqID), expect)
		return true
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	c := CounterFromSeq(seqID)
	maxC := CounterFromSeq(d.maxSeq)

	if d.maxSeq == 0 {
		// First structured frame ever seen on this peer.
		d.maxSeq = seqID
		d.minCounter = (c - dedupWindow) & 0xFFFF
		d.setBit(c)
		return false
	}

	// Compare counters in 16-bit modular arithmetic. A move is only treated
	// as "forward" when it is clearly ahead (gap < half the counter space).
	// A gap >= half the space means the counter actually wrapped *behind*
	// (or is an ancient/forward-wrapped frame) and must be checked against the
	// in-window bitmask.
	const halfCounter = 0x8000
	diff := counterDiff(c, maxC) // (c - maxC) mod 65536, 0..65535
	if diff > 0 && diff < halfCounter {
		// Genuine forward move: slide the live window forward to
		// [c - dedupWindow, c]. Evict every counter that has just fallen off
		// the lower edge so the bitmask never accumulates set bits forever.
		//
		// Without this slide the full 16-bit bitmask keeps every seen counter
		// set (the old evictBehind only fired on jumps >= dedupWindow, so it
		// never ran for normal sequential traffic). Once the 32-bit source
		// counter's low 16 bits wrap (~every 65536 frames), those stale bits
		// make every out-of-order frame (routine under direct+relay multi-path
		// delivery) look like a duplicate and get dropped — exactly the
		// intermittent packet loss / "unstable TAP transmission" symptom.
		// The slide is amortised O(1) per frame: only ~diff counters leave
		// the window per move.
		newMin := (c - dedupWindow) & 0xFFFF
		if d.maxSeq != 0 {
			d.evictRange(d.minCounter, newMin)
		}
		d.maxSeq = seqID
		d.minCounter = newMin
		d.setBit(c)
		return false
	}

	// c is behind maxC (or wrapped around). Check the in-window bitmask.
	behind := counterDiff(maxC, c) // (maxC - c) mod 65536, 0..65535
	if behind >= halfCounter {
		// Counter wrapped fully forward (huge jump) — re-anchor instead of
		// shifting 64k bits, then accept.
		d.clearAll()
		atomic.AddUint64(&d.windowRets, 1)
		log.Debug("Dedup: large forward jump, re-anchor max=%d", seqID)
		d.maxSeq = seqID
		d.minCounter = (c - dedupWindow) & 0xFFFF
		d.setBit(c)
		return false
	}
	// Within the live window: a frame is a duplicate only if its specific
	// counter bit has already been seen. We deliberately do NOT treat "older
	// than max" as a duplicate, because multi-path delivery routinely produces
	// out-of-order frames that must still be accepted. Cross-session stale
	// replays are caught separately by the epoch check in IsDuplicate
	// (mismatched connEpoch → replay drop). SyncFrom() positions maxSeq so the
	// window does not start at 0 and marks the anchor bit.
	if d.testBit(c) {
		return true
	}
	d.setBit(c)
	return false
}

// --- internal helpers ---

// setBit marks counter c as seen in the sliding dedup window. The counter is
// masked to its low 16 bits (the window depth) so the 32-bit structured counter
// never indexes out of the fixed-size recvd array.
func (d *Deduplicator) setBit(c uint64) {
	c &= 0xFFFF
	word := c / 64
	bit := c % 64
	d.recvd[word] |= 1 << bit
}

// testBit reports whether counter c has been seen within the sliding window.
func (d *Deduplicator) testBit(c uint64) bool {
	c &= 0xFFFF
	word := c / 64
	bit := c % 64
	return d.recvd[word]&(1<<bit) != 0
}

// clearBit clears counter c from the dedup bitmask.
func (d *Deduplicator) clearBit(c uint64) {
	c &= 0xFFFF
	word := c / 64
	bit := c % 64
	d.recvd[word] &^= 1 << bit
}

// dedupWindow is the out-of-order tolerance, in counters. Counters that fall
// more than dedupWindow behind the current max are evicted from the bitmask so
// the window stays bounded: without eviction, the full 16-bit bitmask would
// keep every seen counter set forever, and after the counter wraps (every
// 65536 frames) previously-set bits would cause spurious "duplicate" drops.
const dedupWindow = 1 << 14 // 16384 counters of out-of-order tolerance

// evictRange clears bitmask bits for counters in the (from, to] range in 16-bit
// modular arithmetic, i.e. the counters that have just slid out of the live dedup
// window as the max counter advanced from `from` to `to`. Sliding (rather than
// clearing the whole 64k bitmask) is what keeps out-of-order tolerance at
// dedupWindow instead of degrading to zero — previously the bitmask kept every
// seen counter set forever, so an out-of-order frame was dropped as a "duplicate"
// the moment its low-16 counter had been seen before (which, after the counter
// wraps, is every frame). The number of counters cleared per call equals the
// forward jump size, so the cost is amortised O(1) per frame.
func (d *Deduplicator) evictRange(from, to uint64) {
	// (to-from) mod 65536 — number of counters strictly between from (exclusive)
	// and to (inclusive) on the 16-bit ring.
	n := counterDiff(to, from)
	if n == 0 {
		return
	}
	x := (from + 1) & 0xFFFF
	for i := uint64(0); i < n; i++ {
		d.clearBit(x)
		x = (x + 1) & 0xFFFF
	}
}

func (d *Deduplicator) clearAll() {
	for i := range d.recvd {
		d.recvd[i] = 0
	}
}

// counterDiff returns (a-b) in 16-bit modular arithmetic (0..65535).
func counterDiff(a, b uint64) uint64 {
	return (a - b) & 0xFFFF
}

func popcount(x uint64) int {
	n := 0
	for x != 0 {
		n += int(x & 1)
		x >>= 1
	}
	return n
}
