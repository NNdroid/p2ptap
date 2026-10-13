package obfuscate

import (
	"sync"
	"sync/atomic"
)

// Deduplicator tracks received structured SeqIDs to discard duplicates in
// 'redundant' (multi-path) strategy and to reject cross-session/stale frames.
//
// With structured SeqIDs (ver:4|srcHash:16|connEpoch:12|counter:32) the dedup
// bitmask is keyed on the low 16 bits of the counter — the window is a ring of
// 65536 slots, which is all the recvd array can address. Distances between two
// counters, however, MUST be computed over the full 32-bit field: comparing
// only the low 16 bits cannot tell "65536 ahead" from "seen a moment ago", so
// a counter exactly 65536 behind used to be rejected as a duplicate of one
// still live in the window. See IsDuplicate.
//
// A peer's reported SeqID is anchored via SyncFrom() on connect, and the
// expected connEpoch (negotiated at handshake) is recorded via SetConnEpoch().
// Any frame whose epoch does not match is rejected, which is the robust
// anti-replay guarantee against captured frames from a previous session — with
// no wall-clock dependency.
type Deduplicator struct {
	mu                sync.Mutex
	maxSeq            uint64                // highest full structured SeqID seen
	minCounter        uint64                // lowest counter still inside the live window
	recvd             [counterWindow]uint64 // 64-bit bitmask rings (1 bit per counter)
	seenCount         uint64                // number of set bits; protected by mu
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
	// Maintain the population when bits change instead of scanning all 1024
	// words for the receive loop's per-packet telemetry. Divide by the LIVE
	// window, not the whole ring: seenCount only ever counts bits inside
	// dedupWindow, so dividing by counterWindow*64 reported ~0.4% no matter how
	// loaded the window was and hid the real reorder headroom.
	return float64(d.seenCount) / float64(dedupWindow)
}

// SetConnEpoch records the per-connection epoch negotiated with this peer
// during the SeqSync handshake. Every subsequently received frame is required
// to carry this exact epoch; a mismatch means the frame originates from a
// different (e.g. previous) session and is rejected as a stale replay.
func (d *Deduplicator) SetConnEpoch(epoch uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ep := epoch & 0xFFF
	if d.epochSet && d.expectedConnEpoch != ep {
		d.clearAll()
		d.maxSeq = 0
		d.minCounter = 0
		atomic.AddUint64(&d.windowRets, 1)
	}
	d.expectedConnEpoch = ep
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
	d.clearAll()
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

// DedupDropReason classifies why a frame was rejected, so a caller can tell a
// harmless redundant-delivery duplicate from a protocol-level desync that needs
// healing. The two are indistinguishable through IsDuplicate alone, which is
// what let a stale-epoch desync run forever without anyone noticing: the frame
// was well-formed and decrypted cleanly, so only the dedup window saw it.
type DedupDropReason uint8

const (
	DedupDropNone       DedupDropReason = iota // accepted (not a drop)
	DedupDropSameSeq                           // this counter was already delivered: redundant multi-path copy
	DedupDropFarBehind                         // trails the live window beyond tolerance: replay, not reordering
	DedupDropStaleEpoch                        // connEpoch mismatch: cross-session frame, or a sender out of step
)

// IsDuplicate returns true if seqID is a duplicate or a stale/cross-session
// replay. Otherwise records it and returns false.
func (d *Deduplicator) IsDuplicate(seqID uint64) bool {
	dup, _ := d.IsDuplicateReason(seqID)
	return dup
}

// IsDuplicateReason is IsDuplicate with the drop classified. Use it on any path
// where a drop should be able to trigger recovery: only SameSeq is benign.
func (d *Deduplicator) IsDuplicateReason(seqID uint64) (bool, DedupDropReason) {
	if seqID == 0 || !IsStructuredSeq(seqID) {
		// Unstructured / raw frames: never dedup (handled upstream).
		return false, DedupDropNone
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// --- Anti-replay via per-connection epoch ---
	// Plaintext peers can send before their first SeqSync. Adopt the FIRST
	// epoch atomically, but never let later data replace an established epoch.
	if !d.epochSet {
		d.expectedConnEpoch = ConnEpochFromSeq(seqID)
		d.epochSet = true
	}
	if d.epochSet && ConnEpochFromSeq(seqID) != d.expectedConnEpoch {
		atomic.AddUint64(&d.replayDrops, 1)
		log.Debug("Dedup: stale epoch drop seq=%d got=%d expect=%d", seqID, ConnEpochFromSeq(seqID), d.expectedConnEpoch)
		return true, DedupDropStaleEpoch
	}

	c := CounterFromSeq(seqID)
	maxC := CounterFromSeq(d.maxSeq)

	if d.maxSeq == 0 {
		// First structured frame ever seen on this peer.
		d.maxSeq = seqID
		d.minCounter = (c - dedupWindow) & 0xFFFF
		d.setBit(c)
		return false, DedupDropNone
	}

	// Decide direction and distance using the FULL 32-bit counter field.
	//
	// This is the security-critical part. Comparing only the low 16 bits left
	// a frame that trailed the live window by 65536+ counters indistinguishable
	// from one a couple of places behind: its bit had already been evicted as
	// the window advanced, so testBit() reported "unseen" and the stale frame
	// was accepted. Replaying a captured frame whose AEAD still verifies under
	// the current key therefore re-injected it into TAP. Working mod 2^32 lets
	// "far behind" and "far ahead" be told apart, which mod 2^16 cannot.
	const cntMask32 = 0xFFFFFFFF
	ahead32 := (c - maxC) & cntMask32
	behind32 := (maxC - c) & cntMask32

	if ahead32 < behind32 {
		// c genuinely leads maxC. A short move slides the live window to
		// [c-dedupWindow, c], evicting the counters that just fell off the
		// lower edge so the bitmask never accumulates set bits forever.
		//
		// A large jump is slid too, never clearAll'd: wiping the whole bitmap
		// also wipes the counters that are still inside maxBehindTolerance
		// (which equals dedupWindow), so a frame already delivered at
		// counter c-k with k <= dedupWindow could not be told apart from a
		// duplicate once maxC jumped past c. Sliding costs at most one ring of
		// bit clears and leaves exactly [c-dedupWindow, c] preserved, which is
		// the only range where a duplicate can still matter.
		newMin := (c - dedupWindow) & 0xFFFF
		d.evictRange(d.minCounter, newMin)
		if ahead32 > dedupWindow {
			atomic.AddUint64(&d.windowRets, 1)
			log.Debug("Dedup: large forward jump, slid window max=%d ahead=%d", seqID, ahead32)
		}
		d.maxSeq = seqID
		d.minCounter = newMin
		d.setBit(c)
		return false, DedupDropNone
	}

	// c trails maxC by behind32.
	//
	// ROUND 8 FIX: the previous code re-anchored and accepted any frame
	// >= halfCounter (32768) behind, creating a massive replay window.
	// Frames this far behind are replays, not multi-path reordering —
	// real reordering is bounded by a few hundred counters. We now
	// reject frames that trail by more than maxBehindTolerance instead
	// of re-anchoring, and reduce the sliding window to a tighter
	// dedupWindow (256) that still covers practical reordering.
	if behind32 > maxBehindTolerance {
		atomic.AddUint64(&d.replayDrops, 1)
		log.Debug("Dedup: far-behind replay drop behind=%d max=%d", behind32, maxC)
		return true, DedupDropFarBehind
	}

	// Inside live distance: a frame is a duplicate only if its specific
	// counter bit has already been seen. We deliberately do NOT treat "older
	// than max" as a duplicate, because multi-path delivery routinely produces
	// out-of-order frames that must still be accepted. Cross-session stale
	// replays are caught separately by the epoch check above (mismatched
	// connEpoch → replay drop). SyncFrom() positions maxSeq so the window does
	// not start at 0 and marks the anchor bit.
	if d.testBit(c) {
		return true, DedupDropSameSeq
	}
	d.setBit(c)
	return false, DedupDropNone
}

// dedupWindow is the out-of-order tolerance, in counters: how many counters
// behind the current max a seen-counter is still remembered for. Counters that
// fall further behind are evicted from the bitmask as the window slides, which
// bounds the replay window.
//
// It MUST equal maxBehindTolerance. Below that, a counter that is still inside
// the replay tolerance has already been evicted, so testBit reports "unseen"
// and the frame is delivered a second time — a silent duplicate TAP write in
// the (dedupWindow, maxBehindTolerance] band. Above it, the window would
// remember counters that IsDuplicate would reject anyway, widening the replay
// window for no reordering gain. Raised from 256 to 1024: at 256 counters a
// 100 Mbps link covers about 25 ms of skew, which is smaller than one relay
// hop, so real reordering already fell into the blind band.
//
// The recvd array is a fixed 65536-bit ring either way, so widening the window
// costs no extra memory.
const dedupWindow = maxBehindTolerance

// maxBehindTolerance is the maximum number of counters a frame may trail the
// current max before it is rejected as a replay. Frames this far behind are
// not multi-path reordering — they are captured-and-replayed. The previous
// code re-anchored and accepted any frame >= halfCounter (32768) behind,
// creating a massive replay window. See dedupWindow for why it and the
// eviction horizon must stay equal.
const maxBehindTolerance = 1024

// --- internal helpers ---

// setBit marks counter c as seen in the sliding dedup window. The counter is
// masked to its low 16 bits (the window depth) so the 32-bit structured counter
// never indexes out of the fixed-size recvd array.
func (d *Deduplicator) setBit(c uint64) {
	c &= 0xFFFF
	word := c / 64
	bit := c % 64
	mask := uint64(1) << bit
	if d.recvd[word]&mask == 0 {
		d.recvd[word] |= mask
		d.seenCount++
	}
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
	mask := uint64(1) << bit
	if d.recvd[word]&mask != 0 {
		d.recvd[word] &^= mask
		d.seenCount--
	}
}

// dedupWindow is the out-of-order tolerance, in counters. Counters that fall

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
	d.seenCount = 0
}

// counterDiff returns (a-b) in 16-bit modular arithmetic (0..65535).
func counterDiff(a, b uint64) uint64 {
	return (a - b) & 0xFFFF
}
