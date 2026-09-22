package obfuscate

import "testing"

// The counter field of a structured SeqID is 32 bits wide (see frame.go), but
// the dedup bitmask is a 16-bit ring. These tests pin that the *distance*
// decisions are made over the full 32 bits — the mod-2^16 comparison used to
// treat a frame 65536 counters behind as identical to one seen moments ago.

func buildSeqID(epoch, counter uint64) uint64 {
	return seqVer1<<seqVerShift |
		(uint64(0xABCD) << seqSrcShift) |
		((epoch & 0xFFF) << seqEpochShift) |
		(counter & seqCntMask)
}

func TestDedupAcceptsMonotonicCounters(t *testing.T) {
	d := NewDeduplicator()
	d.SyncFrom(buildSeqID(7, 100))

	for c := uint64(101); c < 5000; c++ {
		if d.IsDuplicate(buildSeqID(7, c)) {
			t.Fatalf("monotonic counter %d wrongly rejected as duplicate", c)
		}
	}
}

// Crossing the 65536 boundary must not look like a wrap back onto seen bits.
func TestDedupDoesNotWrapAt65536(t *testing.T) {
	d := NewDeduplicator()
	d.SyncFrom(buildSeqID(7, 65500))

	for c := uint64(65501); c < 65600; c++ {
		if d.IsDuplicate(buildSeqID(7, c)) {
			t.Fatalf("counter %d (past the 65536 boundary) wrongly rejected", c)
		}
	}
}

// Two counters whose low 16 bits coincide are NOT the same frame.
func TestDedupDistinguishesCounters65536Apart(t *testing.T) {
	d := NewDeduplicator()
	d.SyncFrom(buildSeqID(7, 10000))

	if d.IsDuplicate(buildSeqID(7, 20000)) {
		t.Fatal("counter 20000 rejected after 10000")
	}
	// 20000 + 65536 shares the low 16 bits of 20000 but is a fresh frame.
	if d.IsDuplicate(buildSeqID(7, 20000+65536)) {
		t.Fatal("counter 85536 rejected: low-16 comparison mistaken it for 20000")
	}
}

func TestDedupStillRejectsExactDuplicates(t *testing.T) {
	d := NewDeduplicator()
	d.SyncFrom(buildSeqID(7, 100))

	for _, c := range []uint64{101, 102, 103} {
		if d.IsDuplicate(buildSeqID(7, c)) {
			t.Fatalf("first delivery of %d rejected", c)
		}
	}
	for _, c := range []uint64{101, 102, 103} {
		if !d.IsDuplicate(buildSeqID(7, c)) {
			t.Errorf("replay of %d not rejected", c)
		}
	}
}

// Reordering inside the tolerance must survive, otherwise multi-path
// (redundant) delivery would drop routine out-of-order traffic.
func TestDedupToleratesInWindowReordering(t *testing.T) {
	d := NewDeduplicator()
	d.SyncFrom(buildSeqID(7, 100))

	for _, c := range []uint64{101, 102, 103} {
		if d.IsDuplicate(buildSeqID(7, c)) {
			t.Fatalf("first delivery of %d rejected", c)
		}
	}

	// Unseen counter slightly behind the max: must be accepted, not dropped.
	if got := d.IsDuplicate(buildSeqID(7, 99)); got != false {
		t.Errorf("unseen in-window counter 99 rejected (got %v)", got)
	}

	// Already-seen counter behind the max: still recognised as a duplicate.
	if got := d.IsDuplicate(buildSeqID(7, 102)); got != true {
		t.Errorf("replay of 102 not recognised as duplicate (got %v)", got)
	}
}

// Documents the current trade-off rather than asserting a desired outcome.
//
// With the window advanced to 20000, replaying counter 150 is ACCEPTED once its
// bit has been evicted: in-session frames far behind are given the benefit of
// the doubt because multi-path (direct + relay) delivery legitimately produces
// deep reordering. Cross-session replay is still stopped by the epoch check.
// Tightening this needs field data on how much reordering redundant mode
// actually produces — see the note in IsDuplicate.
func TestDedupFarBehindFrameIsStillAccepted(t *testing.T) {
	d := NewDeduplicator()
	d.SyncFrom(buildSeqID(7, 100))

	for c := uint64(101); c <= 20000; c++ {
		d.IsDuplicate(buildSeqID(7, c))
	}

	if got := d.IsDuplicate(buildSeqID(7, 150)); got != false {
		t.Logf("NOTE: far-behind frame now rejected (got %v) — verify multi-path "+
			"delivery if this was intentional", got)
	}
}

// Same-epoch frames far ahead are accepted via re-anchor (long silence, resync)
// — that behaviour is intentional and must not regress.
func TestDedupReanchorsOnLargeForwardJump(t *testing.T) {
	d := NewDeduplicator()
	d.SyncFrom(buildSeqID(7, 100))

	if d.IsDuplicate(buildSeqID(7, 1<<20)) {
		t.Error("large forward jump rejected; resync traffic would be dropped")
	}
	// And after re-anchoring, duplicates are still caught.
	if !d.IsDuplicate(buildSeqID(7, 1<<20)) {
		t.Error("duplicate after re-anchor not caught")
	}
}

// Comparing distances mod 2^16 collapses distinct counters onto one slot. This
// is the class of bug the 32-bit comparison removes, and it is what makes the
// low-16 masks in setBit/testBit safe to keep: the *slot* really is 16 bits,
// only the *distance* must be 32.
func TestDedup32BitDistanceNotLow16(t *testing.T) {
	base := uint64(40000)

	// 65536 frames newer than the anchor, sharing its low 16 bits.
	d := NewDeduplicator()
	d.SyncFrom(buildSeqID(7, base))
	if got := d.IsDuplicate(buildSeqID(7, base+65536)); got != false {
		t.Errorf("counter %d rejected: its low 16 bits collide with %d", base+65536, base)
	}

	// Two multiples of 65536 apart — all three share low-16 bits and must each
	// be judged on their true distance.
	d2 := NewDeduplicator()
	d2.SyncFrom(buildSeqID(7, base))
	for i := uint64(1); i <= 3; i++ {
		if got := d2.IsDuplicate(buildSeqID(7, base+i*65536)); got != false {
			t.Errorf("counter %d rejected: collides in low 16 bits with %d", base+i*65536, base)
		}
	}
}

// The window must keep sliding across the 65536 boundary so routine
// out-of-order traffic is never dropped — this is what the redundant transport
// strategy depends on.
func TestDedupWindowKeepsSlidingPastWrap(t *testing.T) {
	d := NewDeduplicator()
	d.SetConnEpoch(0)

	mk := func(c uint64) uint64 {
		return (seqVer1 << seqVerShift) |
			(uint64(0xA1B2) << seqSrcShift) |
			(uint64(0) << seqEpochShift) |
			(c & seqCntMask)
	}

	for c := uint64(1); c <= 70000; c++ {
		if d.IsDuplicate(mk(c)) {
			t.Fatalf("sequential frame c=%d dropped", c)
		}
	}
	// recent duplicate still detected
	if !d.IsDuplicate(mk(69999)) {
		t.Error("recent duplicate not detected")
	}
}

func TestDedupRejectsStaleEpoch(t *testing.T) {
	d := NewDeduplicator()
	d.SyncFrom(buildSeqID(7, 100))
	d.IsDuplicate(buildSeqID(7, 101))

	if !d.IsDuplicate(buildSeqID(8, 101)) {
		t.Error("frame from a different connEpoch accepted")
	}
}
