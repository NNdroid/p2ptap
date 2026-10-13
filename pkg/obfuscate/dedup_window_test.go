package obfuscate

import "testing"

// These tests pin the relationship between the two constants that decide
// duplicate handling. dedupWindow is how far behind maxSeq a seen-counter is
// still remembered; maxBehindTolerance is how far behind a frame may trail
// before it is rejected as a replay.
//
// When dedupWindow was 256 and maxBehindTolerance was 1024, a frame 257-1024
// counters behind had already been evicted from the seen-bitmap, so testBit
// reported "unseen" and it was delivered to TAP a second time — a silent
// duplicate with no error and no log. The window and the tolerance had to be
// equal.

func TestDedupWindowEqualsTolerance(t *testing.T) {
	if dedupWindow != maxBehindTolerance {
		t.Fatalf("dedupWindow (%d) must equal maxBehindTolerance (%d): the gap is a "+
			"blind band where an already-delivered frame is re-accepted",
			dedupWindow, maxBehindTolerance)
	}
}

// A counter delivered inside the tolerance must keep its seen-bit when maxSeq
// advances past dedupWindow.
func TestDedupFarBehindInsideToleranceIsNotReaccepted(t *testing.T) {
	d := NewDeduplicator()
	d.SyncFrom(buildSeqID(7, 1000))

	// Deliver counter 1500 first, while it is AHEAD of maxSeq.
	if d.IsDuplicate(buildSeqID(7, 1500)) {
		t.Fatal("counter 1500 rejected on its first delivery")
	}
	// Advance 500 counters: more than the old 256-wide window.
	if d.IsDuplicate(buildSeqID(7, 2000)) {
		t.Fatal("counter 2000 rejected")
	}
	// Counter 1500 now trails by 500. It was already delivered, so it must be
	// recognised as a duplicate.
	if !d.IsDuplicate(buildSeqID(7, 1500)) {
		t.Fatal("counter 1500 re-accepted after maxSeq advanced past it")
	}
}

// A frame inside the tolerance must also be ACCEPTED when it has never been
// delivered — eviction must not turn a new frame into a drop.
func TestDedupFarBehindInsideToleranceStillAcceptsNew(t *testing.T) {
	d := NewDeduplicator()
	d.SyncFrom(buildSeqID(7, 1000))
	if d.IsDuplicate(buildSeqID(7, 2000)) {
		t.Fatal("counter 2000 rejected")
	}
	if d.IsDuplicate(buildSeqID(7, 1500)) {
		t.Fatal("counter 1500 (500 behind, never delivered) wrongly rejected")
	}
}

// Far-behind replays are still rejected.
func TestDedupBeyondToleranceIsStillRejected(t *testing.T) {
	d := NewDeduplicator()
	d.SyncFrom(buildSeqID(7, 2000))
	if !d.IsDuplicate(buildSeqID(7, 2000-maxBehindTolerance-1)) {
		t.Fatal("a counter just past the tolerance must be rejected as a replay")
	}
	drops := d.ReplayDrops()
	if drops != 1 {
		t.Fatalf("ReplayDrops = %d, want 1", drops)
	}
}

// The forward-jump path used to clearAll the bitmap, which wiped the counters
// still inside the tolerance and let an already-delivered frame through a
// second time. It must slide instead.
func TestDedupLargeForwardJumpKeepsToleranceCounters(t *testing.T) {
	d := NewDeduplicator()
	d.SyncFrom(buildSeqID(7, 1000))

	// Deliver 4500: a 3500-counter forward jump, far past the window.
	if d.IsDuplicate(buildSeqID(7, 4500)) {
		t.Fatal("counter 4500 rejected on its first delivery")
	}
	// One more modest advance.
	if d.IsDuplicate(buildSeqID(7, 5000)) {
		t.Fatal("counter 5000 rejected")
	}
	// 4500 trails by 500 — inside the tolerance, and already delivered.
	if !d.IsDuplicate(buildSeqID(7, 4500)) {
		t.Fatal("counter 4500 re-accepted after a large forward jump wiped the window")
	}
}

// The live window is dedupWindow counters deep, so the utilisation metric must
// divide by that, not by the whole 65536-counter ring. The old denominator
// reported ~0.0015% whatever happened, which made the reorder headroom look
// enormous.
func TestDedupWindowUtilizationUsesLiveWindow(t *testing.T) {
	d := NewDeduplicator()
	d.SyncFrom(buildSeqID(7, 1000)) // clears the bitmap, then marks one counter

	want := 1.0 / float64(dedupWindow)
	if got := d.WindowUtilization(); got != want {
		t.Fatalf("WindowUtilization = %v, want 1/%d = %v", got, dedupWindow, want)
	}
}
