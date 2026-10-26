package main

import (
	"fmt"
	"testing"
)

// TestUnauthTrackerRingEvictsOldest pins the recent-events ring: past the cap
// the oldest events are overwritten in place, the aggregate counters keep
// counting past it, and Stats returns the surviving window newest-first.
func TestUnauthTrackerRingEvictsOldest(t *testing.T) {
	const ringCap = 7
	tr := newUnauthTracker(ringCap)
	total := ringCap * 2
	for i := 0; i < total; i++ {
		tr.Record(unauthTypeRelayFrame, fmt.Sprintf("peer_%d", i), fmt.Sprintf("detail_%d", i))
	}

	stats := tr.Stats()
	if stats.TotalDropped != int64(total) {
		t.Fatalf("TotalDropped: got %d, want %d", stats.TotalDropped, total)
	}
	if got := stats.ByType[unauthTypeRelayFrame]; got != int64(total) {
		t.Fatalf("ByType[relay_frame]: got %d, want %d", got, total)
	}
	if len(stats.RecentEvents) != ringCap {
		t.Fatalf("RecentEvents len: got %d, want %d", len(stats.RecentEvents), ringCap)
	}
	// Newest first: the surviving window is the last ringCap of the 0-indexed
	// adds, so output slot i holds add total-1-i.
	for i, ev := range stats.RecentEvents {
		want := total - 1 - i
		if ev.PeerID != fmt.Sprintf("peer_%d", want) || ev.Detail != fmt.Sprintf("detail_%d", want) {
			t.Fatalf("RecentEvents[%d] = peer=%q detail=%q, want peer_%d/detail_%d",
				i, ev.PeerID, ev.Detail, want, want)
		}
	}
}

// TestUnauthTrackerUnknownType records an event whose category has no
// preallocated counter: the global total and the recent list still advance, but
// no bogus per-type entry appears.
func TestUnauthTrackerUnknownType(t *testing.T) {
	tr := newUnauthTracker(4)
	tr.Record("not_a_real_type", "peer", "detail")

	stats := tr.Stats()
	if stats.TotalDropped != 1 || len(stats.RecentEvents) != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if _, ok := stats.ByType["not_a_real_type"]; ok {
		t.Fatalf("unknown type must not get a per-type counter: %+v", stats.ByType)
	}
}

// TestUnauthTrackerCapFloor: the ring is indexed with %len, so a zero or
// negative cap must clamp to a usable size rather than panic on the first
// Record.
func TestUnauthTrackerCapFloor(t *testing.T) {
	for _, bad := range []int{0, -5} {
		tr := newUnauthTracker(bad)
		tr.Record(unauthTypeMeta, "peer", "detail")
		if stats := tr.Stats(); len(stats.RecentEvents) != 1 {
			t.Fatalf("cap=%d: RecentEvents len = %d, want 1", bad, len(stats.RecentEvents))
		}
	}
}
