package obfuscate

import (
	"testing"
)

// IsDuplicateReason is what lets a receive path tell a benign duplicate (the
// same counter redelivered over a second path — normal and expected in a
// multi-path mesh) from a protocol-level desync that has to trigger recovery.
// Before the classification existed, every drop collapsed into one bool, so a
// stale-epoch desync was invisible: those frames are well-formed and decrypt
// cleanly, nothing else in the stack saw them.
func TestIsDuplicateReasonClassifies(t *testing.T) {
	d := NewDeduplicator()
	d.SyncFrom(buildSeqID(7, 100))

	// Unstructured / raw frames are never deduped.
	if dup, reason := d.IsDuplicateReason(0); dup || reason != DedupDropNone {
		t.Errorf("zero seqID: got (%v, %v), want (false, None)", dup, reason)
	}

	// A fresh counter is accepted.
	if dup, reason := d.IsDuplicateReason(buildSeqID(7, 101)); dup || reason != DedupDropNone {
		t.Errorf("fresh counter: got (%v, %v), want (false, None)", dup, reason)
	}

	// The same counter arriving again — a redundant multi-path copy. Benign.
	if dup, reason := d.IsDuplicateReason(buildSeqID(7, 101)); !dup || reason != DedupDropSameSeq {
		t.Errorf("same counter: got (%v, %v), want (true, SameSeq)", dup, reason)
	}

	// A frame trailing the live window past the tolerance is a replay, not a
	// reorder. Needs healing.
	// Advance the live window, then replay a frame 3000 counters behind it.
	if dup, _ := d.IsDuplicateReason(buildSeqID(7, 3101)); dup {
		t.Fatal("a 3000-counter forward jump was dropped")
	}
	if dup, reason := d.IsDuplicateReason(buildSeqID(7, 101)); !dup || reason != DedupDropFarBehind {
		t.Errorf("far behind: got (%v, %v), want (true, FarBehind)", dup, reason)
	}

	// A mismatched epoch is a cross-session frame or a sender out of step.
	if dup, reason := d.IsDuplicateReason(buildSeqID(8, 101)); !dup || reason != DedupDropStaleEpoch {
		t.Errorf("stale epoch: got (%v, %v), want (true, StaleEpoch)", dup, reason)
	}

	// IsDuplicate is the thin wrapper: its behaviour must be unchanged by the
	// classification, since every existing caller depends on it.
	if !d.IsDuplicate(buildSeqID(7, 101)) {
		t.Error("IsDuplicate stopped reporting the same-seq duplicate")
	}
	if d.IsDuplicate(buildSeqID(7, 3100)) {
		t.Error("IsDuplicate started reporting an in-window counter as a duplicate")
	}
}
