package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// Regression test for a shipped crash: "panic: assignment to entry in nil map"
// in noteRelayUpgradeResult, taken from a live Android build. relayUpgradeFails
// and relayUpgradeNext are never allocated by NewNode, so the first failed
// direct-upgrade of a relay-only peer wrote into a nil map and killed the whole
// engine. Every path in this file must therefore survive a bare &Node{}, which
// is also how the in-package tests construct a Node.
func TestNoteRelayUpgradeResultOnBareNode(t *testing.T) {
	n := &Node{}
	pid := peer.ID("12D3KooWRelayOnlyPeerRegression01")

	for fails := 1; fails <= 7; fails++ {
		n.noteRelayUpgradeResult(pid, false)

		if got := n.relayUpgradeFails[pid]; got != fails {
			t.Fatalf("failure %d: count = %d, want %d", fails, got, fails)
		}
		if fails < 2 {
			// A single failure is retried on the next tick: no backoff yet.
			if _, ok := n.relayUpgradeNext[pid]; ok {
				t.Fatalf("failure %d: expected no backoff entry", fails)
			}
			continue
		}
		want := relayUpgradeBaseBackoff << uint(fails-2)
		if want > relayUpgradeMaxBackoff {
			want = relayUpgradeMaxBackoff
		}
		deadline := time.Until(n.relayUpgradeNext[pid])
		if deadline < want-time.Second || deadline > want+time.Second {
			t.Fatalf("failure %d: backoff deadline %v, want within 1s of %v", fails, deadline, want)
		}
	}

	// Steady state: an unreachable peer costs one attempt per cap, not per tick.
	n.noteRelayUpgradeResult(pid, false)
	if deadline := time.Until(n.relayUpgradeNext[pid]); deadline > relayUpgradeMaxBackoff+time.Second {
		t.Fatalf("backoff deadline %v exceeds the %v cap", deadline, relayUpgradeMaxBackoff)
	}

	// A successful upgrade clears both the count and the backoff, so a peer that
	// later becomes reachable is not throttled by its old failures.
	n.noteRelayUpgradeResult(pid, true)
	if got := n.relayUpgradeFails[pid]; got != 0 {
		t.Fatalf("upgrade cleared, but failure count is still %d", got)
	}
	if _, ok := n.relayUpgradeNext[pid]; ok {
		t.Fatal("upgrade cleared, but a backoff entry is still present")
	}
}

// A success on a peer that was never recorded must not allocate either map: the
// clear path is a no-op on nil maps (delete is safe), which keeps the common
// case from churning allocations.
func TestNoteRelayUpgradeSuccessDoesNotAllocate(t *testing.T) {
	n := &Node{}
	pid := peer.ID("12D3KooWRelayOnlyPeerSuccess0001")

	n.noteRelayUpgradeResult(pid, true)

	if n.relayUpgradeFails != nil || n.relayUpgradeNext != nil {
		t.Fatal("successful upgrade on an unrecorded peer must not allocate the backoff maps")
	}
}

// clearRelayOnlyPeer and isRelayOnlyPeer delete from nil maps, which is legal;
// the whole relay-only bookkeeping must stay usable on a bare &Node{}.
func TestRelayOnlyBookkeepingOnBareNode(t *testing.T) {
	n := &Node{}
	pid := peer.ID("12D3KooWRelayOnlyPeerBookkeep1")

	n.clearRelayOnlyPeer(pid) // no-op before marking
	n.markRelayOnlyPeer(pid)
	if !n.isRelayOnlyPeer(pid) {
		t.Fatal("peer marked relay-only but isRelayOnlyPeer reports false")
	}
	n.noteRelayUpgradeResult(pid, false)
	n.clearRelayOnlyPeer(pid)

	if n.isRelayOnlyPeer(pid) {
		t.Fatal("clearRelayOnlyPeer did not clear the classification")
	}
	if got := n.relayUpgradeFails[pid]; got != 0 {
		t.Fatalf("clearRelayOnlyPeer did not reset the failure count: %d", got)
	}
}

// Backoff gates candidacy: a single failure is retried immediately, the second
// one starts the window, and the window expiring admits the peer back.
func TestRelayUpgradeCandidatesHonourBackoff(t *testing.T) {
	n := &Node{}
	throttled := peer.ID("12D3KooWRelayOnlyPeerThrott01")
	free := peer.ID("12D3KooWRelayOnlyPeerFree00001")

	n.markRelayOnlyPeer(throttled)
	n.markRelayOnlyPeer(free)

	now := time.Now()
	assertCandidates(t, n, now, []peer.ID{throttled, free}, "with no failures recorded")

	n.noteRelayUpgradeResult(throttled, false) // fails=1: still eligible
	assertCandidates(t, n, now, []peer.ID{throttled, free}, "after one failure (no backoff yet)")

	n.noteRelayUpgradeResult(throttled, false) // fails=2: 1m backoff starts
	assertCandidates(t, n, now, []peer.ID{free}, "inside the backoff window")

	assertCandidates(t, n, now.Add(relayUpgradeBaseBackoff+time.Minute),
		[]peer.ID{throttled, free}, "after the backoff window elapsed")
}

func assertCandidates(t *testing.T, n *Node, now time.Time, want []peer.ID, ctx string) {
	t.Helper()
	out := n.relayUpgradeCandidates(now)
	if len(out) != len(want) {
		t.Fatalf("%s: got %d candidate(s), want %d: %v", ctx, len(out), len(want), out)
	}
	for _, p := range want {
		got := false
		for _, q := range out {
			if q.String() == p.String() {
				got = true
				break
			}
		}
		if !got {
			t.Fatalf("%s: %s missing from candidates %v", ctx, p, out)
		}
	}
}
