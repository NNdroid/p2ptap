package node

import (
	"testing"
	"time"
)

// TestPeerStallBreaker covers the peer-egress stall circuit-breaker:
//
//   - a peer is only "stalled" after markPeerStalled (a write timeout), never
//     before — a healthy peer must never be short-circuited;
//   - the window expires on its own, so a peer that recovers is served again;
//   - re-arming inside the window is silent (no duplicate Warn per frame).
//
// This matters because a false positive silently blackholes a healthy peer's
// traffic, while a stuck breaker lets a wedged peer keep pinning a dispatch
// worker for the full write deadline.
func TestPeerStallBreaker(t *testing.T) {
	n := &Node{}
	pid := newTestPeerID(t)

	// Healthy peer: never stalled.
	if n.peerStalled(pid) {
		t.Fatalf("peer stalled before any write timeout")
	}

	n.markPeerStalled(pid)
	if !n.peerStalled(pid) {
		t.Fatalf("peer not stalled right after markPeerStalled")
	}

	// Re-arming while still inside the window keeps it stalled but must not
	// panic or change the outcome.
	n.markPeerStalled(pid)
	if !n.peerStalled(pid) {
		t.Fatalf("peer unstalled after re-arm inside the window")
	}

	// Expire the window by back-dating the recorded stall: the breaker must
	// clear itself and let traffic through again.
	n.peerStall.Store(pid, time.Now().Add(-peerStallCooldown-time.Second))
	if n.peerStalled(pid) {
		t.Fatalf("peer still stalled after the cooldown elapsed")
	}
	if _, ok := n.peerStall.Load(pid); ok {
		t.Fatalf("expired stall entry was not cleaned up (map grows unbounded)")
	}

	// A recovered peer that stalls again must be breakable again.
	n.markPeerStalled(pid)
	if !n.peerStalled(pid) {
		t.Fatalf("peer could not be re-stalled after recovery")
	}
}

// TestPeerStallBreakerPerPeer ensures one stalled peer does not affect others —
// the breaker is the mechanism that protects global throughput, so a leaked
// "all peers stalled" state would be a total egress outage.
func TestPeerStallBreakerPerPeer(t *testing.T) {
	n := &Node{}
	stalled := newTestPeerID(t)
	healthy := newTestPeerID(t)

	n.markPeerStalled(stalled)

	if !n.peerStalled(stalled) {
		t.Fatalf("stalled peer not reported as stalled")
	}
	if n.peerStalled(healthy) {
		t.Fatalf("healthy peer reported as stalled: breaker leaked across peers")
	}
}
