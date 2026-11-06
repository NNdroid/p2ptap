package node

import (
	"context"
	"errors"
	"fmt"
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

// TestPeerStallBreakerDoesNotReArm is the regression guard for the
// "multipath peer stays online but ping never comes back" blackhole: several
// dispatch workers can all time out in the same instant. Re-arming the window
// on each of them let the breaker expire NEVER, so every frame for that peer
// was dropped and no send ever reached the stream-repair path again.
func TestPeerStallBreakerDoesNotReArm(t *testing.T) {
	n := &Node{}
	pid := newTestPeerID(t)

	// Back-date the first stall to 2s ago (still inside the 3s window) so any
	// re-arm would be visible as a timestamp change.
	first := time.Now().Add(-2 * time.Second)
	n.peerStall.Store(pid, first)
	for i := 0; i < 8; i++ { // simulate NumCPU workers timing out together
		n.markPeerStalled(pid)
	}
	got, _ := n.peerStall.Load(pid)
	if !got.(time.Time).Equal(first) {
		t.Fatalf("stall window was re-armed (%v -> %v): breaker can never expire under sustained timeouts",
			first, got.(time.Time))
	}
	if !n.peerStalled(pid) {
		t.Fatalf("peer unstalled while still inside the original window")
	}

	// The window is anchored to the FIRST timeout, so it must clear on that
	// deadline — no matter how many later timeouts arrived.
	n.peerStall.Store(pid, time.Now().Add(-peerStallCooldown-time.Millisecond))
	if n.peerStalled(pid) {
		t.Fatalf("breaker did not expire at the original deadline")
	}
}

// TestTimeoutSendErrorDoesNotTriggerReconnect guards the WAN-timeout root
// cause: a slow-link write timeout must NOT escalate to reconnectPeer, which
// closes every transport connection, clears readiness and forces a full ECDH
// re-handshake on BOTH ends. That teardown is what turned one transient
// timeout into a permanent data-plane blackhole on cross-WAN multipath links.
func TestTimeoutSendErrorDoesNotTriggerReconnect(t *testing.T) {
	n := &Node{} // nil Dispatcher: any escalation would panic here
	pid := newTestPeerID(t)

	timeoutErrs := []error{
		context.DeadlineExceeded,
		timeoutReadError{},
		fmt.Errorf("send batch: %w", context.DeadlineExceeded),
	}
	for _, err := range timeoutErrs {
		if !isTimeoutErr(err) {
			t.Fatalf("timeout error %v not classified as slow-link", err)
		}
		n.handleUnicastFailure(pid, nil, err)
	}
	if n.lastReconnectTime != nil {
		t.Fatalf("write timeout escalated to a full peer reconnect: %v", n.lastReconnectTime)
	}
	if isTimeoutErr(errors.New("stream reset")) || isTimeoutErr(nil) {
		t.Fatalf("non-timeout errors must still escalate to reconnect")
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
