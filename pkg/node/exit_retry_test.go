package node

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// newRetryTestNode builds a minimal Node with a fake-route GatewayManager and a
// never-cancelled context. Host is left nil so peerReachable reports false
// unless a test explicitly connects the peer.
func newRetryTestNode(t *testing.T) (*Node, *fakeRouteBackend) {
	t.Helper()
	gm, fb := newFakeGM(t)
	return &Node{
		ctx:     context.Background(),
		Gateway: gm,
	}, fb
}

// waitForExitRetryCleared polls until exitRetryDesired == want or the timeout
// elapses, asserting on the final state.
func waitForExitRetryCleared(t *testing.T, n *Node, want peer.ID) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		n.exitRetryMu.Lock()
		got := n.exitRetryDesired
		n.exitRetryMu.Unlock()
		if got == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	n.exitRetryMu.Lock()
	defer n.exitRetryMu.Unlock()
	t.Fatalf("exitRetryDesired = %q, want %q (retry loop did not settle)", n.exitRetryDesired, want)
}

// TestRetryExitNodeEmptyPID verifies that an empty peer ID is a no-op (no state,
// no goroutine, no panic).
func TestRetryExitNodeEmptyPID(t *testing.T) {
	n, _ := newRetryTestNode(t)
	n.retryExitNodeAfterDisconnect("", "10.0.0.2", "fd00::2")

	n.exitRetryMu.Lock()
	defer n.exitRetryMu.Unlock()
	if n.exitRetryDesired != "" {
		t.Fatalf("exitRetryDesired = %q, want empty", n.exitRetryDesired)
	}
	if n.exitRetryIP4 != "" || n.exitRetryIP6 != "" {
		t.Fatalf("exitRetry IPs not empty after empty-PID retry: %q %q", n.exitRetryIP4, n.exitRetryIP6)
	}
}

// TestRetryExitNodeOperatorCancel verifies the core fix: after a retry is
// scheduled for a disconnected exit peer, a later operator action (an Exit Node
// state transition such as ClearExitNode) cancels the pending re-apply so the
// automatic loop never resurrects a choice the user just overrode.
func TestRetryExitNodeOperatorCancel(t *testing.T) {
	n, _ := newRetryTestNode(t)
	pid := peer.ID("peer-exit")

	n.retryExitNodeAfterDisconnect(pid, "10.0.0.2", "fd00::2")

	n.exitRetryMu.Lock()
	if n.exitRetryDesired != pid {
		n.exitRetryMu.Unlock()
		t.Fatalf("exitRetryDesired = %q, want %q", n.exitRetryDesired, pid)
	}
	n.exitRetryMu.Unlock()

	// Let the loop run at least one poll cycle, then act as the operator: a
	// ClearExitNode transition bumps ExitChangeSeq, which the loop observes and
	// aborts on.
	time.Sleep(1300 * time.Millisecond)
	if err := n.Gateway.ClearExitNode(); err != nil {
		t.Fatalf("ClearExitNode: %v", err)
	}
	waitForExitRetryCleared(t, n, "")
}

// TestClearExitNodeRetryDesiredGen verifies that clearExitNodeRetryDesired only
// clears the exact (pid, gen) the caller owns, never a newer retry.
func TestClearExitNodeRetryDesiredGen(t *testing.T) {
	n, _ := newRetryTestNode(t)
	pid := peer.ID("peer-exit")

	n.retryExitNodeAfterDisconnect(pid, "10.0.0.2", "fd00::2")
	n.exitRetryMu.Lock()
	gen := n.exitRetryGen
	n.exitRetryMu.Unlock()

	// A stale gen must not clear the pending retry.
	n.clearExitNodeRetryDesired(pid, gen+100)
	n.exitRetryMu.Lock()
	if n.exitRetryDesired != pid {
		n.exitRetryMu.Unlock()
		t.Fatalf("stale gen cleared pending retry (desired=%q)", n.exitRetryDesired)
	}
	n.exitRetryMu.Unlock()

	// The owning gen clears it.
	n.clearExitNodeRetryDesired(pid, gen)
	n.exitRetryMu.Lock()
	defer n.exitRetryMu.Unlock()
	if n.exitRetryDesired != "" {
		t.Fatalf("owning gen did not clear pending retry (desired=%q)", n.exitRetryDesired)
	}
}

// TestReapplyExitNodeNoIPs verifies that a re-apply with no gateway TAP IPs is
// refused instead of installing a bogus route.
func TestReapplyExitNodeNoIPs(t *testing.T) {
	n, _ := newRetryTestNode(t)
	if err := n.reapplyExitNode(peer.ID("peer-exit"), "", ""); err == nil {
		t.Fatal("reapplyExitNode with empty IPs succeeded, want error")
	}
}

// TestReapplyExitNodeInstallsRoute verifies that a re-apply with valid gateway
// IPs installs the TAP default route through the same SetExitNode path the
// WebUI uses, using a fake route backend so no host routing is touched.
func TestReapplyExitNodeInstallsRoute(t *testing.T) {
	n, fb := newRetryTestNode(t)
	pid := peer.ID("peer-exit")

	if err := n.reapplyExitNode(pid, "10.0.0.2", "fd00::2"); err != nil {
		t.Fatalf("reapplyExitNode: %v", err)
	}
	if !n.Gateway.IsExitNodeActive() {
		t.Fatal("exit node not active after reapply")
	}
	found := false
	for _, ip := range fb.addDef {
		if ip == "10.0.0.2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("IPv4 TAP default route not installed by reapply (addDef=%v)", fb.addDef)
	}
}

// TestPeerEndpointsNilHost verifies peerEndpoints is safe with a nil host.
func TestPeerEndpointsNilHost(t *testing.T) {
	n, _ := newRetryTestNode(t)
	if got := n.peerEndpoints(peer.ID("peer-exit")); got != nil {
		t.Fatalf("peerEndpoints with nil host = %v, want nil", got)
	}
}
