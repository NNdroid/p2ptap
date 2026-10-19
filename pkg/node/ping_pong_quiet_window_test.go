package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// TestPingPongReconnectQuietWindow pins the invariant that motivated widening the
// old hard-coded 45s: a peer whose echo stream stalls but which has demonstrably
// sent us data inside the window must NOT be re-handshaken. reconnectPeer is a
// full state reset (Dispatcher.RemovePeer, echoPool.Invalidate,
// clearCachedHandshakeEph, peerReady.Delete, ClosePeer) — it wipes the
// negotiated SeqSync cipher, so spending that on a live path was pure cost.
func TestPingPongReconnectQuietWindow(t *testing.T) {
	// A fresh node has no inbound-frame history, so its first echo failure
	// must escalate.
	n := &Node{}
	peerID := peer.ID("quiet-peer")
	if !n.pingPongShouldReconnect(peerID) {
		t.Fatal("peer with no inbound history must be allowed to reconnect")
	}

	// A single recent inbound frame suppresses the escalation.
	n.notePeerRx(peerID)
	if n.pingPongShouldReconnect(peerID) {
		t.Fatal("recent inbound data must suppress reconnectPeer (it would wipe the cipher)")
	}
}

// TestPingPongReconnectQuietWindowExpiry pins the other half: the suppression
// expires, so a peer that goes genuinely silent still gets reconnected. Without
// this the widened window would turn the probe into a permanent no-op.
func TestPingPongReconnectQuietWindowExpiry(t *testing.T) {
	n := &Node{}
	peerID := peer.ID("going-silent")

	// Backdate the inbound frame to just outside the window.
	n.peerRxMu.Lock()
	if m := n.peerLastRx.Load(); m != nil {
		if v, ok := (*m)[peerID]; ok {
			v.Store(time.Now().Add(-(pingPongReconnectQuietWindow + time.Second)).UnixNano())
		}
	}
	n.peerRxMu.Unlock()

	if !n.pingPongShouldReconnect(peerID) {
		t.Fatal("a silent peer must eventually reconnect again")
	}

	// ...and never, ever for a peer that has never sent anything.
	if !n.pingPongShouldReconnect(peer.ID("never-heard")) {
		t.Fatal("a peer with no inbound history must be allowed to reconnect")
	}
}

// TestPingPongQuietWindowCoversTheOldThreshold guards the direction of the
// change itself: the previous implementation hard-coded 45s. If a future edit
// shrinks the window below that, this test catches the regression that
// reintroduces the 20s cipher-wipe churn.
func TestPingPongQuietWindowCoversTheOldThreshold(t *testing.T) {
	if pingPongReconnectQuietWindow < 45*time.Second {
		t.Fatalf("pingPongReconnectQuietWindow = %s, which is below the old hard-coded 45s",
			pingPongReconnectQuietWindow)
	}
}
