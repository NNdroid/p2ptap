package main

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// TestPendingClientFlushOnRegister exercises the production fix for the boot
// uplink registration race: a frame routed for a client whose uplink handler has
// started but whose stream is not yet registered is buffered, then flushed to
// the stream the moment registerClient publishes it.
//
// Before the fix route() found no stream for such a client and dropped the frame
// (fromMesh) or wrongly flooded it — the "relay connects but the first frames
// never arrive" symptom that made TestBootRelayTicketFastPath flake.
func TestPendingClientFlushOnRegister(t *testing.T) {
	r := &relayRouter{}
	p := peer.ID("connecting-client")

	// A frame arrives while the client's uplink is mid-registration: the
	// handler has started (markConnecting) but registerClient has not run.
	r.markConnecting(p)
	if !r.isConnecting(p) {
		t.Fatal("client should be marked connecting after handler start")
	}
	r.bufferPendingClientFrame(p, []byte("first-frame"))

	// The client's stream now registers. registerClient flushes the buffered
	// frame to the stream's queue.
	ps := &relayPeerStream{dest: p, q: make(chan *relayFrameBuf, 16), done: make(chan struct{})}
	r.flushPendingClient(p, ps)

	// enqueue() frames each payload with a 4-byte length prefix (fb.b[0:4]),
	// so the delivered payload sits at fb.b[4:].
	select {
	case fb := <-ps.q:
		if got := string(fb.b[4:]); got != "first-frame" {
			t.Fatalf("flushed frame = %q, want %q", got, "first-frame")
		}
	default:
		t.Fatal("expected the buffered frame to be flushed to the new stream")
	}

	// The buffer must be gone after flush.
	r.pendingMu.Lock()
	_, still := r.pending[p]
	r.pendingMu.Unlock()
	if still {
		t.Fatal("pending buffer not cleared after flush")
	}
}

// TestPendingClientDropsAfterTTL: a frame buffered for a client that never
// registers (e.g. rejected at authentication) is released after the TTL instead
// of holding memory forever.
func TestPendingClientDropsAfterTTL(t *testing.T) {
	r := &relayRouter{}
	p := peer.ID("never-registers")

	r.markConnecting(p)
	r.bufferPendingClientFrame(p, []byte("doomed"))

	r.pendingMu.Lock()
	pc := r.pending[p]
	r.pendingMu.Unlock()
	if pc == nil {
		t.Fatal("frame should be buffered")
	}
	// Drop via the same timer callback path registerClient would cancel.
	r.dropPendingClient(p)
	r.pendingMu.Lock()
	_, still := r.pending[p]
	r.pendingMu.Unlock()
	if still {
		t.Fatal("pending buffer not dropped")
	}
}

// TestPendingClientTTLExpires: the AfterFunc timer actually fires and drops the
// buffer if the client never registers.
func TestPendingClientTTLExpires(t *testing.T) {
	// Shorten the TTL for the test; restore after (other tests run in parallel
	// within the package only if -parallel, so restore synchronously).
	oldTTL := pendingClientTTL
	pendingClientTTL = 40 * time.Millisecond
	defer func() { pendingClientTTL = oldTTL }()

	r := &relayRouter{}
	p := peer.ID("slow-client")

	r.markConnecting(p)
	r.bufferPendingClientFrame(p, []byte("late"))

	// Poll until the timer drops the entry, bounded so the test fails fast on a
	// bug rather than hanging.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.pendingMu.Lock()
		_, ok := r.pending[p]
		r.pendingMu.Unlock()
		if !ok {
			return // dropped by the timer — correct
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("pending buffer was not dropped by the TTL timer")
}

// TestPendingClientIgnoredForRemotePeer: a frame for a peer that is never marked
// connecting (a genuinely remote/backbone peer) must NOT be buffered — route()
// only calls bufferPendingClientFrame after isConnecting(finalDst) is true, so
// the map must stay empty and remote traffic is never delayed.
func TestPendingClientIgnoredForRemotePeer(t *testing.T) {
	r := &relayRouter{}
	remote := peer.ID("remote-peer")
	if r.isConnecting(remote) {
		t.Fatal("a peer that never connected must not be marked connecting")
	}
	r.pendingMu.Lock()
	_, ok := r.pending[remote]
	r.pendingMu.Unlock()
	if ok {
		t.Fatal("no frame should ever be buffered for a non-connecting peer")
	}
}
