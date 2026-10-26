package node

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"
)

// newTestRelayConn builds a relayConn with no writeLoop goroutine running.
// teardownConn's wg.Wait() therefore returns immediately, which isolates the
// drain-under-test from any concurrent writer.
func newTestRelayConn(t *testing.T) *relayConn {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &relayConn{
		ctx:     ctx,
		cancel:  cancel,
		writeCh: make(chan relayJob, relayPoolMaxQueue),
	}
}

// TestRelayConnTeardownDrainsQueuedJobs locks teardownConn's drain: a frame
// queued before the teardown must have its onFail called and must not be left
// sitting in a channel nobody reads. writeLoop drains once on exit, but that
// drain runs before teardownConn returns, so the belt is what covers the frame
// enqueued after the writer gave up.
func TestRelayConnTeardownDrainsQueuedJobs(t *testing.T) {
	hop := test.RandPeerIDFatal(t)
	rc := newTestRelayConn(t)
	rc.peer = hop

	p := &relayStreamPool{conns: map[peer.ID]*relayConn{hop: rc}}

	aFailed, bFailed := false, false
	rc.writeCh <- relayJob{data: []byte("a"), onFail: func() { aFailed = true }}
	rc.writeCh <- relayJob{data: []byte("b"), onFail: func() { bFailed = true }}

	p.teardownConn(rc)

	if !aFailed || !bFailed {
		t.Fatalf("teardown must fail every queued job (a=%v b=%v)", aFailed, bFailed)
	}
	if got := len(rc.writeCh); got != 0 {
		t.Fatalf("teardown must leave the queue empty, got %d jobs left", got)
	}
}

// TestRelayPoolSubmitFailsAfterTeardown is the regression test for the silent
// loss. writeCh is buffered and never closed, so a Submit that already holds the
// relayConn can enqueue SUCCESSFULLY after the writeLoop has drained and exited.
// Before the post-enqueue ctx check that returned true with onFail never called
// and no goroutine left to consume the job — the frame was gone and the caller
// believed it was delivered.
//
// Reachable in production: the reaper deletes the map entry and tears the conn
// down outside the pool lock (reapOrphaned), while a concurrent Submit has
// already obtained the same rc via getOrCreate. The <ctx.Done()> select arm is
// not sufficient, because the send branch can win the race after cancel() has
// already been observed and drained.
func TestRelayPoolSubmitFailsAfterTeardown(t *testing.T) {
	hop := test.RandPeerIDFatal(t)
	rc := newTestRelayConn(t)
	rc.peer = hop

	p := &relayStreamPool{conns: map[peer.ID]*relayConn{hop: rc}}

	// No goroutine is draining rc.writeCh any more.
	p.teardownConn(rc)

	// ctx.Done() is already closed, so the send arm and the ctx arm of the
	// select are BOTH ready and Go picks at random — the pre-fix bug only shows
	// on the iterations where the send wins. Loop until the send arm is hit for
	// certain (2^100 is the pre-fix chance of passing every iteration).
	for i := 0; i < 100; i++ {
		failed := false
		if ok := p.Submit(hop, []byte("lost"), nil, func() { failed = true }); ok {
			t.Fatalf("iteration %d: Submit into a torn-down conn reported success", i)
		}
		if !failed {
			t.Fatalf("iteration %d: Submit into a torn-down conn did not call onFail", i)
		}
	}
	if got := len(rc.writeCh); got != 0 {
		t.Fatalf("Submit must not strand jobs in a dead queue, got %d", got)
	}
}

// TestRelayPoolSubmitSucceedsOnLiveConn is the positive control: a conn whose
// context is still alive accepts the enqueue and does not call onFail, even
// though nothing is draining it yet. Guards against the post-enqueue check being
// widened into an unconditional failure.
func TestRelayPoolSubmitSucceedsOnLiveConn(t *testing.T) {
	hop := test.RandPeerIDFatal(t)
	rc := newTestRelayConn(t)
	rc.peer = hop

	p := &relayStreamPool{conns: map[peer.ID]*relayConn{hop: rc}}

	failed := false
	ok := p.Submit(hop, []byte("ok"), nil, func() { failed = true })
	if !ok {
		t.Fatal("Submit into a live conn must report success")
	}
	if failed {
		t.Fatal("Submit into a live conn must not call onFail")
	}
	if got := len(rc.writeCh); got != 1 {
		t.Fatalf("exactly one job must be queued, got %d", got)
	}
}

// TestRelayStreamPoolShutdownDrains is the same invariant for the shutdown path,
// which used to inline cancel/Wait/closeStream without the drain — the same
// silent loss at node exit.
func TestRelayStreamPoolShutdownDrains(t *testing.T) {
	hop := test.RandPeerIDFatal(t)
	rc := newTestRelayConn(t)
	rc.peer = hop

	pctx, pcancel := context.WithCancel(context.Background())
	t.Cleanup(pcancel)
	p := &relayStreamPool{
		conns:  map[peer.ID]*relayConn{hop: rc},
		ctx:    pctx,
		cancel: pcancel,
	}

	failed := false
	rc.writeCh <- relayJob{data: []byte("pending"), onFail: func() { failed = true }}

	p.shutdown()

	if !failed {
		t.Fatal("shutdown must fail queued jobs rather than dropping them")
	}
	if got := len(rc.writeCh); got != 0 {
		t.Fatalf("shutdown must leave the queue empty, got %d jobs left", got)
	}
}
