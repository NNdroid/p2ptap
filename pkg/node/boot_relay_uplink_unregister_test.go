package node

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// failingWriteStream is a network.Stream that fails every Write. Only the
// methods bootRelayWriteLoop actually calls are defined; the embedded interface
// is nil on purpose so any other call panics loudly instead of succeeding
// against a non-existent transport.
type failingWriteStream struct {
	network.Stream
	writeErr error
	closed   atomic.Bool
}

func (s *failingWriteStream) Write([]byte) (int, error)        { return 0, s.writeErr }
func (s *failingWriteStream) SetWriteDeadline(time.Time) error { return nil }
func (s *failingWriteStream) Close() error {
	s.closed.Store(true)
	return nil
}

// newTestBootRelayNode builds a Node with only what the boot-relay registration
// paths touch. bootRelayRegister/Unregister/hasBootRelayUplink use bootRelayMu
// and bootRelayConns exclusively; bootRelayWriteLoop nil-checks protoTracker and
// only dereferences n.Host on the 15 s heartbeat tick, which these tests never
// reach.
func newTestBootRelayNode() *Node {
	return &Node{bootRelayConns: map[peer.ID]*bootRelayConn{}}
}

// TestBootRelayWriteLoopUnregistersOnWriteFailure pins the map invariant: a conn
// is registered only while it is alive. Before the fix the write loop drained,
// cancelled rc and returned WITHOUT unregistering, so bootRelayConns[boot] kept
// pointing at a dead conn. Routing then believed the uplink was alive for the
// whole re-open backoff and sent every frame for the target to a dead boot.
// The submit itself reported failure (no silent loss), but nothing fell over to
// a healthy sibling boot in a multi-boot deployment.
func TestBootRelayWriteLoopUnregistersOnWriteFailure(t *testing.T) {
	boot := peer.ID("uplink-failure-boot")
	n := newTestBootRelayNode()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rc := &bootRelayConn{
		boot:    boot,
		ctx:     ctx,
		cancel:  cancel,
		stream:  &failingWriteStream{writeErr: errors.New("uplink write failed")},
		writeCh: make(chan bootRelayJob, 1),
	}
	n.bootRelayRegister(boot, rc)
	if len(n.bootRelayConns) != 1 {
		t.Fatal("setup: boot must be registered")
	}

	done := make(chan struct{})
	go func() { n.bootRelayWriteLoop(rc); close(done) }()

	failed := false
	rc.writeCh <- bootRelayJob{data: []byte("frame"), onFail: func() { failed = true }}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("write loop did not exit after a failed write")
	}

	if _, ok := n.bootRelayConns[boot]; ok {
		t.Fatal("write loop must unregister the conn on a failed write so routing stops selecting this boot")
	}
	if !failed {
		t.Fatal("queued job must get onFail when the uplink write fails")
	}
}

// TestBootRelayWriteLoopUnregistersOnCtxCancel covers the other exit path: the
// reader side cancels rc after its ReadFrame returns, and the writer has to drop
// its own registration too — it cannot assume the reader already did.
func TestBootRelayWriteLoopUnregistersOnCtxCancel(t *testing.T) {
	boot := peer.ID("ctx-cancel-boot")
	n := newTestBootRelayNode()

	ctx, cancel := context.WithCancel(context.Background())
	stream := &failingWriteStream{} // write never attempted: ctx is done first
	rc := &bootRelayConn{boot: boot, ctx: ctx, cancel: cancel, stream: stream, writeCh: make(chan bootRelayJob, 1)}
	n.bootRelayRegister(boot, rc)

	done := make(chan struct{})
	go func() { n.bootRelayWriteLoop(rc); close(done) }()
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("write loop did not exit after its context was cancelled")
	}
	if _, ok := n.bootRelayConns[boot]; ok {
		t.Fatal("write loop must unregister the conn when its context is cancelled")
	}
}

// TestHasBootRelayUplinkFalseForDeadConn pins the second half of the invariant:
// a conn whose context is already done must not be reported as an uplink even
// while its registration is still in the map. This is what stops a multi-boot
// deployment from piling traffic onto a boot that is mid-re-open.
func TestHasBootRelayUplinkFalseForDeadConn(t *testing.T) {
	boot := peer.ID("dead-uplink-boot")
	n := newTestBootRelayNode()

	ctx, cancel := context.WithCancel(context.Background())
	rc := &bootRelayConn{boot: boot, ctx: ctx, cancel: cancel, writeCh: make(chan bootRelayJob, 1)}
	n.bootRelayRegister(boot, rc)

	if !n.hasBootRelayUplink(boot) {
		t.Fatal("a live conn must be reported as an uplink")
	}
	cancel()
	if n.hasBootRelayUplink(boot) {
		t.Fatal("a conn whose context is done must not be reported as an uplink")
	}

	// The bare test stub keeps reporting as an uplink, so the existing routing
	// tests that fake a live uplink with no writer continue to work.
	stubBoot := peer.ID("stub-uplink-boot")
	n.bootRelayRegister(stubBoot, &bootRelayConn{boot: stubBoot})
	if !n.hasBootRelayUplink(stubBoot) {
		t.Fatal("a nil-context stub conn must still be reported as an uplink")
	}
}
