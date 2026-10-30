package main

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/test"

	"p2ptap/pkg/routing"
)

// gatedStream is a stream whose Write blocks until the test releases it, which
// is how a wedged destination (peer not reading, congestion window closed, QUIC
// path stalled) behaves from the boot's point of view.
type gatedStream struct {
	*fakeStream
	gate    chan struct{}
	entered chan struct{}
	once    sync.Once
	closed  atomic.Bool
}

func newGatedStream() *gatedStream {
	return &gatedStream{
		fakeStream: &fakeStream{},
		gate:       make(chan struct{}),
		entered:    make(chan struct{}, 1),
	}
}

func (s *gatedStream) Write(p []byte) (int, error) {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-s.gate
	return s.fakeStream.Write(p)
}

func (s *gatedStream) SetWriteDeadline(time.Time) error { return nil }

func (s *gatedStream) Close() error {
	s.closed.Store(true)
	return nil
}

func (s *gatedStream) release() {
	s.once.Do(func() { close(s.gate) })
}

// TestRelayRouterSlowDestinationDoesNotStallOtherDestinations is the regression
// test for the head-of-line blocking that survived the per-stream write lock.
//
// route() is called from ONE goroutine per attached client uplink, so when the
// write ran inline a single wedged destination stalled every frame that same
// client wanted to deliver — to any other destination — until the 5s write
// deadline expired. The client's stream window then closed behind it, which is
// what "the tunnel is connected but nothing loads" looks like from the user's
// side.
//
// With per-destination writer queues the slow stream can only back up its own
// queue: route() to a healthy destination must return immediately and that
// destination must receive its frame while the other write is still blocked.
func TestRelayRouterSlowDestinationDoesNotStallOtherDestinations(t *testing.T) {
	rr, acl := newTestRelayRouter(t)
	const netID = "test-net"

	sender := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(sender, netID)

	slowDest := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(slowDest, netID)
	slow := newGatedStream()
	rr.registerClient(slowDest, slow)
	defer slow.release()

	fastDest := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(fastDest, netID)
	fast := &fakeStream{}
	rr.registerClient(fastDest, fast)

	slowFrame := packTestFrame(t, netID, routing.BootRelayKindData, "", slowDest, sender, 2,
		bytes.Repeat([]byte("s"), 400))
	fastFrame := packTestFrame(t, netID, routing.BootRelayKindData, "", fastDest, sender, 2,
		bytes.Repeat([]byte("f"), 400))

	// Exactly the sequence one client uplink's read loop performs.
	start := time.Now()
	rr.route(slowFrame, false, sender)
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("route() blocked for %v on a wedged destination: the write still runs on the caller's goroutine", elapsed)
	}

	// Wait until the slow writer is actually parked inside Write, so the next
	// route() cannot pass just because the first frame had not started yet.
	select {
	case <-slow.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("slow destination's writer never started a write")
	}

	start = time.Now()
	rr.route(fastFrame, false, sender)
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("route() to a healthy destination took %v while another destination's write was blocked", elapsed)
	}

	deadline := time.Now().Add(2 * time.Second)
	for fast.count() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("healthy destination never received its frame while the other destination's write was blocked")
		}
		time.Sleep(time.Millisecond)
	}
	if slow.count() != 0 {
		t.Fatalf("the blocked destination must not have completed a write, got %d", slow.count())
	}

	slow.release()
	settleRelay(t, rr)
	if slow.count() != 1 {
		t.Fatalf("the blocked destination must receive its frame once released, got %d writes", slow.count())
	}
}

// TestRelayRouterDropsWhenQueueFullInsteadOfBlocking pins the backpressure
// policy: once a destination is more than bootRelayWriterMaxPendingBytes behind,
// frames are dropped and counted instead of blocking every other flow. An L2
// tunnel recovers from a dropped frame (TCP retransmits); it cannot recover from
// an uplink read loop that stops reading.
func TestRelayRouterDropsWhenQueueFullInsteadOfBlocking(t *testing.T) {
	rr, acl := newTestRelayRouter(t)
	const netID = "test-net"

	sender := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(sender, netID)

	dest := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(dest, netID)
	wedged := newGatedStream()
	rr.registerClient(dest, wedged)
	defer wedged.release()

	frame := packTestFrame(t, netID, routing.BootRelayKindData, "", dest, sender, 2,
		bytes.Repeat([]byte("x"), 1200))

	// 2000 x ~1.2 KB is ~2.4 MB, well past the per-destination byte bound. If any
	// of these route() calls blocked, this loop would crawl or hang.
	start := time.Now()
	for i := 0; i < 2000; i++ {
		rr.route(frame, false, sender)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("2000 route() calls to a wedged destination took %v: they are blocking on the write", elapsed)
	}

	if got := atomic.LoadUint64(&rr.framesDropped); got == 0 {
		t.Fatal("queue never reported a drop, but 2.4 MB was pushed at a blocked destination")
	}

	// The queue must be bounded, not have absorbed all 2000 frames.
	rr.mu.RLock()
	ps := rr.clientStreams[dest]
	rr.mu.RUnlock()
	if ps == nil {
		t.Fatal("destination stream disappeared")
	}
	if pending := ps.pendingBytes.Load(); pending > bootRelayWriterMaxPendingBytes {
		t.Fatalf("queue holds %d bytes, above the %d-byte bound", pending, bootRelayWriterMaxPendingBytes)
	}

	wedged.release()
	settleRelay(t, rr)
}

// TestRelayRouterCopiesFrameBeforeEnqueue is the aliasing guard. route() is
// called as route(buf[:n], ...) with the read loop's reusable buffer, so queuing
// that slice instead of a copy would send whatever the NEXT read put into the
// same buffer — silent payload corruption that no framing check can catch.
func TestRelayRouterCopiesFrameBeforeEnqueue(t *testing.T) {
	rr, acl := newTestRelayRouter(t)
	const netID = "test-net"

	sender := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(sender, netID)
	dest := test.RandPeerIDFatal(t)
	acl.AddAuthenticated(dest, netID)
	stream := &fakeStream{}
	rr.registerClient(dest, stream)

	// Stand-in for the read loop's buffer: route() must not retain it.
	buf := packTestFrame(t, netID, routing.BootRelayKindData, "", dest, sender, 2,
		bytes.Repeat([]byte("payload/"), 32))
	want := append([]byte(nil), buf...)

	rr.route(buf, false, sender)
	for i := range buf {
		buf[i] = 0xEE
	}

	settleRelay(t, rr)

	got := stream.written(0)
	if len(got) != len(want)+4 {
		t.Fatalf("delivered %d bytes, want %d (4-byte length prefix + frame)", len(got), len(want)+4)
	}
	if !bytes.Equal(got[4:], want) {
		t.Fatal("queued frame aliased the caller's buffer: the payload was overwritten before the write")
	}
}
