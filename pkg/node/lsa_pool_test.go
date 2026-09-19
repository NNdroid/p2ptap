package node

import (
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// parkedStream mimics the real deadlock trigger: an owner goroutine parked in
// a stream operation holding the per-peer mutex, for which ONLY a cross-goroutine
// Close wakes it (the libp2p stream contract). Invalidate must not sit on
// m.Lock() forever — that exact hang wedged Android's P2PTap.stop() (holding
// the package mutex) inside Node.Close's InvalidateAll whenever host.Close
// timed out leaving a relay-ctrl tunnel stream alive, and the UI froze on
// "Stopping…" permanently.

type parkedStream struct {
	network.Stream // only Close is exercised; other methods would nil-panic on purpose
	closeCh        chan struct{}
	closeOnce      sync.Once
}

func (s *parkedStream) Close() error {
	s.closeOnce.Do(func() { close(s.closeCh) })
	return nil
}

func newTestStreamPool() *lsaStreamPool {
	return &lsaStreamPool{
		streams:  make(map[peer.ID]network.Stream),
		writeMu:  make(map[peer.ID]*sync.Mutex),
		protocol: protocol.ID("/p2ptap/test/1.0.0"),
	}
}

func TestInvalidateSelfHealsParkedStreamOwner(t *testing.T) {
	pool := newTestStreamPool()
	target := peer.ID("parked-owner-peer")
	m := &sync.Mutex{}
	pool.writeMu[target] = m
	st := &parkedStream{closeCh: make(chan struct{})}
	pool.streams[target] = st

	m.Lock()
	ownerDone := make(chan struct{})
	go func() {
		defer func() { m.Unlock(); close(ownerDone) }()
		<-st.closeCh // parked "inside ReadFrame", woken only by Close
	}()
	time.Sleep(50 * time.Millisecond) // owner is settled into its park

	start := time.Now()
	pool.Invalidate(target)
	elapsed := time.Since(start)

	if elapsed > peerInvalidateWaitTimeout+time.Second {
		t.Fatalf("Invalidate blocked %v — force-close did not self-heal the parked owner", elapsed)
	}
	select {
	case <-ownerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("forced Close never woke the parked owner — stream Close contract violated")
	}

	pool.mu.Lock()
	_, still := pool.streams[target]
	pool.mu.Unlock()
	if still {
		t.Fatal("parked stream must be removed from the pool")
	}
}

func TestInvalidateBoundedAgainstStuckOwner(t *testing.T) {
	// Adversarial worst case: an owner that never releases m even after the
	// forced Close. Invalidate MUST still return in bounded time — that is the
	// guarantee Stop()/Node.Close can never hang again.
	pool := newTestStreamPool()
	target := peer.ID("stuck-owner-peer")
	m := &sync.Mutex{}
	pool.writeMu[target] = m
	st := &parkedStream{closeCh: make(chan struct{})}
	pool.streams[target] = st

	m.Lock()
	stop := make(chan struct{})
	go func() { <-stop; m.Unlock() }()
	defer close(stop)

	done := make(chan time.Duration, 1)
	go func() {
		s := time.Now()
		pool.Invalidate(target)
		done <- time.Since(s)
	}()
	maxWait := peerInvalidateWaitTimeout + 3*time.Second
	select {
	case d := <-done:
		if d > peerInvalidateWaitTimeout+time.Second {
			t.Fatalf("Invalidate exceeded its documented bound: %v", d)
		}
	case <-time.After(maxWait):
		t.Fatal("Invalidate never returned against a stuck owner — Stop() would hang forever")
	}
}
