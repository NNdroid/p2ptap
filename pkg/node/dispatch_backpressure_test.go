package node

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestDispatchBackpressureElapsedTimerKeepsFreeSlot(t *testing.T) {
	for i := 0; i < 1000; i++ {
		n := &Node{dispatchCh: make(chan dispatchTask, 1)}
		expired := make(chan time.Time, 1)
		expired <- time.Now()
		if !n.enqueueDispatchWithin(dispatchTask{}, expired) || len(n.dispatchCh) != 1 {
			t.Fatal("elapsed timer discarded an available queue slot")
		}
	}
}

func TestDispatchBackpressureAbsorbsShortStall(t *testing.T) {
	n := &Node{dispatchCh: make(chan dispatchTask, 1)}
	n.dispatchCh <- dispatchTask{}
	done := make(chan struct{})
	go func() {
		time.Sleep(10 * time.Millisecond) // exceeds the old 5ms grace
		<-n.dispatchCh
		close(done)
	}()
	n.dispatchNonblocking(dispatchTask{data: []byte("pending")})
	<-done
	if atomic.LoadUint64(&n.dispatchDropCount) != 0 || len(n.dispatchCh) != 1 {
		t.Fatal("short healthy-worker stall lost a frame")
	}
	if string((<-n.dispatchCh).data) != "pending" {
		t.Fatal("wrong task enqueued after stall")
	}
}

func TestDispatchBackpressureSustainedFullQueueRemainsBounded(t *testing.T) {
	n := &Node{dispatchCh: make(chan dispatchTask, 1)}
	n.dispatchCh <- dispatchTask{data: []byte("first")}
	expired := make(chan time.Time, 1)
	expired <- time.Now()
	if n.enqueueDispatchWithin(dispatchTask{data: []byte("second")}, expired) {
		t.Fatal("full queue accepted beyond its capacity")
	}
	start := time.Now()
	n.dispatchNonblocking(dispatchTask{data: acquireFrameBuf(100), owned: true})
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatal("full queue blocked without bound")
	}
	if atomic.LoadUint64(&n.dispatchDropCount) != 1 || len(n.dispatchCh) != 1 || string((<-n.dispatchCh).data) != "first" {
		t.Fatal("full queue broke drop or ownership accounting")
	}
}
