package node

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/tap"
)

// frame returns a TAP-payload-sized byte slice for a content tag. A real
// Ethernet frame is >= ethernetHeaderLen (14); validateTapWrite rejects runt
// frames, so the test payloads are padded to a plausible size while keeping the
// tag as a prefix so delivery order is assertable.
func frame(tag string) []byte {
	for len(tag) < ethernetHeaderLen+6 {
		tag += "."
	}
	return []byte(tag)
}

// reorderHarness is a minimal Node + drain that captures the order in which TAP
// write jobs are delivered to the tapWriteCh. The drain mirrors the real TAP
// writer loop: it reads a job, finishes it (releasing the pooled buffer), and
// records the payload. Because enqueueTapWritePrepared enqueues synchronously,
// the channel order equals the in-order delivery order we want to assert.
type reorderHarness struct {
	t    *testing.T
	n    *Node
	fp   *obfuscate.FramePacker
	mu   sync.Mutex
	got  []string
	want int // number of deliveries expected; set BEFORE pushing frames
	done chan struct{}
}

func newReorderHarness(t *testing.T, maxWindow int, releaseDelay time.Duration) *reorderHarness {
	t.Helper()
	a, _ := tap.NewMemTAPPair("reorder-a", "reorder-b")
	h := &reorderHarness{
		t:    t,
		n:    &Node{TAP: a, tapWriteCh: make(chan tapWriteJob, 4096)},
		fp:   obfuscate.NewFramePackerFull(nil),
		done: make(chan struct{}),
	}
	h.fp.SetSourceIdentity("reorder-peer")
	h.n.rxReorderEnabled.Store(true)
	h.n.rxReorderWindow = maxWindow
	h.n.rxReorderDelay = releaseDelay
	go h.drain()
	return h
}

// expect declares how many frames will be delivered; must be called before the
// first push so the drain knows when to signal completion.
func (h *reorderHarness) expect(n int) {
	h.mu.Lock()
	h.want = n
	h.mu.Unlock()
}

func (h *reorderHarness) drain() {
	for job := range h.n.tapWriteCh {
		copied := string(job.data)
		h.n.finishTapWriteJob(job, len(job.data), nil)
		h.mu.Lock()
		h.got = append(h.got, copied)
		if h.want > 0 && len(h.got) >= h.want {
			select {
			case <-h.done:
			default:
				close(h.done)
			}
		}
		h.mu.Unlock()
	}
}

func (h *reorderHarness) seqID(epoch, counter uint64) uint64 {
	return h.fp.MakeSeqID(counter, epoch)
}

func (h *reorderHarness) waitDelivered() {
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		h.t.Fatal("timed out waiting for reordered TAP deliveries")
	}
}

func (h *reorderHarness) gotFrames() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.got))
	copy(out, h.got)
	return out
}

func TestRxReorderDeliversInOrder(t *testing.T) {
	h := newReorderHarness(t, 64, 200*time.Millisecond)
	p := peer.ID("rx-reorder-in-order")
	h.expect(4)

	// Counters arrive strictly in order: every frame delivers immediately.
	for c := uint64(100); c < 104; c++ {
		h.n.rxReorderFor(p).push(h.seqID(1, c), []tapWriteJob{{data: frame(fmt.Sprintf("f%d", c))}})
	}
	h.waitDelivered()
	got := h.gotFrames()
	if len(got) != 4 {
		t.Fatalf("delivered %d frames, want 4", len(got))
	}
	for i, f := range got {
		if want := string(frame(fmt.Sprintf("f%d", 100+i))); f != want {
			t.Fatalf("delivery[%d] = %q, want %q", i, f, want)
		}
	}
}

func TestRxReorderGapFillsInOrder(t *testing.T) {
	h := newReorderHarness(t, 64, 500*time.Millisecond)
	p := peer.ID("rx-reorder-gap")
	h.expect(3)

	// 10 delivers; 12 is buffered behind the missing 11; 11 arrives and flushes
	// the buffered tail in order.
	h.n.rxReorderFor(p).push(h.seqID(1, 10), []tapWriteJob{{data: frame("f10")}})
	h.n.rxReorderFor(p).push(h.seqID(1, 12), []tapWriteJob{{data: frame("f12")}})
	h.n.rxReorderFor(p).push(h.seqID(1, 11), []tapWriteJob{{data: frame("f11")}})
	h.waitDelivered()

	got := h.gotFrames()
	if len(got) != 3 {
		t.Fatalf("delivered %d frames, want 3: %v", len(got), got)
	}
	for i, want := range []string{"f10", "f11", "f12"} {
		if got[i] != string(frame(want)) {
			t.Fatalf("delivery[%d] = %q, want %q (order must be preserved)", i, got[i], frame(want))
		}
	}
}

func TestRxReorderForceReleaseOnDelay(t *testing.T) {
	h := newReorderHarness(t, 64, 50*time.Millisecond)
	p := peer.ID("rx-reorder-delay")
	h.expect(3)

	// 10 delivers; 12 is buffered behind the (never arriving) 11; a later 13
	// triggers the delay-based force release, flushing the buffered tail.
	h.n.rxReorderFor(p).push(h.seqID(1, 10), []tapWriteJob{{data: frame("f10")}})
	h.n.rxReorderFor(p).push(h.seqID(1, 12), []tapWriteJob{{data: frame("f12")}})
	time.Sleep(60 * time.Millisecond)
	h.n.rxReorderFor(p).push(h.seqID(1, 13), []tapWriteJob{{data: frame("f13")}})
	h.waitDelivered()

	got := h.gotFrames()
	if len(got) != 3 {
		t.Fatalf("delivered %d frames, want 3: %v", len(got), got)
	}
	// The hole at 11 is treated as lost; 12 and 13 are flushed in counter order.
	if got[0] != string(frame("f10")) || got[1] != string(frame("f12")) || got[2] != string(frame("f13")) {
		t.Fatalf("delivery = %v, want [f10 f12 f13]", got)
	}
}

func TestRxReorderWindowOverflowFastForwards(t *testing.T) {
	h := newReorderHarness(t, 4, 500*time.Millisecond)
	p := peer.ID("rx-reorder-window")
	h.expect(5)

	// 10 delivers; 12,13,14 buffer behind the missing 11 (window has room).
	// 15 is 5 counters past next(11): beyond maxWindow, so the stale tail is
	// flushed and the queue re-anchors at 16.
	h.n.rxReorderFor(p).push(h.seqID(1, 10), []tapWriteJob{{data: frame("f10")}})
	for _, c := range []uint64{12, 13, 14} {
		h.n.rxReorderFor(p).push(h.seqID(1, c), []tapWriteJob{{data: frame(fmt.Sprintf("f%d", c))}})
	}
	h.n.rxReorderFor(p).push(h.seqID(1, 15), []tapWriteJob{{data: frame("f15")}})
	h.waitDelivered()

	got := h.gotFrames()
	if len(got) != 5 {
		t.Fatalf("delivered %d frames, want 5: %v", len(got), got)
	}
	// The lost hole at 11 is skipped; the buffered tail flushes before the
	// fast-forwarded frame.
	want := []string{"f10", "f12", "f13", "f14", "f15"}
	for i, w := range want {
		if got[i] != string(frame(w)) {
			t.Fatalf("delivery[%d] = %q, want %q", i, got[i], frame(w))
		}
	}
}

func TestRxReorderDropsLateFrameAfterFastForward(t *testing.T) {
	h := newReorderHarness(t, 4, 500*time.Millisecond)
	p := peer.ID("rx-reorder-late")
	h.expect(2)

	h.n.rxReorderFor(p).push(h.seqID(1, 10), []tapWriteJob{{data: frame("f10")}})
	// 15 is beyond the window: fast-forward, next re-anchors at 16.
	h.n.rxReorderFor(p).push(h.seqID(1, 15), []tapWriteJob{{data: frame("f15")}})
	h.waitDelivered()
	// A frame from before the fast-forward is now too late: dropped, not delivered.
	h.n.rxReorderFor(p).push(h.seqID(1, 12), []tapWriteJob{{data: frame("f12")}})
	time.Sleep(20 * time.Millisecond)
	if got := h.gotFrames(); len(got) != 2 {
		t.Fatalf("delivered %d frames, want 2 (late frame must be dropped): %v", len(got), got)
	}
}

func TestRxReorderEpochChangeResetsWindow(t *testing.T) {
	h := newReorderHarness(t, 64, 500*time.Millisecond)
	p := peer.ID("rx-reorder-epoch")
	h.expect(3)

	// Epoch 1: 10 delivers, 12 buffers behind missing 11.
	h.n.rxReorderFor(p).push(h.seqID(1, 10), []tapWriteJob{{data: frame("e1-f10")}})
	h.n.rxReorderFor(p).push(h.seqID(1, 12), []tapWriteJob{{data: frame("e1-f12")}})
	// Epoch 2 starts at a lower counter: the buffered tail belongs to the old
	// session and must flush before re-anchoring on the new epoch.
	h.n.rxReorderFor(p).push(h.seqID(2, 5), []tapWriteJob{{data: frame("e2-f5")}})
	h.waitDelivered()

	got := h.gotFrames()
	if len(got) != 3 {
		t.Fatalf("delivered %d frames, want 3: %v", len(got), got)
	}
	if got[0] != string(frame("e1-f10")) || got[1] != string(frame("e1-f12")) || got[2] != string(frame("e2-f5")) {
		t.Fatalf("delivery = %v, want [e1-f10 e1-f12 e2-f5]", got)
	}
}

// TestRxReorderBatchDeliversTogether verifies that a coalesced batch (several
// sub-frames sharing one seqID) is held and released as one logical frame: all
// sub-frames reach TAP consecutively and in order, ahead of the next counter.
func TestRxReorderBatchDeliversTogether(t *testing.T) {
	h := newReorderHarness(t, 64, 500*time.Millisecond)
	p := peer.ID("rx-reorder-batch")
	h.expect(5)

	// Counter 10 is a batch of three sub-frames; 11 and 12 are plain frames.
	batch := []tapWriteJob{
		{data: frame("b10-a")},
		{data: frame("b10-b")},
		{data: frame("b10-c")},
	}
	h.n.rxReorderFor(p).push(h.seqID(1, 10), batch)
	h.n.rxReorderFor(p).push(h.seqID(1, 11), []tapWriteJob{{data: frame("f11")}})
	h.n.rxReorderFor(p).push(h.seqID(1, 12), []tapWriteJob{{data: frame("f12")}})
	h.waitDelivered()

	got := h.gotFrames()
	if len(got) != 5 {
		t.Fatalf("delivered %d frames, want 5: %v", len(got), got)
	}
	want := []string{"b10-a", "b10-b", "b10-c", "f11", "f12"}
	for i, w := range want {
		if got[i] != string(frame(w)) {
			t.Fatalf("delivery[%d] = %q, want %q", i, got[i], frame(w))
		}
	}
}

// TestRxReorderBatchHeldBehindGap verifies a batch buffered behind a missing
// counter is released together (in order) once the gap fills.
func TestRxReorderBatchHeldBehindGap(t *testing.T) {
	h := newReorderHarness(t, 64, 500*time.Millisecond)
	p := peer.ID("rx-reorder-batch-gap")
	h.expect(4)

	// 10 delivers; the batch at 12 is buffered behind the missing 11.
	h.n.rxReorderFor(p).push(h.seqID(1, 10), []tapWriteJob{{data: frame("f10")}})
	batch := []tapWriteJob{
		{data: frame("b12-a")},
		{data: frame("b12-b")},
	}
	h.n.rxReorderFor(p).push(h.seqID(1, 12), batch)
	// 11 arrives: the batch at 12 flushes together, in order.
	h.n.rxReorderFor(p).push(h.seqID(1, 11), []tapWriteJob{{data: frame("f11")}})
	h.waitDelivered()

	got := h.gotFrames()
	if len(got) != 4 {
		t.Fatalf("delivered %d frames, want 4: %v", len(got), got)
	}
	want := []string{"f10", "f11", "b12-a", "b12-b"}
	for i, w := range want {
		if got[i] != string(frame(w)) {
			t.Fatalf("delivery[%d] = %q, want %q", i, got[i], frame(w))
		}
	}
}

func TestRxReorderDisabledIsPassthrough(t *testing.T) {
	h := newReorderHarness(t, 64, 200*time.Millisecond)
	h.n.rxReorderEnabled.Store(false)
	p := peer.ID("rx-reorder-bypass")
	h.expect(2)

	// With reorder disabled, out-of-order arrival goes straight to TAP in
	// arrival order (no buffering), matching best_path semantics.
	h.n.reorderTapWrite(p, h.seqID(1, 20), frame("f20"), false, "", "")
	h.n.reorderTapWrite(p, h.seqID(1, 19), frame("f19"), false, "", "")
	h.waitDelivered()

	got := h.gotFrames()
	if len(got) != 2 || got[0] != string(frame("f20")) || got[1] != string(frame("f19")) {
		t.Fatalf("passthrough delivery = %v, want [f20 f19] (arrival order)", got)
	}
}
