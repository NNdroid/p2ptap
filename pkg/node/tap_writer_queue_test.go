package node

import (
	"bytes"
	"context"
	"testing"
	"time"

	"p2ptap/pkg/config"
	"p2ptap/pkg/tap"
)

// These tests exercise the two ownership/backpressure invariants that let the
// receive path hand frames to the dedicated writer without aliasing scratch
// buffers or converting a full queue into packet loss.
func testEthernetFrame(fill byte) []byte {
	frame := bytes.Repeat([]byte{fill}, 64)
	copy(frame[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	frame[12], frame[13] = 0x08, 0x00
	return frame
}

func TestEnqueueTapWriteOwnsCallerBuffer(t *testing.T) {
	a, b := tap.NewMemTAPPair("writer-a", "writer-b")
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := config.DefaultConfig()
	n := &Node{
		TAP:        a,
		Config:     cfg,
		ctx:        ctx,
		tapWriteCh: make(chan tapWriteJob, 4),
	}

	frame := testEthernetFrame(0x5a)
	want := append([]byte(nil), frame...)
	if err := n.enqueueTapWrite(frame, false, ""); err != nil {
		t.Fatalf("enqueueTapWrite: %v", err)
	}
	// Simulate the stream reader immediately reusing its scratch buffer before
	// the dedicated writer gets CPU time.
	for i := range frame {
		frame[i] = 0xee
	}

	n.wg.Add(1)
	go n.tapWriteLoop()

	got := make([]byte, len(want))
	readDone := make(chan error, 1)
	go func() {
		_, err := b.Read(got)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("peer TAP read: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("dedicated TAP writer did not drain queued frame")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("queued TAP frame aliased caller buffer: got %x want %x", got, want)
	}

	cancel()
	n.wg.Wait()
}

func TestEnqueueTapWriteFullQueueFallsBackSynchronously(t *testing.T) {
	a, b := tap.NewMemTAPPair("fallback-a", "fallback-b")
	defer a.Close()
	defer b.Close()
	cfg := config.DefaultConfig()
	n := &Node{
		TAP:        a,
		Config:     cfg,
		tapWriteCh: make(chan tapWriteJob, 1),
	}

	first := testEthernetFrame(0x11)
	second := testEthernetFrame(0x22)
	if err := n.enqueueTapWrite(first, false, ""); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	// No writer is running, so the queue is now full. The second frame must
	// synchronously hit the TAP rather than being dropped.
	if err := n.enqueueTapWrite(second, false, ""); err != nil {
		t.Fatalf("full-queue fallback: %v", err)
	}

	got := make([]byte, len(second))
	if nr, err := b.Read(got); err != nil || nr != len(second) {
		t.Fatalf("peer TAP read = (%d, %v), want (%d, nil)", nr, err, len(second))
	}
	if !bytes.Equal(got, second) {
		t.Fatal("queue-full fallback did not synchronously deliver second frame")
	}

	// Release the intentionally undrained first queued buffer.
	job := <-n.tapWriteCh
	releaseFrameBuf(job.data)
}
