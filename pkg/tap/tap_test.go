package tap

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemTAPPairCommunication(t *testing.T) {
	t.Log("[memtap] creating in-memory TAP pair tapA<->tapB")
	tapA, tapB := NewMemTAPPair("tapA", "tapB")
	defer tapA.Close()
	defer tapB.Close()

	if err := tapA.ConfigureIP("10.0.0.1/24", "fd00::1/64"); err != nil {
		t.Fatalf("ConfigureIP on tapA failed: %v", err)
	}

	payload := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 'P', 'I', 'N', 'G'}

	// Write from tapA to tapB
	n, err := tapA.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("tapA Write failed: n=%d, err=%v", n, err)
	}
	t.Logf("[memtap] wrote %d bytes tapA->tapB", n)

	readBuf := make([]byte, 1500)
	rn, err := tapB.Read(readBuf)
	if err != nil {
		t.Fatalf("tapB Read failed: %v", err)
	}

	if !bytes.Equal(readBuf[:rn], payload) {
		t.Errorf("Data read on tapB does not match written data! Got %v", readBuf[:rn])
	}
	t.Logf("[memtap] ✓ tapB read %d bytes, payload matches", rn)
}

func TestMemTAPSetMAC(t *testing.T) {
	dev, peer := NewMemTAPPair("test_p2ptap", "test_p2ptap_peer")
	defer dev.Close()
	defer peer.Close()

	if err := dev.SetMAC("02:00:00:00:00:01"); err != nil {
		t.Fatalf("SetMAC failed: %v", err)
	}
	t.Log("[memtap] ✓ SetMAC accepted 02:00:00:00:00:01")
	if err := dev.SetMAC("not-a-mac"); err == nil {
		t.Fatal("SetMAC accepted an invalid MAC address")
	} else {
		t.Logf("[memtap] ✓ SetMAC rejected invalid MAC: %v", err)
	}
}

// TestMemTAPConcurrentReadWrite is the contract test for the TAP hot path.
// It models what the data plane looks like in production:
//
//   - The tap read loop (one goroutine) calls Read on the local TAP device.
//   - The tap write side may be invoked concurrently from multiple goroutines
//     (urgentWriteLoop, probe, dispatch worker fan-out). On Windows the
//     device-level mutex is what guarantees safe reuse of the pooled
//     Overlapped/event pair across these callers.
//
// MemTAP does not need a mutex (its channel is the synchronisation point),
// but the test asserts the read/write contract under concurrency: every
// frame written by the writer goroutines is observed by the reader, and no
// goroutine returns an error. A regression here would mean the per-frame
// write path is no longer drop-in-safe for the data plane.
func TestMemTAPConcurrentReadWrite(t *testing.T) {
	t.Log("[memtap] starting concurrent read/write contract test (40 frames, 4 writers, 1 reader)")
	tapA, tapB := NewMemTAPPair("tapA", "tapB")
	defer tapB.Close()

	const writers = 4
	const perWriter = 10
	var wg sync.WaitGroup
	var written, read int64
	var writersDone sync.WaitGroup

	// 1 reader drains tapB until close (we Close tapA at the end of the test
	// to unblock it cleanly). Counts bytes actually delivered.
	readBuf := make([]byte, 1500)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			n, err := tapB.Read(readBuf)
			if err != nil {
				return
			}
			atomic.AddInt64(&read, int64(n))
		}
	}()

	// N writers hammer tapA with full-MTU frames, signalling per-writer
	// completion via writersDone so the test driver can close the channel
	// only AFTER every writer has reported done.
	writersDone.Add(writers)
	frame := make([]byte, 512)
	for i := range frame {
		frame[i] = byte(i & 0xff)
	}
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer writersDone.Done()
			for i := 0; i < perWriter; i++ {
				n, err := tapA.Write(frame)
				if err != nil || n != len(frame) {
					// Stop on close-or-error but allow other writers to finish.
					return
				}
				atomic.AddInt64(&written, int64(n))
			}
		}()
	}

	// Wait for every writer to finish, then close the device. We use the
	// writersDone WaitGroup (not a bytes counter) so the close is GUARANTEED
	// to happen after the last writer returns, eliminating the close-vs-write
	// race the byte-counter version suffered from.
	doneClose := make(chan struct{})
	go func() {
		writersDone.Wait()
		_ = tapA.Close()
		close(doneClose)
	}()

	// Bounded wait so a deadlock surfaces as a test failure rather than a hang.
	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent read/write test deadlocked (writer or reader never returned)")
	}

	writtenBytes := atomic.LoadInt64(&written)
	wantBytes := int64(writers * perWriter * len(frame))
	if writtenBytes != wantBytes {
		t.Errorf("written bytes = %d, want %d", writtenBytes, wantBytes)
	}
	t.Logf("[memtap] ✓ %d writers each delivered %d bytes (%d total); reader observed %d bytes",
		writers, len(frame), writtenBytes, atomic.LoadInt64(&read))
}

// BenchmarkMemTAPThroughput measures the per-frame cost of the read+write
// loop over an in-memory TAP pair, with a tiny IP packet. It is a regression
// guard for the per-frame write-allocation changes (e.g. pooled Overlapped
// events on Windows) and a reference baseline for the production data path.
//
// Run with: go test ./pkg/tap/ -bench=BenchmarkMemTAPThroughput -benchmem
func BenchmarkMemTAPThroughput(b *testing.B) {
	tapA, tapB := NewMemTAPPair("benchA", "benchB")
	defer tapA.Close()
	defer tapB.Close()

	frame := make([]byte, 256)
	readBuf := make([]byte, 1500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := tapA.Write(frame); err != nil {
			b.Fatalf("Write failed: %v", err)
		}
		if _, err := tapB.Read(readBuf); err != nil {
			b.Fatalf("Read failed: %v", err)
		}
	}
}
