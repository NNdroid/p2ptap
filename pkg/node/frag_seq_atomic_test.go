package node

import (
	"sync"
	"testing"
	"time"
)

func TestFragNextOrigSeqDoesNotWaitForReassemblyLock(t *testing.T) {
	f := newFragReassembler()

	// Simulate RX reassembly holding its state mutex. TX sequence allocation is
	// independent state and must still make progress; the old implementation
	// used this same mutex and therefore stalled full-duplex fragmented traffic.
	f.mu.Lock()
	done := make(chan uint32, 1)
	go func() {
		done <- f.nextOrigSeq()
	}()

	select {
	case seq := <-done:
		if seq != 1 {
			f.mu.Unlock()
			t.Fatalf("first fragment sequence = %d, want 1", seq)
		}
		f.mu.Unlock()
	case <-time.After(500 * time.Millisecond):
		f.mu.Unlock()
		t.Fatal("TX fragment sequence allocation blocked behind RX reassembly mutex")
	}
}

func TestFragNextOrigSeqConcurrentUnique(t *testing.T) {
	const (
		workers = 64
		per     = 100
		total   = workers * per
	)

	f := newFragReassembler()
	results := make(chan uint32, total)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for range per {
				results <- f.nextOrigSeq()
			}
		}()
	}
	wg.Wait()
	close(results)

	seen := make([]bool, total+1)
	for seq := range results {
		if seq == 0 || seq > total {
			t.Fatalf("sequence %d outside expected range [1,%d]", seq, total)
		}
		if seen[seq] {
			t.Fatalf("duplicate fragment sequence %d", seq)
		}
		seen[seq] = true
	}
	for seq := 1; seq <= total; seq++ {
		if !seen[seq] {
			t.Fatalf("missing fragment sequence %d", seq)
		}
	}
}

func BenchmarkFragNextOrigSeqParallel(b *testing.B) {
	f := newFragReassembler()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = f.nextOrigSeq()
		}
	})
}
