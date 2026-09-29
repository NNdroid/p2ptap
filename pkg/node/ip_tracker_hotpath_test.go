package node

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
)

func makeIPv4TrackerFrame() []byte {
	frame := make([]byte, 14+20)
	copy(frame[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	frame[14] = 0x45
	frame[23] = 6
	copy(frame[26:30], []byte{10, 0, 0, 1})
	copy(frame[30:34], []byte{10, 0, 0, 2})
	return frame
}

func TestIPTrackerExtractAndRecordAccountsBothEndpoints(t *testing.T) {
	tr := NewIPTrafficTracker()
	frame := makeIPv4TrackerFrame()
	tr.ExtractAndRecord(frame, true)

	src := tr.getOrCreate("10.0.0.1")
	dst := tr.getOrCreate("10.0.0.2")
	if got := atomic.LoadUint64(&src.txPackets); got != 1 {
		t.Fatalf("source tx packets = %d, want 1", got)
	}
	if got := atomic.LoadUint64(&dst.txPackets); got != 1 {
		t.Fatalf("destination tx packets = %d, want 1", got)
	}
	if got := src.macString(); got != "02:00:00:00:00:01" {
		t.Fatalf("source MAC = %q, want 02:00:00:00:00:01", got)
	}
	if got := dst.macString(); got != "02:00:00:00:00:02" {
		t.Fatalf("destination MAC = %q, want 02:00:00:00:00:02", got)
	}
}

func TestIPTrackerConcurrentMACPublication(t *testing.T) {
	tr := NewIPTrafficTracker()
	const workers = 32
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		i := i
		go func() {
			defer wg.Done()
			mac := "02:00:00:00:00:01"
			if i&1 != 0 {
				mac = "02:00:00:00:00:02"
			}
			for j := 0; j < 200; j++ {
				tr.recordTxAt("10.0.0.1", 64, mac, 1234)
			}
		}()
	}
	wg.Wait()

	item := tr.getOrCreate("10.0.0.1")
	if got := atomic.LoadUint64(&item.txPackets); got != workers*200 {
		t.Fatalf("tx packets = %d, want %d", got, workers*200)
	}
	if mac := item.macString(); mac != "02:00:00:00:00:01" && mac != "02:00:00:00:00:02" {
		t.Fatalf("unexpected published MAC %q", mac)
	}
}

func BenchmarkIPTrackerExtractAndRecordParallel(b *testing.B) {
	tr := NewIPTrafficTracker()
	frame := makeIPv4TrackerFrame()
	tr.ExtractAndRecord(frame, true)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tr.ExtractAndRecord(frame, true)
		}
	})
}
