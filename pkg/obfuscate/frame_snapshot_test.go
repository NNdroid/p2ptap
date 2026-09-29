package obfuscate

import (
	"testing"
	"time"

	"p2ptap/pkg/config"
)

func TestFramePackerSnapshotReadDoesNotWaitForConfigMutex(t *testing.T) {
	fp := NewFramePackerFull(&config.ObfuscationConfig{
		Enable:    true,
		Mode:      "fixed",
		FixedSize: 1500,
	})

	// Simulate a slow config writer. Data-plane readers must use the already
	// published immutable snapshot instead of waiting behind fp.mu.
	fp.mu.Lock()
	done := make(chan int, 1)
	go func() {
		done <- fp.MaxPackedLen(100)
	}()

	select {
	case got := <-done:
		fp.mu.Unlock()
		if got != 1500 {
			t.Fatalf("MaxPackedLen while config mutex held = %d, want 1500", got)
		}
	case <-time.After(500 * time.Millisecond):
		fp.mu.Unlock()
		t.Fatal("data-plane packer snapshot blocked behind config mutex")
	}
}

func TestFramePackerUpdateConfigPublishesSnapshot(t *testing.T) {
	fp := NewFramePackerFull(&config.ObfuscationConfig{
		Enable:    true,
		Mode:      "fixed",
		FixedSize: 1024,
	})
	if got := fp.MaxPackedLen(100); got != 1024 {
		t.Fatalf("initial MaxPackedLen = %d, want 1024", got)
	}

	fp.UpdateConfig(&config.ObfuscationConfig{
		Enable:    true,
		Mode:      "fixed",
		FixedSize: 2048,
	})
	if got := fp.MaxPackedLen(100); got != 2048 {
		t.Fatalf("MaxPackedLen after hot reload = %d, want 2048", got)
	}
}

func BenchmarkFramePackerSnapshotParallel(b *testing.B) {
	fp := NewFramePackerFull(&config.ObfuscationConfig{
		Enable:    true,
		Mode:      "fixed",
		FixedSize: 1500,
	})
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = fp.MaxPackedLen(1500)
		}
	})
}
