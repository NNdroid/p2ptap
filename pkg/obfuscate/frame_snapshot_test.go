package obfuscate

import (
	"testing"
	"time"

	"p2ptap/pkg/config"
)

func TestFramePackerSnapshotReadDoesNotWaitForConfigMutex(t *testing.T) {
	fp := NewFramePackerFull(&config.ObfuscationConfig{
		Enable:       true,
		PaddingRules: "0 -> 1500-1500",
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
		if want := HeaderLen + 1500; got != want {
			t.Fatalf("MaxPackedLen while config mutex held = %d, want %d", got, want)
		}
	case <-time.After(500 * time.Millisecond):
		fp.mu.Unlock()
		t.Fatal("data-plane packer snapshot blocked behind config mutex")
	}
}

func TestFramePackerUpdateConfigPublishesSnapshot(t *testing.T) {
	fp := NewFramePackerFull(&config.ObfuscationConfig{
		Enable:       true,
		PaddingRules: "0 -> 1024-1024",
	})
	if got := fp.MaxPackedLen(100); got != HeaderLen+1024 {
		t.Fatalf("initial MaxPackedLen = %d, want %d", got, HeaderLen+1024)
	}

	fp.UpdateConfig(&config.ObfuscationConfig{
		Enable:       true,
		PaddingRules: "0 -> 2048-2048",
	})
	if got := fp.MaxPackedLen(100); got != HeaderLen+2048 {
		t.Fatalf("MaxPackedLen after hot reload = %d, want %d", got, HeaderLen+2048)
	}
}

func BenchmarkFramePackerSnapshotParallel(b *testing.B) {
	fp := NewFramePackerFull(&config.ObfuscationConfig{
		Enable:       true,
		PaddingRules: "0 -> 1500-1500",
	})
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = fp.MaxPackedLen(1500)
		}
	})
}
