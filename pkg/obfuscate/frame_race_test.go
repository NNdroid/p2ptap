package obfuscate

import (
	"sync"
	"testing"

	"p2ptap/pkg/config"
)

// These exist to be run under -race:
//
//	go test -race -run TestFramePackerConcurrent ./pkg/obfuscate/
//
// They model the real concurrency the data path sees: several dispatch workers
// calling Pack/MaxPackedLen every frame, while a hot reload rewrites the same
// fields via UpdateConfig/SetSendAlgo.

func mkCfg(mode string) *config.ObfuscationConfig {
	return &config.ObfuscationConfig{
		Enable:             true,
		Mode:               mode,
		FixedSize:          1200,
		BlockSize:          256,
		JitterRange:        8,
		MinSize:            200,
		MaxSize:            1400,
		AutoDetectInterval: 1,
		AllowModeSwitch:    true,
	}
}

// Pack, MaxPackedLen and SetSendAlgo used to touch shared fields with no
// synchronisation at all.
func TestFramePackerConcurrentPackAndAlgoUpdate(t *testing.T) {
	fp := NewFramePackerFull(mkCfg("random"))

	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2048)
			payload := make([]byte, 300)
			for i := 0; i < 300; i++ {
				fp.SetSendAlgo(byte(i % 3))
				if _, err := fp.Pack(fp.NextSeqID(1), payload, buf); err != nil {
					return
				}
			}
		}()
	}
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2048)
			payload := make([]byte, 300)
			for i := 0; i < 300; i++ {
				n := fp.MaxPackedLen(len(payload))
				if n < 0 || n > len(buf) {
					t.Errorf("MaxPackedLen out of range: %d", n)
					return
				}
				if _, err := fp.Pack(fp.NextSeqID(1), payload, buf); err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
}

// The interesting one: UpdateConfig runs from the hot-reload goroutine and
// rewrites Mode while Pack is reading it. Mode is a string — a torn read here
// is a bad pointer, not just a wrong value.
func TestFramePackerConcurrentPackAndHotReload(t *testing.T) {
	fp := NewFramePackerFull(mkCfg("random"))

	modes := []string{"random", "fixed", "block", "dynamic", "auto"}

	var wg sync.WaitGroup
	// hot reload goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 400; i++ {
			fp.UpdateConfig(mkCfg(modes[i%len(modes)]))
		}
	}()
	// data path workers
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2048)
			payload := make([]byte, 600)
			for i := 0; i < 400; i++ {
				_ = fp.MaxPackedLen(len(payload))
				if _, err := fp.Pack(fp.NextSeqID(1), payload, buf); err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
}

// Algo()/Pack must observe algo updates atomically, never a partially written
// byte (it is a single byte, so the point is proving no race is reported).
func TestFramePackerAlgoVisibleAcrossGoroutines(t *testing.T) {
	fp := NewFramePackerFull(mkCfg("random"))
	_ = fp // keep constructor result used

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			fp.SetSendAlgo(ObfAlgoAESGCM)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			if got := fp.Algo(); got != ObfAlgoAESGCM && got != ObfAlgoChaCha20 && got != ObfAlgoNone {
				t.Errorf("implausible algo byte %d", got)
				return
			}
		}
	}()
	wg.Wait()
}
