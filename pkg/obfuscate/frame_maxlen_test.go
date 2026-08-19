package obfuscate

import (
	"bytes"
	"testing"
)

// TestMaxPackedLenNeverUnderAllocates is a safety net for the per-frame relay
// allocation: MaxPackedLen must return an upper bound that Pack never exceeds,
// for every obfuscation mode and a wide range of payload sizes. If this ever
// fails, Pack would return ErrBufferTooSmall and blackhole relayed traffic.
func TestMaxPackedLenNeverUnderAllocates(t *testing.T) {
	modes := []string{"none", "fixed", "block", "dynamic", "random", "auto"}
	payloadSizes := []int{0, 1, 60, 200, 1000, 1400, 4000, 65000}

	for _, mode := range modes {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			fp := &FramePacker{
				Enable:      true,
				Mode:        mode,
				FixedSize:   1500,
				BlockSize:   256,
				JitterRange: 50,
				MinSize:     512,
				MaxSize:     1500,
			}
			for _, pl := range payloadSizes {
				payload := bytes.Repeat([]byte{0xAB}, pl)
				buf := make([]byte, fp.MaxPackedLen(pl))
				n, err := fp.Pack(1, payload, buf)
				if err != nil {
					t.Fatalf("mode=%s payload=%d: Pack returned error %v (buffer size %d)", mode, pl, err, len(buf))
				}
				if n > len(buf) {
					t.Fatalf("mode=%s payload=%d: Pack wrote %d bytes into a %d-byte buffer", mode, pl, n, len(buf))
				}
				// Invariant: actual size never exceeds the advertised upper bound.
				if n > fp.MaxPackedLen(pl) {
					t.Fatalf("mode=%s payload=%d: Pack size %d > MaxPackedLen %d", mode, pl, n, fp.MaxPackedLen(pl))
				}
			}
		})
	}
}

// TestMaxPackedLenShrinksSlack verifies the new bound is materially smaller than
// the old blanket +4096 idiom for realistic relay envelopes, i.e. that the
// optimization actually removes per-frame heap waste.
func TestMaxPackedLenShrinksSlack(t *testing.T) {
	fp := &FramePacker{
		Enable:      true,
		Mode:        "random",
		FixedSize:   1500,
		BlockSize:   256,
		JitterRange: 50,
		MinSize:     512,
		MaxSize:     1500,
	}
	// A typical relayed inner frame is a full-MTU overlay frame (~1400 bytes).
	pl := 1400
	oldWay := pl + HeaderLen + 4096
	newWay := fp.MaxPackedLen(pl)
	if newWay >= oldWay {
		t.Fatalf("expected MaxPackedLen (%d) to be well below the old +4096 slack (%d)", newWay, oldWay)
	}
	// The new bound should be on the order of the obfuscated envelope, not 4KB fatter.
	if newWay > pl+HeaderLen+200 {
		t.Fatalf("MaxPackedLen %d still far exceeds payload+header+padding headroom", newWay)
	}
}
