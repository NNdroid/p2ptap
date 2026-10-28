package obfuscate

import (
	"bytes"
	"testing"

	"p2ptap/pkg/config"
)

// TestMaxPackedLenNeverUnderAllocates is a safety net for the per-frame relay
// allocation: MaxPackedLen must return an upper bound that Pack never exceeds,
// for every padding rule and a wide range of payload sizes. If this ever fails,
// Pack would return ErrBufferTooSmall and blackhole relayed traffic.
func TestMaxPackedLenNeverUnderAllocates(t *testing.T) {
	rules := []string{
		"",                    // disabled (empty rule falls back to default, enable=false)
		"0 -> 400-600",        // default-style band
		"0 -> 1500-1500",      // fixed target
		"0 -> 256-256\n1024 -> 1100-1400", // multi-band
	}
	payloadSizes := []int{0, 1, 60, 200, 1000, 1400, 4000, 65000}

	for _, rule := range rules {
		rule := rule
		name := "disabled"
		if rule != "" {
			name = rule
		}
		t.Run(name, func(t *testing.T) {
			fp := NewFramePackerFull(&config.ObfuscationConfig{Enable: rule != "", PaddingRules: rule})
			for _, pl := range payloadSizes {
				payload := bytes.Repeat([]byte{0xAB}, pl)
				buf := make([]byte, fp.MaxPackedLen(pl))
				n, err := fp.Pack(1, payload, buf)
				if err != nil {
					t.Fatalf("rule=%q payload=%d: Pack returned error %v (buffer size %d)", rule, pl, err, len(buf))
				}
				if n > len(buf) {
					t.Fatalf("rule=%q payload=%d: Pack wrote %d bytes into a %d-byte buffer", rule, pl, n, len(buf))
				}
				// Invariant: actual size never exceeds the advertised upper bound.
				if n > fp.MaxPackedLen(pl) {
					t.Fatalf("rule=%q payload=%d: Pack size %d > MaxPackedLen %d", rule, pl, n, fp.MaxPackedLen(pl))
				}
			}
		})
	}
}

// TestMaxPackedLenShrinksSlack verifies the new bound is materially smaller than
// the old blanket +4096 idiom for realistic relay envelopes, i.e. that the
// optimization actually removes per-frame heap waste.
func TestMaxPackedLenShrinksSlack(t *testing.T) {
	fp := NewFramePackerFull(&config.ObfuscationConfig{Enable: true, PaddingRules: "0 -> 400-600"})
	// A typical relayed inner frame is a full-MTU overlay frame (~1400 bytes),
	// which is above the default band's 400 target and therefore unpadded.
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
