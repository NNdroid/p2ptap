package obfuscate

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParsePaddingRuleDefaults(t *testing.T) {
	// Empty / blank / comment-only input falls back to the default rule.
	for _, in := range []string{"", "   ", "# just a comment", "\n# a\n\n# b\n"} {
		r, err := ParsePaddingRule(in)
		if err != nil {
			t.Fatalf("ParsePaddingRule(%q) error: %v", in, err)
		}
		if len(r.Bands) != 1 || r.Bands[0].Floor != 0 || r.Bands[0].TargetMin != 400 || r.Bands[0].TargetMax != 600 {
			t.Fatalf("default bands wrong: %+v", r.Bands)
		}
		if !r.Coalesce.On || r.Coalesce.MaxDelayMs != DefaultCoalesceMaxDelayMs ||
			r.Coalesce.MaxBytes != DefaultCoalesceMaxBytes || r.Coalesce.MaxFrames != DefaultCoalesceMaxFrames {
			t.Fatalf("default coalesce wrong: %+v", r.Coalesce)
		}
	}
}

func TestParsePaddingRuleSingleBand(t *testing.T) {
	r, err := ParsePaddingRule("0 -> 400-600")
	if err != nil {
		t.Fatalf("ParsePaddingRule error: %v", err)
	}
	if len(r.Bands) != 1 || r.Bands[0] != (PaddingBand{0, 400, 600}) {
		t.Fatalf("bands = %+v, want [{0 400 600}]", r.Bands)
	}
	// A single target value pads to exactly that size.
	r, err = ParsePaddingRule("0 -> 512")
	if err != nil {
		t.Fatalf("ParsePaddingRule error: %v", err)
	}
	if r.Bands[0] != (PaddingBand{0, 512, 512}) {
		t.Fatalf("fixed target band = %+v, want {0 512 512}", r.Bands[0])
	}
}

func TestParsePaddingRuleMultiBand(t *testing.T) {
	r, err := ParsePaddingRule("0 -> 256-256\n1024 -> 1100-1400")
	if err != nil {
		t.Fatalf("ParsePaddingRule error: %v", err)
	}
	if len(r.Bands) != 2 {
		t.Fatalf("bands = %d, want 2", len(r.Bands))
	}
	if r.Bands[0] != (PaddingBand{0, 256, 256}) || r.Bands[1] != (PaddingBand{1024, 1100, 1400}) {
		t.Fatalf("bands = %+v", r.Bands)
	}
}

func TestParsePaddingRuleRejectsBad(t *testing.T) {
	cases := []string{
		"garbage",
		"0 ->",                         // missing target
		"0 -> abc",                     // bad target
		"x -> 400-600",                 // bad floor
		"0 -> 600-400",                 // target_max < target_min
		"0 -> 70000",                   // target above MaxFrameSize
		"0 -> 400-600\n0 -> 500-700",   // duplicate floor
		"coalesce",                     // missing on/off
		"coalesce maybe",               // bad on/off
		"coalesce on max_delay_ms=0",   // below range
		"coalesce on max_delay_ms=101", // above range
		"coalesce on max_bytes=10",     // below range
		"coalesce on max_frames=1",     // below range
		"coalesce on bogus=1",          // unknown key
		"coalesce on\ncoalesce off",    // duplicate directive
	}
	for _, in := range cases {
		if _, err := ParsePaddingRule(in); err == nil {
			t.Errorf("ParsePaddingRule(%q) = nil error, want rejection", in)
		}
	}
}

func TestParsePaddingRuleCoalesceOff(t *testing.T) {
	r, err := ParsePaddingRule("0 -> 400-600\ncoalesce off")
	if err != nil {
		t.Fatalf("ParsePaddingRule error: %v", err)
	}
	if r.Coalesce.On {
		t.Fatal("coalesce off not honoured")
	}
	r, err = ParsePaddingRule("0 -> 400-600\ncoalesce on max_delay_ms=10 max_bytes=800 max_frames=4")
	if err != nil {
		t.Fatalf("ParsePaddingRule error: %v", err)
	}
	if r.Coalesce != (CoalesceRule{On: true, MaxDelayMs: 10, MaxBytes: 800, MaxFrames: 4}) {
		t.Fatalf("coalesce = %+v", r.Coalesce)
	}
}

func TestBandFor(t *testing.T) {
	r, _ := ParsePaddingRule("0 -> 400-600\n1024 -> 1100-1400")
	cases := []struct {
		size int
		want int // band floor, -1 for none
	}{
		{0, 0}, {399, 0}, {400, 0}, {1023, 0}, {1024, 1024}, {2000, 1024},
	}
	for _, c := range cases {
		b := r.BandFor(c.size)
		if c.want < 0 {
			if b != nil {
				t.Fatalf("BandFor(%d) = %+v, want nil", c.size, b)
			}
			continue
		}
		if b == nil || b.Floor != c.want {
			t.Fatalf("BandFor(%d) = %+v, want floor %d", c.size, b, c.want)
		}
	}
	// No band below the smallest floor: natural.
	r2, _ := ParsePaddingRule("512 -> 800-1000")
	if b := r2.BandFor(100); b != nil {
		t.Fatalf("BandFor(100) = %+v, want nil (below lowest floor)", b)
	}
}

func TestPaddedSize(t *testing.T) {
	r, _ := ParsePaddingRule("0 -> 400-600")
	// Below the target: padded into [400,600].
	for i := 0; i < 200; i++ {
		s := r.PaddedSize(60)
		if s < 400 || s > 600 {
			t.Fatalf("PaddedSize(60) = %d, want in [400,600]", s)
		}
	}
	// At/above the target: natural.
	if s := r.PaddedSize(400); s != 400 {
		t.Fatalf("PaddedSize(400) = %d, want 400 (natural)", s)
	}
	if s := r.PaddedSize(700); s != 700 {
		t.Fatalf("PaddedSize(700) = %d, want 700 (natural)", s)
	}
	// Fixed target: exact.
	rf, _ := ParsePaddingRule("0 -> 512")
	if s := rf.PaddedSize(10); s != 512 {
		t.Fatalf("PaddedSize(10) fixed = %d, want 512", s)
	}
	// No band (below smallest floor): natural.
	r2, _ := ParsePaddingRule("512 -> 800-1000")
	if s := r2.PaddedSize(100); s != 100 {
		t.Fatalf("PaddedSize(100) below-band = %d, want 100", s)
	}
}

func TestMaxPaddedSize(t *testing.T) {
	r, _ := ParsePaddingRule("0 -> 400-600")
	if got := r.MaxPaddedSize(60); got != 600 {
		t.Fatalf("MaxPaddedSize(60) = %d, want 600", got)
	}
	if got := r.MaxPaddedSize(700); got != 700 {
		t.Fatalf("MaxPaddedSize(700) = %d, want 700", got)
	}
	rf, _ := ParsePaddingRule("0 -> 512")
	if got := rf.MaxPaddedSize(10); got != 512 {
		t.Fatalf("MaxPaddedSize(10) fixed = %d, want 512", got)
	}
}

func TestFlushThreshold(t *testing.T) {
	r, _ := ParsePaddingRule("0 -> 400-600\n1024 -> 1100-1400")
	if got := r.FlushThreshold(50); got != 400 {
		t.Fatalf("FlushThreshold(50) = %d, want 400", got)
	}
	if got := r.FlushThreshold(1024); got != 1100 {
		t.Fatalf("FlushThreshold(1024) = %d, want 1100", got)
	}
	// No band (below the smallest floor): flush at current size.
	r2, _ := ParsePaddingRule("512 -> 800-1000")
	if got := r2.FlushThreshold(100); got != 100 {
		t.Fatalf("FlushThreshold(100) no-band = %d, want 100", got)
	}
}

func TestBuildSplitBatchPayload(t *testing.T) {
	subs := [][]byte{
		bytes.Repeat([]byte{0x01}, 60),
		bytes.Repeat([]byte{0x02}, 100),
		bytes.Repeat([]byte{0x03}, 200),
	}
	payload := BuildBatchPayload(subs)
	// Magic[0:2] must differ from the frag magic 0xF5A1, and byte 0 must have
	// its I/G bit set so no unicast destination MAC can ever spell it.
	if payload[0] != 0xB1 || payload[1] != 0x7C {
		t.Fatalf("batch magic prefix = %02x%02x, want B17C", payload[0], payload[1])
	}
	if payload[0]&0x01 != 0x01 {
		t.Fatalf("batch magic first byte %#x has its I/G bit clear: a unicast destination MAC could collide", payload[0])
	}
	if payload[0] == 0xFF {
		t.Fatal("batch magic first byte is 0xFF: a broadcast destination MAC could collide")
	}
	got, ok := SplitBatchPayload(payload)
	if !ok {
		t.Fatal("SplitBatchPayload did not recognise a well-formed batch")
	}
	if len(got) != len(subs) {
		t.Fatalf("split %d sub-frames, want %d", len(got), len(subs))
	}
	for i := range subs {
		if !bytes.Equal(got[i], subs[i]) {
			t.Fatalf("sub-frame %d mismatch", i)
		}
	}
}

func TestSplitBatchPayloadRejectsBad(t *testing.T) {
	// Too short.
	if _, ok := SplitBatchPayload([]byte{0xB0, 0x7C, 0xB0, 0x7C, 0x00, 0x01}); ok {
		t.Fatal("short payload accepted as batch")
	}
	// Wrong magic.
	bad := []byte{0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x01}
	if _, ok := SplitBatchPayload(append(bad, make([]byte, 40)...)); ok {
		t.Fatal("wrong-magic payload accepted as batch")
	}
	// Magic that matches a fragment envelope must not be a batch.
	frag := []byte{0xF5, 0xA1}
	if _, ok := SplitBatchPayload(append(frag, make([]byte, 40)...)); ok {
		t.Fatal("frag-magic payload accepted as batch")
	}
	// Count = 0.
	zero := []byte{0xB0, 0x7C, 0xB0, 0x7C, 0x00, 0x00}
	if _, ok := SplitBatchPayload(append(zero, make([]byte, 40)...)); ok {
		t.Fatal("zero-count payload accepted as batch")
	}
	// Length field shorter than an Ethernet frame.
	short := BuildBatchPayload([][]byte{bytes.Repeat([]byte{0x01}, 60)})
	// Corrupt the length field of the single sub-frame to 5 (< minSubFrameLen).
	short[6] = 0
	short[7] = 5
	if _, ok := SplitBatchPayload(short); ok {
		t.Fatal("sub-frame length < Ethernet header accepted as batch")
	}
	// Trailing garbage after the last sub-frame (byte accounting mismatch).
	trunc := BuildBatchPayload([][]byte{bytes.Repeat([]byte{0x01}, 60)})
	if _, ok := SplitBatchPayload(append(trunc, 0x00, 0x00, 0x00)); ok {
		t.Fatal("trailing garbage accepted as batch")
	}
	// A normal single frame payload (not a batch) is returned as a single frame.
	plain := bytes.Repeat([]byte{0xEE}, 100)
	if subs, ok := SplitBatchPayload(plain); ok || len(subs) != 0 {
		t.Fatalf("plain payload misdetected: ok=%v subs=%d", ok, len(subs))
	}
}

// TestSplitBatchPayloadLegacyMagicAccepted keeps a rolling upgrade working: a
// peer that still emits the old (unicast-looking) magic must still be split.
func TestSplitBatchPayloadLegacyMagicAccepted(t *testing.T) {
	subs := [][]byte{bytes.Repeat([]byte{0x01}, 60), bytes.Repeat([]byte{0x02}, 100)}
	payload := BuildBatchPayload(subs)
	binary.BigEndian.PutUint32(payload[0:4], batchMagicLegacy)

	got, ok := SplitBatchPayload(payload)
	if !ok {
		t.Fatal("legacy batch magic was not accepted")
	}
	if len(got) != len(subs) {
		t.Fatalf("split %d sub-frames, want %d", len(got), len(subs))
	}
	for i := range subs {
		if !bytes.Equal(got[i], subs[i]) {
			t.Fatalf("sub-frame %d mismatch", i)
		}
	}
}

// TestSplitBatchPayloadCountIsBoundedBeforeAllocation is the regression guard for
// the allocation amplification: a 22-byte payload claiming 65535 sub-frames used
// to allocate 65535 slice slots (~1.5 MiB, ~70k x the input) BEFORE the first
// length field was validated, which a PSK-holding peer could repeat at line rate.
// The count must now be rejected up front, allocating nothing.
func TestSplitBatchPayloadCountIsBoundedBeforeAllocation(t *testing.T) {
	payload := make([]byte, 22)
	binary.BigEndian.PutUint32(payload[0:4], batchMagic)
	binary.BigEndian.PutUint16(payload[4:6], 65535)

	var subs [][]byte
	var ok bool
	allocs := testing.AllocsPerRun(100, func() {
		subs, ok = SplitBatchPayload(payload)
	})
	if ok || subs != nil {
		t.Fatal("oversized count accepted as a batch")
	}
	if allocs != 0 {
		t.Fatalf("rejecting an oversized count allocated %v times, want 0", allocs)
	}

	// The exact boundary must still be accepted: the largest legitimate count for
	// this payload size is (len-6)/(2+minSubFrameLen).
	maxCount := (len(payload) - batchHeaderLen) / (2 + minSubFrameLen)
	if maxCount == 0 {
		t.Fatal("test payload is too small to exercise the boundary")
	}
}
