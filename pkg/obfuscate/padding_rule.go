package obfuscate

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// ─── Padding rule grammar ────────────────────────────────────────────────────
//
// Padding is configured by a single declarative rule string (PaddingRules).
// This is the ONLY padding mechanism; the historical fixed/block/random/
// dynamic/auto modes are gone. The grammar is:
//
//	# comment (lines starting with '#', blank lines ignored)
//	<floor> -> <target_min>[-<target_max>]      # one band per line
//	coalesce on|off [max_delay_ms=N] [max_bytes=N] [max_frames=N]
//
// Semantics:
//   - Bands are ordered by floor. A payload of size S belongs to the band
//     with the largest floor <= S; if no band has floor <= S the payload is
//     sent at its natural size.
//   - If S < band.target_min the payload is padded to a random size in
//     [target_min, target_max] (a single target value pads to exactly that
//     size). If S >= target_min the payload is sent unpadded — this is the
//     "enough data, do not pad" rule. The default rule "0 -> 400-600" pads
//     anything under 400 bytes to a random 400-600 and sends >= 400 naturally.
//   - The optional coalesce directive controls packet coalescing: unicast
//     frames are buffered per destination and flushed once the accumulated
//     bytes reach the current band's target_min (unpadded), or once
//     max_delay_ms elapses (padded to the band target), capped by max_bytes /
//     max_frames. Default: on, max_delay_ms=2, max_bytes=1400, max_frames=16.

const (
	// DefaultPaddingRules is the rule shipped in the default config: payloads
	// under 400 bytes are padded to a random 400-600; 400+ go out naturally.
	DefaultPaddingRules = "0 -> 400-600"

	// DefaultCoalesceMaxDelayMs bounds how long a coalescing buffer may hold a
	// frame before it is flushed (and padded to the band target if still short).
	DefaultCoalesceMaxDelayMs = 2
	// DefaultCoalesceMaxBytes caps a single coalesced batch payload.
	DefaultCoalesceMaxBytes = 1400
	// DefaultCoalesceMaxFrames caps the sub-frames in one coalesced batch.
	DefaultCoalesceMaxFrames = 16
)

// PaddingBand is one size class: payloads with floor <= S pad to the band's
// target range once S is below target_min.
type PaddingBand struct {
	Floor     int
	TargetMin int
	TargetMax int
}

// CoalesceRule carries the batch-to-avoid-padding knobs parsed from the
// optional "coalesce" directive.
type CoalesceRule struct {
	On         bool
	MaxDelayMs int
	MaxBytes   int
	MaxFrames  int
}

// PaddingRule is a fully parsed, validated padding configuration.
type PaddingRule struct {
	Bands    []PaddingBand
	Coalesce CoalesceRule
}

// DefaultPaddingRule returns the built-in rule: under 400 pads to a random
// 400-600, 400+ natural, coalescing on with the default knobs.
func DefaultPaddingRule() *PaddingRule {
	return &PaddingRule{
		Bands: []PaddingBand{{Floor: 0, TargetMin: 400, TargetMax: 600}},
		Coalesce: CoalesceRule{
			On:         true,
			MaxDelayMs: DefaultCoalesceMaxDelayMs,
			MaxBytes:   DefaultCoalesceMaxBytes,
			MaxFrames:  DefaultCoalesceMaxFrames,
		},
	}
}

// ParsePaddingRule parses the rule grammar. An empty/blank string returns the
// default rule. A malformed rule returns an error with a description of the
// offending line.
func ParsePaddingRule(s string) (*PaddingRule, error) {
	if strings.TrimSpace(s) == "" {
		return DefaultPaddingRule(), nil
	}
	rule := &PaddingRule{}
	coalesce := CoalesceRule{
		On:         true,
		MaxDelayMs: DefaultCoalesceMaxDelayMs,
		MaxBytes:   DefaultCoalesceMaxBytes,
		MaxFrames:  DefaultCoalesceMaxFrames,
	}
	coalesceSeen := false

	for lineNo, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "coalesce") || strings.HasPrefix(line, "Coalesce") {
			if coalesceSeen {
				return nil, fmt.Errorf("padding rule line %d: duplicate 'coalesce' directive", lineNo+1)
			}
			coalesceSeen = true
			if err := parseCoalesceLine(line, &coalesce); err != nil {
				return nil, fmt.Errorf("padding rule line %d: %w", lineNo+1, err)
			}
			continue
		}
		band, err := parseBandLine(line)
		if err != nil {
			return nil, fmt.Errorf("padding rule line %d: %w", lineNo+1, err)
		}
		rule.Bands = append(rule.Bands, band)
	}

	if len(rule.Bands) == 0 {
		// A rule with only a coalesce directive (no bands) is degenerate: fall
		// back to the default band set so padding still behaves.
		rule.Bands = DefaultPaddingRule().Bands
	}

	// Sort by floor ascending and validate strict ordering.
	for i := 1; i < len(rule.Bands); i++ {
		if rule.Bands[i].Floor <= rule.Bands[i-1].Floor {
			return nil, fmt.Errorf("padding rule: band floors must be strictly ascending (got %d after %d)",
				rule.Bands[i].Floor, rule.Bands[i-1].Floor)
		}
	}
	for i := range rule.Bands {
		b := &rule.Bands[i]
		if b.Floor < 0 || b.TargetMin < 0 || b.TargetMax < b.TargetMin {
			return nil, fmt.Errorf("padding rule: band %d: need 0 <= floor <= target_min <= target_max", b.Floor)
		}
		if b.TargetMax > MaxFrameSize {
			return nil, fmt.Errorf("padding rule: band %d: target_max %d exceeds MaxFrameSize %d", b.Floor, b.TargetMax, MaxFrameSize)
		}
	}
	if coalesce.MaxDelayMs < 1 || coalesce.MaxDelayMs > 100 {
		return nil, fmt.Errorf("padding rule: max_delay_ms must be in [1,100] (got %d)", coalesce.MaxDelayMs)
	}
	if coalesce.MaxBytes < 64 || coalesce.MaxBytes > MaxFrameSize {
		return nil, fmt.Errorf("padding rule: max_bytes must be in [64,%d] (got %d)", MaxFrameSize, coalesce.MaxBytes)
	}
	if coalesce.MaxFrames < 2 || coalesce.MaxFrames > 64 {
		return nil, fmt.Errorf("padding rule: max_frames must be in [2,64] (got %d)", coalesce.MaxFrames)
	}
	rule.Coalesce = coalesce
	return rule, nil
}

func parseBandLine(line string) (PaddingBand, error) {
	arrow := strings.Index(line, "->")
	if arrow < 0 {
		return PaddingBand{}, fmt.Errorf("expected '<floor> -> <target>', got %q", line)
	}
	floor, err := strconv.Atoi(strings.TrimSpace(line[:arrow]))
	if err != nil {
		return PaddingBand{}, fmt.Errorf("invalid floor %q", strings.TrimSpace(line[:arrow]))
	}
	target := strings.TrimSpace(line[arrow+2:])
	if target == "" {
		return PaddingBand{}, fmt.Errorf("missing target after '->'")
	}
	targetMin, targetMax, err := parseTarget(target)
	if err != nil {
		return PaddingBand{}, err
	}
	return PaddingBand{Floor: floor, TargetMin: targetMin, TargetMax: targetMax}, nil
}

func parseTarget(target string) (int, int, error) {
	if dash := strings.Index(target, "-"); dash >= 0 {
		minS := strings.TrimSpace(target[:dash])
		maxS := strings.TrimSpace(target[dash+1:])
		tMin, err := strconv.Atoi(minS)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid target_min %q", minS)
		}
		tMax, err := strconv.Atoi(maxS)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid target_max %q", maxS)
		}
		return tMin, tMax, nil
	}
	v, err := strconv.Atoi(target)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid target %q", target)
	}
	return v, v, nil
}

func parseCoalesceLine(line string, c *CoalesceRule) error {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return fmt.Errorf("expected 'coalesce on|off [max_delay_ms=N] [max_bytes=N] [max_frames=N]'")
	}
	switch strings.ToLower(fields[1]) {
	case "on":
		c.On = true
	case "off":
		c.On = false
	default:
		return fmt.Errorf("expected 'on' or 'off', got %q", fields[1])
	}
	for _, f := range fields[2:] {
		eq := strings.Index(f, "=")
		if eq <= 0 {
			return fmt.Errorf("expected key=value, got %q", f)
		}
		key := strings.TrimSpace(f[:eq])
		val, err := strconv.Atoi(strings.TrimSpace(f[eq+1:]))
		if err != nil {
			return fmt.Errorf("invalid value for %q: %q", key, f[eq+1:])
		}
		switch key {
		case "max_delay_ms":
			c.MaxDelayMs = val
		case "max_bytes":
			c.MaxBytes = val
		case "max_frames":
			c.MaxFrames = val
		default:
			return fmt.Errorf("unknown coalesce key %q", key)
		}
	}
	return nil
}

// BandFor returns the band with the largest floor <= size, or nil if no band
// applies (the payload is sent at its natural size).
func (r *PaddingRule) BandFor(size int) *PaddingBand {
	if r == nil {
		return nil
	}
	for i := len(r.Bands) - 1; i >= 0; i-- {
		if r.Bands[i].Floor <= size {
			return &r.Bands[i]
		}
	}
	return nil
}

// PaddedSize returns the target PAYLOAD size (header excluded) for a payload
// of the given size: the natural size when it already reaches the band target,
// otherwise a random size in the band's [target_min, target_max] range.
func (r *PaddingRule) PaddedSize(size int) int {
	if r == nil {
		return size
	}
	b := r.BandFor(size)
	if b == nil || size >= b.TargetMin {
		return size
	}
	return randomBetween(b.TargetMin, b.TargetMax)
}

// MaxPaddedSize returns the worst-case PADDED payload size for a payload of
// the given size — the upper bound Pack may grow it to. Used to size output
// buffers so Pack never returns ErrBufferTooSmall.
func (r *PaddingRule) MaxPaddedSize(size int) int {
	if r == nil {
		return size
	}
	b := r.BandFor(size)
	if b == nil || size >= b.TargetMin {
		return size
	}
	return b.TargetMax
}

// FlushThreshold returns the accumulated-bytes threshold at which a coalescing
// buffer should flush unpadded for the given current buffer size: the current
// band's target_min. It returns the size itself when no band applies (nothing
// to pad toward, so the buffer should not grow further waiting for a band).
func (r *PaddingRule) FlushThreshold(size int) int {
	if r == nil {
		return size
	}
	b := r.BandFor(size)
	if b == nil {
		return size
	}
	return b.TargetMin
}

// ─── Batch sub-frame format ─────────────────────────────────────────────────
//
// A coalesced batch is carried inside ONE obfuscate frame payload:
//
//	[batchMagic:4][count:2][ (len:2)(pkt) × count ]
//
// All sub-frames share the frame's single SeqID, so fragmentation, dedup and
// reordering operate on the batch as one logical frame; the receiver splits it
// back into per-frame TAP writes.
//
// The magic is chosen so that the splitter cannot mistake an ordinary Ethernet
// frame for a batch. The bytes it inspects are the FRONT of a TAP frame when the
// payload is not a batch, and a TAP frame starts with its destination MAC:
//
//   - byte 0 must have its I/G bit SET (0xB1 = ...0001), because a unicast
//     destination MAC always has that bit clear. A batch magic starting with a
//     unicast-looking byte could collide with a real frame's destination MAC.
//   - byte 0 must not be 0xFF, so a broadcast frame (ff:ff:...:) can never match.
//
// The pre-existing 0xB07C prefix had its I/G bit CLEAR and could therefore
// collide with the unicast destination MAC b0:7c:b0:7c:xx:xx. It is still
// ACCEPTED on receive (batchMagicLegacy) so that a rolling upgrade, where the
// peer still emits the old value, keeps working; only the new value is emitted.
// batchMagic[0:2] also differs from the fragmentation envelope magic (0xF5A1)
// so a batch is never mistaken for a fragment envelope.

const (
	batchMagic       uint32 = 0xB17CB17C // emits: I/G bit set, not 0xFF
	batchMagicLegacy uint32 = 0xB07CB07C // accepts only: pre-multicast-safe value
	batchHeaderLen          = 6          // magic(4) + count(2)
	// minSubFrameLen is the smallest legal sub-frame (an Ethernet header).
	// Shorter payloads are not a batch.
	minSubFrameLen = 14
)

// BatchHeaderLen exposes the batch envelope header length.
const BatchHeaderLen = batchHeaderLen

// BuildBatchPayload wraps sub-frames into one batch payload (see format above).
// Callers must ensure each sub-frame is a complete Ethernet frame.
//
// Returns nil (never a truncated batch) when the sub-frame count does not fit
// the 16-bit count field: writing uint16(len(subFrames)) there would silently
// truncate the count and corrupt SplitBatchPayload's exact byte accounting,
// making the receiver reject a frame it could otherwise deliver. The caller
// must fall back to per-frame delivery.
func BuildBatchPayload(subFrames [][]byte) []byte {
	if len(subFrames) > 65535 {
		return nil
	}
	total := batchHeaderLen
	for _, f := range subFrames {
		total += 2 + len(f)
	}
	buf := make([]byte, 0, total)
	buf = binary.BigEndian.AppendUint32(buf, batchMagic)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(subFrames)))
	for _, f := range subFrames {
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(f)))
		buf = append(buf, f...)
	}
	return buf
}

// BatchPayloadSize returns the exact byte count BuildBatchPayload (or
// BuildBatchPayloadInto) will emit for subFrames, so a caller can size a buffer
// to build the batch in place without a transient allocation.
func BatchPayloadSize(subFrames [][]byte) int {
	total := batchHeaderLen
	for _, f := range subFrames {
		total += 2 + len(f)
	}
	return total
}

// BuildBatchPayloadInto is BuildBatchPayload with a caller-owned destination
// sized >= BatchPayloadSize(subFrames). The returned slice aliases dst. When dst
// is the Pack output buffer's payload region (dst == outBuf[HeaderLen:]), the
// copy inside Pack becomes a no-op — the fragmentFrame pattern — saving one
// allocation and one copy per batch. Returns nil (never a truncated batch) when
// the count does not fit the 16-bit field or dst is too small.
func BuildBatchPayloadInto(dst []byte, subFrames [][]byte) []byte {
	if len(subFrames) > 65535 {
		return nil
	}
	need := BatchPayloadSize(subFrames)
	if cap(dst) < need {
		return nil
	}
	buf := dst[:0]
	buf = binary.BigEndian.AppendUint32(buf, batchMagic)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(subFrames)))
	for _, f := range subFrames {
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(f)))
		buf = append(buf, f...)
	}
	return buf
}

// SplitBatchPayload detects and splits a batch payload. It returns the
// sub-frames (aliasing payload) and true only when the magic matches AND the
// structure is fully consistent (count >= 1, every length >= minSubFrameLen,
// exact byte accounting). Any inconsistency means the payload is a single
// frame (or a fragment envelope / control frame) and returns false.
func SplitBatchPayload(payload []byte) ([][]byte, bool) {
	if len(payload) < batchHeaderLen+2+minSubFrameLen {
		return nil, false
	}
	if magic := binary.BigEndian.Uint32(payload[0:4]); magic != batchMagic && magic != batchMagicLegacy {
		return nil, false
	}
	count := int(binary.BigEndian.Uint16(payload[4:6]))
	if count < 1 {
		return nil, false
	}
	// Bound the count BEFORE allocating. A sub-frame costs at least
	// 2 (its length field) + minSubFrameLen bytes, so a payload of this size
	// can never legitimately claim more than maxCount of them. Without this
	// check a 22-byte payload bearing the magic and count=65535 makes the
	// receiver allocate 65535 slice slots (1.5 MiB, a ~71494x amplification)
	// before the first length field is even read — a PSK-holding peer can
	// repeat that at line rate and turn the splitter into a GC bomb. The
	// structural walk below is unchanged; this only makes the rejected case
	// cheap.
	if maxCount := (len(payload) - batchHeaderLen) / (2 + minSubFrameLen); count > maxCount {
		return nil, false
	}
	off := batchHeaderLen
	subs := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		if off+2 > len(payload) {
			return nil, false
		}
		l := int(binary.BigEndian.Uint16(payload[off : off+2]))
		off += 2
		if l < minSubFrameLen || off+l > len(payload) {
			return nil, false
		}
		subs = append(subs, payload[off:off+l])
		off += l
	}
	if off != len(payload) {
		return nil, false
	}
	return subs, true
}
