package routing

import (
	"encoding/binary"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

func testBootRelayID(t *testing.T) peer.ID {
	t.Helper()
	_, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	p, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("IDFromPublicKey: %v", err)
	}
	return p
}

// testBootRelayIDs returns a random pair of peer IDs so the tests exercise
// realistic Ed25519 CIDs rather than hand-built stubs.
func testBootRelayIDs(t *testing.T) (peer.ID, peer.ID) {
	t.Helper()
	return testBootRelayID(t), testBootRelayID(t)
}

const testBootRelayNetID = "0123456789abcdef" // 16 hex chars, as NetworkIDFromPSK emits

func TestUnpackBootRelayFrameRoundTrip(t *testing.T) {
	dst, src := testBootRelayIDs(t)
	payload := []byte("hello relay")

	for _, tc := range []struct {
		name  string
		kind  byte
		proto protocol.ID
	}{
		{name: "data", kind: BootRelayKindData, proto: ""},
		{name: "control", kind: BootRelayKindControl, proto: "/p2ptap/seqsync/1.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := PackBootRelayFrame(testBootRelayNetID, tc.kind, tc.proto, dst, src, 3, payload)
			if err != nil {
				t.Fatalf("PackBootRelayFrame: %v", err)
			}
			gotNetID, gotKind, gotProto, gotDst, gotSrc, gotTTL, gotPayload, err := UnpackBootRelayFrame(f)
			if err != nil {
				t.Fatalf("UnpackBootRelayFrame: %v", err)
			}
			if gotNetID != testBootRelayNetID {
				t.Errorf("netID = %q, want %q", gotNetID, testBootRelayNetID)
			}
			if gotKind != tc.kind {
				t.Errorf("kind = 0x%02x, want 0x%02x", gotKind, tc.kind)
			}
			if gotProto != tc.proto {
				t.Errorf("proto = %q, want %q", gotProto, tc.proto)
			}
			if gotDst != dst || gotSrc != src {
				t.Errorf("peers = %s/%s, want %s/%s", gotDst, gotSrc, dst, src)
			}
			if gotTTL != 3 {
				t.Errorf("ttl = %d, want 3", gotTTL)
			}
			if string(gotPayload) != string(payload) {
				t.Errorf("payload = %q, want %q", gotPayload, payload)
			}
		})
	}
}

// TestUnpackBootRelayFrameNotStrippedForWellFormedFrame pins the ordering
// invariant: a frame that parses honestly must never be altered by the
// framing-heuristic retry, even when the retry's gate would also match.
//
// The frame is sized to be strip-eligible by construction rather than by
// mutating it afterwards, since mutating the first four bytes would also
// destroy the netID length field. The four header bytes are fixed by the
// header alone (netIDLen, the first netID byte, kind, protoLen high byte), so
// the payload is chosen until len-4 equals exactly the uint32 at offset 0.
func TestUnpackBootRelayFrameNotStrippedForWellFormedFrame(t *testing.T) {
	dst, src := testBootRelayIDs(t)
	netID := "a"

	hdrOnly, err := PackBootRelayFrame(netID, BootRelayKindData, "", dst, src, 5, nil)
	if err != nil {
		t.Fatalf("PackBootRelayFrame(hdrOnly): %v", err)
	}
	key := binary.BigEndian.Uint32(hdrOnly[:4])
	payloadLen := int(key) + 4 - len(hdrOnly)
	if payloadLen <= 0 {
		t.Fatalf("test setup: negative payload length %d", payloadLen)
	}
	payload := make([]byte, payloadLen)

	frame, err := PackBootRelayFrame(netID, BootRelayKindData, "", dst, src, 5, payload)
	if err != nil {
		t.Fatalf("PackBootRelayFrame: %v", err)
	}
	if want := uint32(len(frame) - 4); binary.BigEndian.Uint32(frame[:4]) != want {
		t.Fatalf("test setup: frame is not strip-eligible (have 0x%08x want 0x%08x)",
			binary.BigEndian.Uint32(frame[:4]), want)
	}

	_, gotKind, _, gotDst, gotSrc, gotTTL, gotPayload, err := UnpackBootRelayFrame(frame)
	if err != nil {
		t.Fatalf("UnpackBootRelayFrame: %v", err)
	}
	if gotKind != BootRelayKindData {
		t.Errorf("kind = 0x%02x, want 0x%02x (the retry must not have consumed bytes)",
			gotKind, BootRelayKindData)
	}
	if gotDst != dst || gotSrc != src {
		t.Fatalf("peers = %s/%s, want %s/%s", gotDst, gotSrc, dst, src)
	}
	if gotTTL != 5 {
		t.Errorf("ttl = %d, want 5", gotTTL)
	}
	if len(gotPayload) != payloadLen {
		t.Errorf("payload len = %d, want %d", len(gotPayload), payloadLen)
	}
}

// TestUnpackBootRelayFrameStripsDoubleFraming covers the motivating case: an
// intermediate bridge wrapped an already-wrapped frame in a second
// [4B len][payload] envelope. The honest parse fails, the strip retry succeeds.
func TestUnpackBootRelayFrameStripsDoubleFraming(t *testing.T) {
	dst, src := testBootRelayIDs(t)
	payload := []byte("double framed")

	frame, err := PackBootRelayFrame(testBootRelayNetID, BootRelayKindData, "", dst, src, 2, payload)
	if err != nil {
		t.Fatalf("PackBootRelayFrame: %v", err)
	}

	// Sanity: the bare frame must parse, and it must not already be
	// strip-eligible (so the wrapper below is what changes the outcome).
	if _, _, _, _, _, _, _, err := unpackBootRelayFrame(frame); err != nil {
		t.Fatalf("bare frame failed to parse: %v", err)
	}
	if binary.BigEndian.Uint32(frame[:4]) == uint32(len(frame)-4) {
		t.Fatalf("test setup: frame is accidentally self-strippable")
	}

	wrapped := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(wrapped[:4], uint32(len(frame)))
	copy(wrapped[4:], frame)

	// Only the recovery wrapper may succeed; the unconditional parse must not.
	if _, _, _, _, _, _, _, err := unpackBootRelayFrame(wrapped); err == nil {
		t.Fatalf("wrapped frame parsed without the retry path")
	}

	_, _, _, gotDst, gotSrc, gotTTL, gotPayload, err := UnpackBootRelayFrame(wrapped)
	if err != nil {
		t.Fatalf("UnpackBootRelayFrame after strip: %v", err)
	}
	if gotDst != dst || gotSrc != src {
		t.Errorf("peers = %s/%s, want %s/%s", gotDst, gotSrc, dst, src)
	}
	if gotTTL != 2 {
		t.Errorf("ttl = %d, want 2", gotTTL)
	}
	if string(gotPayload) != string(payload) {
		t.Errorf("payload = %q, want %q", gotPayload, payload)
	}
}

// TestUnpackBootRelayFrameStripsTripleFraming checks the retry is not merely a
// one-shot: a third wrapping layer is still rejected, which is the honest
// answer for an unknowable number of envelope layers.
func TestUnpackBootRelayFrameStripsTripleFraming(t *testing.T) {
	dst, src := testBootRelayIDs(t)

	frame, err := PackBootRelayFrame(testBootRelayNetID, BootRelayKindData, "", dst, src, 1, []byte("x"))
	if err != nil {
		t.Fatalf("PackBootRelayFrame: %v", err)
	}
	once := frame
	for i := 0; i < 2; i++ {
		w := make([]byte, 4+len(once))
		binary.BigEndian.PutUint32(w[:4], uint32(len(once)))
		copy(w[4:], once)
		once = w
	}
	if _, _, _, _, _, _, _, err := UnpackBootRelayFrame(once); err == nil {
		t.Fatalf("triple-wrapped frame parsed; only one framing layer may be stripped")
	}
}

// TestUnpackBootRelayFrameRejectsGarbage pins the negative cases: none of them
// may be salvaged by the retry path.
func TestUnpackBootRelayFrameRejectsGarbage(t *testing.T) {
	dst, src := testBootRelayIDs(t)

	// A bare relay envelope has no netID prefix; the honest parse must fail and
	// the retry must not produce a spurious result.
	env, err := PackRelayFrame(dst, src, 1, []byte("payload"))
	if err != nil {
		t.Fatalf("PackRelayFrame: %v", err)
	}

	cases := map[string][]byte{
		"empty": {},
		"short": {0x00, 0x10},
		// A relay envelope with no boot-relay prefix: its 0x02 version byte is
		// read as the high byte of a 513-byte netID, which must be refused by
		// maxNetIDLen and must not be salvaged by stripping.
		"bare relay envelope": append([]byte{}, env...),
		"raw Ethernet": {
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x63, 0x08, 0x00, 0x45,
		},
		"zero length head": {0x00, 0x00, 0x01, 0x2f, 0x70, 0x2f, 0x70, 0x2f, 0x32, 0x70, 0x74, 0x61, 0x70},
		"truncated frame":  append([]byte{}, env[:10]...),
	}
	// netIDLen 0xFFFF must be refused by the maxNetIDLen bound, not by an
	// out-of-range read.
	bogusNetID := make([]byte, 2)
	binary.BigEndian.PutUint16(bogusNetID, 0xFFFF)
	bogusNetID = append(bogusNetID, []byte("not even close")...)
	cases["huge netIDLen"] = bogusNetID

	for name, data := range cases {
		if _, _, _, _, _, _, _, err := UnpackBootRelayFrame(data); err == nil {
			t.Errorf("%s: unexpected success on %x", name, data)
		}
	}
}

// TestUnpackBootRelayFrameBogusLengthMustNotStrip verifies the retry only fires
// when the length field and the remainder actually agree.
func TestUnpackBootRelayFrameBogusLengthMustNotStrip(t *testing.T) {
	dst, src := testBootRelayIDs(t)
	frame, err := PackBootRelayFrame(testBootRelayNetID, BootRelayKindData, "", dst, src, 1, []byte("x"))
	if err != nil {
		t.Fatalf("PackBootRelayFrame: %v", err)
	}

	wrapped := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(wrapped[:4], 0xDEADBEEF)
	copy(wrapped[4:], frame)
	if _, _, _, _, _, _, _, err := UnpackBootRelayFrame(wrapped); err == nil {
		t.Fatalf("stripped a prefix whose length did not match the remainder")
	}
}

// TestUnpackBootRelayFrameUnknownKindRejected locks the strict kind check: the
// old parser accepted any kind byte and trusted the rest of the buffer.
func TestUnpackBootRelayFrameUnknownKindRejected(t *testing.T) {
	dst, src := testBootRelayIDs(t)
	frame, err := PackBootRelayFrame(testBootRelayNetID, BootRelayKindData, "", dst, src, 1, []byte("x"))
	if err != nil {
		t.Fatalf("PackBootRelayFrame: %v", err)
	}

	for _, kind := range []byte{0x02, 0x7f, 0xff} {
		corrupt := append([]byte{}, frame...)
		corrupt[len(testBootRelayNetID)+2] = kind // the kind byte
		if _, gotKind, _, _, _, _, _, err := UnpackBootRelayFrame(corrupt); err == nil {
			t.Errorf("kind 0x%02x accepted (got kind 0x%02x)", kind, gotKind)
		}
	}
}

// TestStripFramingPrefixBounds pins the boundary conditions of the retry gate
// at unit level. The retry is only safe because both ends of the length check
// must agree, so a one-byte mismatch on either side must not strip.
func TestStripFramingPrefixBounds(t *testing.T) {
	for n := 0; n <= 4; n++ {
		data := make([]byte, n)
		if _, ok := stripFramingPrefix(data); ok {
			t.Fatalf("len %d: stripFramingPrefix reported true, want false (nothing to strip)", n)
		}
	}

	data := make([]byte, 12)
	binary.BigEndian.PutUint32(data[:4], 8)
	_, ok := stripFramingPrefix(data)
	if !ok {
		t.Fatalf("exact match did not strip")
	}
	if got, _ := stripFramingPrefix(data); len(got) != 8 {
		t.Fatalf("stripped result len = %d, want 8", len(got))
	}

	for _, want := range []uint32{0, 7, 9, 0xFFFFFF} {
		d := make([]byte, 12)
		binary.BigEndian.PutUint32(d[:4], want)
		if _, ok := stripFramingPrefix(d); ok {
			t.Errorf("length %d with remainder 8: stripFramingPrefix reported true, want false", want)
		}
	}
}

// TestUnpackBootRelayFrameRetryCannotFabricate verifies the retry only ever
// exposes bytes that were already in the packet: a buffer that fails the honest
// parse and whose strip gate is not satisfied must fail, with no partial
// result handed to the caller.
func TestUnpackBootRelayFrameRetryCannotFabricate(t *testing.T) {
	dst, src := testBootRelayIDs(t)

	// A valid frame with its kind byte corrupted fails the honest parse, and its
	// first four bytes do not form a matching length prefix, so no retry fires.
	frame, err := PackBootRelayFrame(testBootRelayNetID, BootRelayKindData, "", dst, src, 1, []byte("x"))
	if err != nil {
		t.Fatalf("PackBootRelayFrame: %v", err)
	}
	lenPrefix := binary.BigEndian.Uint32(frame[:4])
	if lenPrefix == uint32(len(frame)-4) {
		t.Fatalf("test setup: frame is accidentally strip-eligible")
	}
	frame[2+len(testBootRelayNetID)] = 0x99 // the kind byte
	if _, _, _, _, _, _, _, err := UnpackBootRelayFrame(frame); err == nil {
		t.Fatalf("corrupted frame parsed")
	}
}
