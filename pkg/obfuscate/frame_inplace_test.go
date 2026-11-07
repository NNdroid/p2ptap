package obfuscate

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestSealFrameInPlaceMatchesEncryptPayloadRegion pins the core invariant of
// the in-place TX seal: the sealed bytes must be IDENTICAL to the copying
// EncryptPayloadRegion output, so a receiver cannot tell which path produced
// the frame.
func TestSealFrameInPlaceMatchesEncryptPayloadRegion(t *testing.T) {
	cipher, err := NewObfCipher(ObfAlgoChaCha20, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := NewObfCipher(ObfAlgoAESGCM, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []ObfCipher{cipher, gcm} {
		for _, payloadLen := range []int{0, 1, 63, 400, 1091, 1500, 4096} {
			// A packed frame with trailing padding: payload + 37 bytes of padding.
			frame := buildPackedTestFrame(t, payloadLen, 37)

			want, err := EncryptPayloadRegion(frame, c)
			if err != nil {
				t.Fatalf("payloadLen=%d: EncryptPayloadRegion: %v", payloadLen, err)
			}
			got, ok := SealFrameInPlace(frame, c)
			if !ok {
				t.Fatalf("payloadLen=%d: SealFrameInPlace refused (capacity %d-%d < %d)",
					payloadLen, cap(frame), len(frame), c.Overhead())
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s payloadLen=%d: in-place seal diverged: len(got)=%d len(want)=%d",
					AlgoName(c.Algo()), payloadLen, len(got), len(want))
			}
			// The input frame must have been consumed in place (same array).
			if &got[0] != &frame[0] {
				t.Fatalf("payloadLen=%d: in-place seal allocated a new buffer", payloadLen)
			}
		}
	}
}

// TestSealFrameInPlaceRoundTrip runs the full seal -> open cycle through the
// in-place path and verifies the receiver reconstructs the original packed
// frame (payload length restored, padding preserved).
func TestSealFrameInPlaceRoundTrip(t *testing.T) {
	cipher, err := NewObfCipher(ObfAlgoAESGCM, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, payloadLen := range []int{1, 1091, 1500} {
		frame := buildPackedTestFrame(t, payloadLen, 37)
		orig := append([]byte(nil), frame...)

		sealed, ok := SealFrameInPlace(frame, cipher)
		if !ok {
			t.Fatalf("payloadLen=%d: refused", payloadLen)
		}
		opened, err := DecryptPayloadRegion(sealed, cipher)
		if err != nil {
			t.Fatalf("payloadLen=%d: open: %v", payloadLen, err)
		}
		if !bytes.Equal(opened, orig) {
			t.Fatalf("payloadLen=%d: round trip diverged (len opened=%d want=%d)",
				payloadLen, len(opened), len(orig))
		}
	}
}

// TestSealFrameInPlaceRefusesExactFit covers the fallback trigger: an
// exact-capacity backing array has no room for the tag, so the helper must
// return ok=false with the frame untouched.
func TestSealFrameInPlaceRefusesExactFit(t *testing.T) {
	cipher, err := NewObfCipher(ObfAlgoChaCha20, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	frame := buildPackedTestFrame(t, 200, 37)
	before := append([]byte(nil), frame...)
	exact := frame[:len(frame):len(frame)] // cap == len: zero headroom
	got, ok := SealFrameInPlace(exact, cipher)
	if ok {
		t.Fatalf("exact-fit buffer accepted; sealed len=%d", len(got))
	}
	if !bytes.Equal(frame, before) {
		t.Fatal("refused seal mutated the frame")
	}
}

// TestSealFrameInPlaceNoneCipherIsIdentity pins the nil/none-cipher branch:
// the frame passes through unchanged (it already IS its sealed form).
func TestSealFrameInPlaceNoneCipherIsIdentity(t *testing.T) {
	frame := buildPackedTestFrame(t, 100, 37)
	before := append([]byte(nil), frame...)
	got, ok := SealFrameInPlace(frame, nil)
	if !ok || !bytes.Equal(got, frame) {
		t.Fatalf("nil cipher: ok=%v aliased=%v", ok, bytes.Equal(got, frame))
	}
	none, err := NewObfCipher(ObfAlgoNone, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, ok = SealFrameInPlace(frame, none)
	if !ok || !bytes.Equal(got, before) {
		t.Fatalf("none cipher: ok=%v unchanged=%v", ok, bytes.Equal(got, before))
	}
}

// buildPackedTestFrame builds a packed obfuscate frame of the given payload
// and padding lengths, the way FramePacker.Pack would. The backing array
// carries 64 bytes of spare capacity, mirroring the pooled buffers the node
// hands it (SealFrameInPlace needs that headroom for the AEAD tag).
func buildPackedTestFrame(t *testing.T, payloadLen, paddingLen int) []byte {
	t.Helper()
	buf := make([]byte, HeaderLen+payloadLen+paddingLen, HeaderLen+payloadLen+paddingLen+64)
	frame := buf[:HeaderLen+payloadLen+paddingLen]
	binary.BigEndian.PutUint16(frame[0:2], uint16(FrameMagic))
	binary.BigEndian.PutUint64(frame[2:10], 0x10000000abcd) // arbitrary structured-ish seq
	frame[10] = ObfAlgoAESGCM                               // algo byte; seal rewrites nothing here
	binary.BigEndian.PutUint16(frame[11:13], uint16(payloadLen))
	binary.BigEndian.PutUint16(frame[13:15], uint16(paddingLen))
	for i := range frame[HeaderLen:] {
		frame[HeaderLen+i] = byte(i * 7)
	}
	return frame
}
