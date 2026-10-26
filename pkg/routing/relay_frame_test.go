package routing

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func generatePeer(t *testing.T) peer.ID {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("Key gen error: %v", err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("PeerID error: %v", err)
	}
	return id
}

func TestRelayFramePackUnpackV2(t *testing.T) {
	dst := generatePeer(t)
	src := generatePeer(t)
	payload := []byte("Hello P2PTAP Overlay Multi-Hop Relay Test Payload")
	ttl := uint8(4)
	t.Logf("[relay-frame] pack dst=%s src=%s ttl=%d payloadLen=%d", dst.ShortString(), src.ShortString(), ttl, len(payload))

	packed, err := PackRelayFrame(dst, src, ttl, payload)
	if err != nil {
		t.Fatalf("PackRelayFrame failed: %v", err)
	}
	t.Logf("[relay-frame] packed %d bytes", len(packed))

	rxDst, rxSrc, rxTTL, rxPayload, err := UnpackRelayFrame(packed)
	if err != nil {
		t.Fatalf("UnpackRelayFrame failed: %v", err)
	}

	if rxDst != dst {
		t.Errorf("Expected destination %s, got %s", dst, rxDst)
	}
	if rxSrc != src {
		t.Errorf("Expected source %s, got %s", src, rxSrc)
	}
	if rxTTL != ttl {
		t.Errorf("Expected TTL %d, got %d", ttl, rxTTL)
	}
	if !bytes.Equal(rxPayload, payload) {
		t.Errorf("Payload mismatch: got %s", string(rxPayload))
	}
	t.Logf("[relay-frame] ✓ round-trip dst=%s src=%s ttl=%d payloadLen=%d", rxDst.ShortString(), rxSrc.ShortString(), rxTTL, len(rxPayload))
}

func TestUnpackRelayFrame_Short(t *testing.T) {
	_, _, _, _, err := UnpackRelayFrame([]byte{0x02, 0x01, 0x00})
	if err == nil {
		t.Error("Expected error for short frame, got nil")
	} else {
		t.Logf("[relay-frame] ✓ short frame (%d bytes) rejected: %v", 3, err)
	}
}

func TestUnpackRelayFrame_BadVersion(t *testing.T) {
	_, _, _, _, err := UnpackRelayFrame([]byte{0xFF, 0x01, 0x00, 0x00})
	if err == nil {
		t.Error("Expected error for bad version, got nil")
	} else {
		t.Logf("[relay-frame] ✓ bad-version frame rejected: %v", err)
	}
}

func TestRelayFramePackUnpackV3(t *testing.T) {
	dst := generatePeer(t)
	src := generatePeer(t)
	payload := []byte("Hello P2PTAP Overlay Multi-Hop Relay Test Payload")
	ttl := uint8(3)

	packed, err := PackRelayFrameV3(dst, src, ttl, payload)
	if err != nil {
		t.Fatalf("PackRelayFrameV3 failed: %v", err)
	}

	// The header must be 0x03 and the peer IDs must be the raw multihash bytes,
	// not base58 text — that is the entire point of the version.
	if packed[0] != RelayHeaderVersionV3 {
		t.Fatalf("version byte = 0x%02x, want 0x%02x", packed[0], RelayHeaderVersionV3)
	}
	dstLen := int(binary.BigEndian.Uint16(packed[2:4]))
	if !bytes.Equal(packed[4:4+dstLen], []byte(dst)) {
		t.Fatalf("dst is not the raw multihash: %x", packed[4:4+dstLen])
	}

	rxDst, rxSrc, rxTTL, rxPayload, err := UnpackRelayFrame(packed)
	if err != nil {
		t.Fatalf("UnpackRelayFrame failed on v3 frame: %v", err)
	}
	if rxDst != dst {
		t.Errorf("Expected destination %s, got %s", dst, rxDst)
	}
	if rxSrc != src {
		t.Errorf("Expected source %s, got %s", src, rxSrc)
	}
	if rxTTL != ttl {
		t.Errorf("Expected TTL %d, got %d", ttl, rxTTL)
	}
	if !bytes.Equal(rxPayload, payload) {
		t.Errorf("Payload mismatch: got %s", string(rxPayload))
	}
}

// TestRelayFrameV3HeaderIsCompact pins the size and the encoding difference
// between the two versions. If this ever stops being smaller, the version byte
// is not buying anything and the config flag should be revisited.
func TestRelayFrameV3HeaderIsCompact(t *testing.T) {
	dst := generatePeer(t)
	src := generatePeer(t)
	payload := []byte("payload")

	v2, err := PackRelayFrame(dst, src, 1, payload)
	if err != nil {
		t.Fatalf("PackRelayFrame: %v", err)
	}
	v3, err := PackRelayFrameV3(dst, src, 1, payload)
	if err != nil {
		t.Fatalf("PackRelayFrameV3: %v", err)
	}

	if len(v3) >= len(v2) {
		t.Fatalf("v3 header is not smaller: v2=%d v3=%d", len(v2), len(v3))
	}
	if v2[0] != RelayHeaderVersion || v3[0] != RelayHeaderVersionV3 {
		t.Fatalf("version bytes v2=0x%02x v3=0x%02x", v2[0], v3[0])
	}
	// Same TTL, same payload, so the only difference is the header.
	if v2[1] != v3[1] {
		t.Errorf("ttl differs: v2=%d v3=%d", v2[1], v3[1])
	}
	if !bytes.Equal(v2[len(v2)-len(payload):], v3[len(v3)-len(payload):]) {
		t.Errorf("payload region differs between versions")
	}
	t.Logf("[relay-frame] v2=%d bytes, v3=%d bytes, saving %d (%.0f%%) per frame header",
		len(v2), len(v3), len(v2)-len(v3), 100*float64(len(v2)-len(v3))/float64(len(v2)))
}

// TestUnpackRelayFrameRejectsVersionSwap verifies that neither version can be
// mistaken for the other: a relabelled frame must fail, not silently decode
// garbage as a valid peer ID.
func TestUnpackRelayFrameRejectsVersionSwap(t *testing.T) {
	dst := generatePeer(t)
	src := generatePeer(t)

	v2, err := PackRelayFrame(dst, src, 1, []byte("p"))
	if err != nil {
		t.Fatalf("PackRelayFrame: %v", err)
	}
	relaided := append([]byte{}, v2...)
	relaided[0] = RelayHeaderVersionV3
	if _, _, _, _, err := UnpackRelayFrame(relaided); err == nil {
		t.Errorf("v2 frame relabelled as v3 was accepted (base58 text decoded as a multihash)")
	}

	v3, err := PackRelayFrameV3(dst, src, 1, []byte("p"))
	if err != nil {
		t.Fatalf("PackRelayFrameV3: %v", err)
	}
	downgraded := append([]byte{}, v3...)
	downgraded[0] = RelayHeaderVersion
	if _, _, _, _, err := UnpackRelayFrame(downgraded); err == nil {
		t.Errorf("v3 frame relabelled as v2 was accepted (raw multihash decoded as base58)")
	}
}

// TestUnpackRelayFrameV3RejectsBadMultihash checks the v3 path validates its
// peer IDs instead of casting arbitrary bytes.
func TestUnpackRelayFrameV3RejectsBadMultihash(t *testing.T) {
	dst := generatePeer(t)
	src := generatePeer(t)

	packed, err := PackRelayFrameV3(dst, src, 1, []byte("p"))
	if err != nil {
		t.Fatalf("PackRelayFrameV3: %v", err)
	}
	dstLen := int(binary.BigEndian.Uint16(packed[2:4]))
	corruptAt := map[string]int{
		"garbaged dst multihash": 4,
		"garbaged src multihash": 4 + dstLen + 2,
	}
	for name, off := range corruptAt {
		corrupt := append([]byte{}, packed...)
		corrupt[off] ^= 0xFF // destroys the multihash code byte
		if _, _, _, _, err := UnpackRelayFrame(corrupt); err == nil {
			t.Errorf("%s (offset %d): expected a rejected frame", name, off)
		}
	}
}

// TestUnpackRelayFrameV3RejectsBase58Text is the regression guard for why the
// v3 decoder checks the multihash code byte: mh.Cast accepts a base58 CID
// string as a raw multihash, so without the check a v3 field holding v2 text
// would decode to an unrelated peer ID rather than being rejected.
func TestUnpackRelayFrameV3RejectsBase58Text(t *testing.T) {
	dst := generatePeer(t)
	src := generatePeer(t)

	// mh.Cast alone happily accepts the base58 string as a multihash.
	if id, err := peer.IDFromBytes([]byte(dst.String())); err == nil {
		t.Logf("[relay-frame] mh.Cast accepts base58 text as a multihash: %s -> %s", dst.ShortString(), id.ShortString())
		if id == dst {
			t.Fatalf("test setup: base58 text decoded to the same peer ID, so this guard would be vacuous")
		}
	} else {
		t.Fatalf("test setup: peer.IDFromBytes rejected base58 text (%v), so the code-byte check is unneeded", err)
	}

	packed, err := PackRelayFrame(dst, src, 1, []byte("p"))
	if err != nil {
		t.Fatalf("PackRelayFrame: %v", err)
	}
	relaided := append([]byte{}, packed...)
	relaided[0] = RelayHeaderVersionV3
	if _, _, _, _, err := UnpackRelayFrame(relaided); err == nil {
		t.Errorf("v2 frame relabelled as v3 was accepted; base58 text must not pass as a multihash")
	}
}

// TestUnpackRelayFrameV3ClampsTTL confirms the attacker-controlled TTL clamp
// applies to the v3 header exactly as it does to v2.
func TestUnpackRelayFrameV3ClampsTTL(t *testing.T) {
	dst := generatePeer(t)
	src := generatePeer(t)

	packed, err := PackRelayFrameV3(dst, src, 255, []byte("p"))
	if err != nil {
		t.Fatalf("PackRelayFrameV3: %v", err)
	}
	_, _, ttl, _, err := UnpackRelayFrame(packed)
	if err != nil {
		t.Fatalf("UnpackRelayFrame: %v", err)
	}
	if ttl != MaxRelayTTL {
		t.Errorf("ttl = %d, want clamp to %d", ttl, MaxRelayTTL)
	}
}
