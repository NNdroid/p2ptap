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

	packed, err := PackRelayFrame(dst, src, ttl, payload)
	if err != nil {
		t.Fatalf("PackRelayFrame failed: %v", err)
	}

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
}

func TestRelayFramePackUnpackV1(t *testing.T) {
	// Build a legacy v1 frame by hand to verify backward-compatible parsing.
	dst := generatePeer(t)
	src := generatePeer(t)
	payload := []byte("Legacy payload")
	ttl := uint8(3)

	// Use v2 pack but then extract the payload and manually reconstruct v1 offset.
	v2Packed, err := PackRelayFrame(dst, src, ttl, payload)
	if err != nil {
		t.Fatalf("PackRelayFrame v2 failed: %v", err)
	}

	// Header layout for v2:
	//   ver(1) ttl(1) dstLen(2) dst(dstLen) srcLen(2) src(srcLen) payload
	// For v1 we want:
	//   ver(1) ttl(1) dstLen(2) dst(dstLen) payload
	// But payload must be the same raw bytes — so we reconstruct v1 header
	// by appending the v2 payload to a v1 header.
	dstBytes := []byte(dst.String())
	dstLen := len(dstBytes)

	// Find where v2 payload starts: 1+1+2+dstLen+2+srcLen
	srcLen := len(src.String())
	v2PayloadStart := 6 + dstLen + srcLen
	v2Payload := v2Packed[v2PayloadStart:]

	// Build v1 header: ver=0x01 ttl dstLen dst
	buf := make([]byte, 4+dstLen+len(v2Payload))
	buf[0] = RelayHeaderVersionV1
	buf[1] = ttl
	binary.BigEndian.PutUint16(buf[2:4], uint16(dstLen))
	copy(buf[4:], dstBytes)
	copy(buf[4+dstLen:], v2Payload)

	// Verify raw header byte for byte.
	if buf[0] != 0x01 {
		t.Fatalf("Expected v1 header byte 0x01, got 0x%02x", buf[0])
	}

	rxDst, rxSrc, rxTTL, rxPayload, err := UnpackRelayFrame(buf)
	if err != nil {
		t.Fatalf("UnpackRelayFrame on v1 frame failed: %v", err)
	}

	if rxDst != dst {
		t.Errorf("v1: Expected destination %s, got %s", dst, rxDst)
	}
	if rxSrc != "" {
		t.Errorf("v1: Expected empty source, got %s", rxSrc)
	}
	if rxTTL != ttl {
		t.Errorf("v1: Expected TTL %d, got %d", ttl, rxTTL)
	}
	if !bytes.Equal(rxPayload, v2Payload) {
		t.Errorf("v1: Payload mismatch")
	}
}

func TestUnpackRelayFrame_Short(t *testing.T) {
	_, _, _, _, err := UnpackRelayFrame([]byte{0x02, 0x01, 0x00})
	if err == nil {
		t.Error("Expected error for short frame, got nil")
	}
}

func TestUnpackRelayFrame_BadVersion(t *testing.T) {
	_, _, _, _, err := UnpackRelayFrame([]byte{0xFF, 0x01, 0x00, 0x00})
	if err == nil {
		t.Error("Expected error for bad version, got nil")
	}
}
