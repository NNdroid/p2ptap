package routing

import (
	"bytes"
	"crypto/rand"
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
