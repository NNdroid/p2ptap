package node

import (
	"bytes"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/obfuscate"
)

// minimalDecryptNode builds the smallest Node that decryptPeerFrame touches.
// Mirrors the harness in seqsync_ring_test.go.
func minimalDecryptNode() *Node {
	return &Node{
		peerReady:               sync.Map{},
		peerRxDecryptRecentErrs: sync.Map{},
		handshakeFingerprint:    atomic.Pointer[string]{},
	}
}

func sealWithCipher(t *testing.T, c obfuscate.ObfCipher, plain string) []byte {
	const hLen = 15
	frame := make([]byte, hLen+len(plain))
	for i := 0; i < 10; i++ {
		frame[i] = byte(i)
	}
	frame[10] = 0x01
	frame[13] = 0x02
	binary.BigEndian.PutUint16(frame[11:13], uint16(len(plain)))
	copy(frame[hLen:], plain)
	enc, err := obfuscate.EncryptPayloadRegion(frame, c)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return enc
}

// TestDecryptPeerFrameRolloverPrevGen proves the SINGLE-connection key ROLLOVER
// tolerance (Risk #3). When a peer rekeys, its TX side may briefly keep sealing
// with the PREVIOUS generation key while our RX slot has already moved to the new
// key. decryptPeerFrame must try prevRxCipher before declaring garbage — this is
// the "link looks healthy but frames silently dropped right after a rekey"
// failure mode.
func TestDecryptPeerFrameRolloverPrevGen(t *testing.T) {
	const algo = obfuscate.ObfAlgoChaCha20
	mkCipher := func(base byte) obfuscate.ObfCipher {
		k := make([]byte, 32)
		for i := range k {
			k[i] = base + byte(i)
		}
		c, err := obfuscate.NewObfCipher(algo, k)
		if err != nil {
			t.Fatalf("cipher build: %v", err)
		}
		return c
	}
	cur := mkCipher(10)
	prev := mkCipher(20)

	n := minimalDecryptNode()
	tbl := make(map[peer.ID]*PeerObf)
	n.perPeerObf.Store(&tbl)
	p := newTestPeerID(t)
	n.storePeerObf(p, &PeerObf{
		algo:         algo,
		txCipher:     cur,
		rxCipher:     cur,
		negotiated:   true,
		txKey:        append([]byte(nil), make([]byte, 32)...),
		rxKey:        append([]byte(nil), make([]byte, 32)...),
		prevRxCipher: prev,
		prevRxKey:    append([]byte(nil), make([]byte, 32)...),
	})

	// Frame sealed with the PREV gen key must open via prevRxCipher fallback.
	oldFrame := sealWithCipher(t, prev, "still-sealing-with-old-key")
	dec, ok, garb := n.decryptPeerFrame(oldFrame, p)
	if garb || !ok {
		t.Fatalf("prev-gen frame must open via prevRxCipher: ok=%v garb=%v", ok, garb)
	}
	if !bytes.Equal(dec[15:], []byte("still-sealing-with-old-key")) {
		t.Fatalf("prev-gen decrypted wrong payload: %q", dec[15:])
	}

	// Current gen must still open directly.
	curFrame := sealWithCipher(t, cur, "current-key-frame")
	if _, ok, garb := n.decryptPeerFrame(curFrame, p); garb || !ok {
		t.Fatalf("current gen must open directly: ok=%v garb=%v", ok, garb)
	}
}

// TestDecryptPeerFrameStructuralCorruptionNotGarbage proves a payload that is NOT
// a well-formed obfuscate frame (obfuscate.ErrFrameCorrupted) is returned as
// "not decrypted, not garbage". It must NOT count toward the decrypt-fail counter
// that triggers ForceSyncSeq — a malformed frame is structural, not a key
// divergence, so we must not thrash the re-handshake on it.
func TestDecryptPeerFrameStructuralCorruptionNotGarbage(t *testing.T) {
	const algo = obfuscate.ObfAlgoChaCha20
	k := make([]byte, 32)
	for i := range k {
		k[i] = 0x42
	}
	c, err := obfuscate.NewObfCipher(algo, k)
	if err != nil {
		t.Fatalf("cipher build: %v", err)
	}
	n := minimalDecryptNode()
	tbl := make(map[peer.ID]*PeerObf)
	n.perPeerObf.Store(&tbl)
	p := newTestPeerID(t)
	n.storePeerObf(p, &PeerObf{
		algo:       algo,
		txCipher:   c,
		rxCipher:   c,
		negotiated: true,
		txKey:      append([]byte(nil), make([]byte, 32)...),
		rxKey:      append([]byte(nil), make([]byte, 32)...),
	})

	// A clearly-not-obfuscate blob (too short to carry an obfuscate header).
	junk := []byte("this is not an obfuscate frame at all, just random bytes")
	_, ok, garb := n.decryptPeerFrame(junk, p)
	if ok {
		t.Fatalf("junk must not decrypt")
	}
	if garb {
		t.Fatalf("structurally-malformed frame must NOT be flagged garbage (would wrongly trigger resync)")
	}
}
