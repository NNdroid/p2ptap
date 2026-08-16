package node

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/obfuscate"
)

// TestDecryptPeerFrameRolloverFallback proves the receiver-side dual-key
// fallback: when our RX cipher has been rotated to a NEW key but the peer is
// still sealing frames with its OLD key (it has not yet received our reciprocal
// "ready", or that "ready" was dropped over a lossy circuit-relay), frames
// encrypted with the OLD key must still open via the carried-forward previous
// RX cipher — instead of being dropped as garbage and stranding the link in a
// permanent decrypt-fail loop.
//
// This is the exact production failure mode: a single re-key flips our rxKey
// while the peer lags one generation, and every inbound frame fails AEAD-open
// until both sides converge. The fallback closes that window.
func TestDecryptPeerFrameRolloverFallback(t *testing.T) {
	const algo = obfuscate.ObfAlgoChaCha20
	keyOld := make([]byte, 32)
	for i := range keyOld {
		keyOld[i] = byte(i + 1)
	}
	keyNew := make([]byte, 32)
	for i := range keyNew {
		keyNew[i] = byte(200 - i)
	}
	cOld, err := obfuscate.NewObfCipher(algo, keyOld)
	if err != nil {
		t.Fatalf("old cipher build: %v", err)
	}
	cNew, err := obfuscate.NewObfCipher(algo, keyNew)
	if err != nil {
		t.Fatalf("new cipher build: %v", err)
	}

	// Minimal Node carrying only the fields decryptPeerFrame touches.
	n := &Node{
		peerReady:             sync.Map{},
		peerRxDecryptRecentErrs: sync.Map{},
		handshakeFingerprint:  atomic.Pointer[string]{},
	}
	tbl := make(map[peer.ID]*PeerObf)
	n.perPeerObf.Store(&tbl)

	p := newTestPeerID(t)

	// Step 1: peer negotiated with OLD key (rxCipher = cOld).
	n.storePeerObf(p, &PeerObf{
		algo:     algo,
		txCipher: cOld,
		rxCipher: cOld,
		negotiated: true,
		txKey:    append([]byte(nil), keyOld...),
		rxKey:    append([]byte(nil), keyOld...),
	})

	// Step 2: we rotate to NEW key; the previous RX cipher is carried forward
	// as the fallback (exactly what negotiateObfWithPeer does on a key change).
	n.storePeerObf(p, &PeerObf{
		algo:       algo,
		txCipher:   cNew,
		rxCipher:   cNew,
		negotiated: true,
		txKey:      append([]byte(nil), keyNew...),
		rxKey:      append([]byte(nil), keyNew...),
		prevRxCipher: cOld,
		prevRxKey:    append([]byte(nil), keyOld...),
	})

	// Build a valid packed frame sealed with the OLD key (the peer has not yet
	// rotated). Replicates EncryptPayloadRegion's contract: nonce derived from
	// the immutable header, payload at [hLen:hLen+pLen].
	const plain = "hello-p2ptap-rollover-window"
	plainBytes := []byte(plain)
	const hLen = 15
	frame := make([]byte, hLen+len(plainBytes))
	for i := 0; i < 10; i++ {
		frame[i] = byte(i)
	}
	frame[10] = 0x01
	frame[13] = 0x02
	binary.BigEndian.PutUint16(frame[11:13], uint16(len(plainBytes)))
	copy(frame[hLen:], plainBytes)
	enc, err := obfuscate.EncryptPayloadRegion(frame, cOld)
	if err != nil {
		t.Fatalf("encrypt with old key: %v", err)
	}

	// The NEW (current) RX cipher must NOT open it...
	if _, _, garbage := n.decryptPeerFrame(enc, p); garbage {
		t.Fatalf("current NEW key unexpectedly opened an OLD-key frame (test premise broken)")
	}
	// ...but decryptPeerFrame must fall back to the previous cipher and succeed.
	dec, decrypted, garbage := n.decryptPeerFrame(enc, p)
	if garbage {
		t.Fatalf("expected OLD-key frame to open via fallback, got garbage")
	}
	if !decrypted {
		t.Fatalf("expected decrypted=true via fallback, got false")
	}
	if string(dec[hLen:hLen+len(plainBytes)]) != plain {
		t.Fatalf("fallback decrypted wrong payload: got %q want %q", string(dec[hLen:hLen+len(plainBytes)]), plain)
	}
}
