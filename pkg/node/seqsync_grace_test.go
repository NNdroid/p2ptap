package node

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/obfuscate"
)

// TestRxKeyGraceAbsorbsLingeringOldConnectionFrame proves the post-clear key
// grace window: when this node clears a peer's cipher on disconnect but the
// peer keeps its previous session open and keeps sealing frames with the OLD
// key for a few seconds, the next DIRECT re-handshake must seed the OLD RX
// cipher as a fallback so those straggler frames open instead of being dropped.
//
// This is the production failure in the 2026-08-12 16:47 log: a fresh handshake
// committed rxKeyFP=a00b8521 and most frames decrypted fine, but one frame
// (seqID ...818) arrived from the peer's still-alive OLD connection sealed with
// the pre-reconnect key and failed AEAD. Previously that frame was dropped;
// with the grace window it is absorbed.
func TestRxKeyGraceAbsorbsLingeringOldConnectionFrame(t *testing.T) {
	const algo = obfuscate.ObfAlgoChaCha20
	keyOld := make([]byte, 32)
	for i := range keyOld {
		keyOld[i] = byte(i + 11)
	}
	keyNew := make([]byte, 32)
	for i := range keyNew {
		keyNew[i] = byte(123 - i)
	}
	cOld, err := obfuscate.NewObfCipher(algo, keyOld)
	if err != nil {
		t.Fatalf("old cipher build: %v", err)
	}
	cNew, err := obfuscate.NewObfCipher(algo, keyNew)
	if err != nil {
		t.Fatalf("new cipher build: %v", err)
	}

	n := &Node{
		peerReady:              sync.Map{},
		peerRxDecryptRecentErrs: sync.Map{},
		handshakeFingerprint:   atomic.Pointer[string]{},
	}
	tbl := make(map[peer.ID]*PeerObf)
	n.perPeerObf.Store(&tbl)

	p := newTestPeerID(t)

	// 1) Peer negotiated with the OLD key (rxCipher = cOld).
	n.storePeerObf(p, &PeerObf{
		algo:       algo,
		txCipher:   cOld,
		rxCipher:   cOld,
		negotiated: true,
		txKey:      append([]byte(nil), keyOld...),
		rxKey:      append([]byte(nil), keyOld...),
	})

	// 2) Disconnect clears the cipher but captures the OLD RX key into the grace
	//    window (the real removePeerObf path).
	n.captureRxKeyGrace(p)
	if _, ok := n.rxKeyGrace.Load(p); !ok {
		t.Fatalf("expected rxKeyGrace to retain the cleared RX key")
	}

	// 3) Next DIRECT re-handshake negotiates a NEW key (perPeerObf now has no
	//    entry for p). SeedPrevRxFromGrace must carry the OLD cipher forward.
	po := &PeerObf{
		algo:       algo,
		txCipher:   cNew,
		rxCipher:   cNew,
		negotiated: true,
		txKey:      append([]byte(nil), keyNew...),
		rxKey:      append([]byte(nil), keyNew...),
	}
	if !n.seedPrevRxFromGrace(p, po) {
		t.Fatalf("expected grace key to be seeded on post-clear re-handshake")
	}
	if len(po.rxRing) == 0 {
		t.Fatalf("RX ring not seeded from grace window (want OLD cipher retained)")
	}
	n.storePeerObf(p, po)

	// Build a valid packed frame sealed with the OLD key (a lingering
	// old-connection frame). Mirrors EncryptPayloadRegion's contract.
	const plain = "lingering-old-connection-frame"
	plainBytes := []byte(plain)
	const hLen = 15
	frame := make([]byte, hLen+len(plainBytes))
	for i := 0; i < 10; i++ {
		frame[i] = byte(i + 5)
	}
	frame[10] = 0x01
	frame[13] = 0x02
	binary.BigEndian.PutUint16(frame[11:13], uint16(len(plainBytes)))
	copy(frame[hLen:], plainBytes)
	encOld, err := obfuscate.EncryptPayloadRegion(frame, cOld)
	if err != nil {
		t.Fatalf("encrypt with old key: %v", err)
	}

	// The NEW (current) RX cipher must NOT open it...
	if _, _, garbage := n.decryptPeerFrame(encOld, p); garbage {
		t.Fatalf("current NEW key unexpectedly opened an OLD-key frame (premise broken)")
	}
	// ...but the grace-seeded previous cipher must, so the link tolerates the
	// lingering old-connection frame instead of dropping it.
	dec, decrypted, garbage := n.decryptPeerFrame(encOld, p)
	if garbage {
		t.Fatalf("expected OLD-key lingering frame to open via grace fallback, got garbage")
	}
	if !decrypted {
		t.Fatalf("expected decrypted=true via grace fallback, got false")
	}
	if string(dec[hLen:hLen+len(plainBytes)]) != plain {
		t.Fatalf("grace fallback decrypted wrong payload: got %q want %q", string(dec[hLen:hLen+len(plainBytes)]), plain)
	}

	// And a frame sealed with the NEW key still opens on the current cipher.
	encNew, err := obfuscate.EncryptPayloadRegion(frame, cNew)
	if err != nil {
		t.Fatalf("encrypt with new key: %v", err)
	}
	if _, decrypted, garbage := n.decryptPeerFrame(encNew, p); garbage || !decrypted {
		t.Fatalf("expected NEW-key frame to open on current cipher (garbage=%v decrypted=%v)", garbage, decrypted)
	}
}
