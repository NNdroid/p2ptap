package node

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/obfuscate"
)

// TestRemovePeerObfRetainsCipher is the regression test for the ROOT-CAUSE fix
// of the persistent "decrypt FAILED … (no fallback — …)" loops: removePeerObf
// must NOT wipe a peer's negotiated cipher + RX fallback ring on disconnect.
// Before this fix a disconnect rebuilt a fresh PeerObf (ring=0); the peer almost
// always reconnects and keeps sealing with its CURRENT key for a short window,
// but the fresh PeerObf could open none of those frames. Now the cipher + ring
// are retained so a reconnect is seamless and the re-handshake merely rotates.
//
// This is the production failure in the 2026-08-12 17:34:47 trace: a fresh
// PeerObf (ring=0, prevRxKeyFP=(none)) could not open any of the peer's
// in-flight frames even though the re-handshake "converged" — because the peer
// was still sealing with a pre-reconnect generation the wiped ring no longer
// held.
func TestRemovePeerObfRetainsCipher(t *testing.T) {
	const algo = obfuscate.ObfAlgoChaCha20
	mkKey := func(base byte) []byte {
		k := make([]byte, 32)
		for i := range k {
			k[i] = base + byte(i)
		}
		return k
	}
	kOld, kNew := mkKey(10), mkKey(200)
	cOld, err := obfuscate.NewObfCipher(algo, kOld)
	if err != nil {
		t.Fatalf("cOld build: %v", err)
	}
	cNew, err := obfuscate.NewObfCipher(algo, kNew)
	if err != nil {
		t.Fatalf("cNew build: %v", err)
	}

	// Minimal Node (Host intentionally nil — pushPeerEncryption must be
	// nil-safe so this path is unit-testable).
	n := &Node{
		peerReady:               sync.Map{},
		peerRxDecryptRecentErrs: sync.Map{},
		handshakeFingerprint:    atomic.Pointer[string]{},
	}
	tbl := make(map[peer.ID]*PeerObf)
	n.perPeerObf.Store(&tbl)

	p := newTestPeerID(t)

	// Peer negotiated with the CURRENT key and an older generation in the ring
	// (e.g. a lingering DIRECT-connection key while the RELAY-connection key is
	// current).
	n.storePeerObf(p, &PeerObf{
		algo:     algo,
		txCipher: cNew,
		rxCipher: cNew,
		negotiated: true,
		txKey:    append([]byte(nil), kNew...),
		rxKey:    append([]byte(nil), kNew...),
		rxRing:   []rxRingSlot{{cipher: cOld, key: append([]byte(nil), kOld...)}},
	})

	// Disconnect: the real removePeerObf path. Must RETAIN the entry.
	n.removePeerObf(p)
	if po := n.peerObf(p); po == nil {
		t.Fatalf("removePeerObf must retain the peer's cipher across disconnect (got nil)")
	} else {
		if po.rxCipher == nil {
			t.Fatalf("retained PeerObf lost its rxCipher")
		}
		if len(po.rxRing) != 1 {
			t.Fatalf("retained PeerObf must keep its RX ring (len=%d want 1)", len(po.rxRing))
		}
	}

	// The peer reconnects and keeps sealing with its OLD (DIRECT) key for a few
	// frames before flipping to the new key. Those frames MUST still open via the
	// RETAINED ring — this is exactly what the cleared-ring bug broke.
	const hLen = 15
	sealWith := func(c obfuscate.ObfCipher, plain string) []byte {
		plainBytes := []byte(plain)
		frame := make([]byte, hLen+len(plainBytes))
		for i := 0; i < 10; i++ {
			frame[i] = byte(i)
		}
		frame[10] = 0x01
		frame[13] = 0x02
		binary.BigEndian.PutUint16(frame[11:13], uint16(len(plainBytes)))
		copy(frame[hLen:], plainBytes)
		enc, e := obfuscate.EncryptPayloadRegion(frame, c)
		if e != nil {
			t.Fatalf("encrypt (%q): %v", plain, e)
		}
		return enc
	}
	oldFrame := sealWith(cOld, "pre-reconnect-direct-frame")
	if dec, ok, garb := n.decryptPeerFrame(oldFrame, p); garb || !ok {
		t.Fatalf("retained ring must open pre-reconnect OLD-key frame (decrypted=%v garbage=%v)", ok, garb)
	} else if string(dec[hLen:hLen+len("pre-reconnect-direct-frame")]) != "pre-reconnect-direct-frame" {
		t.Fatalf("retained ring decrypted wrong payload")
	}
	newFrame := sealWith(cNew, "post-reconnect-current-frame")
	if _, ok, garb := n.decryptPeerFrame(newFrame, p); garb || !ok {
		t.Fatalf("current NEW-key frame must open (decrypted=%v garbage=%v)", ok, garb)
	}
}

// TestRxKeyGraceRetainsFullRing proves the defense-in-depth hardening of the
// post-clear grace window: captureRxKeyGrace now snapshots the ENTIRE RX fallback
// ring (not just the last cipher), and seedPrevRxFromGrace replays it all. This
// covers the case where the peer holds several live generations at once
// (DIRECT + CIRCUIT-RELAY each negotiate their own cipher) and is still sealing
// with any of them on a lingering old stream after we reset.
func TestRxKeyGraceRetainsFullRing(t *testing.T) {
	const algo = obfuscate.ObfAlgoChaCha20
	mkKey := func(base byte) []byte {
		k := make([]byte, 32)
		for i := range k {
			k[i] = base + byte(i)
		}
		return k
	}
	k1, k2, k3 := mkKey(1), mkKey(100), mkKey(200)
	c1, e1 := obfuscate.NewObfCipher(algo, k1)
	if e1 != nil {
		t.Fatalf("c1 build: %v", e1)
	}
	c2, e2 := obfuscate.NewObfCipher(algo, k2)
	if e2 != nil {
		t.Fatalf("c2 build: %v", e2)
	}
	c3, e3 := obfuscate.NewObfCipher(algo, k3)
	if e3 != nil {
		t.Fatalf("c3 build: %v", e3)
	}

	n := &Node{
		peerReady:               sync.Map{},
		peerRxDecryptRecentErrs: sync.Map{},
		handshakeFingerprint:    atomic.Pointer[string]{},
	}
	tbl := make(map[peer.ID]*PeerObf)
	n.perPeerObf.Store(&tbl)
	p := newTestPeerID(t)

	// Current generation 3, with generations 1 and 2 retained in the ring.
	n.storePeerObf(p, &PeerObf{
		algo:     algo,
		txCipher: c3,
		rxCipher: c3,
		negotiated: true,
		txKey:    append([]byte(nil), k3...),
		rxKey:    append([]byte(nil), k3...),
		rxRing: []rxRingSlot{
			{cipher: c1, key: append([]byte(nil), k1...)},
			{cipher: c2, key: append([]byte(nil), k2...)},
		},
	})

	// Capture the full ring into the grace window (the real removePeerObf path).
	n.captureRxKeyGrace(p)
	g, ok := n.rxKeyGrace.Load(p)
	if !ok {
		t.Fatalf("rxKeyGrace must retain the full ring")
	}
	gk := g.(*rxGraceKey)
	if len(gk.ring) != 2 {
		t.Fatalf("grace ring must hold 2 generations (got %d)", len(gk.ring))
	}

	// A post-clear re-handshake seeds a FRESH po (current = gen3). seedPrevRxFromGrace
	// must replay the whole retained ring (the 2 OLDER generations; the primary is
	// already po.rxKey/current and is tried first by decryptPeerFrame) so ANY
	// lingering frame opens.
	po := &PeerObf{
		algo:     algo,
		txCipher: c3,
		rxCipher: c3,
		negotiated: true,
		txKey:    append([]byte(nil), k3...),
		rxKey:    append([]byte(nil), k3...),
	}
	if !n.seedPrevRxFromGrace(p, po) {
		t.Fatalf("expected grace key to seed on post-clear re-handshake")
	}
	// The 2 older generations land in the ring; the current (gen3) is po.rxKey.
	if len(po.rxRing) != 2 {
		t.Fatalf("seeded ring must hold 2 older generations (the primary is current), got %d", len(po.rxRing))
	}

	const hLen = 15
	sealWith := func(c obfuscate.ObfCipher, plain string) []byte {
		plainBytes := []byte(plain)
		frame := make([]byte, hLen+len(plainBytes))
		for i := 0; i < 10; i++ {
			frame[i] = byte(i)
		}
		frame[10] = 0x01
		frame[13] = 0x02
		binary.BigEndian.PutUint16(frame[11:13], uint16(len(plainBytes)))
		copy(frame[hLen:], plainBytes)
		enc, e := obfuscate.EncryptPayloadRegion(frame, c)
		if e != nil {
			t.Fatalf("encrypt (%q): %v", plain, e)
		}
		return enc
	}
	for _, tc := range []struct {
		c     obfuscate.ObfCipher
		plain string
	}{
		{c1, "gen1-direct-lingering"},
		{c2, "gen2-relay-lingering"},
		{c3, "gen3-current"},
	} {
		f := sealWith(tc.c, tc.plain)
		dec, ok, garb := n.decryptPeerFrame(f, p)
		if garb || !ok {
			t.Fatalf("frame %q must open via retained ring (decrypted=%v garbage=%v)", tc.plain, ok, garb)
		}
		if string(dec[hLen:hLen+len(tc.plain)]) != tc.plain {
			t.Fatalf("frame %q decrypted wrong payload: %q", tc.plain, string(dec[hLen:hLen+len(tc.plain)]))
		}
	}
}
