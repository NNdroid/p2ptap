package node

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/obfuscate"
)

// TestDecryptPeerFrameMultiConnectionRing proves the receiver-side KEY RING
// fallback: a peer that holds several live ciphers at once (every live
// connection — DIRECT and CIRCUIT-RELAY — runs its own SeqSync handshake and
// therefore carries its own cipher, and the peer may round-robin outbound
// traffic across them) sends frames under several different keys. Because the
// per-peer RX slot holds only the CURRENT key, decryptPeerFrame must try the
// bounded ring of recent RX ciphers (newest-first) before declaring a frame
// garbage. This is the production failure where seqIDs alternate OK/FAIL with a
// strictly-increasing counter — the peer seals even frames with key A and odd
// frames with key B, so only one of them matches the current slot.
func TestDecryptPeerFrameMultiConnectionRing(t *testing.T) {
	const algo = obfuscate.ObfAlgoChaCha20

	mkKey := func(base byte) []byte {
		k := make([]byte, 32)
		for i := range k {
			k[i] = byte(base) + byte(i)
		}
		return k
	}
	keys := [3][]byte{mkKey(1), mkKey(100), mkKey(200)}
	ciphers := make([]obfuscate.ObfCipher, 3)
	for i, k := range keys {
		c, err := obfuscate.NewObfCipher(algo, k)
		if err != nil {
			t.Fatalf("cipher %d build: %v", i, err)
		}
		ciphers[i] = c
	}

	// Minimal Node carrying only the fields decryptPeerFrame touches.
	n := &Node{
		peerReady:              sync.Map{},
		peerRxDecryptRecentErrs: sync.Map{},
		handshakeFingerprint:   atomic.Pointer[string]{},
	}
	tbl := make(map[peer.ID]*PeerObf)
	n.perPeerObf.Store(&tbl)

	p := newTestPeerID(t)

	// Simulate THREE sequential (re)key handshakes — one per live connection —
	// exactly as negotiateObfWithPeer accumulates them: each commit pushes the
	// outgoing current RX cipher into the ring. After gen-3 commits, the ring
	// holds generations 1 and 2; current is generation 3.
	//
	// Commit order: gen1 → gen2 (ring=[1]) → gen3 (ring=[1,2]).
	n.storePeerObf(p, &PeerObf{
		algo: algo, txCipher: ciphers[0], rxCipher: ciphers[0], negotiated: true,
		txKey: append([]byte(nil), keys[0]...), rxKey: append([]byte(nil), keys[0]...),
	})
	n.storePeerObf(p, &PeerObf{
		algo: algo, txCipher: ciphers[1], rxCipher: ciphers[1], negotiated: true,
		txKey: append([]byte(nil), keys[1]...), rxKey: append([]byte(nil), keys[1]...),
		rxRing: []rxRingSlot{{cipher: ciphers[0], key: append([]byte(nil), keys[0]...)}},
	})
	n.storePeerObf(p, &PeerObf{
		algo: algo, txCipher: ciphers[2], rxCipher: ciphers[2], negotiated: true,
		txKey: append([]byte(nil), keys[2]...), rxKey: append([]byte(nil), keys[2]...),
		rxRing: []rxRingSlot{
			{cipher: ciphers[0], key: append([]byte(nil), keys[0]...)},
			{cipher: ciphers[1], key: append([]byte(nil), keys[1]...)},
		},
	})

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
		enc, err := obfuscate.EncryptPayloadRegion(frame, c)
		if err != nil {
			t.Fatalf("encrypt (%q): %v", plain, err)
		}
		return enc
	}

	// Current generation (3) must open on the first attempt.
	cur := sealWith(ciphers[2], "gen3-current-connection")
	if dec, ok, garb := n.decryptPeerFrame(cur, p); garb || !ok {
		t.Fatalf("current gen3 frame should open directly: decrypted=%v garbage=%v", ok, garb)
	} else if string(dec[hLen:hLen+len("gen3-current-connection")]) != "gen3-current-connection" {
		t.Fatalf("current gen3 decrypted wrong payload")
	}

	// Oldest generation (1) — the peer is STILL sealing with its DIRECT-connection
	// key while we flipped to the RELAY-connection key — must open via the ring.
	old := sealWith(ciphers[0], "gen1-old-direct-connection")
	if _, _, garb := n.decryptPeerFrame(old, p); garb {
		t.Fatalf("expected gen1 frame to open via ring, got garbage")
	}
	dec, ok, garb := n.decryptPeerFrame(old, p)
	if garb || !ok {
		t.Fatalf("gen1 frame must open via ring: decrypted=%v garbage=%v", ok, garb)
	}
	if string(dec[hLen:hLen+len("gen1-old-direct-connection")]) != "gen1-old-direct-connection" {
		t.Fatalf("gen1 ring-decrypted wrong payload")
	}

	// Middle generation (2) must also open via the ring.
	mid := sealWith(ciphers[1], "gen2-mid-connection")
	if dec, ok, garb := n.decryptPeerFrame(mid, p); garb || !ok {
		t.Fatalf("gen2 frame must open via ring: decrypted=%v garbage=%v", ok, garb)
	} else if string(dec[hLen:hLen+len("gen2-mid-connection")]) != "gen2-mid-connection" {
		t.Fatalf("gen2 ring-decrypted wrong payload")
	}

	// A frame sealed with a key we NEVER negotiated must remain garbage.
	rogueKey := mkKey(250)
	rogue, err := obfuscate.NewObfCipher(algo, rogueKey)
	if err != nil {
		t.Fatalf("rogue cipher build: %v", err)
	}
	rogueFrame := sealWith(rogue, "never-negotiated-key")
	if _, ok, garb := n.decryptPeerFrame(rogueFrame, p); !garb || ok {
		t.Fatalf("rogue-key frame must be garbage (garbage=%v decrypted=%v)", garb, ok)
	}
}
