package node

import (
	"crypto/rand"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/config"
	"p2ptap/pkg/obfuscate"
)

// TestSealPeerFrameCountsPerPeer verifies the core of the per-peer re-key change:
// every AEAD-encrypted frame sealed TO a given peer bumps that peer's own
// framesSinceRekey counter exactly once, and the counter is independent per peer
// (NOT the old process-wide FramePacker counter, which advanced for ALL peers).
// This is what lets a chatty peer rotate promptly while a quiet peer keeps its
// key longer, without ever touching the global nonce-safety guarantee.
func TestSealPeerFrameCountsPerPeer(t *testing.T) {
	algo := obfuscate.ObfAlgoChaCha20
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	cipher, err := obfuscate.NewObfCipher(algo, key)
	if err != nil {
		t.Fatalf("NewObfCipher: %v", err)
	}

	// A minimal Node needs only the per-peer table + a Packer to build a sample
	// frame to seal. sealPeerFrame never touches the libp2p Host.
	n := &Node{}
	fp := obfuscate.NewFramePackerFull(&config.ObfuscationConfig{Enable: true, Mode: "fixed", FixedSize: 512, BlockSize: 128})
	fp.SetSourceIdentity("testnode")
	seqID := fp.NextSeqID(0)
	buf := make([]byte, 4096)
	packedLen, perr := fp.Pack(seqID, []byte("payload-under-test"), buf)
	if perr != nil {
		t.Fatalf("Pack: %v", perr)
	}
	frame := buf[:packedLen]

	pA := peer.ID("peerA")
	pB := peer.ID("peerB")

	poA := &PeerObf{algo: algo, txCipher: cipher, rxCipher: cipher, negotiated: true, negotiatedAtSeq: 0}
	tbl := map[peer.ID]*PeerObf{pA: poA}
	n.perPeerObf.Store(&tbl)

	const nFrames = 7
	for i := 0; i < nFrames; i++ {
		out, serr := n.sealPeerFrame(pA, cipher, frame)
		if serr != nil {
			t.Fatalf("sealPeerFrame(peerA) iter %d: %v", i, serr)
		}
		if out == nil {
			t.Fatalf("sealPeerFrame(peerA) iter %d: nil output", i)
		}
	}
	if got := poA.framesSinceRekey.Load(); got != nFrames {
		t.Fatalf("peerA framesSinceRekey = %d, want %d", got, nFrames)
	}

	// A second peer has its OWN independent counter, and sealing to it does not
	// disturb peerA's count.
	poB := &PeerObf{algo: algo, txCipher: cipher, rxCipher: cipher, negotiated: true, negotiatedAtSeq: 0}
	tbl = map[peer.ID]*PeerObf{pB: poB}
	n.perPeerObf.Store(&tbl)

	if _, serr := n.sealPeerFrame(pB, cipher, frame); serr != nil {
		t.Fatalf("sealPeerFrame(peerB): %v", serr)
	}
	if got := poB.framesSinceRekey.Load(); got != 1 {
		t.Fatalf("peerB framesSinceRekey = %d, want 1", got)
	}
	// peerA's previously-stored po is untouched (it was replaced by the new table).
	if poA.framesSinceRekey.Load() != nFrames {
		t.Fatalf("peerA count mutated by peerB seal: got %d, want %d", poA.framesSinceRekey.Load(), nFrames)
	}
}

// TestSealPeerFrameNilCipher fails fast rather than shipping an unsealed frame.
// The previous inline EncryptPayloadRegion call would nil-panic on a nil cipher
// (data path); sealPeerFrame must surface that as an error so callers keep their
// "never ship unsealed" contract.
func TestSealPeerFrameNilCipher(t *testing.T) {
	n := &Node{}
	fp := obfuscate.NewFramePackerFull(&config.ObfuscationConfig{Enable: true, Mode: "fixed", FixedSize: 512, BlockSize: 128})
	fp.SetSourceIdentity("testnode")
	buf := make([]byte, 4096)
	packedLen, _ := fp.Pack(fp.NextSeqID(0), []byte("x"), buf)
	if _, err := n.sealPeerFrame(peer.ID("peerX"), nil, buf[:packedLen]); err == nil {
		t.Fatalf("expected error for nil cipher, got nil")
	}
}
