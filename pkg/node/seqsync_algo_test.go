package node

import (
	"testing"

	"p2ptap/pkg/obfuscate"
)

// aesAlgos mirrors mySupportedAlgos() for an explicit "aes-gcm" config.
var aesAlgos = []byte{obfuscate.ObfAlgoAESGCM, obfuscate.ObfAlgoChaCha20, obfuscate.ObfAlgoNone}

// chaChaAlgos mirrors mySupportedAlgos() for "chacha20" or "auto".
var chaChaAlgos = []byte{obfuscate.ObfAlgoChaCha20, obfuscate.ObfAlgoAESGCM, obfuscate.ObfAlgoNone}

// noneAlgos mirrors mySupportedAlgos() for "none".
var noneAlgos = []byte{obfuscate.ObfAlgoNone}

// TestSelectAlgoSymmetricIsCommutative proves the negotiation never depends on
// which peer is "leader": selectAlgoSymmetric(a,b) == selectAlgoSymmetric(b,a).
// This is the regression lock for the old PeerID-ordered scheme that let a
// node's explicit config be silently overridden.
func TestSelectAlgoSymmetricIsCommutative(t *testing.T) {
	pairs := [][2][]byte{
		{aesAlgos, chaChaAlgos},
		{aesAlgos, aesAlgos},
		{chaChaAlgos, chaChaAlgos},
		{aesAlgos, noneAlgos},
		{chaChaAlgos, noneAlgos},
	}
	for _, p := range pairs {
		ab := selectAlgoSymmetric(p[0], p[1])
		ba := selectAlgoSymmetric(p[1], p[0])
		if ab != ba {
			t.Errorf("asymmetric negotiation: selectAlgoSymmetric(a,b)=%s but selectAlgoSymmetric(b,a)=%s for a=%v b=%v",
				obfuscate.AlgoName(ab), obfuscate.AlgoName(ba), p[0], p[1])
		}
	}
}

// TestSelectAlgoHonorsExplicitAES locks the exact bug the user hit: one peer
// configured "aes-gcm" (advertises AES first) while the other is "auto"
// (advertises ChaCha20 first). The negotiated algorithm MUST be AES — not
// ChaCha20, and not dependent on PeerID ordering.
func TestSelectAlgoHonorsExplicitAES(t *testing.T) {
	got := selectAlgoSymmetric(aesAlgos, chaChaAlgos)
	if got != obfuscate.ObfAlgoAESGCM {
		t.Fatalf("explicit AES peer + auto peer should negotiate AES, got %s", obfuscate.AlgoName(got))
	}
	// And the reversed argument order must yield the same (no PeerID dependence).
	gotRev := selectAlgoSymmetric(chaChaAlgos, aesAlgos)
	if gotRev != obfuscate.ObfAlgoAESGCM {
		t.Fatalf("reversed order should still be AES, got %s", obfuscate.AlgoName(gotRev))
	}
}

// TestSelectAlgoBothAutoDefaultsToChaCha20 locks the CPU-friendly default: when
// BOTH peers are "auto"/"chacha20" (no explicit pin), the negotiated algorithm
// follows the global default order [ChaCha20, AES, None] => ChaCha20.
func TestSelectAlgoBothAutoDefaultsToChaCha20(t *testing.T) {
	got := selectAlgoSymmetric(chaChaAlgos, chaChaAlgos)
	if got != obfuscate.ObfAlgoChaCha20 {
		t.Fatalf("both-auto should default to ChaCha20, got %s", obfuscate.AlgoName(got))
	}
}

// TestSelectAlgoPlaintextFallback locks that a peer configured "none" forces
// plaintext obfuscation regardless of the other side's preference.
func TestSelectAlgoPlaintextFallback(t *testing.T) {
	got := selectAlgoSymmetric(aesAlgos, noneAlgos)
	if got != obfuscate.ObfAlgoNone {
		t.Fatalf("explicit AES + none should negotiate plaintext, got %s", obfuscate.AlgoName(got))
	}
}
