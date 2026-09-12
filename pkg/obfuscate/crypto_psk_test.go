package obfuscate

import (
	"bytes"
	"testing"
)

// TestDeriveKeysPSKBinding locks the membership-isolation invariant of the
// SeqSync key schedule: folding the PSK into the HKDF salt (see DeriveKeysPSK)
// makes the per-peer AEAD keys reproducible ONLY by a peer that knows the same
// PSK. Without this, completing the identity-only libp2p transport handshake
// would be enough to mesh in a PSK "private" network.
func TestDeriveKeysPSKBinding(t *testing.T) {
	a, err := GenerateObfKeyPair()
	if err != nil {
		t.Fatalf("keypair A: %v", err)
	}
	b, err := GenerateObfKeyPair()
	if err != nil {
		t.Fatalf("keypair B: %v", err)
	}
	pubA, _ := a.PublicKeyBytes()
	pubB, _ := b.PublicKeyBytes()

	bothSamePSK := []byte("shared-network-secret")
	pskA := []byte("network-A")
	pskB := []byte("network-B")

	// Same PSK on both ends → identical (keyA,keyB), the normal mesh case.
	aKeyA, aKeyB, err := DeriveKeysPSK(a.priv, pubB, bothSamePSK)
	if err != nil {
		t.Fatalf("derive A: %v", err)
	}
	bKeyA, bKeyB, err := DeriveKeysPSK(b.priv, pubA, bothSamePSK)
	if err != nil {
		t.Fatalf("derive B: %v", err)
	}
	if !bytes.Equal(aKeyA, bKeyA) || !bytes.Equal(aKeyB, bKeyB) {
		t.Fatal("matching PSK must derive identical keys on both ends")
	}

	// Mismatched PSK → keys diverge: a wrong-PSK peer cannot decrypt or forge.
	wrongA, _, err := DeriveKeysPSK(a.priv, pubB, pskA)
	if err != nil {
		t.Fatalf("derive wrongA: %v", err)
	}
	wrongB, _, err := DeriveKeysPSK(b.priv, pubA, pskB)
	if err != nil {
		t.Fatalf("derive wrongB: %v", err)
	}
	if bytes.Equal(aKeyA, wrongA) {
		t.Fatal("PSK-A key must differ from the correct key")
	}
	if bytes.Equal(aKeyA, wrongB) {
		t.Fatal("PSK-B key must differ from the correct key")
	}
	// Two different wrong PSKs must also differ from each other.
	if bytes.Equal(wrongA, wrongB) {
		t.Fatal("distinct wrong PSKs must derive distinct keys")
	}

	// Empty PSK → byte-for-byte the legacy (no-salt) schedule.
	legacyA, legacyB, err := DeriveKeys(a.priv, pubB)
	if err != nil {
		t.Fatalf("derive legacy A: %v", err)
	}
	emptyA, emptyB, err := DeriveKeysPSK(a.priv, pubB, nil)
	if err != nil {
		t.Fatalf("derive empty-PSK A: %v", err)
	}
	if !bytes.Equal(legacyA, emptyA) || !bytes.Equal(legacyB, emptyB) {
		t.Fatal("empty PSK must match DeriveKeys (pre-binding compat)")
	}
	emptyB2, _, err := DeriveKeysPSK(b.priv, pubA, nil)
	if err != nil {
		t.Fatalf("derive empty-PSK B: %v", err)
	}
	if !bytes.Equal(legacyA, emptyB2) {
		t.Fatal("empty-PSK derivation must still match across the pair")
	}
}
