package node

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/tap"
)

// newTestPeerID mints a fresh random libp2p peer ID for use as a (re)connecting
// peer in handshake-level tests.
func newTestPeerID(t *testing.T) peer.ID {
	t.Helper()
	_, pub, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("failed to generate test peer key: %v", err)
	}
	p, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to derive test peer ID: %v", err)
	}
	return p
}

// simulateHandshake mirrors the PFS key path used by a single SeqSync handshake
// with peer p:
//  1. mint a ONE-SHOT ephemeral ECDH key locally (mintObfHandshakeKey);
//  2. derive its public key (obfPubFromPair) and fingerprint;
//  3. record the fingerprint via setHandshakeFingerprint, so ObfFingerprint()
//     reflects the latest handshake key (per the user's PFS enhancement).
//
// It returns the fingerprint that the handshake recorded, which must differ
// across two independent handshakes (each mints a brand-new ephemeral key).
func (n *Node) simulateHandshake(t *testing.T, p peer.ID) string {
	t.Helper()
	kp := n.mintObfHandshakeKey(p)
	if kp == nil {
		t.Fatalf("mintObfHandshakeKey returned nil for %s", p)
	}
	pub := n.obfPubFromPair(kp)
	if len(pub) == 0 {
		t.Fatalf("mintObfHandshakeKey produced empty pub for %s", p)
	}
	t.Logf("[handshake] minted ephemeral ECDH pub (%d bytes) for peer %s", len(pub), p.ShortString())
	fp := kp.Fingerprint()
	if fp == "" {
		t.Fatalf("mintObfHandshakeKey returned empty fingerprint for %s", p)
	}
	t.Logf("[handshake] derived fingerprint %s (PFS one-shot, NOT long-lived)", fp)
	n.setHandshakeFingerprint(fp)
	if got := n.ObfFingerprint(); got != fp {
		t.Fatalf("ObfFingerprint() = %q, want handshake fingerprint %q", got, fp)
	}
	return fp
}

// TestHandshakeFingerprintDiffersAcrossReconnects asserts the PFS property that
// two successive reconnect handshakes with the same peer produce different
// recorded fingerprints: each handshake mints a fresh one-shot ephemeral key,
// so ObfFingerprint() must change between reconnects.
func TestHandshakeFingerprintDiffersAcrossReconnects(t *testing.T) {
	// Run in memory mode: inject an in-memory TAP pair so the test needs no
	// real TAP/Wintun device or admin privileges (permissionless CI). The
	// simulated handshake only exercises mintObfHandshakeKey / ObfFingerprint,
	// which depend on n.obfKeyPair (set during construction) and not on a live
	// TAP data path.
	tapDev, _ := tap.NewMemTAPPair("tapTest", "pipeTest")
	n, err := NewNodeWithTAP(createTestNodeConfig("10.0.0.99/24", "fd00::99/64", "best_path"), tapDev, nil)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer n.Close()

	p := newTestPeerID(t)

	fp1 := n.simulateHandshake(t, p)
	fp2 := n.simulateHandshake(t, p)
	t.Logf("[handshake] reconnect 1 fp=%s | reconnect 2 fp=%s", fp1, fp2)

	if fp1 == fp2 {
		t.Fatalf("expected different fingerprints across two reconnects, both = %q (PFS one-shot key reuse!)", fp1)
	}
	if fp1 == "" || fp2 == "" {
		t.Fatalf("fingerprints must be non-empty: fp1=%q fp2=%q", fp1, fp2)
	}
	t.Log("[handshake] ✓ two reconnects produced distinct fingerprints (PFS verified)")
}

// TestHandshakeEphemeralCacheReusedWithinRound pins the regression fix for the
// "Rx 100% decrypt-fail, rxKeyFP constant, fundamentally divergent key" outage.
// The root cause was the responder committing a NEW cipher generation on every
// ack-send while the initiator (whose ack-reads were dropped over a lossy relay)
// stayed pinned to one — the two ends disagreed on the generation. The fix makes
// the negotiated cipher deterministic per handshake round by reusing the SAME
// one-shot ephemeral across all retries / self-heals. This test asserts:
//  1. repeated useCachedHandshakeEph calls within a round return the SAME key
//     (so every attempt derives the identical generation);
//  2. distinct peers never share an ephemeral;
//  3. clearCachedHandshakeEph forces a FRESH key on the next round (PFS intact).
func TestHandshakeEphemeralCacheReusedWithinRound(t *testing.T) {
	tapDev, _ := tap.NewMemTAPPair("tapTest", "pipeTest")
	n, err := NewNodeWithTAP(createTestNodeConfig("10.0.0.99/24", "fd00::99/64", "best_path"), tapDev, nil)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer n.Close()

	p1 := newTestPeerID(t)
	p2 := newTestPeerID(t)

	// Within one round, every call must return the SAME ephemeral.
	k1a := n.useCachedHandshakeEph(p1)
	k1b := n.useCachedHandshakeEph(p1)
	k1c := n.useCachedHandshakeEph(p1)
	if k1a == nil || k1b == nil || k1c == nil {
		t.Fatalf("useCachedHandshakeEph returned nil (encryption disabled?): a=%v b=%v c=%v", k1a, k1b, k1c)
	}
	if k1a.Fingerprint() != k1b.Fingerprint() || k1b.Fingerprint() != k1c.Fingerprint() {
		t.Fatalf("ephemeral NOT reused within a round: %s / %s / %s (would cause divergent generations on retry)",
			k1a.Fingerprint(), k1b.Fingerprint(), k1c.Fingerprint())
	}

	// A different peer must get a distinct ephemeral.
	k2 := n.useCachedHandshakeEph(p2)
	if k2 == nil {
		t.Fatalf("useCachedHandshakeEph(p2) returned nil")
	}
	if k2.Fingerprint() == k1a.Fingerprint() {
		t.Fatalf("two peers unexpectedly shared an ephemeral key: %s", k2.Fingerprint())
	}

	// Clearing the cache for p1 must force a FRESH key on the next round
	// (forward secrecy preserved across rounds), yet p2's cached key stays put.
	n.clearCachedHandshakeEph(p1)
	k1d := n.useCachedHandshakeEph(p1)
	if k1d == nil {
		t.Fatalf("useCachedHandshakeEph(p1) after clear returned nil")
	}
	if k1d.Fingerprint() == k1a.Fingerprint() {
		t.Fatalf("clearCachedHandshakeEph did NOT mint a fresh key: still %s", k1d.Fingerprint())
	}
	if n.useCachedHandshakeEph(p2).Fingerprint() != k2.Fingerprint() {
		t.Fatalf("clearing p1's cache disturbed p2's cached ephemeral")
	}

	t.Log("[handshake] ✓ ephemeral reused within a round, fresh after clear, per-peer isolated")
}
