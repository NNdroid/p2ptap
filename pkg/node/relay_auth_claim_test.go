package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// TestTryClaimRelayAuthCooldown covers the three claim outcomes of the shared
// relay-auth gate: first claim wins, a concurrent claim loses (single-flight),
// and a claim within the retry cooldown of a RELEASED attempt loses until the
// cooldown expires. The cooldown is what stops the TAP hot path's per-frame
// ensureRelayAuth goroutines from storming a dead boot with full PSK
// handshakes; single-flight alone only deduplicates concurrent attempts.
func TestTryClaimRelayAuthCooldown(t *testing.T) {
	n := &Node{
		relayAuthInProgress:  make(map[peer.ID]bool),
		relayAuthLastAttempt: make(map[peer.ID]time.Time),
	}
	p := peer.ID("12D3KooWTestPeer")
	other := peer.ID("12D3KooWOtherPeer")

	if !n.tryClaimRelayAuth(p) {
		t.Fatal("first claim for a fresh peer must succeed")
	}
	if n.tryClaimRelayAuth(p) {
		t.Fatal("second claim while in progress must fail (single-flight)")
	}
	// A different peer is not affected by p's claim.
	if !n.tryClaimRelayAuth(other) {
		t.Fatal("claim for an unrelated peer must succeed")
	}
	n.releaseRelayAuthClaim(other)

	// Release the claim: single-flight no longer blocks, but the cooldown does.
	n.releaseRelayAuthClaim(p)
	if n.tryClaimRelayAuth(p) {
		t.Fatal("claim within the retry cooldown must fail")
	}

	// Backdate the attempt past the cooldown: the next claim succeeds.
	n.relayAuthMu.Lock()
	n.relayAuthLastAttempt[p] = time.Now().Add(-relayAuthRetryCooldown - time.Second)
	n.relayAuthMu.Unlock()
	if !n.tryClaimRelayAuth(p) {
		t.Fatal("claim after the cooldown expired must succeed")
	}
	n.releaseRelayAuthClaim(p)
}
