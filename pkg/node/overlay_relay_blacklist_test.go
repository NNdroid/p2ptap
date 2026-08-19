package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// TestOverlayRelayBlacklistLifecycle verifies the overlay-relay-hop circuit
// breaker: a fresh hop is not blacklisted, blacklisting makes it report as
// blacklisted, and an expired entry is purged on access so a recovered hop is
// retried. Mirrors TestBootRelayBlacklistLifecycle.
func TestOverlayRelayBlacklistLifecycle(t *testing.T) {
	n := &Node{overlayRelayBlacklist: make(map[peer.ID]time.Time)}
	hop := peer.ID("overlayhop1")

	if n.isOverlayRelayBlacklisted(hop) {
		t.Fatal("fresh overlay relay hop should not be blacklisted")
	}
	n.blacklistOverlayRelay(hop)
	if !n.isOverlayRelayBlacklisted(hop) {
		t.Fatal("blacklisted overlay relay hop should report as blacklisted")
	}

	// An expired entry must be purged on access so a hop that later comes up is
	// retried instead of being permanently avoided.
	n.overlayRelayBlacklist[hop] = time.Now().Add(-time.Minute)
	if n.isOverlayRelayBlacklisted(hop) {
		t.Fatal("expired overlay blacklist entry should be purged on access")
	}
}

// TestOverlayRelayBlacklistNoExtend verifies that re-blacklisting an already
// active (non-expired) entry does NOT refresh/extend its expiry window, so a
// continuously-failing hop cannot keep pushing its blacklist into the future.
func TestOverlayRelayBlacklistNoExtend(t *testing.T) {
	n := &Node{overlayRelayBlacklist: make(map[peer.ID]time.Time)}
	hop := peer.ID("overlayhop2")

	n.blacklistOverlayRelay(hop)
	first := n.overlayRelayBlacklist[hop]

	// Advance the clock a little and re-blacklist; expiry must stay anchored to
	// the first call (TTL from the original blacklist, not a refresh).
	time.Sleep(20 * time.Millisecond)
	n.blacklistOverlayRelay(hop)
	second := n.overlayRelayBlacklist[hop]
	if second.After(first.Add(10 * time.Millisecond)) {
		t.Fatalf("re-blacklist should not extend expiry: first=%v second=%v", first, second)
	}
}
