package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestBootRelayBlacklistLifecycle(t *testing.T) {
	n := &Node{bootRelayBlacklist: make(map[peer.ID]time.Time)}
	p := peer.ID("boot1")

	if n.isBootRelayBlacklisted(p) {
		t.Fatal("fresh boot should not be blacklisted")
	}
	n.blacklistBootRelay(p)
	if !n.isBootRelayBlacklisted(p) {
		t.Fatal("blacklisted boot should report as blacklisted")
	}

	// An expired entry must be purged on access so a boot that later comes up
	// is retried instead of being permanently avoided.
	n.bootRelayBlacklist[p] = time.Now().Add(-time.Minute)
	if n.isBootRelayBlacklisted(p) {
		t.Fatal("expired blacklist entry should be purged on access")
	}
}
