package node

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func mustPeerID(t *testing.T) peer.ID {
	t.Helper()
	k, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	pid, err := peer.IDFromPublicKey(k.GetPublic())
	if err != nil {
		t.Fatalf("IDFromPublicKey: %v", err)
	}
	return pid
}

func peerAddr(pid peer.ID, port int) multiaddr.Multiaddr {
	ma, err := multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/" + fmt.Sprintf("%d", port) + "/p2p/" + pid.String())
	if err != nil {
		panic(err)
	}
	return ma
}

// TestBuildConnManagerProtectsBootstrapAndStaticPeers pins the wiring that keeps
// a p2ptap bootstrap link from being silently trimmed. Before this, the node
// installed no ConnManager at all, so libp2p's default (160/192 connections, a
// trim pass every 10 s) was free to close them. Bootstrap links are the most
// idle-looking in the swarm, because peerPingPongLoop skips them on purpose —
// so they were the first candidates to be trimmed.
func TestBuildConnManagerProtectsBootstrapAndStaticPeers(t *testing.T) {
	bootA, bootB, staticC := mustPeerID(t), mustPeerID(t), mustPeerID(t)

	staticPeers := []string{
		peerAddr(staticC, 20002).String(), // valid, protected
		peerAddr(staticC, 20003).String(), // duplicate of the previous, not double-counted
		"definitely not a multiaddr",      // skipped
		"/ip4/1.2.3.4/tcp/5001",           // no /p2p/ component, skipped
		"",                                // empty, skipped
	}

	cm, n, err := buildConnManager([]peer.AddrInfo{
		{ID: bootA, Addrs: []multiaddr.Multiaddr{peerAddr(bootA, 20000)}},
		{ID: bootB, Addrs: []multiaddr.Multiaddr{peerAddr(bootB, 20001)}},
		{ID: staticC, Addrs: []multiaddr.Multiaddr{peerAddr(staticC, 20004)}},
	}, staticPeers)
	if err != nil {
		t.Fatalf("buildConnManager: %v", err)
	}
	if n != 3 {
		t.Fatalf("protected = %d, want 3 (2 bootstrap + 1 static, duplicates and garbage collapsed)", n)
	}
	for _, pid := range []peer.ID{bootA, bootB, staticC} {
		if !cm.IsProtected(pid, bootstrapConnProtectTag) {
			t.Fatalf("peer %s is not protected under %q", pid, bootstrapConnProtectTag)
		}
	}

	// An unlisted peer must not be protected: the tag is opt-in per peer.
	other := mustPeerID(t)
	if cm.IsProtected(other, "") {
		t.Fatalf("unrelated peer %s reports as protected", other)
	}

	// Protection must be revocable. Unprotect returns whether the peer is STILL
	// protected by some other tag, so false is the expected answer here.
	if still := cm.Unprotect(bootA, bootstrapConnProtectTag); still {
		t.Fatal("Unprotect reported another tag still protecting the peer")
	}
	if cm.IsProtected(bootA, "") {
		t.Fatalf("peer %s still protected after Unprotect", bootA)
	}
}

func TestBuildConnManagerWatermarks(t *testing.T) {
	if connMgrLowWater >= connMgrHighWater {
		t.Fatalf("watermarks low=%d high=%d", connMgrLowWater, connMgrHighWater)
	}
	cm, n, err := buildConnManager(nil, nil)
	if err != nil {
		t.Fatalf("buildConnManager: %v", err)
	}
	if n != 0 {
		t.Fatalf("empty input protected %d peers, want 0", n)
	}
	if cm == nil {
		t.Fatal("buildConnManager returned a nil manager")
	}
}
