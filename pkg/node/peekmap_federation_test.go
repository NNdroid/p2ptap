package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"

	"p2ptap/pkg/tap"
)

// newFederationTestNode spins up a node with a MemTAP, suitable for exercising
// peek-map ingest logic.
func newFederationTestNode(t *testing.T, v4, v6 string) *Node {
	t.Helper()
	dev, _ := tap.NewMemTAPPair("fedTap"+v4, "fedPipe"+v4)
	cfg := createTestNodeConfig(v4, v6, "best_path")
	n, err := NewNodeWithTAP(cfg, dev, nil)
	if err != nil {
		t.Fatalf("create node %s: %v", v4, err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

// TestRegisterPeekMapAddrsAcceptsOwnAndRejectsForged covers the endpoint
// propagation that makes a peer discovered across a federated boot backbone
// actually DIALABLE.
//
// The forgery case is the important one: peek-map frames are relayed by a boot
// and re-stamped with the *publisher's* ID, but the payload is opaque to the
// boot. A malicious publisher could therefore attach addresses claiming to
// belong to a different peer. Accepting those would let it redirect other
// peers' dials to an address it controls, so an address whose embedded /p2p/<id>
// disagrees with the publisher must be dropped.
func TestRegisterPeekMapAddrsAcceptsOwnAndRejectsForged(t *testing.T) {
	n := newFederationTestNode(t, "10.9.0.1/24", "fd09::1/64")

	publisher := test.RandPeerIDFatal(t)
	victim := test.RandPeerIDFatal(t)

	n.registerPeekMapAddrs(publisher, []string{
		"/ip4/203.0.113.10/tcp/4001",                            // plain addr -> accept
		"/ip4/203.0.113.11/udp/4001/quic-v1/p2p/" + publisher.String(), // own /p2p/ suffix -> strip + accept
		"/ip4/203.0.113.12/tcp/4001/p2p/" + victim.String(),     // claims another peer -> reject
		"totally-not-a-multiaddr",                               // garbage -> skip
	})

	got := n.Host.Peerstore().Addrs(publisher)
	if len(got) != 2 {
		t.Fatalf("expected 2 accepted addrs for the publisher, got %d: %v", len(got), got)
	}
	for _, a := range got {
		s := a.String()
		if s == "/ip4/203.0.113.12/tcp/4001" {
			t.Fatalf("accepted a forged address that claimed to belong to %s", victim.ShortString())
		}
		// The /p2p/ component must be stripped, otherwise the peerstore entry is
		// not usable for dialling.
		if len(s) > 0 && s != "/ip4/203.0.113.10/tcp/4001" && s != "/ip4/203.0.113.11/udp/4001/quic-v1" {
			t.Fatalf("unexpected stored addr %q", s)
		}
	}
	// The victim must not have gained an address from someone else's claim.
	if vaddrs := n.Host.Peerstore().Addrs(victim); len(vaddrs) != 0 {
		t.Fatalf("forged address leaked into victim's peerstore entry: %v", vaddrs)
	}

	// No addrs must be a no-op rather than an error.
	before := len(n.Host.Peerstore().Addrs(publisher))
	n.registerPeekMapAddrs(publisher, nil)
	if after := len(n.Host.Peerstore().Addrs(publisher)); after != before {
		t.Fatalf("nil addr list changed the peerstore (%d -> %d)", before, after)
	}
}

// TestConsiderDiscoveredBootDecisions pins the guardrails on cluster stitching.
// Attaching to a boot found over the backbone is what makes a remote cluster
// reachable, but doing it unconditionally would (a) let every client fan out to
// every boot in the federation, defeating the point of separate clusters, and
// (b) permanently give up on a boot whose first announcement arrived before its
// addresses did.
func TestConsiderDiscoveredBootDecisions(t *testing.T) {
	n := newFederationTestNode(t, "10.9.0.2/24", "fd09::2/64")

	countMarked := func() int {
		c := 0
		n.discoveredBoots.Range(func(_, _ any) bool { c++; return true })
		return c
	}

	// 1. Self is never a discovery target.
	n.considerDiscoveredBoot(n.Host.ID())
	if countMarked() != 0 {
		t.Fatalf("self must not be marked as a discovered boot")
	}

	// 2. A boot with no known endpoint must NOT stay marked — otherwise the
	// retry on the next announcement (which may carry addrs) never happens.
	noAddr := test.RandPeerIDFatal(t)
	n.considerDiscoveredBoot(noAddr)
	if _, seen := n.discoveredBoots.Load(noAddr); seen {
		t.Fatalf("a boot with no dialable addr must not be marked, so a later " +
			"announcement carrying addresses can retry")
	}

	// 3. The feature switch must be honoured.
	withAddr := test.RandPeerIDFatal(t)
	n.registerPeekMapAddrs(withAddr, []string{"/ip4/203.0.113.20/tcp/4001"})
	n.Config.DiscoverBootMesh = false
	n.considerDiscoveredBoot(withAddr)
	if _, seen := n.discoveredBoots.Load(withAddr); seen {
		t.Fatalf("DiscoverBootMesh=false must prevent attaching to discovered boots")
	}
	n.Config.DiscoverBootMesh = true

	// 4. A boot already in our own config belongs to the normal bootstrap path.
	configured := test.RandPeerIDFatal(t)
	n.Config.BootstrapPeers = []string{"/ip4/203.0.113.30/tcp/4001/p2p/" + configured.String()}
	if !n.isBootstrapPeer(configured) {
		t.Fatalf("precondition: %s should be recognised as a configured bootstrap peer", configured.ShortString())
	}
	n.considerDiscoveredBoot(configured)
	if _, seen := n.discoveredBoots.Load(configured); seen {
		t.Fatalf("a configured bootstrap peer must not be double-tracked as a discovered boot")
	}

	// 5. Cap enforcement: pre-fill the tracker to the cap, then verify a new
	// candidate WITH a usable address is refused.
	for i := 0; i < maxDiscoveredBoots; i++ {
		n.discoveredBoots.Store(test.RandPeerIDFatal(t), struct{}{})
	}
	overflow := test.RandPeerIDFatal(t)
	n.registerPeekMapAddrs(overflow, []string{"/ip4/203.0.113.40/tcp/4001"})
	n.considerDiscoveredBoot(overflow)
	if _, seen := n.discoveredBoots.Load(overflow); seen {
		t.Fatalf("attached to a %d-th discovered boot despite the cap of %d",
			maxDiscoveredBoots+1, maxDiscoveredBoots)
	}
}

// TestConsiderDiscoveredBootUsesExistingConnection verifies the already-attached
// path: when the boot is reachable we only need to subscribe to its peek-map, so
// its cluster's clients start flowing to us. This is the branch that actually
// merges two clusters into one relay domain.
func TestConsiderDiscoveredBootUsesExistingConnection(t *testing.T) {
	n := newFederationTestNode(t, "10.9.0.3/24", "fd09::3/64")
	fakeBoot := newFederationTestNode(t, "10.9.0.4/24", "fd09::4/64")

	// Attach first, mimicking a boot we are already talking to.
	if err := n.Host.Connect(n.ctx, peer.AddrInfo{
		ID:    fakeBoot.Host.ID(),
		Addrs: fakeBoot.Host.Addrs(),
	}); err != nil {
		t.Fatalf("connect to fake boot: %v", err)
	}

	n.considerDiscoveredBoot(fakeBoot.Host.ID())

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, seen := n.discoveredBoots.Load(fakeBoot.Host.ID()); seen {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("an already-connected discovered boot was never tracked, so we would " +
				"never subscribe to its peek-map and never see its cluster's clients")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Idempotency: a repeat announcement must not re-trigger anything.
	before := 0
	n.discoveredBoots.Range(func(_, _ any) bool { before++; return true })
	n.considerDiscoveredBoot(fakeBoot.Host.ID())
	after := 0
	n.discoveredBoots.Range(func(_, _ any) bool { after++; return true })
	if before != after {
		t.Fatalf("repeat announcement changed tracker size (%d -> %d)", before, after)
	}
}

// TestLocalPeekMapNodeInfoCarriesEndpoints guards the publisher side: if we stop
// advertising our own addresses, every peer that learns about us indirectly
// (through a boot, or across a federated backbone) becomes visible-but-
// unreachable, which is a silent failure mode.
func TestLocalPeekMapNodeInfoCarriesEndpoints(t *testing.T) {
	n := newFederationTestNode(t, "10.9.0.5/24", "fd09::5/64")

	info := n.localPeekMapNodeInfo()
	if info.PeerID != n.Host.ID().String() {
		t.Fatalf("peer_id mismatch: %s vs %s", info.PeerID, n.Host.ID().String())
	}
	if info.IsBoot {
		t.Fatalf("a mesh member must not announce itself as a boot")
	}
	if len(info.Addrs) == 0 {
		t.Fatalf("localPeekMapNodeInfo published no addrs — peers that learn about us " +
			"indirectly would have no way to dial us")
	}
	if len(info.Addrs) != len(n.Host.Addrs()) {
		t.Fatalf("expected all %d host addrs to be published, got %d",
			len(n.Host.Addrs()), len(info.Addrs))
	}
	// The published form must round-trip back into the peerstore.
	peerB := newFederationTestNode(t, "10.9.0.6/24", "fd09::6/64")
	peerB.registerPeekMapAddrs(n.Host.ID(), info.Addrs)
	if got := peerB.Host.Peerstore().Addrs(n.Host.ID()); len(got) == 0 {
		t.Fatalf("published addrs did not survive the round-trip into a peer's peerstore")
	}
}
