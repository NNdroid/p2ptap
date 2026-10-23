package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/test"
	"github.com/multiformats/go-multiaddr"
)

// TestPeekMapAddrRemovalRetractsOnlyNamedAddrs covers the retraction half of
// the boot's peer address announcements. A boot that sees a peer's real public
// address has to be able to withdraw it again when the peer moves network or
// drops a link — otherwise the mesh keeps dialing a dead NAT mapping until the
// TTL runs out, which on AddressTTL is an hour of wasted 15s dials per peer.
//
// The two properties that matter are immediacy (the address is gone on the next
// lookup, not after the TTL) and narrowness (only the named address is dropped,
// so the peer's circuit address and anything learned from the DHT survive).
func TestPeekMapAddrRemovalRetractsOnlyNamedAddrs(t *testing.T) {
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Skipf("libp2p.New: %v", err)
	}
	defer h.Close()
	n := &Node{Host: h}

	pID := test.RandPeerIDFatal(t)
	stranger := test.RandPeerIDFatal(t)

	const (
		// Bare form, as the addr book stores and returns it.
		keep    = "/ip4/203.0.113.5/udp/443/quic-v1"
		drop    = "/ip4/198.51.100.9/tcp/4001"
		sibling = "/ip4/192.0.2.77/tcp/8443"
	)
	suffixed := func(base, id string) string { return base + "/p2p/" + id }

	// An address the node already had from somewhere else — a retraction must
	// leave it alone.
	h.Peerstore().AddAddrs(pID, newAddrs(t, []string{sibling}), time.Hour)

	// Everything after the first two is a claim a node must refuse.
	n.registerPeekMapAddrs(pID, []string{
		suffixed(keep, pID.String()),
		suffixed(drop, pID.String()),
		"not-a-multiaddr",
		drop, // no /p2p/ suffix
		suffixed("/ip4/1.2.3.5/tcp/9", stranger.String()), // suffix names someone else
	})

	got := addrSet(h.Peerstore().Addrs(pID))
	for _, want := range []string{keep, drop, sibling} {
		if !got[want] {
			t.Fatalf("registered addrs missing %q: %v", want, got)
		}
	}

	// Immediacy: one lookup later the stale address must already be gone.
	n.removePeekMapAddrs(pID, []string{suffixed(drop, pID.String())})
	got = addrSet(h.Peerstore().Addrs(pID))
	if got[drop] {
		t.Fatalf("retracted addr %q still present immediately after removal: %v", drop, got)
	}
	for _, want := range []string{keep, sibling} {
		if !got[want] {
			t.Fatalf("removal of %q took away an unrelated addr %q: %v", drop, want, got)
		}
	}

	// Narrowness again, from the other side: a publisher may only retract
	// addresses that name the peer being described.
	strangerAddr := "/ip4/203.0.113.99/tcp/9999"
	h.Peerstore().AddAddrs(stranger, newAddrs(t, []string{strangerAddr}), time.Hour)
	n.removePeekMapAddrs(pID, []string{suffixed(strangerAddr, stranger.String())})
	if got := addrSet(h.Peerstore().Addrs(stranger)); !got[strangerAddr] {
		t.Fatalf("retraction naming a different peer was applied: %v", got)
	}

	// Repeating a retraction, or retracting an address we never had, must be a
	// quiet no-op rather than an error path.
	n.removePeekMapAddrs(pID, []string{suffixed(drop, pID.String()), "not-a-multiaddr", drop})
	if got := addrSet(h.Peerstore().Addrs(pID)); got[drop] || !got[keep] || !got[sibling] {
		t.Fatalf("repeat retraction disturbed the addr book: %v", got)
	}

	// Empty inputs are the common case on a disconnect where nothing was
	// recorded, and must not clear the peer.
	n.removePeekMapAddrs(pID, nil)
	if got := addrSet(h.Peerstore().Addrs(pID)); !got[keep] || !got[sibling] {
		t.Fatalf("nil removal cleared the peer: %v", got)
	}
}

func newAddrs(t *testing.T, strs []string) []multiaddr.Multiaddr {
	t.Helper()
	out := make([]multiaddr.Multiaddr, 0, len(strs))
	for _, s := range strs {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("NewMultiaddr(%q): %v", s, err)
		}
		out = append(out, ma)
	}
	return out
}

func addrSet(addrs []multiaddr.Multiaddr) map[string]bool {
	out := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		if a != nil {
			out[a.String()] = true
		}
	}
	return out
}
