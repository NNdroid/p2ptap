package node

import (
	"context"
	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/routing"
	"testing"
	"testing/synctest"
	"time"
)

func TestRouteSelectionPublishedReadsAvoidCacheMutex(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := routing.NewRouter(peer.ID("A"))
		r.SetEdge(peer.ID("A"), peer.ID("B"), 10, routing.LinkDirect)
		n := &Node{Router: r}
		n.getCachedRoutes()
		n.cachedRoutesMu.Lock()
		defer n.cachedRoutesMu.Unlock()
		done := make(chan struct{})
		go func() { n.getCachedRoutes(); close(done) }()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Fatal("published route read blocked on cache mutex")
		}
	})
}

func TestRouteSelectionRejectsBlacklistedHopAndHonorsRemainingTTL(t *testing.T) {
	a, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	c, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b.SetStreamHandler(OverlayRelayProtocolID, func(s network.Stream) { s.Reset() })
	c.SetStreamHandler(OverlayRelayProtocolID, func(s network.Stream) { s.Reset() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Connect(ctx, peer.AddrInfo{ID: b.ID(), Addrs: b.Addrs()}); err != nil {
		t.Fatal(err)
	}
	if err := a.Connect(ctx, peer.AddrInfo{ID: c.ID(), Addrs: c.Addrs()}); err != nil {
		t.Fatal(err)
	}
	a.Peerstore().AddProtocols(b.ID(), OverlayRelayProtocolID)
	a.Peerstore().AddProtocols(c.ID(), OverlayRelayProtocolID)
	d, e := peer.ID("destination"), peer.ID("extra-hop")
	r := routing.NewRouter(a.ID())
	r.SetEdge(a.ID(), b.ID(), 1, routing.LinkDirect)
	r.SetEdge(b.ID(), e, 1, routing.LinkDirect)
	r.SetEdge(e, d, 1, routing.LinkDirect)
	r.SetEdge(a.ID(), c.ID(), 20, routing.LinkDirect)
	r.SetEdge(c.ID(), d, 20, routing.LinkDirect)
	n := &Node{Host: a, Router: r, overlayRelayBlacklist: make(map[peer.ID]time.Time)}
	if got, ok := n.overlayRoute(d, 5, ""); !ok || got.NextHop != b.ID() {
		t.Fatalf("initial route %+v/%v", got, ok)
	}
	if got, ok := n.overlayRoute(d, 2, ""); !ok || got.NextHop != c.ID() {
		t.Fatalf("remaining TTL chose impossible route %+v/%v", got, ok)
	}
	n.blacklistOverlayRelay(b.ID())
	if got, ok := n.overlayRoute(d, 5, ""); !ok || got.NextHop != c.ID() {
		t.Fatalf("blacklisted hop chosen %+v/%v", got, ok)
	}
	if got := n.relayHopForTarget(d); got != c.ID() {
		t.Fatalf("dispatcher differs from TAP choice: %s", got)
	}
	if _, ok := n.overlayRoute(d, 5, c.ID()); ok {
		t.Fatal("transit sent frame back to previous hop")
	}
}

func TestRouteSelectionCacheTracksWithdrawal(t *testing.T) {
	a, b, c, d := peer.ID("A"), peer.ID("B"), peer.ID("C"), peer.ID("D")
	r := routing.NewRouter(a)
	r.SetEdge(a, b, 1, routing.LinkDirect)
	r.SetEdge(b, d, 1, routing.LinkDirect)
	r.SetEdge(a, c, 100, routing.LinkDirect)
	r.SetEdge(c, d, 1, routing.LinkDirect)
	n := &Node{Router: r}
	before := n.getCachedRoutes()
	if before[d].NextHop != b {
		t.Fatal("initial route wrong")
	}
	r.RemoveDirectLink(b)
	if got := n.getCachedRoutes()[d]; got.NextHop != c {
		t.Fatalf("cached disconnected hop: %+v", got)
	}
	if before[d].NextHop != b {
		t.Fatal("published old snapshot mutated")
	}
	r.UpdateDirectLink(b, 1, routing.LinkDirect)
	if got := n.getCachedRoutes()[d]; got.NextHop != b {
		t.Fatal("recovered route not visible")
	}
}

func TestRouteSelectionTAPRTTCannotChangePhysicalEdge(t *testing.T) {
	a, b, c := peer.ID("A"), peer.ID("B"), peer.ID("C")
	r := routing.NewRouter(a)
	r.SetEdge(a, c, 200, routing.LinkDirect)
	r.SetEdge(a, b, 20, routing.LinkDirect)
	r.SetEdge(b, c, 20, routing.LinkDirect)
	n := &Node{Router: r}
	now := time.Unix(1700000000, 0)
	n.recordPeerRTTProbeAt(c, rttSourceTAPICMP, 40*time.Millisecond, true, now)
	n.recordPeerRTTProbeAt(c, rttSourceP2PEcho, 200*time.Millisecond, true, now)
	display := n.peerRTTMeasurement(c, now)
	if display.rttMs != 40 || display.source != rttSourceTAPICMP {
		t.Fatal("TAP telemetry lost")
	}
	if _, ok := routingRTTMsFromSnapshot(display); ok {
		t.Fatal("end-to-end measurement accepted as link weight")
	}
	link := n.peerLinkRTTMeasurement(c, now)
	weight, ok := preferredLinkRTTMs(link, 200)
	if !ok || weight != 200 {
		t.Fatalf("incorrect physical weight %d", weight)
	}
	r.UpdateLinkRTT(c, weight)
	if r.ComputeRoutes()[c].NextHop != b {
		t.Fatal("TAP measurement sent traffic back over slow direct link")
	}
}
