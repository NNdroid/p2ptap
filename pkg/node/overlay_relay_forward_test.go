package node

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/routing"
	"p2ptap/pkg/tap"
)

// TestOverlayRelayForwardThroughRelayNode reproduces the reported production
// failure: traffic cannot be forwarded THROUGH the relay node
// "DESKTOP-VCJ70RT" to reach the destination "fah0-vm0-ndbbd0".
//
// Topology modelled here (the relay is in the MIDDLE, not at an endpoint):
//
//	NodeA (source)  ──  NodeB (relay, = DESKTOP-VCJ70RT)  ──  NodeC (dest, = fah0-vm0-ndbbd0)
//
// NodeA is connected to NodeB and NodeB is connected to NodeC, but NodeA is
// deliberately NOT connected to NodeC. Therefore every A->C frame must be
// wrapped in an overlay-relay envelope and forwarded hop-by-hop A->B->C over
// the OverlayRelayProtocolID stream pool.
//
// This is a TRUE multi-hop relay. The existing 3-node e2e suite connects A<->C
// directly, so it never exercises a frame whose final destination is not
// directly reachable from the origin — exactly the case that was broken.
//
// Regression contract:
//   - NodeA MUST compute a non-direct route to NodeC with NextHop == NodeB.
//   - An ICMP Echo from A->C MUST be delivered on NodeC's TAP (relayed via B).
func TestOverlayRelayForwardThroughRelayNode(t *testing.T) {
	// --- Topology: A -- B(relay) -- C, with A NOT connected to C ---
	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")
	tapC, pipeC := tap.NewMemTAPPair("tapC", "pipeC")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
	cfgC := createTestNodeConfig("10.0.0.3/24", "fd00::3/64", "best_path")

	aNode, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	defer aNode.Close()
	bNode, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create NodeB: %v", err)
	}
	defer bNode.Close()
	cNode, err := NewNodeWithTAP(cfgC, tapC, nil)
	if err != nil {
		t.Fatalf("create NodeC: %v", err)
	}
	defer cNode.Close()

	aNode.Start()
	bNode.Start()
	cNode.Start()

	connect := func(a, b *Node) {
		ti := b.Host.Peerstore().PeerInfo(b.Host.ID())
		ti.Addrs = b.Host.Addrs()
		if cerr := a.Host.Connect(a.ctx, ti); cerr != nil {
			t.Fatalf("connect %s->%s: %v", a.Host.ID().ShortString(), b.Host.ID().ShortString(), cerr)
		}
	}
	// Only the two real edges exist. A<->C is intentionally left unconnected so
	// that A->C traffic is forced through the relay B.
	connect(aNode, bNode)
	connect(bNode, cNode)

	// The encrypted overlay must be ready on BOTH hops so each relay seal
	// (A->B, then B->C) has a usable per-peer cipher. Without this the relay
	// envelope would have to travel in plaintext and the relay path is not
	// truly exercised.
	waitOverlayReady(t, aNode, bNode)
	waitOverlayReady(t, bNode, cNode)
	waitStreamReady(t, aNode, bNode)
	waitStreamReady(t, bNode, aNode)
	waitStreamReady(t, bNode, cNode)
	waitStreamReady(t, cNode, bNode)
	time.Sleep(300 * time.Millisecond)

	_ = pipeA.ConfigureIP("10.0.0.1/24", "fd00::1/64")
	_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")
	_ = pipeC.ConfigureIP("10.0.0.3/24", "fd00::3/64")

	// Seed peer metadata on every node so TAP IPs resolve to peer IDs in both
	// the egress (A resolves 10.0.0.3 -> C) and the relay-forward (B/C routing)
	// paths.
	peers := map[*Node]PeerMeta{
		aNode: {NodeName: "A", TapIP: "10.0.0.1/24", TapIPv6: "fd00::1/64", TapMAC: aNode.localMAC.String()},
		bNode: {NodeName: "B-relay", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: bNode.localMAC.String()},
		cNode: {NodeName: "C", TapIP: "10.0.0.3/24", TapIPv6: "fd00::3/64", TapMAC: cNode.localMAC.String()},
	}
	for src := range peers {
		for dst, dm := range peers {
			if src == dst {
				continue
			}
			src.storePeerMeta(dst.Host.ID(), dm)
		}
	}

	// --- Deterministically teach NodeA that C is reachable via NodeB ---
	// In production this edge arrives through B's flooded LSA (B advertises its
	// direct neighbour C). We seed it directly so the test isolates the RELAY
	// FORWARD data path (the reported failure) rather than LSA-propagation
	// timing, and so the failure mode is unambiguous.
	aNode.Router.UpdateDirectLink(bNode.Host.ID(), 10, routing.LinkDirect) // A-B direct edge
	bNode.Router.UpdateDirectLink(aNode.Host.ID(), 10, routing.LinkDirect) // keep B's graph consistent
	bNode.Router.UpdateDirectLink(cNode.Host.ID(), 12, routing.LinkDirect) // B-C direct edge

	// NOTE: each node fires an INITIAL LSA broadcast at startup using
	// time.Now().UnixNano() as the sequence (node.go:1469). That value (~1.7e18)
	// is already recorded in A's seqMap[B], so any smaller seed seq would be
	// dropped as stale. Use a seq strictly greater than UnixNano to win.
	lsa := bNode.Router.BuildLSA(uint64(time.Now().UnixNano())+1, routing.NodeIdentity{
		NodeName:          bNode.nodeName,
		TapIP:             bNode.Config.TapIP,
		TapIPv6:           bNode.Config.TapIPv6,
		TapMAC:            bNode.Config.TapMAC,
		OS:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		IsExitNode:        bNode.Config.ExitNode.Enable,
		AdvertisedSubnets: bNode.Config.AdvertisedSubnets,
	})
	if !aNode.Router.ProcessLSA(lsa) {
		t.Fatalf("NodeA.ProcessLSA (from B) returned false — could not seed B-C topology (lsa seq=%d, neighbors=%v)",
			lsa.Seq, lsa.Neighbors)
	}
	aNode.invalidateRouteCache()

	// DIAGNOSTIC 1: NodeA must actually have a non-direct route to C via B.
	routes := aNode.Router.ComputeRoutes()
	rc, ok := routes[cNode.Host.ID()]
	if !ok {
		t.Fatalf("DIAGNOSTIC: NodeA has NO computed route to NodeC even after seeding — " +
			"this is a ROUTE-DISCOVERY failure (different from the relay-forward bug)")
	}
	if rc.IsDirect {
		t.Fatalf("DIAGNOSTIC: NodeA route to C is DIRECT (nextHop=%s); A and C must NOT be "+
			"directly connected in this topology", rc.NextHop)
	}
	if rc.NextHop != bNode.Host.ID() {
		t.Fatalf("DIAGNOSTIC: NodeA route to C nextHop=%s, expected the relay NodeB=%s",
			rc.NextHop, bNode.Host.ID())
	}
	t.Logf("✓ NodeA computed non-direct route to C: nextHop=B(relay), hops=%d, IsDirect=false, totalRTT=%dms",
		len(rc.Path), rc.TotalRTTMs)

	// Also confirm the relay B itself has a direct route to C (it must, to
	// forward the frame onward). This validates the second hop's routing.
	rb, okB := bNode.Router.ComputeRoutes()[cNode.Host.ID()]
	if !okB || rb.NextHop != cNode.Host.ID() {
		t.Fatalf("DIAGNOSTIC: relay NodeB has no usable direct route to C (nextHop=%v) — cannot forward",
			rb.NextHop)
	}
	t.Logf("✓ Relay NodeB has direct route to C for the second hop")

	// --- Drain the destination TAP continuously so the relayed frame is not lost ---
	readerC := newFrameReader(pipeC)
	defer readerC.Close()
	readerA := newFrameReader(pipeA)
	defer readerA.Close()

	// --- Send A -> C (must be relayed A->B->C) ---
	// Src MAC = A, Dst MAC = C, Dst IP = 10.0.0.3 (resolves to C on NodeA).
	pingFrame := constructICMPv4Packet(testMACA, testMACC,
		net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.3"), 4242, 1)

	t.Log("Sending ICMP Echo A(10.0.0.1) -> C(10.0.0.3) — expected to be relayed through B(DESKTOP-VCJ70RT)...")
	writeAndExpectWithRetry(t, pipeA, readerC, pingFrame,
		[]byte("P2PTAP_PING_V4_TEST_DATA"), "IPv4 A -> relay(B) -> C")

	t.Log("✓ Overlay-relay forwarding A -> B(relay) -> C delivered successfully")
}

// TestOverlayRelayPreservesInnerIPTTL locks an invariant the DESKTOP-VCJ70RT
// relay production capture surfaced: the overlay relay MUST NOT touch the inner
// IP packet's TTL. A real capture on fah0-vm0 showed `ICMP time exceeded
// in-transit` for relayed pings — which can ONLY be generated at the IP layer
// when something decremented the inner IP TTL to 1 before delivery. p2ptap's
// relay path rewrites only the L2 dst MAC (rewriteRxDstMAC) and tapWrites the
// raw frame; the relay-envelope TTL (MaxRelayTTL) is a SEPARATE hop counter and
// must never leak into the carried IP packet. If a future refactor ever
// decrements the inner IP TTL per relay hop, this test fails.
//
// We send an ICMP Echo with a NON-default TTL (32) A->C via relay B and assert
// the frame NodeC receives still carries TTL == 32.
func TestOverlayRelayPreservesInnerIPTTL(t *testing.T) {
	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")
	tapC, pipeC := tap.NewMemTAPPair("tapC", "pipeC")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
	cfgC := createTestNodeConfig("10.0.0.3/24", "fd00::3/64", "best_path")

	aNode, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	defer aNode.Close()
	bNode, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create NodeB: %v", err)
	}
	defer bNode.Close()
	cNode, err := NewNodeWithTAP(cfgC, tapC, nil)
	if err != nil {
		t.Fatalf("create NodeC: %v", err)
	}
	defer cNode.Close()

	aNode.Start()
	bNode.Start()
	cNode.Start()

	connect := func(a, b *Node) {
		ti := b.Host.Peerstore().PeerInfo(b.Host.ID())
		ti.Addrs = b.Host.Addrs()
		if cerr := a.Host.Connect(a.ctx, ti); cerr != nil {
			t.Fatalf("connect %s->%s: %v", a.Host.ID().ShortString(), b.Host.ID().ShortString(), cerr)
		}
	}
	connect(aNode, bNode)
	connect(bNode, cNode)

	waitOverlayReady(t, aNode, bNode)
	waitOverlayReady(t, bNode, cNode)
	waitStreamReady(t, aNode, bNode)
	waitStreamReady(t, bNode, aNode)
	waitStreamReady(t, bNode, cNode)
	waitStreamReady(t, cNode, bNode)
	time.Sleep(300 * time.Millisecond)

	_ = pipeA.ConfigureIP("10.0.0.1/24", "fd00::1/64")
	_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")
	_ = pipeC.ConfigureIP("10.0.0.3/24", "fd00::3/64")

	peers := map[*Node]PeerMeta{
		aNode: {NodeName: "A", TapIP: "10.0.0.1/24", TapIPv6: "fd00::1/64", TapMAC: aNode.localMAC.String()},
		bNode: {NodeName: "B-relay", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: bNode.localMAC.String()},
		cNode: {NodeName: "C", TapIP: "10.0.0.3/24", TapIPv6: "fd00::3/64", TapMAC: cNode.localMAC.String()},
	}
	for src := range peers {
		for dst, dm := range peers {
			if src == dst {
				continue
			}
			src.storePeerMeta(dst.Host.ID(), dm)
		}
	}

	aNode.Router.UpdateDirectLink(bNode.Host.ID(), 10, routing.LinkDirect)
	bNode.Router.UpdateDirectLink(aNode.Host.ID(), 10, routing.LinkDirect)
	bNode.Router.UpdateDirectLink(cNode.Host.ID(), 12, routing.LinkDirect)

	lsa := bNode.Router.BuildLSA(uint64(time.Now().UnixNano())+1, routing.NodeIdentity{
		NodeName:          bNode.nodeName,
		TapIP:             bNode.Config.TapIP,
		TapIPv6:           bNode.Config.TapIPv6,
		TapMAC:            bNode.Config.TapMAC,
		OS:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		IsExitNode:        bNode.Config.ExitNode.Enable,
		AdvertisedSubnets: bNode.Config.AdvertisedSubnets,
	})
	if !aNode.Router.ProcessLSA(lsa) {
		t.Fatalf("NodeA.ProcessLSA (from B) returned false")
	}
	aNode.invalidateRouteCache()

	readerC := newFrameReader(pipeC)
	defer readerC.Close()
	readerA := newFrameReader(pipeA)
	defer readerA.Close()

	// Build an ICMP Echo with a UNIQUE marker and a NON-default IP TTL (32) so
	// we can prove the relay does not decrement it. The inner IP TTL lives at
	// Ethernet offset 14 + IP header offset 8 = 22 (see node_tapprobe.go:298).
	pingFrame := constructICMPv4PacketWithData(testMACA, testMACC,
		net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.3"), 7321, 1,
		[]byte("P2PTAP_TTL_PRESERVE_MARKER"))
	const sentTTL = 32
	pingFrame[22] = sentTTL

	t.Log("Sending ICMP Echo A(10.0.0.1) -> C(10.0.0.3) TTL=32 — relayed via B; expecting TTL==32 on arrival")
	if _, werr := pipeA.Write(pingFrame); werr != nil {
		t.Fatalf("Write A->C (TTL test) failed: %v", werr)
	}
	got := readerC.expect(t, []byte("P2PTAP_TTL_PRESERVE_MARKER"), "relayed ICMP A->C preserving inner IP TTL")
	if len(got) < 23 {
		t.Fatalf("received relayed frame too short (%d bytes) to carry an IP header", len(got))
	}
	rcvTTL := got[22]
	if rcvTTL != sentTTL {
		t.Fatalf("overlay relay MUTATED inner IP TTL: sent %d, received %d (relay must NOT decrement IP TTL)",
			sentTTL, rcvTTL)
	}
	t.Logf("✓ Overlay relay preserved inner IP TTL (%d -> %d) across A -> B(relay) -> C", sentTTL, rcvTTL)
}

// testMACD is the synthetic TAP MAC assigned to NodeD in the 3-hop test below.
var testMACD = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x04}

// TestOverlayRelayForwardThreeHop extends the 2-hop reproduction to a TRUE
// multi-hop chain that is NOT reachable in a single relay hop:
//
//	NodeA -- NodeB(relay) -- NodeC(relay) -- NodeD(dest)
//
// Only ADJACENT links exist (A-B, B-C, C-D); A-D, A-C and B-D are NOT
// connected. Therefore an A->D frame must be wrapped and re-wrapped TWICE,
// traversing B then C, each time decrementing TTL and re-sealing the relay
// envelope for the next hop. This exercises the handleRelayStream forward
// branch (ttl > 1) at BOTH relay nodes — the exact code path that had
// previously been broken by double-encryption / wrong-key bugs — on top of
// the egress guard fixed for the 2-hop case.
//
// Regression contract:
//   - NodeA MUST compute a non-direct route to NodeD with NextHop == NodeB.
//   - NodeB MUST compute a non-direct route to NodeD with NextHop == NodeC.
//   - An ICMP Echo from A->D MUST be delivered on NodeD's TAP (relayed A->B->C->D).
func TestOverlayRelayForwardThreeHop(t *testing.T) {
	// --- Topology: A -- B(relay) -- C(relay) -- D, adjacent-only links ---
	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")
	tapC, pipeC := tap.NewMemTAPPair("tapC", "pipeC")
	tapD, pipeD := tap.NewMemTAPPair("tapD", "pipeD")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
	cfgC := createTestNodeConfig("10.0.0.3/24", "fd00::3/64", "best_path")
	cfgD := createTestNodeConfig("10.0.0.4/24", "fd00::4/64", "best_path")

	aNode, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	defer aNode.Close()
	bNode, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create NodeB: %v", err)
	}
	defer bNode.Close()
	cNode, err := NewNodeWithTAP(cfgC, tapC, nil)
	if err != nil {
		t.Fatalf("create NodeC: %v", err)
	}
	defer cNode.Close()
	dNode, err := NewNodeWithTAP(cfgD, tapD, nil)
	if err != nil {
		t.Fatalf("create NodeD: %v", err)
	}
	defer dNode.Close()

	aNode.Start()
	bNode.Start()
	cNode.Start()
	dNode.Start()

	connect := func(a, b *Node) {
		ti := b.Host.Peerstore().PeerInfo(b.Host.ID())
		ti.Addrs = b.Host.Addrs()
		if cerr := a.Host.Connect(a.ctx, ti); cerr != nil {
			t.Fatalf("connect %s->%s: %v", a.Host.ID().ShortString(), b.Host.ID().ShortString(), cerr)
		}
	}
	// Only adjacent edges. All non-adjacent pairs are intentionally left
	// unconnected so A->D is forced through B and C.
	connect(aNode, bNode)
	connect(bNode, cNode)
	connect(cNode, dNode)

	// Encrypted overlay must be ready on EVERY adjacent hop so each relay seal
	// (A->B, B->C, C->D) has a usable per-peer cipher.
	waitOverlayReady(t, aNode, bNode)
	waitOverlayReady(t, bNode, cNode)
	waitOverlayReady(t, cNode, dNode)
	waitStreamReady(t, aNode, bNode)
	waitStreamReady(t, bNode, aNode)
	waitStreamReady(t, bNode, cNode)
	waitStreamReady(t, cNode, bNode)
	waitStreamReady(t, cNode, dNode)
	waitStreamReady(t, dNode, cNode)
	time.Sleep(300 * time.Millisecond)

	_ = pipeA.ConfigureIP("10.0.0.1/24", "fd00::1/64")
	_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")
	_ = pipeC.ConfigureIP("10.0.0.3/24", "fd00::3/64")
	_ = pipeD.ConfigureIP("10.0.0.4/24", "fd00::4/64")

	// Seed peer metadata on every node so TAP IPs resolve to peer IDs.
	peers := map[*Node]PeerMeta{
		aNode: {NodeName: "A", TapIP: "10.0.0.1/24", TapIPv6: "fd00::1/64", TapMAC: aNode.localMAC.String()},
		bNode: {NodeName: "B-relay1", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: bNode.localMAC.String()},
		cNode: {NodeName: "C-relay2", TapIP: "10.0.0.3/24", TapIPv6: "fd00::3/64", TapMAC: cNode.localMAC.String()},
		dNode: {NodeName: "D", TapIP: "10.0.0.4/24", TapIPv6: "fd00::4/64", TapMAC: dNode.localMAC.String()},
	}
	for src := range peers {
		for dst, dm := range peers {
			if src == dst {
				continue
			}
			src.storePeerMeta(dst.Host.ID(), dm)
		}
	}

	// --- Deterministic link-state: every adjacent edge, both directions ---
	aNode.Router.UpdateDirectLink(bNode.Host.ID(), 10, routing.LinkDirect)
	bNode.Router.UpdateDirectLink(aNode.Host.ID(), 10, routing.LinkDirect)
	bNode.Router.UpdateDirectLink(cNode.Host.ID(), 11, routing.LinkDirect)
	cNode.Router.UpdateDirectLink(bNode.Host.ID(), 11, routing.LinkDirect)
	cNode.Router.UpdateDirectLink(dNode.Host.ID(), 12, routing.LinkDirect)
	dNode.Router.UpdateDirectLink(cNode.Host.ID(), 12, routing.LinkDirect)

	// Seed LSAs with seq > UnixNano (see 2-hop test note: node.go:1469 fires an
	// initial broadcast at startup using UnixNano, recorded in seqMap).
	seedLSA := func(from, to *Node) {
		lsa := from.Router.BuildLSA(uint64(time.Now().UnixNano())+1, routing.NodeIdentity{
			NodeName:          from.nodeName,
			TapIP:             from.Config.TapIP,
			TapIPv6:           from.Config.TapIPv6,
			TapMAC:            from.Config.TapMAC,
			OS:                runtime.GOOS,
			Arch:              runtime.GOARCH,
			IsExitNode:        from.Config.ExitNode.Enable,
			AdvertisedSubnets: from.Config.AdvertisedSubnets,
		})
		if !to.Router.ProcessLSA(lsa) {
			t.Fatalf("ProcessLSA(%s->%s) returned false (seq=%d neighbors=%v)",
				from.Host.ID().ShortString(), to.Host.ID().ShortString(), lsa.Seq, lsa.Neighbors)
		}
	}
	seedLSA(bNode, aNode) // A learns B's neighbours {A,C}
	seedLSA(cNode, aNode) // A learns C's neighbours {B,D}  -> completes A..D chain
	seedLSA(cNode, bNode) // B learns C's neighbours {B,D}  -> B can route B..D via C
	aNode.invalidateRouteCache()
	bNode.invalidateRouteCache()

	// DIAGNOSTIC 1: A must have a non-direct route to D via B.
	ra, okA := aNode.Router.ComputeRoutes()[dNode.Host.ID()]
	if !okA {
		t.Fatalf("DIAGNOSTIC: NodeA has NO computed route to NodeD even after seeding")
	}
	if ra.IsDirect {
		t.Fatalf("DIAGNOSTIC: NodeA route to D is DIRECT (nextHop=%s); A and D must NOT be directly connected", ra.NextHop)
	}
	if ra.NextHop != bNode.Host.ID() {
		t.Fatalf("DIAGNOSTIC: NodeA route to D nextHop=%s, expected relay NodeB=%s", ra.NextHop, bNode.Host.ID())
	}
	t.Logf("✓ NodeA computed non-direct route to D: nextHop=B(relay1), path=%v, IsDirect=false, totalRTT=%dms",
		ra.Path, ra.TotalRTTMs)

	// DIAGNOSTIC 2: B must have a non-direct route to D via C (second relay leg).
	rb, okB := bNode.Router.ComputeRoutes()[dNode.Host.ID()]
	if !okB {
		t.Fatalf("DIAGNOSTIC: relay NodeB has NO computed route to NodeD")
	}
	if rb.IsDirect {
		t.Fatalf("DIAGNOSTIC: NodeB route to D is DIRECT (nextHop=%s); B and D must NOT be directly connected", rb.NextHop)
	}
	if rb.NextHop != cNode.Host.ID() {
		t.Fatalf("DIAGNOSTIC: NodeB route to D nextHop=%s, expected relay NodeC=%s", rb.NextHop, cNode.Host.ID())
	}
	t.Logf("✓ Relay NodeB computed non-direct route to D: nextHop=C(relay2), IsDirect=false")

	// --- Drain destination TAP continuously ---
	readerD := newFrameReader(pipeD)
	defer readerD.Close()
	readerA := newFrameReader(pipeA)
	defer readerA.Close()

	// --- Send A -> D (must be relayed A->B->C->D) ---
	// Use the caller-supplied-data variant so the frame embeds the UNIQUE
	// "P2PTAP_PING_V4_3HOP_TEST" marker — writeAndExpectWithRetry matches via
	// bytes.Contains(f, payload), so the marker MUST be present in the ICMP
	// body or the assertion can never succeed. (The plain constructICMPv4Packet
	// helper hardcodes a different marker.)
	pingFrame := constructICMPv4PacketWithData(testMACA, testMACD,
		net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.4"), 4243, 1,
		[]byte("P2PTAP_PING_V4_3HOP_TEST"))

	t.Log("Sending ICMP Echo A(10.0.0.1) -> D(10.0.0.4) — expected to traverse relay B then C...")
	writeAndExpectWithRetry(t, pipeA, readerD, pingFrame,
		[]byte("P2PTAP_PING_V4_3HOP_TEST"), "IPv4 A -> relay(B) -> relay(C) -> D")

	t.Log("✓ Overlay-relay forwarding A -> B -> C -> D delivered successfully")
}

// TestCanEgressToPeerRelayAware locks the relay-aware usability gate that the
// unicast egress path AND the broadcast fan-out now share (canEgressToPeer).
//
// The bug class we are guarding against: a RELAYED (non-direct) destination is
// never directly connected to the origin, so a gate written as
//   !isPeerReady(dest) && obfCipherForPeer(dest)==nil  -> drop
// is ALWAYS true for it and blackholes every relay-only frame. The gate must
// instead check the RELAY HOP's readiness.
//
// An end-to-end broadcast test cannot isolate this gate in the project's
// overlay-relay topology: each relay hop is a DIRECT libp2p link, so an
// intermediate node re-floods the broadcast to the next hop and would deliver
// it even if the origin's gate wrongly dropped it. Testing the gate function in
// isolation is therefore the precise, non-masked lock.
func TestCanEgressToPeerRelayAware(t *testing.T) {
	// --- Topology: A -- B(relay) -- C, A NOT connected to C ---
	tapA, _ := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, _ := tap.NewMemTAPPair("tapB", "pipeB")
	tapC, _ := tap.NewMemTAPPair("tapC", "pipeC")

	aNode, err := NewNodeWithTAP(createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path"), tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	defer aNode.Close()
	bNode, err := NewNodeWithTAP(createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path"), tapB, nil)
	if err != nil {
		t.Fatalf("create NodeB: %v", err)
	}
	defer bNode.Close()
	cNode, err := NewNodeWithTAP(createTestNodeConfig("10.0.0.3/24", "fd00::3/64", "best_path"), tapC, nil)
	if err != nil {
		t.Fatalf("create NodeC: %v", err)
	}
	defer cNode.Close()

	aNode.Start()
	bNode.Start()
	cNode.Start()

	connect := func(a, b *Node) {
		ti := b.Host.Peerstore().PeerInfo(b.Host.ID())
		ti.Addrs = b.Host.Addrs()
		if cerr := a.Host.Connect(a.ctx, ti); cerr != nil {
			t.Fatalf("connect %s->%s: %v", a.Host.ID().ShortString(), b.Host.ID().ShortString(), cerr)
		}
	}
	connect(aNode, bNode)
	connect(bNode, cNode)

	waitOverlayReady(t, aNode, bNode)
	waitStreamReady(t, aNode, bNode)
	waitStreamReady(t, bNode, aNode)
	time.Sleep(300 * time.Millisecond)

	// Teach A that C is reachable via B (relay), mirroring the 2-hop repro.
	aNode.Router.UpdateDirectLink(bNode.Host.ID(), 10, routing.LinkDirect)
	bNode.Router.UpdateDirectLink(aNode.Host.ID(), 10, routing.LinkDirect)
	bNode.Router.UpdateDirectLink(cNode.Host.ID(), 12, routing.LinkDirect)
	lsa := bNode.Router.BuildLSA(uint64(time.Now().UnixNano())+1, routing.NodeIdentity{
		NodeName:          bNode.nodeName,
		TapIP:             bNode.Config.TapIP,
		TapIPv6:           bNode.Config.TapIPv6,
		TapMAC:            bNode.Config.TapMAC,
		OS:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		IsExitNode:        bNode.Config.ExitNode.Enable,
		AdvertisedSubnets: bNode.Config.AdvertisedSubnets,
	})
	if !aNode.Router.ProcessLSA(lsa) {
		t.Fatalf("NodeA.ProcessLSA (from B) returned false")
	}
	aNode.invalidateRouteCache()

	cID := cNode.Host.ID()
	bID := bNode.Host.ID()

	// Sanity: C is NOT directly connected to A, and A holds no direct cipher
	// for C — the OLD gate would have dropped every frame to C.
	if aNode.Host.Network().Connectedness(cID) == network.Connected {
		t.Fatalf("precondition violated: A is directly connected to C (topology bug)")
	}
	if aNode.obfCipherForPeer(cID) != nil {
		t.Fatalf("precondition violated: A already holds a cipher for relay-only C")
	}

	// KEY ASSERTION: a relay-only destination must be egressable because the
	// gate now checks the RELAY HOP (B), which IS directly ready.
	if !aNode.canEgressToPeer(cID) {
		t.Fatalf("canEgressToPeer(C) == false: relay-only destination would be blackholed " +
			"(the original 'forward through relay' bug)")
	}
	if !aNode.canEgressToPeer(bID) {
		t.Fatalf("canEgressToPeer(B) == false: directly-connected relay hop must be egressable")
	}

	// A peer with NO route and NO readiness must remain non-egressable (we must
	// not start shipping frames into the void).
	bogus := peer.ID("bogus-peer-id-with-no-route")
	if aNode.canEgressToPeer(bogus) {
		t.Fatalf("canEgressToPeer(bogus) == true: an unreachable peer must NOT be egressable")
	}

	t.Log("✓ canEgressToPeer is relay-aware: relay-only C egressable via hop B; unreachable bogus peer is not")
}
