package node

import (
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/tap"
)

// TestStaticOnlyMeshConvergesWithoutBootstrap is the acceptance test for
// "static peer as the discovery entry point": a mesh that has NO bootstrap node
// at all must still converge end-to-end.
//
// Topology (B is an ORDINARY peer, NOT a bootstrap / circuit-relay):
//
//	NodeA ──static──▶ NodeB ◀──static── NodeC
//
// A and C never connect directly and there is no boot node anywhere, so:
//   - No Circuit Relay v2 circuit can exist (that requires a connected BOOT
//     with relay service). SynthesizeRelayCircuitAddrs must return nothing.
//   - The ONLY way A can reach C is the overlay relay hop through B, using the
//     relay-ctrl tunnel for the control plane.
//
// Unlike TestRelayCtrlEstablishesEndToEndCipher, this test seeds NOTHING by
// hand: no UpdateDirectLink, no ProcessLSA, no storePeerMeta, no explicit
// triggerPeerRekey / syncMetadataToPeer. Everything must come from the
// production loops, which is what makes it a real "can I run a p2ptap mesh
// without any bootstrap server?" contract:
//
//	1. B floods its LSA on connect      -> A learns the B-C edge
//	2. B replays its cached LSA snapshot -> A learns C's OWN self-advertised
//	   edges + identity immediately (a late joiner otherwise waits for C's next
//	   15s broadcast, or never learns them at all)
//	3. relayControlReconciler (5s)       -> A<->C cipher over the relay-ctrl tunnel
//	4. metaSyncLoop / LSA piggyback      -> A learns C's identity
//	5. dispatch                          -> encrypted ICMP A -> B -> C
//
// C joins B FIRST and A joins LAST on purpose, so A is the late joiner whose
// convergence depends on the snapshot replay rather than luck of ordering.
func TestStaticOnlyMeshConvergesWithoutBootstrap(t *testing.T) {
	tapA, pipeA := tap.NewMemTAPPair("smTapA", "smPipeA")
	tapB, pipeB := tap.NewMemTAPPair("smTapB", "smPipeB")
	tapC, pipeC := tap.NewMemTAPPair("smTapC", "smPipeC")

	// .11/.12/.13 keeps the derived listen ports (19011-19013) clear of the
	// other 3-node suites so parallel package runs don't fight over binds.
	cfgA := createTestNodeConfig("10.0.0.11/24", "fd00::11/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.12/24", "fd00::12/64", "best_path")
	cfgC := createTestNodeConfig("10.0.0.13/24", "fd00::13/64", "best_path")

	// The whole point: not a single bootstrap peer anywhere.
	for _, c := range []*struct {
		name  string
		boots []string
	}{{"A", cfgA.BootstrapPeers}, {"B", cfgB.BootstrapPeers}, {"C", cfgC.BootstrapPeers}} {
		if len(c.boots) != 0 {
			t.Fatalf("precondition violated: node %s has %d bootstrap peers configured; "+
				"this test must run with a completely boot-less mesh", c.name, len(c.boots))
		}
	}

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

	// Dial exactly what a `static_peers` entry would dial. connectWithRetry is
	// what Start() uses for static peers; Host.Connect is its terminal step and
	// keeps the test deterministic.
	dialStatic := func(from, to *Node) {
		ti := to.Host.Peerstore().PeerInfo(to.Host.ID())
		ti.Addrs = to.Host.Addrs()
		from.Host.Peerstore().AddAddrs(ti.ID, ti.Addrs, staticPeerAddrTTLForTest)
		if cerr := from.Host.Connect(from.ctx, ti); cerr != nil {
			t.Fatalf("static dial %s->%s: %v",
				from.Host.ID().ShortString(), to.Host.ID().ShortString(), cerr)
		}
	}
	// C attaches first, A joins LAST (late joiner).
	dialStatic(cNode, bNode)
	waitOverlayReady(t, cNode, bNode)
	waitStreamReady(t, bNode, cNode)
	waitStreamReady(t, cNode, bNode)
	// Let B ingest and cache C's self-advertised LSA before A shows up; that
	// cache is exactly what the snapshot replay hands to A.
	time.Sleep(1500 * time.Millisecond)

	dialStatic(aNode, bNode)
	waitOverlayReady(t, aNode, bNode)
	waitStreamReady(t, aNode, bNode)
	waitStreamReady(t, bNode, aNode)

	_ = pipeA.ConfigureIP("10.0.0.11/24", "fd00::11/64")
	_ = pipeB.ConfigureIP("10.0.0.12/24", "fd00::12/64")
	_ = pipeC.ConfigureIP("10.0.0.13/24", "fd00::13/64")

	aID := aNode.Host.ID()
	bID := bNode.Host.ID()
	cID := cNode.Host.ID()

	// --- Preconditions that make the relay path mandatory ---
	if aNode.isDirectlyConnected(cID) {
		t.Fatalf("DIAGNOSTIC: A and C are directly connected — the relay path is not being exercised")
	}
	if aNode.isBootstrapPeer(bID) {
		t.Fatalf("DIAGNOSTIC: B is classified as a bootstrap peer — this test must relay through an ORDINARY peer")
	}
	if addrs := aNode.SynthesizeRelayCircuitAddrs(cID); len(addrs) != 0 {
		t.Fatalf("DIAGNOSTIC: a circuit-relay address was synthesized (%v) — "+
			"there is no boot relay in this mesh, so reachability must come from the overlay hop", addrs)
	}
	t.Logf("✓ boot-less precondition: A↮C direct, B is an ordinary peer, no circuit addrs available")

	// --- 1+2. Topology convergence, entirely from the production LSA path ---
	// graph[C] holds C's OWN advertisement. B's on-connect flood only carries
	// B's own edges, so C's self-advertised edge can only reach A through the
	// snapshot replay.
	//
	// The 6s budget is load-bearing: C attached ~1.5s before A, so C's NEXT
	// periodic LSA (15s cadence, gossip-forwarded by B) cannot arrive inside
	// this window. A generous timeout here would silently accept the slow
	// periodic path and stop testing the replay at all.
	const snapshotBudget = 6 * time.Second
	snapDeadline := time.Now().Add(snapshotBudget)
	var learnedCSelf bool
	learnStart := time.Now()
	for time.Now().Before(snapDeadline) {
		if _, ok := aNode.Router.GetEdge(cID, bID); ok {
			learnedCSelf = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !learnedCSelf {
		t.Fatalf("NodeA did not learn C's self-advertised C-B edge within %v — the on-connect LSA "+
			"snapshot replay did not run, so a late joiner in a boot-less mesh only discovers the "+
			"far side after C's next 15s periodic broadcast (or never)", snapshotBudget)
	}
	t.Logf("✓ A learned C's self-advertised edge in %v via B's LSA snapshot replay",
		time.Since(learnStart).Round(time.Millisecond))

	waitRouteVia(t, aNode, cID, bID)
	waitRouteVia(t, cNode, aID, bID)
	t.Logf("✓ both A and C computed a relayed route to each other via B")

	// --- 3. Control plane comes up on its own (reconciler, 5s tick) ---
	// NOTE: deliberately no triggerPeerRekey call here.
	waitCipherReady(t, aNode, cID)
	waitCipherReady(t, cNode, aID)
	if po := aNode.peerObf(cID); po == nil || !po.negotiated {
		t.Fatalf("A has no negotiated cipher for C")
	}
	if po := cNode.peerObf(aID); po == nil || !po.negotiated {
		t.Fatalf("C has no negotiated cipher for A")
	}
	t.Logf("✓ A↔C cipher negotiated automatically by relayControlReconciler (no boot circuit involved)")

	// --- 4. Identity arrives on its own (meta loop / LSA piggyback) ---
	// NOTE: deliberately no syncMetadataToPeer call here.
	waitMetaReady(t, aNode, cID)
	t.Logf("✓ A learned C's identity automatically")

	// --- 5. Encrypted data plane A -> B -> C ---
	readerC := newFrameReader(pipeC)
	defer readerC.Close()

	pingFrame := constructICMPv4Packet(testMACA, testMACC,
		net.ParseIP("10.0.0.11"), net.ParseIP("10.0.0.13"), 4343, 1)

	t.Log("Sending ICMP Echo A(10.0.0.11) -> C(10.0.0.13) through the boot-less overlay relay...")
	writeAndExpectWithRetry(t, pipeA, readerC, pingFrame,
		[]byte("P2PTAP_PING_V4_TEST_DATA"), "IPv4 A -> relay(B) -> C, no bootstrap node in the mesh")

	t.Log("✓ A p2ptap mesh with ZERO bootstrap nodes converged and delivered end-to-end encrypted traffic")
}

// staticPeerAddrTTLForTest mirrors the PermanentAddrTTL that Start() uses when
// registering `static_peers` addresses in the peerstore.
const staticPeerAddrTTLForTest = time.Duration(1) << 62

// waitRouteVia polls until node a computes a NON-direct route to target whose
// next hop is wantHop.
func waitRouteVia(t *testing.T, a *Node, target, wantHop peer.ID) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		a.invalidateRouteCache()
		r, ok := a.Router.ComputeRoutes()[target]
		if ok && !r.IsDirect && r.NextHop == wantHop {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never computed a relayed route to %s via %s (ok=%v nextHop=%v direct=%v)",
				a.Host.ID().ShortString(), target.ShortString(), wantHop.ShortString(),
				ok, r.NextHop, r.IsDirect)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
