package node

import (
	"testing"
	"time"

	"p2ptap/pkg/routing"
	"p2ptap/pkg/tap"
)


// TestLSASnapshotReplayConvergesLateJoiner verifies that a node joining an
// ALREADY-CONVERGED mesh immediately receives the full topology, not just its
// new neighbour's links.
//
// Topology and ordering are the whole point:
//
//	step 1:  B ── C          (connect, let the mesh go quiet)
//	step 2:  A ── B          (A joins late)
//
// Why the ordering matters: LSA forwarding is CHANGE-triggered. By the time A
// connects, B already holds C's LSA, so re-receiving it changes nothing and B
// never forwards it onward. broadcastLSA only ever advertises the sender's OWN
// links, so A learns B's neighbour set (including the B-C edge) but nothing
// authored by C itself. The routing graph is keyed by LSA origin
// (Router.ProcessLSA assigns graph[origin] = neighbours), so graph[C] stays
// EMPTY on A: C looks like a dead-end leaf with no links of its own.
//
// pushLSASnapshotToPeer closes that hole by replaying every cached third-party
// LSA to the newly connected peer. This is what lets a node bootstrap the whole
// mesh through a single StaticPeer with no bootstrap node in the picture.
//
// Regression contract: A must hold C-authored edges within 2s. Without the
// snapshot the only remaining path is C's 15s periodic re-broadcast (a fresh
// sequence number makes ProcessLSA report "changed", so B forwards it then), so
// the 2s bound cleanly separates "snapshot worked" from "waited for the ticker".
func TestLSASnapshotReplayConvergesLateJoiner(t *testing.T) {
	tapA, _ := tap.NewMemTAPPair("snapTapA", "snapPipeA")
	tapB, _ := tap.NewMemTAPPair("snapTapB", "snapPipeB")
	tapC, _ := tap.NewMemTAPPair("snapTapC", "snapPipeC")

	cfgA := createTestNodeConfig("10.9.0.1/24", "fd09::1/64", "best_path")
	cfgB := createTestNodeConfig("10.9.0.2/24", "fd09::2/64", "best_path")
	cfgC := createTestNodeConfig("10.9.0.3/24", "fd09::3/64", "best_path")

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

	aID := aNode.Host.ID()
	bID := bNode.Host.ID()
	cID := cNode.Host.ID()

	// --- step 1: establish B <-> C and wait for it to go quiet ---
	connect(bNode, cNode)
	waitOverlayReady(t, bNode, cNode)

	// B must have cached C's LSA; that cache is the snapshot source.
	deadline := time.Now().Add(10 * time.Second)
	for {
		bNode.lsaCacheMu.RLock()
		_, cached := bNode.lsaCache[cID]
		bNode.lsaCacheMu.RUnlock()
		if cached {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("NodeB never cached NodeC's LSA — snapshot has no source to replay")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Sanity: B really does know C-authored edges (graph[C] populated).
	if _, ok := bNode.Router.GetEdge(cID, bID); !ok {
		t.Fatalf("SANITY: NodeB has no C-authored edge C->B; test premise broken")
	}
	// Sanity: A knows nothing yet.
	if _, ok := aNode.Router.GetEdge(cID, bID); ok {
		t.Fatalf("SANITY: NodeA already holds a C-authored edge before joining")
	}

	// --- step 2: A joins late ---
	joinedAt := time.Now()
	connect(aNode, bNode)

	// A must learn C-AUTHORED edges (graph[C]) fast. Only the on-connect
	// snapshot replay can deliver these; B's own LSA carries graph[B] only.
	snapshotBudget := 2 * time.Second
	converged := false
	for time.Since(joinedAt) < snapshotBudget {
		if _, ok := aNode.Router.GetEdge(cID, bID); ok {
			converged = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !converged {
		t.Fatalf("NodeA did not receive C-authored edges within %v after joining — "+
			"on-connect LSA snapshot replay is not working (fell back to the 15s ticker)",
			snapshotBudget)
	}
	t.Logf("✓ NodeA learned C-authored topology %v after joining (snapshot replay)",
		time.Since(joinedAt).Round(time.Millisecond))

	// A must now be able to route to C with NextHop == B (relayed, not direct).
	routeDeadline := time.Now().Add(2 * time.Second)
	var r routing.RouteInfo
	for {
		aNode.invalidateRouteCache()
		routes := aNode.Router.ComputeRoutes()
		var ok bool
		if r, ok = routes[cID]; ok {
			break
		}
		if time.Now().After(routeDeadline) {
			t.Fatalf("NodeA has no route to NodeC after snapshot convergence")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if r.IsDirect {
		t.Fatalf("NodeA's route to NodeC is marked direct, expected relayed via B")
	}
	if r.NextHop != bID {
		t.Fatalf("NodeA route to C has NextHop %s, expected B (%s)",
			r.NextHop.ShortString(), bID.ShortString())
	}

	t.Logf("✓ NodeA route to C: NextHop=%s path=%v", r.NextHop.ShortString(), r.Path)

	// The snapshot must never echo a peer's own LSA back at it, and must never
	// contain the local node (broadcastLSA owns that advertisement).
	//
	// B caches A's LSA asynchronously: A's ConnectedF broadcasts A's OWN LSA to B
	// (node.go:1578-1586), and B accepts it via handleLSAStream → ProcessLSA →
	// cacheLSA. That arrival is event-driven (a single goroutine spawned on
	// connect), NOT on a fixed tick, so it races the assertion below. On slower
	// schedulers (e.g. macOS, where the dialer's ConnectedF typically fires after
	// the listener's) A's broadcast can land a beat after A already converged via
	// B's snapshot push. Wait for it, exactly like the C-cache wait at line 81 —
	// an instant check here is a false failure, not a real regression.
	cacheDeadline := time.Now().Add(10 * time.Second)
	aCached := false
	selfCached := false
	for {
		bNode.lsaCacheMu.RLock()
		_, selfCached = bNode.lsaCache[bID]
		_, aCached = bNode.lsaCache[aID]
		bNode.lsaCacheMu.RUnlock()
		if aCached {
			break
		}
		if time.Now().After(cacheDeadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if selfCached {
		t.Errorf("NodeB cached its OWN LSA — cacheLSA must skip self-origin")
	}
	if !aCached {
		t.Errorf("NodeB did not cache NodeA's LSA after A joined")
	}
}

// TestLSASeqMonotonicAcrossCallSites guards the sequence-space fix.
//
// The bug: broadcastLSA had two independent sequence sources — the 15s ticker
// used a local counter starting at 1, while every event-driven force push used
// time.Now().UnixNano() (~1.7e18). Router.ProcessLSA rejects lsa.Seq <= lastSeq,
// so the first force push poisoned each peer's seqMap and made EVERY subsequent
// periodic LSA look stale. Because Router.lastUpdated[origin] is refreshed only
// by an ACCEPTED LSA and CleanStaleNodes(60s) purges anything staler than that,
// the entire mesh dropped the origin from its topology graph ~60s after any
// connect/disconnect — silently breaking multi-hop routing.
//
// Contract: one shared monotonic counter, seeded high enough that a RESTARTED
// node is never rejected as stale by peers that remember its previous sequences.
func TestLSASeqMonotonicAcrossCallSites(t *testing.T) {
	tapX, _ := tap.NewMemTAPPair("seqTapX", "seqPipeX")
	cfgX := createTestNodeConfig("10.9.1.1/24", "fd09:1::1/64", "best_path")
	n, err := NewNodeWithTAP(cfgX, tapX, nil)
	if err != nil {
		t.Fatalf("create node: %v", err)
	}
	defer n.Close()

	// Restart safety: the counter must be seeded from wall-clock nanoseconds,
	// not from zero, or a restarted node's LSAs are rejected as stale until the
	// remote CleanStaleNodes purge (up to 60s of invisibility).
	first := n.nextLSASeq()
	minSeed := uint64(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	if first < minSeed {
		t.Fatalf("LSA seq seed %d is below the wall-clock floor %d — a restarted "+
			"node would be rejected as stale by its peers", first, minSeed)
	}

	// Strict monotonicity across many calls, mixing "ticker" and "force push"
	// call sites (both now share nextLSASeq).
	prev := first
	for i := 0; i < 1000; i++ {
		cur := n.nextLSASeq()
		if cur <= prev {
			t.Fatalf("LSA seq not strictly increasing at i=%d: %d after %d", i, cur, prev)
		}
		prev = cur
	}
	t.Logf("✓ LSA seq monotonic: %d -> %d over 1001 calls", first, prev)
}
