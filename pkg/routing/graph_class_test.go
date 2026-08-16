package routing

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"
)

// TestGetGraphCarriesLinkClass locks in that the snapshot exposes each edge's
// transport class.
//
// Before this, GetGraph built TopologyEdge{From,To,RTT} and silently dropped
// LinkEdge.Class, so every consumer downstream (the /api/topology response, the
// WebUI graph) rendered a circuit-relayed link identically to a genuine direct
// one — the single most misleading thing a multi-cluster topology view can do,
// because it hides that a link only exists thanks to a shared relay.
func TestGetGraphCarriesLinkClass(t *testing.T) {
	self := test.RandPeerIDFatal(t)
	direct := test.RandPeerIDFatal(t)
	circuit := test.RandPeerIDFatal(t)

	r := NewRouter(self)
	r.SetEdge(self, direct, 12, LinkDirect)
	r.SetEdge(self, circuit, 480, LinkCircuit)

	snap := r.GetGraph()
	got := map[peer.ID]LinkClass{}
	for _, e := range snap.Edges {
		other := e.To
		if e.To == self {
			other = e.From
		}
		got[other] = e.Class
	}
	if len(snap.Edges) != 2 {
		t.Fatalf("expected 2 undirected edges, got %d: %+v", len(snap.Edges), snap.Edges)
	}
	if got[direct] != LinkDirect {
		t.Errorf("direct edge lost its class: got %v want %v", got[direct], LinkDirect)
	}
	if got[circuit] != LinkCircuit {
		t.Errorf("circuit edge lost its class: got %v want %v", got[circuit], LinkCircuit)
	}
}

// TestGetGraphMergesDisagreeingDirections covers the asymmetric case, which is
// normal rather than exotic: each endpoint reports its OWN view of a link, so we
// can hold a direct connection to a peer while that peer's flooded LSA still
// describes the same link as circuit-relayed.
//
// GetGraph emits every undirected pair once. Keeping "whichever direction the
// map iteration happened to visit first" made the snapshot non-deterministic —
// the very same graph would render the link as direct on one poll and circuit on
// the next. The merge rule is: better (lower) class wins; within one class the
// lower RTT wins.
func TestGetGraphMergesDisagreeingDirections(t *testing.T) {
	self := test.RandPeerIDFatal(t)
	peerB := test.RandPeerIDFatal(t)

	r := NewRouter(self)
	// Our own view: a real direct connection at 15ms.
	r.UpdateDirectLink(peerB, 15, LinkDirect)
	// B's flooded view of the same link: circuit-relayed, much slower.
	applyLSAOrFail(t, r, peerB, self, 620, LinkCircuit)

	// Repeat: a single run could pass by luck given random map ordering.
	for i := 0; i < 50; i++ {
		snap := r.GetGraph()
		if len(snap.Edges) != 1 {
			t.Fatalf("iteration %d: expected exactly 1 undirected edge, got %d: %+v", i, len(snap.Edges), snap.Edges)
		}
		e := snap.Edges[0]
		if e.Class != LinkDirect {
			t.Fatalf("iteration %d: merged edge should keep the better (direct) class, got %v", i, e.Class)
		}
		if e.RTT != 15 {
			t.Fatalf("iteration %d: merged edge should carry the direct RTT 15, got %d", i, e.RTT)
		}
	}
}

// TestGetGraphKeepsLowerRTTWithinSameClass verifies the tie-break inside one
// class, so a stale high-latency direction cannot mask a freshly measured one.
func TestGetGraphKeepsLowerRTTWithinSameClass(t *testing.T) {
	self := test.RandPeerIDFatal(t)
	peerB := test.RandPeerIDFatal(t)

	r := NewRouter(self)
	r.UpdateDirectLink(peerB, 40, LinkDirect)
	applyLSAOrFail(t, r, peerB, self, 9, LinkDirect)

	for i := 0; i < 50; i++ {
		snap := r.GetGraph()
		if len(snap.Edges) != 1 {
			t.Fatalf("iteration %d: expected 1 edge, got %d", i, len(snap.Edges))
		}
		if snap.Edges[0].RTT != 9 {
			t.Fatalf("iteration %d: expected the lower RTT 9 to win, got %d", i, snap.Edges[0].RTT)
		}
	}
}

// applyLSAOrFail feeds a one-neighbour LSA from origin and fails the test if the
// router rejected it. Asserting the return value matters: ProcessLSA silently
// drops an LSA whose Origin is not a decodable peer ID, which would let these
// tests "pass" without ever exercising the merge path.
func applyLSAOrFail(t *testing.T, r *Router, origin, neighbor peer.ID, rtt int64, class LinkClass) {
	t.Helper()
	ok := r.ProcessLSA(&LinkStatePayload{
		Origin:          origin.String(),
		Seq:             1,
		TTL:             3,
		Neighbors:       map[string]int64{neighbor.String(): rtt},
		NeighborClasses: map[string]int{neighbor.String(): int(class)},
		Timestamp:       1,
	})
	if !ok {
		t.Fatalf("router rejected the LSA from %s — the test would not exercise the merge path", origin.ShortString())
	}
}
