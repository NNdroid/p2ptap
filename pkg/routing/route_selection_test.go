package routing

import (
	"github.com/libp2p/go-libp2p/core/peer"
	"math/rand"
	"testing"
)

// An independent oracle enumerates simple paths on small cyclic graphs; it
// catches lost hop-state prefixes without mirroring the layered algorithm.
func TestRouteSelectionMatchesBoundedPathOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(17))
	ids := []peer.ID{"A", "B", "C", "D", "E", "F"}
	for round := 0; round < 80; round++ {
		r := NewRouter(ids[0])
		for i := 0; i < len(ids); i++ {
			for j := i + 1; j < len(ids); j++ {
				if rng.Intn(3) != 0 {
					r.SetEdge(ids[i], ids[j], int64(1+rng.Intn(200)), LinkClass(rng.Intn(2)))
				}
			}
		}
		for budget := 1; budget <= MaxRelayTTL; budget++ {
			want := make(map[peer.ID]int64)
			seen := map[peer.ID]bool{ids[0]: true}
			var walk func(peer.ID, int, int64)
			walk = func(u peer.ID, remaining int, cost int64) {
				if remaining == 0 {
					return
				}
				for v, edge := range r.graph[u] {
					if seen[v] {
						continue
					}
					next := cost + edgeCost(edge)
					if old, ok := want[v]; !ok || next < old {
						want[v] = next
					}
					seen[v] = true
					walk(v, remaining-1, next)
					delete(seen, v)
				}
			}
			walk(ids[0], budget, 0)
			got := r.ComputeRoutesWithinBudget(budget, nil)
			if len(got) != len(want) {
				t.Fatalf("round=%d budget=%d reachable mismatch", round, budget)
			}
			for dst, cost := range want {
				actual, _, ok := r.pathCostLocked(got[dst].Path)
				if !ok || actual != cost || len(got[dst].Path)-1 > budget {
					t.Fatalf("round=%d budget=%d dest=%s: cost=%d want=%d path=%v", round, budget, dst, actual, cost, got[dst].Path)
				}
			}
		}
	}
}

func TestRouteSelectionRetainsFeasibleHopBudgetAlternative(t *testing.T) {
	ids := make([]peer.ID, 7)
	for i := range ids {
		ids[i] = generateTestPeerID(t)
	}
	r := NewRouter(ids[0])
	r.UpdateDirectLink(ids[6], 200, LinkDirect)
	r.UpdateDirectLink(ids[1], 1, LinkDirect)
	for i := 1; i < 6; i++ {
		if !r.ProcessLSA(&LinkStatePayload{Origin: ids[i].String(), Seq: 1, TTL: DefaultLSATTL, Neighbors: map[string]int64{ids[i+1].String(): 1}}) {
			t.Fatal("LSA rejected")
		}
	}
	if route := r.ComputeRoutes()[ids[6]]; !route.IsDirect || route.TotalRTTMs != 200 {
		t.Fatalf("selected impossible path: %+v", route)
	}
	// The node at index 4 has both a cheap four-hop prefix and a dear one-hop
	// prefix. Only the latter can reach the destination inside the five-hop cap.
	r.UpdateDirectLink(ids[4], 50, LinkDirect)
	route := r.ComputeRoutes()[ids[6]]
	if route.NextHop != ids[4] || len(route.Path) != 4 || route.TotalRTTMs != 52 {
		t.Fatalf("lost feasible costlier prefix: %+v", route)
	}
	for _, route := range r.ComputeRoutes() {
		if len(route.Path)-1 > MaxRelayTTL {
			t.Fatalf("exceeded hop budget: %+v", route)
		}
	}
	// A forwarding hop with only one edge left must use the direct alternative.
	if route := r.ComputeRoutesWithinBudget(1, nil)[ids[6]]; !route.IsDirect {
		t.Fatalf("remaining budget ignored: %+v", route)
	}
}

func TestRouteSelectionDisconnectPreservesRemoteLSA(t *testing.T) {
	a, b, c := generateTestPeerID(t), generateTestPeerID(t), generateTestPeerID(t)
	r := NewRouter(a)
	r.UpdateDirectLink(c, 10, LinkDirect)
	r.UpdateDirectLink(b, 20, LinkDirect)
	lsa := &LinkStatePayload{Origin: b.String(), Seq: 7, TTL: DefaultLSATTL, Neighbors: map[string]int64{c.String(): 20}}
	if !r.ProcessLSA(lsa) {
		t.Fatal("LSA rejected")
	}
	// Preserve C's own newer announcement too; disconnect is not a sequence reset.
	if !r.ProcessLSA(&LinkStatePayload{Origin: c.String(), Seq: 9, Neighbors: map[string]int64{b.String(): 20}}) {
		t.Fatal("C LSA rejected")
	}
	rev := r.Revision()
	r.RemoveDirectLink(c)
	route, ok := r.ComputeRoutes()[c]
	if !ok || route.NextHop != b || route.IsDirect {
		t.Fatalf("relay failover lost: %+v", route)
	}
	if _, ok := r.GetEdge(b, c); !ok {
		t.Fatal("unrelated edge deleted")
	}
	if r.Revision() == rev {
		t.Fatal("withdrawal did not advance revision")
	}
	if r.ProcessLSA(&LinkStatePayload{Origin: c.String(), Seq: 8}) {
		t.Fatal("disconnect reset remote LSA sequence")
	}
	r.UpdateLinkRTT(c, 1)
	if _, ok := r.GetEdge(a, c); ok {
		t.Fatal("late probe resurrected disconnected adjacency")
	}
}

func TestRouteSelectionStableAndHysteresis(t *testing.T) {
	a, b, c, d := peer.ID("A"), peer.ID("B"), peer.ID("C"), peer.ID("D")
	r := NewRouter(a)
	r.SetEdge(a, b, 10, LinkDirect)
	r.SetEdge(a, c, 10, LinkDirect)
	r.SetEdge(b, d, 10, LinkDirect)
	r.SetEdge(c, d, 10, LinkDirect)
	for i := 0; i < 200; i++ {
		if route := r.ComputeRoutes()[d]; route.NextHop != b {
			t.Fatalf("unstable equal-cost route: %+v", route)
		}
	}
	previous, _ := r.ComputeRoutesSnapshot(nil)
	r.UpdateLinkRTT(b, 11)
	current, _ := r.ComputeRoutesSnapshot(previous)
	if current[d].NextHop != b || current[d].TotalRTTMs != 21 {
		t.Fatalf("small jitter changed incumbent: %+v", current[d])
	}
	r.UpdateLinkRTT(b, 100)
	current, _ = r.ComputeRoutesSnapshot(current)
	if current[d].NextHop != c {
		t.Fatal("material improvement ignored")
	}
	r.RemoveDirectLink(c)
	current, _ = r.ComputeRoutesSnapshot(current)
	if current[d].NextHop != b {
		t.Fatal("hysteresis retained dead path")
	}
	if route := r.ComputeRoutesWithinBudget(5, map[peer.ID]bool{b: true})[d]; route.NextHop != "" {
		t.Fatal("excluded only remaining hop used")
	}
}

func TestRouteSelectionRevisionIgnoresIdenticalEvidence(t *testing.T) {
	a, b := generateTestPeerID(t), generateTestPeerID(t)
	r := NewRouter(a)
	r.UpdateDirectLink(b, 10, LinkDirect)
	rev := r.Revision()
	r.UpdateDirectLink(b, 10, LinkDirect)
	r.UpdateLinkRTT(b, 10)
	if r.Revision() != rev {
		t.Fatal("unchanged adjacency invalidates packet cache")
	}
	lsa := &LinkStatePayload{Origin: b.String(), Seq: 1, Neighbors: map[string]int64{a.String(): 10}}
	r.ProcessLSA(lsa)
	rev = r.Revision()
	lsa.Seq++
	r.ProcessLSA(lsa)
	if r.Revision() != rev {
		t.Fatal("LSA heartbeat changed graph version")
	}
}
