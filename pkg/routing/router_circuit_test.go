package routing

import (
	"testing"
)

// TestComputeRoutesPrefersDirectOverCircuit pins the core cost-model invariant:
// a circuit-relay path is ONLY a connectivity fallback and must never be
// preferred over a direct (or otherwise non-circuit) path to the same
// destination — even when the circuit path is dramatically lower in raw
// observed latency.
//
// The penalty that realises this is CircuitPenaltyMS (added to every
// LinkCircuit edge in edgeCost). If that penalty is dropped/lowered such that a
// circuit path becomes cheaper than a direct one, this test fails loudly,
// pinning the "circuit = fallback, not preferred" behaviour.
func TestComputeRoutesPrefersDirectOverCircuit(t *testing.T) {
	local := generateTestPeerID(t)
	r := NewRouter(local)

	D := generateTestPeerID(t) // destination reachable BOTH directly and via circuit relay
	R := generateTestPeerID(t) // circuit relay

	// Direct path: local -> D, raw RTT 200ms (slow but direct).
	r.UpdateDirectLink(D, 200, LinkDirect)

	// Circuit path: local -> R (circuit) -> D. The raw observed latency of this
	// whole path is only 10+10 = 20ms — ten times LOWER than the direct path.
	// Without the circuit penalty, Dijkstra would pick the circuit path. With
	// the penalty it must lose to the direct link.
	r.UpdateDirectLink(R, 10, LinkCircuit)
	lsaR := &LinkStatePayload{
		Origin: R.String(),
		Seq:    1,
		TTL:    5,
		Neighbors: map[string]int64{
			local.String(): 10,
			D.String():     10,
		},
	}
	if !r.ProcessLSA(lsaR) {
		t.Fatalf("ProcessLSA(R) returned false")
	}

	routes := r.ComputeRoutes()

	routeD, ok := routes[D]
	if !ok {
		t.Fatalf("Expected a route to D")
	}

	// The direct link MUST be selected, never the circuit relay.
	if routeD.NextHop != D {
		t.Errorf("Expected D routed directly (next hop %s), got relay next hop %s", D.ShortString(), routeD.NextHop.ShortString())
	}
	if !routeD.IsDirect {
		t.Errorf("Expected D to be a DIRECT route, but it was relayed (circuit path was preferred)")
	}

	// Display RTT must be the raw observed sum (200ms direct), NOT the circuit
	// path's 20ms — confirming the penalty drove selection without corrupting
	// the reported latency.
	if routeD.TotalRTTMs != 200 {
		t.Errorf("Expected reported RTT for direct D to be 200ms, got %d", routeD.TotalRTTMs)
	}

	// Sanity: the circuit path really was a tempting alternative. If the penalty
	// were absent, the circuit path's penalised cost (10+10 = 20) would beat the
	// direct path (200). We assert the circuit relay R is reachable, so D had a
	// genuine second option that the cost model correctly rejected.
	if _, ok := routes[R]; !ok {
		t.Fatalf("Expected the circuit relay R to be reachable (so D had a real alternative)")
	}
}

// TestComputeRoutesCircuitAsConnectivityFallback pins the OTHER half of the
// invariant: a peer reachable ONLY through a circuit relay must remain
// reachable (the circuit path is kept as a fallback), and must be reported as a
// relayed (non-direct) route via the relay — never silently dropped, never
// reported as direct.
func TestComputeRoutesCircuitAsConnectivityFallback(t *testing.T) {
	local := generateTestPeerID(t)
	r := NewRouter(local)

	R := generateTestPeerID(t) // circuit relay
	E := generateTestPeerID(t) // destination reachable ONLY via R

	// E has no direct link from local. Its only road out is through the circuit
	// relay R.
	r.UpdateDirectLink(R, 10, LinkCircuit)
	lsaR := &LinkStatePayload{
		Origin: R.String(),
		Seq:    1,
		TTL:    5,
		Neighbors: map[string]int64{
			local.String(): 10,
			E.String():     10,
		},
	}
	if !r.ProcessLSA(lsaR) {
		t.Fatalf("ProcessLSA(R) returned false")
	}

	routes := r.ComputeRoutes()

	routeE, ok := routes[E]
	if !ok {
		t.Fatalf("Expected E to be reachable via circuit fallback, but no route was computed (circuit fallback dropped)")
	}
	if routeE.IsDirect {
		t.Errorf("Expected E to be relayed via circuit (non-direct), got a direct route")
	}
	if routeE.NextHop != R {
		t.Errorf("Expected E routed via circuit relay %s, got next hop %s", R.ShortString(), routeE.NextHop.ShortString())
	}

	// Reported RTT is the raw observed sum along the circuit path (10+10 = 20),
	// confirming fallback routes are surfaced with their true latency.
	if routeE.TotalRTTMs != 20 {
		t.Errorf("Expected reported RTT for circuit-routed E to be 20ms, got %d", routeE.TotalRTTMs)
	}
}

// TestEdgeCostCircuitPenalty pins the exact shape of the cost model that the two
// behavioural tests above rely on: a circuit edge costs
// Weight + CircuitPenaltyMS + HopPenaltyMS, while a direct edge costs only
// Weight + HopPenaltyMS. This stops someone from "fixing" the numbers in a way
// that silently re-prioritises circuit paths.
func TestEdgeCostCircuitPenalty(t *testing.T) {
	direct := edgeCost(LinkEdge{Weight: 10, Class: LinkDirect})
	circuit := edgeCost(LinkEdge{Weight: 10, Class: LinkCircuit})

	wantDirect := int64(10 + HopPenaltyMS)
	wantCircuit := int64(10 + CircuitPenaltyMS + HopPenaltyMS)

	if direct != wantDirect {
		t.Errorf("direct edgeCost = %d, want %d", direct, wantDirect)
	}
	if circuit != wantCircuit {
		t.Errorf("circuit edgeCost = %d, want %d", circuit, wantCircuit)
	}
	if circuit <= direct {
		t.Errorf("circuit edgeCost (%d) must be strictly greater than direct edgeCost (%d)", circuit, direct)
	}
}
