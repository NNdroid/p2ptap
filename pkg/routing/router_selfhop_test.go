package routing

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

// TestComputeRoutesNeverRelaysViaSelf is a regression test for the WebUI
// "Overlay Relay via <self>" mislabel. A route whose next hop equals the local
// node is meaningless — you cannot relay a frame through yourself — and it
// surfaced because (a) the link-state graph could carry a self-edge and (b) the
// WebUI guard compared the next hop against the *destination* peer instead of
// the local node. This test locks in three guarantees:
//
//  1. UpdateDirectLink refuses to record the local node as its own neighbour.
//  2. ProcessLSA drops a self-neighbour entry from any LSA (including our own).
//  3. ComputeRoutes never emits a route whose NextHop == localPeerID, even if a
//     stray self-edge somehow exists in the graph.
func TestComputeRoutesNeverRelaysViaSelf(t *testing.T) {
	local := generateTestPeerID(t)
	r := NewRouter(local)

	A := generateTestPeerID(t)
	B := generateTestPeerID(t)

	// 1. UpdateDirectLink(local, ...) must be a no-op (no self-edge).
	r.UpdateDirectLink(local, 5, LinkDirect)
	if nbrs, ok := r.graph[local]; ok {
		if _, self := nbrs[local]; self {
			t.Fatalf("UpdateDirectLink recorded the local node as its own neighbour")
		}
	}

	// 2. ProcessLSA must drop a self-neighbour entry.
	lsaSelf := &LinkStatePayload{
		Origin: local.String(),
		Seq:    1,
		TTL:    5,
		Neighbors: map[string]int64{
			local.String(): 5, // ← self entry, must be filtered
			A.String():     10,
		},
	}
	if !r.ProcessLSA(lsaSelf) {
		t.Fatalf("ProcessLSA(self) returned false")
	}
	if nbrs, ok := r.graph[local]; ok {
		if _, self := nbrs[local]; self {
			t.Fatalf("ProcessLSA kept the local node as its own neighbour")
		}
		if _, a := nbrs[A]; !a {
			t.Fatalf("ProcessLSA dropped the legitimate neighbour A")
		}
	}

	// Build a real multi-hop topology: local - A - B (no direct local-B link).
	r.UpdateDirectLink(A, 10, LinkDirect)
	lsaA := &LinkStatePayload{
		Origin: A.String(),
		Seq:    1,
		TTL:    5,
		Neighbors: map[string]int64{
			local.String(): 10,
			B.String():     20,
		},
	}
	if !r.ProcessLSA(lsaA) {
		t.Fatalf("ProcessLSA(A) returned false")
	}

	// 3a. Even with a stray self-edge forced directly into the graph, ComputeRoutes
	// must not produce a self next hop.
	r.mu.Lock()
	if r.graph[local] == nil {
		r.graph[local] = make(map[peer.ID]LinkEdge)
	}
	r.graph[local][local] = LinkEdge{Weight: 1} // simulate a self-edge that slipped past guards
	r.mu.Unlock()

	routes := r.ComputeRoutes()

	// B must still be reachable via A (the legitimate hop), never via local.
	routeB, ok := routes[B]
	if !ok {
		t.Fatalf("Expected a route to B")
	}
	if routeB.NextHop == local {
		t.Fatalf("ComputeRoutes emitted a self next hop for B: %s", routeB.NextHop)
	}
	if routeB.NextHop != A {
		t.Errorf("Expected B routed via A, got next hop %s", routeB.NextHop)
	}
	if routeB.IsDirect {
		t.Errorf("Expected B relayed via A, got direct")
	}

	// No route in the whole table may have the local node as its next hop.
	for dest, route := range routes {
		if route.NextHop == local {
			t.Errorf("Route to %s has the local node as next hop (self-relay)", dest)
		}
	}
}

// TestProcessLSASkipsRemoteSelfNeighbour ensures a *remote* peer advertising the
// local node as its own neighbour does not create a self-edge on the local node
// and is simply recorded as a normal remote→local edge.
func TestProcessLSASkipsRemoteSelfNeighbour(t *testing.T) {
	local := generateTestPeerID(t)
	r := NewRouter(local)

	remote := generateTestPeerID(t)
	// remote claims local is its own neighbour — that entry is about `remote`,
	// not `local`, so it must be dropped (a node is never its own neighbour).
	lsa := &LinkStatePayload{
		Origin: remote.String(),
		Seq:    1,
		TTL:    5,
		Neighbors: map[string]int64{
			remote.String(): 7, // self entry for remote → must be filtered
			local.String():  7, // legitimate remote→local edge
		},
	}
	if !r.ProcessLSA(lsa) {
		t.Fatalf("ProcessLSA(remote) returned false")
	}
	if nbrs, ok := r.graph[remote]; ok {
		if _, self := nbrs[remote]; self {
			t.Fatalf("ProcessLSA kept remote node as its own neighbour")
		}
		if _, l := nbrs[local]; !l {
			t.Fatalf("ProcessLSA dropped the legitimate remote→local edge")
		}
	}
}
