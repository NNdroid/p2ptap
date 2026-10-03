package routing

import (
	"github.com/libp2p/go-libp2p/core/peer"
	"math"
)

// Revision changes only when routing evidence changes. Packet readers need no
// graph lock to detect a withdrawn link or a new LSA.
func (r *Router) Revision() uint64 { return r.revision.Load() }

func (r *Router) LocalNeighbors() []peer.ID {
	r.mu.RLock()
	defer r.mu.RUnlock()
	neighbors := make([]peer.ID, 0, len(r.graph[r.localPeerID]))
	for pid := range r.graph[r.localPeerID] {
		neighbors = append(neighbors, pid)
	}
	return neighbors
}

// ComputeRoutesSnapshot pairs the graph revision with immutable decisions.
// Healthy incumbent paths survive changes below 5ms or 10% of their cost.
// Missing edges bypass hysteresis immediately.
func (r *Router) ComputeRoutesSnapshot(previous map[peer.ID]RouteInfo) (map[peer.ID]RouteInfo, uint64) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	routes := r.routesWithinBudgetLocked(MaxRelayTTL, nil)
	for dst, old := range previous {
		best, ok := routes[dst]
		if !ok || best.NextHop == old.NextHop {
			continue
		}
		cost, rtt, valid := r.pathCostLocked(old.Path)
		if !valid || len(old.Path)-1 > MaxRelayTTL {
			continue
		}
		bestCost, _, _ := r.pathCostLocked(best.Path)
		margin := max(int64(5), cost/10)
		if bestCost >= cost || cost-bestCost < margin {
			old.TotalRTTMs = rtt
			old.DirectRTTMs = best.DirectRTTMs
			routes[dst] = old
		}
	}
	return routes, r.revision.Load()
}

// ComputeRoutesWithinBudget finds a feasible alternative, rather than dropping
// the unconstrained optimum. Excluded first hops are already known unusable.
func (r *Router) ComputeRoutesWithinBudget(hops int, excluded map[peer.ID]bool) map[peer.ID]RouteInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.routesWithinBudgetLocked(hops, excluded)
}

type boundedRouteLabel struct {
	cost, rtt       int64
	previous, first peer.ID
}

func (r *Router) routesWithinBudgetLocked(hops int, excluded map[peer.ID]bool) map[peer.ID]RouteInfo {
	hops = min(hops, MaxRelayTTL)
	routes := make(map[peer.ID]RouteInfo)
	if hops <= 0 {
		return routes
	}
	// One label per (node, exact hop count) is essential: a cheaper prefix with
	// more hops must not discard a costlier prefix that can still reach the end.
	layers := make([]map[peer.ID]boundedRouteLabel, hops+1)
	layers[0] = map[peer.ID]boundedRouteLabel{r.localPeerID: {}}
	for h := 1; h <= hops; h++ {
		layers[h] = make(map[peer.ID]boundedRouteLabel)
		for u, prefix := range layers[h-1] {
			for v, edge := range r.graph[u] {
				if v == u || v == r.localPeerID || (h == 1 && excluded[v]) {
					continue
				}
				ec := edgeCost(edge)
				if ec <= 0 || prefix.cost >= math.MaxInt64-ec {
					continue
				}
				first := prefix.first
				if h == 1 {
					first = v
				}
				next := boundedRouteLabel{cost: prefix.cost + ec, rtt: prefix.rtt + edge.Weight, previous: u, first: first}
				old, exists := layers[h][v]
				if !exists || next.cost < old.cost || (next.cost == old.cost && (next.first < old.first || (next.first == old.first && next.previous < old.previous))) {
					layers[h][v] = next
				}
			}
		}
	}
	bestHops := make(map[peer.ID]int)
	for h := 1; h <= hops; h++ {
		for dst, label := range layers[h] {
			oldH, exists := bestHops[dst]
			if !exists || label.cost < layers[oldH][dst].cost {
				bestHops[dst] = h
			}
		}
	}
	for dst, h := range bestHops {
		label := layers[h][dst]
		path := make([]peer.ID, h+1)
		cur := dst
		for i := h; i > 0; i-- {
			path[i] = cur
			cur = layers[i][cur].previous
		}
		path[0] = r.localPeerID
		direct := r.graph[r.localPeerID][dst].Weight
		routes[dst] = RouteInfo{Dest: dst, NextHop: label.first, Path: path, TotalRTTMs: label.rtt, DirectRTTMs: direct, IsDirect: label.first == dst}
	}
	return routes
}

func (r *Router) pathCostLocked(path []peer.ID) (int64, int64, bool) {
	if len(path) < 2 || path[0] != r.localPeerID {
		return 0, 0, false
	}
	var cost, rtt int64
	for i := 1; i < len(path); i++ {
		edge, ok := r.graph[path[i-1]][path[i]]
		ec := edgeCost(edge)
		if !ok || ec <= 0 || cost >= math.MaxInt64-ec {
			return 0, 0, false
		}
		cost += ec
		rtt += edge.Weight
	}
	return cost, rtt, true
}
