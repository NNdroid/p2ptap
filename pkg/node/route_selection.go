package node

import (
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/routing"
)

// overlayRoute returns the same eligible next hop used by both readiness
// checks and forwarding. Exceptional cases search for a feasible alternative
// instead of blindly sending to a blacklisted or unsupported cached hop.
func (n *Node) overlayRoute(target peer.ID, budget int, previous peer.ID) (routing.RouteInfo, bool) {
	if n.Router == nil {
		return routing.RouteInfo{}, false
	}
	usable := func(route routing.RouteInfo) bool {
		return route.NextHop != "" && route.NextHop != previous && len(route.Path)-1 <= budget && n.routeHopUsable(route.NextHop, target)
	}
	if route, ok := n.getCachedRoutes()[target]; ok && usable(route) {
		return route, true
	}
	excluded := make(map[peer.ID]bool)
	if previous != "" {
		excluded[previous] = true
	}
	for _, hop := range n.Router.LocalNeighbors() {
		if !n.routeHopUsable(hop, target) {
			excluded[hop] = true
		}
	}
	route, ok := n.Router.ComputeRoutesWithinBudget(budget, excluded)[target]
	return route, ok && usable(route)
}

func (n *Node) routeHopUsable(hop, target peer.ID) bool {
	if n.Host == nil || hop == n.Host.ID() {
		return false
	}
	if hop == target {
		state := n.Host.Network().Connectedness(hop)
		return state == network.Connected || state == network.Limited
	}
	if n.isBootstrapPeer(hop) {
		return n.hasBootRelayUplink(hop) && !n.isBootRelayBlacklisted(hop)
	}
	state := n.Host.Network().Connectedness(hop)
	return (state == network.Connected || state == network.Limited) && n.supportsOverlayRelay(hop) && !n.isOverlayRelayBlacklisted(hop)
}

func (n *Node) canEgressWithRoute(target peer.ID, route routing.RouteInfo, hasRoute bool) bool {
	if n.pskRequired() && !n.hasNegotiatedCipher(target) {
		return false
	}
	if hasRoute && !route.IsDirect {
		hop := route.NextHop
		if n.isBootstrapPeer(hop) {
			return n.hasBootRelayUplink(hop) && !n.isBootRelayBlacklisted(hop)
		}
		return n.routeHopUsable(hop, target) && (n.isPeerReady(hop) || n.obfCipherForPeer(hop) != nil || n.isDirectlyConnected(hop))
	}
	return n.canEgressToPeer(target)
}
