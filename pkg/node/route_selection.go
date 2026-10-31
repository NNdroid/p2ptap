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
		// A directly-connected target is delivered directly. The overlay
		// blacklist must still apply so the selection gate matches the
		// submission gate (relayPool.Submit rejects a blacklisted hop): without
		// it, a directly-connected target that got circuit-broken as a relay hop
		// would be selected here and then silently dropped at Submit.
		if n.isOverlayRelayBlacklisted(hop) {
			return false
		}
		state := n.Host.Network().Connectedness(hop)
		return state == network.Connected || state == network.Limited
	}
	if n.isBootstrapPeer(hop) {
		return n.hasBootRelayUplink(hop) && !n.isBootRelayBlacklisted(hop)
	}
	state := n.Host.Network().Connectedness(hop)
	// hopStreamLive closes the selection/submission gap for a hop that is
	// libp2p-Connected but whose pool stream is stuck in reconnect backoff:
	// without it the hop is selected and frames queue into a dead conn (the
	// multi-second blackhole). A hop with no pool conn yet is live.
	return (state == network.Connected || state == network.Limited) &&
		n.supportsOverlayRelay(hop) && !n.isOverlayRelayBlacklisted(hop) &&
		(n.relayPool == nil || n.relayPool.hopStreamLive(hop))
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
