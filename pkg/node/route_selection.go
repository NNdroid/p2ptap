package node

import (
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/routing"
)

// routeMemoTTL bounds the overlayRoute fallback memo. The graph recompute it
// caches is a per-frame cost for a degraded peer — exactly when capacity is
// scarcest — so remembering the outcome (including "no route") for a couple of
// seconds is the whole point; the liveness half of the verdict is NOT cached
// (see overlayRoute).
const routeMemoTTL = 2 * time.Second

type routeMemoKey struct {
	target   peer.ID
	previous peer.ID
	budget   int
}

type routeMemoEntry struct {
	route routing.RouteInfo
	ok    bool
	at    time.Time
}

// routeMemoLookup returns the memoized fallback outcome for key, or fresh=false
// when absent/expired. Opportunistically drops expired entries once the map
// grows past a small cap so a churning target set cannot grow it unboundedly.
func (n *Node) routeMemoLookup(target, previous peer.ID, budget int, now time.Time) (routeMemoEntry, bool) {
	k := routeMemoKey{target: target, previous: previous, budget: budget}
	n.routeMemoMu.Lock()
	defer n.routeMemoMu.Unlock()
	e, ok := n.routeFallbackMemo[k]
	if !ok {
		return routeMemoEntry{}, false
	}
	if now.Sub(e.at) >= routeMemoTTL {
		delete(n.routeFallbackMemo, k)
		return routeMemoEntry{}, false
	}
	return e, true
}

func (n *Node) routeMemoStore(target, previous peer.ID, budget int, route routing.RouteInfo, ok bool, now time.Time) {
	k := routeMemoKey{target: target, previous: previous, budget: budget}
	n.routeMemoMu.Lock()
	defer n.routeMemoMu.Unlock()
	if n.routeFallbackMemo == nil {
		n.routeFallbackMemo = make(map[routeMemoKey]routeMemoEntry)
	}
	if len(n.routeFallbackMemo) > 512 {
		for mk, me := range n.routeFallbackMemo {
			if now.Sub(me.at) >= routeMemoTTL {
				delete(n.routeFallbackMemo, mk)
			}
		}
	}
	n.routeFallbackMemo[k] = routeMemoEntry{route: route, ok: ok, at: now}
}

// overlayRoute returns the same eligible next hop used by both readiness
// checks and forwarding. Exceptional cases search for a feasible alternative
// instead of blindly sending to a blacklisted or unsupported cached hop — and
// that search is memoized briefly (see routeMemoTTL): a relay-only peer whose
// hop is momentarily unusable used to pay a graph search PER FRAME. Only the
// graph walk is memoized; usable()'s liveness checks (Connectedness,
// blacklists, uplink state) are re-evaluated on every read, so a hop that dies
// inside the TTL window is still rejected at read time.
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
	now := time.Now()
	if m, fresh := n.routeMemoLookup(target, previous, budget, now); fresh {
		return m.route, m.ok && usable(m.route)
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
	n.routeMemoStore(target, previous, budget, route, ok, now)
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
