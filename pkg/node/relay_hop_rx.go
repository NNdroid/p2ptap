package node

import (
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// noteRelayHopRx records that we just received an inbound OVERLAY-RELAY frame
// carried by hop (the stream's remotePeer). It is distinct from notePeerRx:
// notePeerRx records liveness for the frame's ORIGIN (srcPeer) — used by the
// ping-pong probe to distinguish outbound-vs-return dead at a peer. But a pure
// forwarding hop that relays frames on behalf of remote origins never appears
// as srcPeer, so its own peerLastRx never advances even when it is perfectly
// healthy and delivering our return traffic.
//
// relayStreamPool needs "did hop H recently deliver an inbound frame to us?" as
// the independent return-path proof that clears H's failure streak. That proof
// must be anchored on H-as-carrier, not H-as-origin — hence this separate,
// hop-keyed tracker. A black-holed hop (accepts our stream but never sends
// anything back) never appears as remotePeer on an inbound frame, so its
// relayHopRx stays stale and the pool's circuit-breaker keeps tripping — exactly
// the behaviour TestRelayPoolCircuitBreaksStalledHop pins.
//
// PERF: same copy-on-write shape as peerLastRx — one atomic load of the map
// pointer plus an atomic store on the hop's own counter per inbound relay frame;
// no global lock, no allocation on the hot path. Only inserting a hop (rare)
// copies the map under relayHopRxMu.
func (n *Node) noteRelayHopRx(hop peer.ID) {
	if m := n.relayHopRx.Load(); m != nil {
		if v, ok := (*m)[hop]; ok {
			v.Store(time.Now().UnixNano())
			return
		}
	}
	// Slow path: first relay frame ever carried by this hop.
	n.relayHopRxMu.Lock()
	defer n.relayHopRxMu.Unlock()
	now := time.Now().UnixNano()
	if m := n.relayHopRx.Load(); m != nil {
		if v, ok := (*m)[hop]; ok {
			v.Store(now)
			return
		}
	}
	var next map[peer.ID]*atomic.Int64
	if m := n.relayHopRx.Load(); m != nil {
		next = make(map[peer.ID]*atomic.Int64, len(*m)+1)
		for k, v := range *m {
			next[k] = v
		}
	} else {
		next = make(map[peer.ID]*atomic.Int64, 1)
	}
	v := &atomic.Int64{}
	v.Store(now)
	next[hop] = v
	n.relayHopRx.Store(&next)
}

// relayHopRxWithin reports whether hop carried an inbound relay frame to us
// within the last d. It is the return-path-liveness signal relayStreamPool uses
// to decide the hop's failure streak may be cleared (see relay_pool.go).
func (n *Node) relayHopRxWithin(hop peer.ID, d time.Duration) bool {
	m := n.relayHopRx.Load()
	if m == nil {
		return false
	}
	v, ok := (*m)[hop]
	if !ok {
		return false
	}
	ns := v.Load()
	if ns == 0 {
		return false
	}
	return time.Since(time.Unix(0, ns)) <= d
}
