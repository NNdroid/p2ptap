package node

import (
	"sync"
	"sync/atomic"

	"github.com/libp2p/go-libp2p/core/peer"
)

// peerIDStrings caches the base58 rendering (peer.ID.String()) of every peer
// we have ever touched.
//
// Why this exists: rendering a peer.ID is base58 over its multihash — measured
// at ~933ns and 2 allocations per call. The receive path calls it on EVERY
// inbound frame just to feed string-keyed collector / ACL calls
// (RecordRxSeq, checkACL, CaptureFrameWithPeers), which made a pure
// bookkeeping concern one of the most expensive items on the per-frame path.
//
// Peer IDs are immutable, so a cached rendering can never go stale and the
// cache needs no invalidation. It is copy-on-write: the publish path is the
// only place that takes a mutex, while readers take the published snapshot
// through an atomic pointer (zero locks, zero allocations on the hot path) —
// the same pattern as peerLastRx / perPeerObf / pingPongFailCount.
type peerIDStrings struct {
	mu sync.Mutex
	m  atomic.Pointer[map[peer.ID]string]
}

// get returns the cached base58 string for pid, rendering and publishing it on
// first sight. Hot path: one atomic load plus a map lookup, no allocation.
func (c *peerIDStrings) get(pid peer.ID) string {
	if m := c.m.Load(); m != nil {
		if s, ok := (*m)[pid]; ok {
			return s
		}
	}

	// Slow path: first frame from this peer. Publish a new snapshot under the
	// lock, re-checking inside it so two goroutines racing on the same new
	// peer cannot render and republish twice (double-checked locking).
	c.mu.Lock()
	defer c.mu.Unlock()
	if m := c.m.Load(); m != nil {
		if s, ok := (*m)[pid]; ok {
			return s
		}
	}

	s := pid.String()
	var next map[peer.ID]string
	if m := c.m.Load(); m != nil {
		next = make(map[peer.ID]string, len(*m)+1)
		for k, v := range *m {
			next[k] = v
		}
	} else {
		next = make(map[peer.ID]string, 1)
	}
	next[pid] = s
	c.m.Store(&next)
	return s
}

// peerIDString returns the cached base58 representation of pid.
//
// PERF: use this instead of pid.String() anywhere on a per-frame path. Direct
// String() calls are fine on control paths (connect, probe, error logging).
func (n *Node) peerIDString(pid peer.ID) string { return n.peerIDStrs.get(pid) }
