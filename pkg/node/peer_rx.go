package node

import (
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// notePeerRx records that we just received an inbound frame from p. In an
// asymmetric-routing mesh (each node selects its outbound and return paths
// independently) this is the ONLY local signal for return-path liveness: a
// healthy outbound path proves nothing about whether p can route frames back
// to us. The ping-pong probe uses lastRxFrom to distinguish "outbound dead"
// from "return dead at the peer".
func (n *Node) notePeerRx(p peer.ID) {
	n.peerRxMu.Lock()
	n.peerLastRx[p] = time.Now()
	n.peerRxMu.Unlock()
}

// lastRxFrom returns the time we last received an inbound frame from p, or the
// zero time if none has ever arrived.
func (n *Node) lastRxFrom(p peer.ID) time.Time {
	n.peerRxMu.RLock()
	defer n.peerRxMu.RUnlock()
	return n.peerLastRx[p]
}

// peerRxWithin reports whether we received an inbound frame from p within the
// last d. Called by the ping-pong probe after an echo timeout: if true, the
// outbound path clearly works (p is sending us frames), so the failed echo must
// be a RETURN-path break at p — not a local outbound failure.
func (n *Node) peerRxWithin(p peer.ID, d time.Duration) bool {
	last := n.lastRxFrom(p)
	if last.IsZero() {
		return false
	}
	return time.Since(last) <= d
}
