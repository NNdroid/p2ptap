package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// TestRelayHopRxTracksCarrierNotOrigin pins the semantic distinction that fixes
// the failCount mis-accounting: relayHopRx advances for the hop that CARRIED an
// inbound relay frame (remotePeer), even when the frame originated from a
// different peer — whereas peerLastRx only advances for the origin. A pure
// forwarding hop therefore becomes visible to relayStreamPool as healthy, while
// a hop that never delivers anything back stays stale.
func TestRelayHopRxTracksCarrierNotOrigin(t *testing.T) {
	n := &Node{}

	hop := peer.ID("forwarder-hop")
	origin := peer.ID("remote-origin")

	// Simulate: an inbound relay frame ORIGINATING at `origin` is carried by
	// `hop` (the path handleRelayStream takes when remotePeer != srcPeer).
	n.notePeerRx(origin)
	n.noteRelayHopRx(hop)

	if !n.peerRxWithin(origin, time.Second) {
		t.Fatal("expected peerLastRx to advance for the ORIGIN")
	}
	if n.peerRxWithin(hop, time.Second) {
		t.Fatal("peerLastRx must NOT advance for a pure-forwarding hop (it is not the origin)")
	}

	if !n.relayHopRxWithin(hop, time.Second) {
		t.Fatal("expected relayHopRx to advance for the hop that CARRIED the frame")
	}
	if n.relayHopRxWithin(origin, time.Second) {
		t.Fatal("relayHopRx must NOT advance for the origin (it was the carrier's frame, not the origin carrying one to us)")
	}

	t.Log("✓ relayHopRx keys on carrier; peerLastRx keys on origin — distinct, correct signals")
}

// TestRelayHopRxStaleAfterWindow ensures a hop that stops delivering return
// traffic goes stale after the healthy window, so the pool's failure streak
// stops clearing and the circuit-breaker can trip.
func TestRelayHopRxStaleAfterWindow(t *testing.T) {
	n := &Node{}
	hop := peer.ID("gone-hop")

	n.noteRelayHopRx(hop)
	if !n.relayHopRxWithin(hop, time.Second) {
		t.Fatal("freshly-carried hop should be within the window")
	}
	// Backdate the hop's own counter past the window.
	n.relayHopRxMu.Lock()
	m := n.relayHopRx.Load()
	if m == nil {
		n.relayHopRxMu.Unlock()
		t.Fatal("relayHopRx map not populated")
	}
	(*m)[hop].Store(time.Now().Add(-2 * time.Second).UnixNano())
	n.relayHopRxMu.Unlock()

	if n.relayHopRxWithin(hop, time.Second) {
		t.Fatal("hop that stopped delivering should go stale after the window")
	}
	t.Log("✓ stale hop correctly reports outside the healthy window")
}
