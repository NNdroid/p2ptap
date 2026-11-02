package P2PTap

import (
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/node"
)

// exitNodeActive reports whether the gateway is actually routing through peerID.
//
// The error from setExitNodeLocked cannot answer this: it returns nil for a
// no-op, and the gateway accepts a target it has not yet connected to, so a nil
// error is not evidence that the exit node came up.
func exitNodeActive(n *node.Node, peerID string) bool {
	if n == nil || n.Gateway == nil {
		return false
	}
	return exitPeerMatches(n.Gateway.ActiveExitPeerPID(), peerID)
}

// exitPeerMatches compares the active exit peer against a selection by identity
// rather than by string.
//
// One peer has several textual encodings — base58 "12D3KooW…", base36 "k51…" —
// and comparing them as strings reports a mismatch for the same key. That is
// not cosmetic: a selection stored in one encoding against an activation
// recorded in another made the app show the exit node as unavailable and kept
// re-activating a gateway that was already routing, every fifteen seconds for
// half an hour. Decoding both sides removes the encoding from the question.
//
// An empty active PID means nothing is routing, and a selection that does not
// decode cannot name a peer we activated, so both answer false.
func exitPeerMatches(active peer.ID, want string) bool {
	if active == "" {
		return false
	}
	wantID, err := peer.Decode(strings.TrimSpace(want))
	if err != nil {
		return false
	}
	return active == wantID
}
