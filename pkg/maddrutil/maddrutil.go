// maddrutil — transport-layer multiaddr inspection.
//
// Both the node engine and the web layer need to answer the same two
// questions about a connection address: is it carried over a libp2p Circuit
// Relay v2 hop, and which peer IDs does it name? Answering those with
// strings.Contains over the rendered address is unsafe — it depends on the
// parser's chosen spelling of a protocol and would silently break if the
// rendered form ever changed — so both answers go through the protocol-code
// walk here, exactly once.
//
// This package deliberately holds only multiaddr primitives: it depends on
// go-libp2p's core types and nothing else in this repository. Higher-level
// helpers that need p2ptap's routing or config types stay in pkg/node.
package maddrutil

import (
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// IsCircuitRelay reports whether ma contains a /p2p-circuit/ component,
// i.e. the connection is carried over a libp2p Circuit Relay v2 hop rather
// than directly between the two endpoints.
func IsCircuitRelay(ma multiaddr.Multiaddr) bool {
	for _, c := range ma {
		if c.Protocol().Code == multiaddr.P_CIRCUIT {
			return true
		}
	}
	return false
}

// RelayPeerIDs extracts all /p2p/<id> peer IDs from ma, in address order.
// For a circuit path /p2p/A/p2p-circuit/p2p/B it returns [A, B] — that is,
// the relay hops AND the final destination. Callers that want only the
// hops are expected to drop the last element, which is the destination by
// construction of a circuit address.
func RelayPeerIDs(ma multiaddr.Multiaddr) []peer.ID {
	var ids []peer.ID
	for _, c := range ma {
		if c.Protocol().Code == multiaddr.P_P2P {
			pid, err := peer.Decode(c.Value())
			if err == nil {
				ids = append(ids, pid)
			}
		}
	}
	return ids
}
