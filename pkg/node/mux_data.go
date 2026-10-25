package node

import (
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// handleDataMuxVTP handles VTP data frames arriving on the mux data channel.
// Full implementation will mirror the handleStream VTP pipeline:
// decrypt, unpack, fragment reassembly, dedup, ACL, MAC learning, TAP write.
// Currently a stub; the data channel is registered but processing is deferred.
func (n *Node) handleDataMuxVTP(s network.Stream, from peer.ID, payload []byte) {
	n.processMuxVTPFrame(from, payload)
}

// handleDataMuxRelay handles relay frames arriving on the mux data channel.
// Full implementation will mirror the handleRelayStream relay pipeline:
// decrypt, unpack envelope, origin verification, forward or deliver.
// Currently a stub; the data channel is registered but processing is deferred.
func (n *Node) handleDataMuxRelay(s network.Stream, from peer.ID, payload []byte) {
	n.processMuxRelayFrame(from, payload)
}

// processMuxVTPFrame is a stub for VTP frame processing on the mux data channel.
// The full pipeline (decrypt, unpack, dedup, ACL, MAC learn, TAP write) is the
// same as handleStream's frame loop; extraction is a follow-up refactoring.
func (n *Node) processMuxVTPFrame(from peer.ID, payload []byte) {
	log.Debug("mux data: VTP frame from %s (%d bytes) — processing deferred",
		from.ShortString(), len(payload))
}

// processMuxRelayFrame is a stub for relay frame processing on the mux data channel.
// The full pipeline (decrypt, unpack envelope, origin verify, forward/deliver) is
// the same as handleRelayStream's frame loop; extraction is a follow-up refactoring.
func (n *Node) processMuxRelayFrame(from peer.ID, payload []byte) {
	log.Debug("mux data: relay frame from %s (%d bytes) — processing deferred",
		from.ShortString(), len(payload))
}
