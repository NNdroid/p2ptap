package node

import (
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// muxDecScratchCap is the per-frame decrypt scratch capacity used by the mux
// data channel handlers. It matches the per-stream scratch in handleStream and
// handleRelayStream, so a jumbo frame needs at most one grow.
const muxDecScratchCap = 9600

// The mux data channel is RX-only: no p2ptap node opens /p2ptap/data/1.0.0 as a
// client, so these handlers exist to receive, not to send. That asymmetry is
// deliberate for now — the control plane is already unified on one mux stream
// per peer, and the data plane still uses the three dedicated protocols
// (VTP / relay / boot-relay), each with its own tested pooling and failure
// handling. Routing live relay traffic through this channel would mean changing
// the datapath to a multiplexer that has never carried a production frame, so
// it is a feature project rather than a fix.
//
// The handlers deliberately do NOT register their stream with the Dispatcher
// (handleStream does). A Dispatcher-registered stream can be handed back by
// openStream and used to WRITE raw obfuscate frames, which the mux data channel
// would interpret as mux frames and silently desynchronise. handleDataStream
// tracks no per-peer state either — the engine's streams map holds only control
// streams.

// handleDataMuxVTP handles a VTP frame arriving on the unified mux data channel
// (/p2ptap/data/1.0.0, kind 0x00). It runs the frame through the exact same RX
// pipeline as the legacy per-peer data stream, so the two transports cannot
// diverge.
//
// RecordRx is counted HERE and not in handleDirectFrame: the legacy stream
// handler (handleStream) owns that counter for its own path, and folding the
// count into handleDirectFrame would double-count a frame once per transport.
func (n *Node) handleDataMuxVTP(s network.Stream, from peer.ID, payload []byte) {
	if n.protoTracker != nil {
		n.protoTracker.Data.RecordRx(1, uint64(len(payload)))
	}
	// Return-path liveness, mirroring handleStream: an inbound frame from `from`
	// proves its return path is alive.
	n.notePeerRxTransport(from, transportLabelForConn(s.Conn()), "")
	// muxEngine forks one goroutine per frame, so a per-frame scratch is the
	// correct scope and can never be shared between concurrent frames.
	decScratch := make([]byte, 0, muxDecScratchCap)
	n.handleDirectFrame(from, payload, &decScratch)
}

// handleDataMuxRelay handles an overlay-relay frame arriving on the mux data
// channel (kind 0x01), reusing handleRelayFrame. RecordRx is counted here for
// the same reason as in handleDataMuxVTP.
func (n *Node) handleDataMuxRelay(s network.Stream, from peer.ID, payload []byte) {
	if n.protoTracker != nil {
		n.protoTracker.RelayData.RecordRx(1, uint64(len(payload)))
	}
	relayDecScratch := make([]byte, 0, muxDecScratchCap)
	n.handleRelayFrame(from, payload, &relayDecScratch)
}

// handleDataMuxBootRelay handles a boot-relay frame arriving on the mux data
// channel (kind 0x02). `from` is the boot that bridged the frame, i.e. the
// value handleBootRelayFrame expects as its transport peer.
//
// RecordRx is NOT repeated here: handleBootRelayFrame counts it on entry, so a
// second count would book every boot-relay byte twice on the Datapath card.
func (n *Node) handleDataMuxBootRelay(s network.Stream, from peer.ID, payload []byte) {
	n.handleBootRelayFrame(from, payload)
}
