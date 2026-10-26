package node

import (
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// muxDecScratchCap is the per-frame decrypt scratch capacity used by the mux
// data channel handlers. It matches the per-stream scratch in handleStream and
// handleRelayStream, so a jumbo frame needs at most one grow.
const muxDecScratchCap = 9600

// The mux data channel handlers deliberately do NOT register their stream with
// the Dispatcher (handleStream does). A Dispatcher-registered stream can be
// handed back by openStream and used to WRITE raw obfuscate frames, which the
// mux data channel would interpret as mux frames and silently desynchronise.
// The mux engine owns this stream via muxEngine.streams.

// handleDataMuxVTP handles a VTP frame arriving on the unified mux data channel
// (/p2ptap/data/1.0.0, kind 0x00). It runs the frame through the exact same RX
// pipeline as the legacy per-peer data stream, so the two transports cannot
// diverge.
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
// channel (kind 0x01), reusing handleRelayFrame.
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
func (n *Node) handleDataMuxBootRelay(s network.Stream, from peer.ID, payload []byte) {
	if n.protoTracker != nil {
		n.protoTracker.BootRelay.RecordRx(1, uint64(len(payload)))
	}
	n.handleBootRelayFrame(from, payload)
}
