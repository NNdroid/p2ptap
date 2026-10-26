package node

import (
	"sync"
	"sync/atomic"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// muxDecScratchCap is the per-frame decrypt scratch capacity used by the mux
// data channel handlers. It matches the per-stream scratch in handleStream and
// handleRelayStream, so a jumbo frame needs at most one grow.
const muxDecScratchCap = 9600

// muxDecScratchPool recycles the per-frame decrypt scratch. The data channel
// forks one handler goroutine per frame, so each frame got a fresh 9.6 KiB
// heap allocation even though the buffer is used for a single decrypt and then
// discarded. Each handler owns its scratch exclusively for its lifetime, which
// is what makes pooling safe here.
var muxDecScratchPool = sync.Pool{
	New: func() any {
		return new([muxDecScratchCap]byte)
	},
}

func acquireMuxDecScratch() []byte {
	return muxDecScratchPool.Get().(*[muxDecScratchCap]byte)[:0]
}

func releaseMuxDecScratch(b []byte) {
	muxDecScratchPool.Put((*[muxDecScratchCap]byte)(b[:muxDecScratchCap]))
}

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
//
// inflight is the engine's data-frame fan-out counter (see
// muxInflightDataFramesMax): handleDataStream pre-increments it before forking
// and passes it in so the handler decrements exactly once, no matter how it
// exits. The counter is a plain atomic pointer-sized value, never copied.

// handleDataMuxVTP handles a VTP frame arriving on the unified mux data channel
// (/p2ptap/data/1.0.0, kind 0x00). It runs the frame through the exact same RX
// pipeline as the legacy per-peer data stream, so the two transports cannot
// diverge.
//
// RecordRx is counted HERE and not in handleDirectFrame: the legacy stream
// handler (handleStream) owns that counter for its own path, and folding the
// count into handleDirectFrame would double-count a frame once per transport.
func (n *Node) handleDataMuxVTP(s network.Stream, from peer.ID, payload []byte, inflight *atomic.Int64) {
	inflight.Add(-1)
	if n.protoTracker != nil {
		n.protoTracker.Data.RecordRx(1, uint64(len(payload)))
	}
	// Return-path liveness, mirroring handleStream: an inbound frame from `from`
	// proves its return path is alive.
	n.notePeerRxTransport(from, transportLabelForConn(s.Conn()), "")
	decScratch := acquireMuxDecScratch()
	defer releaseMuxDecScratch(decScratch)
	n.handleDirectFrame(from, payload, &decScratch)
}

// handleDataMuxRelay handles an overlay-relay frame arriving on the mux data
// channel (kind 0x01), reusing handleRelayFrame. RecordRx is counted here for
// the same reason as in handleDataMuxVTP.
func (n *Node) handleDataMuxRelay(s network.Stream, from peer.ID, payload []byte, inflight *atomic.Int64) {
	inflight.Add(-1)
	if n.protoTracker != nil {
		n.protoTracker.RelayData.RecordRx(1, uint64(len(payload)))
	}
	relayDecScratch := acquireMuxDecScratch()
	defer releaseMuxDecScratch(relayDecScratch)
	n.handleRelayFrame(from, payload, &relayDecScratch)
}

// handleDataMuxBootRelay handles a boot-relay frame arriving on the mux data
// channel (kind 0x02). `from` is the boot that bridged the frame, i.e. the
// value handleBootRelayFrame expects as its transport peer.
//
// RecordRx is NOT repeated here: handleBootRelayFrame counts it on entry, so a
// second count would book every boot-relay byte twice on the Datapath card.
func (n *Node) handleDataMuxBootRelay(s network.Stream, from peer.ID, payload []byte, inflight *atomic.Int64) {
	inflight.Add(-1)
	n.handleBootRelayFrame(from, payload)
}
