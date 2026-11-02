package node

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	mux "p2ptap/pkg/mux"
)

// TestDispatchRelayCtrlInnerRoutesMuxControlStream is the regression test for
// the OVERLAY-relay twin of the boot-relay hole closed in 99a02cd.
//
// A peer reachable only through an overlay relay hop carries its metadata (the
// TAP IP an Exit Node routes through) on the unified mux control channel
// /p2ptap/ctrl/1.0.0. muxEngine opens that channel with openControlStream
// (getOrOpenLocked), so for a relay-only peer its bytes are tunnelled through
// this very dispatchRelayCtrlInner final hop. Before the fix that hop had no
// MuxControlProtocolID case and fell into default:, closing the stream before
// the peer's metadata arrived — so a selected Exit Node could never activate
// for an overlay-relayed peer. On Android that left the VPN capturing
// 0.0.0.0/0 into the TUN while the engine dropped every frame (no active exit
// peer): the "app installed but no traffic" black hole.
//
// The test proves the routing without a real network. handleControlStream runs
// mux.ReadFrame straight off the stream, so a frame written to the far end of
// the pipe can only be consumed if the MuxControlProtocolID case actually ran.
// Under the old default: branch nothing reads the pipe and the write blocks
// until its deadline.
func TestDispatchRelayCtrlInnerRoutesMuxControlStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pipeA, pipeB := net.Pipe()
	defer pipeB.Close()

	origin := peer.ID("origin-peer")
	n := &Node{ctx: ctx}
	n.muxEngine = newMuxEngine(n)

	s := &netStream{conn: pipeA, id: "overlay-mux", protoID: RelayCtrlProtocolID}

	done := make(chan struct{})
	go func() {
		defer close(done)
		n.dispatchRelayCtrlInner(s, origin, MuxControlProtocolID)
	}()

	// An arbitrary (unhandled) tag: the mux engine still reads it via
	// mux.ReadFrame, which is the observable that the dispatch reached the mux
	// engine. Unknown tags are dropped by muxEngine.dispatch, so there is no
	// side effect on the minimal Node built above.
	_ = pipeB.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := mux.WriteFrame(pipeB, 0x7e, mux.DirBroadcast, 0, []byte("meta")); err != nil {
		t.Fatalf("mux control stream was not consumed — dispatchRelayCtrlInner "+
			"fell into default: (missing MuxControlProtocolID case): %v", err)
	}

	// Closing the far end makes handleStream's next ReadFrame return EOF, which
	// releases the dispatch goroutine.
	_ = pipeB.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatchRelayCtrlInner did not return after the stream closed")
	}
}
