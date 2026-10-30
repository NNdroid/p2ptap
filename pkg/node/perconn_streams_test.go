package node

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func newPerConnTestHost(t *testing.T) host.Host {
	t.Helper()
	h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func connectPerConnHosts(t *testing.T, a, b host.Host) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := b.Connect(ctx, peer.AddrInfo{ID: a.ID(), Addrs: a.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
}

func drainStream(s network.Stream) {
	defer s.Close()
	_, _ = io.Copy(io.Discard, s)
}

// TestEnsureStreamsOnAllConnsOpensPerConnectionAndIsIdempotent covers the two
// properties the multipath fix depends on:
//
//   - a stream is opened on the connection itself (Conn.NewStream + manual
//     multistream-select), so the remote dispatches it to the normal handler;
//   - the (direction, conn) slot makes a repeat call a no-op instead of opening
//     a duplicate that would immediately close the first.
func TestEnsureStreamsOnAllConnsOpensPerConnectionAndIsIdempotent(t *testing.T) {
	a := newPerConnTestHost(t)
	b := newPerConnTestHost(t)

	var inbound atomic.Int32
	// sda must exist before the handler runs, and the handler must register the
	// inbound stream exactly like handleStream does in production.
	sda := NewStrategyDispatcher(a, "multipath")
	a.SetStreamHandler(ProtocolID, func(s network.Stream) {
		inbound.Add(1)
		sda.RegisterStream(s.Conn().RemotePeer(), streamRegistryKey(s), s)
		go drainStream(s)
	})

	connectPerConnHosts(t, a, b)

	sdb := NewStrategyDispatcher(b, "multipath")
	sdb.SetOutgoingStreamHandler(drainStream)

	if opened := sdb.EnsureStreamsOnAllConns(a.ID()); opened != 1 {
		t.Fatalf("expected exactly one stream on the single connection, got %d", opened)
	}
	if got := len(sdb.GetOrCreatePeerStreams(a.ID()).GetAllStreams()); got != 1 {
		t.Fatalf("expected one registered stream, got %d", got)
	}
	if got := inbound.Load(); got != 1 {
		t.Fatalf("remote should have accepted exactly one stream, got %d", got)
	}

	// Idempotent: the slot for this connection is occupied.
	if again := sdb.EnsureStreamsOnAllConns(a.ID()); again != 0 {
		t.Fatalf("second call must open nothing, opened %d", again)
	}
	if got := sdb.GetOrCreatePeerStreams(a.ID()).GetAllStreams(); len(got) != 1 {
		t.Fatalf("duplicate stream registered: %d", len(got))
	}
	if got := inbound.Load(); got != 1 {
		t.Fatalf("remote received a duplicate stream: %d", got)
	}
}

// TestPeerStreamsKeepsInboundAndOutboundOnSameConn is the regression test for
// the registry key. Both sides of a connection open a data stream toward each
// other (this is what PrimeStream + the peer's own prime do on every connect).
// Those two streams share ONE connection, so the multiaddr-keyed registry put
// them in the same slot and AddStream closed the first one — every peer tore
// down the stream its counterpart had just registered, and only one direction
// survived, which is also why multipath could never see more than one path.
func TestPeerStreamsKeepsInboundAndOutboundOnSameConn(t *testing.T) {
	a := newPerConnTestHost(t)
	b := newPerConnTestHost(t)

	sda := NewStrategyDispatcher(a, "multipath")
	sda.SetOutgoingStreamHandler(drainStream)
	a.SetStreamHandler(ProtocolID, func(s network.Stream) {
		sda.RegisterStream(s.Conn().RemotePeer(), streamRegistryKey(s), s)
		go drainStream(s)
	})

	// B needs the same handler as a real node: without it the remote answers
	// "protocols not supported" and A's per-connection open fails.
	sdb := NewStrategyDispatcher(b, "multipath")
	sdb.SetOutgoingStreamHandler(drainStream)
	b.SetStreamHandler(ProtocolID, func(s network.Stream) {
		sdb.RegisterStream(s.Conn().RemotePeer(), streamRegistryKey(s), s)
		go drainStream(s)
	})

	connectPerConnHosts(t, a, b)

	// B opens its stream toward A first...
	if opened := sdb.EnsureStreamsOnAllConns(a.ID()); opened != 1 {
		t.Fatalf("B could not open its stream: %d", opened)
	}
	// ...then A opens its own toward B. In production both happen on connect.
	if opened := sda.EnsureStreamsOnAllConns(b.ID()); opened != 1 {
		t.Fatalf("A could not open its stream: %d", opened)
	}

	// A must hold BOTH: the inbound stream B opened and its own outbound one.
	// They share one connection, so the old multiaddr key collapsed them into a
	// single slot and closed one.
	streams := sda.GetOrCreatePeerStreams(b.ID()).GetAllStreams()
	if len(streams) != 2 {
		t.Fatalf("expected inbound+outbound streams to coexist on one connection, got %d", len(streams))
	}
	var in, out int
	for _, s := range streams {
		switch s.Stat().Direction {
		case network.DirInbound:
			in++
		case network.DirOutbound:
			out++
		}
	}
	if in != 1 || out != 1 {
		t.Fatalf("expected 1 inbound + 1 outbound, got %d inbound / %d outbound", in, out)
	}
}
