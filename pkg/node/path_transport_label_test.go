package node

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	coretest "github.com/libp2p/go-libp2p/core/test"
)

// The per-path table exists to show WHICH transport each path of a multipath
// peer rides. PathMetricDTO.Transport is documented as the libp2p transport
// ("QUIC"/"TCP"/...), but pathDTOFor filled it with transportLabelForConn —
// the direct/circuit classification — so every direct path rendered as
// "direct" and a peer's QUIC and TCP paths were indistinguishable in the only
// view that is supposed to distinguish them.
func TestPathDTOForNamesTransportNotPathClass(t *testing.T) {
	n := &Node{}
	pid := peer.ID("p2ptap-transport-label-test")
	now := time.Now()

	cases := []struct {
		path      string
		transport string
		kind      string
	}{
		{"/ip4/192.168.1.9/tcp/4001", "TCP", "direct"},
		{"/ip4/100.64.1.2/udp/4001/quic-v1", "QUIC", "direct"},
		{"/ip6/fe80::1/udp/4001/quic-v1/webtransport", "WebTransport", "direct"},
		{"boot-relay://some-hop", "Boot Relay", "boot-relay"},
		{"overlay-relay://some-hop", "Overlay Relay", "overlay-relay"},
		{"relay://some-hop", "Overlay Relay", "overlay-relay"},
	}
	for _, c := range cases {
		dto := n.pathDTOFor(pid, c.path, nil, streamWriteQuality{}, now)
		if dto.Transport != c.transport {
			t.Errorf("path %q transport = %q, want %q", c.path, dto.Transport, c.transport)
		}
		if dto.RelayKind != c.kind {
			t.Errorf("path %q relay_kind = %q, want %q", c.path, dto.RelayKind, c.kind)
		}
		if dto.Active {
			t.Errorf("path %q has no live stream but reported active", c.path)
		}
	}
}

// A circuit address carries the relay's own /tcp (or /quic-v1) component, so
// the transport must be classified as a circuit BEFORE the address is asked
// what transport it names — otherwise a historical relay path is reported as a
// direct TCP path, which is the opposite of what an operator needs to see.
func TestPathDTOForClassifiesCircuitBeforeTransport(t *testing.T) {
	n := &Node{}
	pid := peer.ID("p2ptap-transport-label-test")
	hop := coretest.RandPeerIDFatal(t)
	relayed := "/ip4/203.0.113.7/tcp/4001/p2p/" + hop.String() + "/p2p-circuit"

	dto := n.pathDTOFor(pid, relayed, nil, streamWriteQuality{}, time.Now())
	if dto.Transport != "Circuit Relay" {
		t.Fatalf("circuit path transport = %q, want Circuit Relay", dto.Transport)
	}
	if dto.RelayKind != "circuit-relay" {
		t.Fatalf("circuit path relay_kind = %q, want circuit-relay", dto.RelayKind)
	}
}

// An unparseable path keeps the explicit "Unknown" label rather than guessing.
func TestPathDTOForUnknownPathStaysUnknown(t *testing.T) {
	n := &Node{}
	dto := n.pathDTOFor(peer.ID("p"), "not-a-multiaddr", nil, streamWriteQuality{}, time.Now())
	if dto.Transport != "Unknown" {
		t.Fatalf("unparseable path transport = %q, want Unknown", dto.Transport)
	}
}

// A peer with QUIC and TCP up must name BOTH transports. The peer table used
// to assign the transport inside the connection loop, so the newest connection
// won and the column silently dropped the other live path.
func TestAppendUniqueTransportKeepsEveryDistinctTransport(t *testing.T) {
	var list []string
	for _, name := range []string{"QUIC", "TCP", "QUIC", "TCP", "WebRTC"} {
		list = appendUniqueTransport(list, name)
	}
	if got := strings.Join(list, "+"); got != "QUIC+TCP+WebRTC" {
		t.Fatalf("merged transport label = %q, want QUIC+TCP+WebRTC", got)
	}
	if len(appendUniqueTransport(nil, "TCP")) != 1 {
		t.Fatal("first transport must be kept")
	}
}

// The live-stream branch is the one that carried the bug: it called
// transportLabelForConn, which answers "direct"/"circuit-relay" and says
// nothing about the transport. Assert against a REAL TCP stream so a
// regression cannot hide behind a nil-stream fixture.
func TestPathDTOForNamesTransportOfLiveStream(t *testing.T) {
	a := newPerConnTestHost(t)
	b := newPerConnTestHost(t)
	connectPerConnHosts(t, a, b)

	a.SetStreamHandler(ProtocolID, func(s network.Stream) { drainStream(s) })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := b.NewStream(ctx, a.ID(), ProtocolID)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer s.Close()

	n := &Node{}
	dto := n.pathDTOFor(s.Conn().RemotePeer(), s.Conn().RemoteMultiaddr().String(), s, streamWriteQuality{}, time.Now())
	if dto.Transport != "TCP" {
		t.Fatalf("live TCP stream reported transport %q, want TCP", dto.Transport)
	}
	if !dto.Active {
		t.Fatal("live stream must be reported active")
	}
	if dto.RelayKind != "direct" {
		t.Fatalf("relay_kind = %q, want direct", dto.RelayKind)
	}
}
