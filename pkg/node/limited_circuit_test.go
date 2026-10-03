package node

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	relayclient "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/multiformats/go-multiaddr"
	"p2ptap/pkg/tap"
)

// A real, resource-limited Circuit Relay v2 is the ONLY endpoint transport.
// The oracle is encrypted bidirectional TAP delivery, not just a Connected event.
func TestLimitedCircuitConvergesAndDeliversBothDirections(t *testing.T) {
	relay, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"), libp2p.EnableRelayService(), libp2p.ForceReachabilityPublic())
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	relayInfo := peer.AddrInfo{ID: relay.ID(), Addrs: relay.Addrs()}
	boot := relay.Addrs()[0].String() + "/p2p/" + relay.ID().String()
	newEndpoint := func(ip string) (*Node, *tap.MemTAP) {
		t.Helper()
		cfg := createTestNodeConfig(ip, "", "best_path")
		cfg.BootstrapPeers = []string{boot}
		dev, pipe := tap.NewMemTAPPair("limited-node", "limited-pipe")
		n, err := NewNodeWithTAP(cfg, dev, nil)
		if err != nil {
			dev.Close()
			pipe.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { pipe.Close(); n.Close() })
		// Start only the normal receive writer: no discovery/hole-punch loops
		// may introduce a direct endpoint connection into this topology.
		n.wg.Add(1)
		go n.tapWriteLoop()
		return n, pipe
	}
	a, pipeA := newEndpoint("10.0.0.1/24")
	c, pipeC := newEndpoint("10.0.0.3/24")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := relayclient.Reserve(ctx, c.Host, relayInfo); err != nil {
		t.Fatal(err)
	}
	if err := a.Host.Connect(ctx, relayInfo); err != nil {
		t.Fatal(err)
	}
	circuit, err := multiaddr.NewMultiaddr("/p2p/" + relay.ID().String() + "/p2p-circuit/p2p/" + c.Host.ID().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Host.Connect(ctx, peer.AddrInfo{ID: c.Host.ID(), Addrs: []multiaddr.Multiaddr{circuit}}); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]*Node{{a, c}, {c, a}} {
		if pair[0].Host.Network().Connectedness(pair[1].Host.ID()) != network.Limited {
			t.Fatal("endpoint transport is not Limited")
		}
	}
	// ConnectedF owns the initial handshake. Extra forced rekeys here can
	// rotate one endpoint after the old ready flags satisfied this wait, racing
	// the test's single data frame against a new generation's key commit.
	// Require matching directional keys and completed initial rekey work.
	for {
		poA, poC := a.peerObf(c.Host.ID()), c.peerObf(a.Host.ID())
		_, busyA := a.rekeyPeers.Load(c.Host.ID())
		_, busyC := c.rekeyPeers.Load(a.Host.ID())
		if !busyA && !busyC && a.isPeerReady(c.Host.ID()) && c.isPeerReady(a.Host.ID()) &&
			poA != nil && poC != nil && poA.negotiated && poC.negotiated &&
			bytes.Equal(poA.txKey, poC.rxKey) && bytes.Equal(poC.txKey, poA.rxKey) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("Limited control handshake did not converge", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	for i, pair := range []struct {
		src, dst     *Node
		pipe         *tap.MemTAP
		srcIP, dstIP string
	}{
		{a, c, pipeC, "10.0.0.1", "10.0.0.3"}, {c, a, pipeA, "10.0.0.3", "10.0.0.1"},
	} {
		payload := constructICMPv4Packet(pair.src.localMAC, pair.dst.localMAC, net.ParseIP(pair.srcIP), net.ParseIP(pair.dstIP), 42, i+1)
		packed := make([]byte, pair.src.Packer.MaxPackedLen(len(payload)))
		seq := pair.src.Packer.NextSeqID(pair.src.txEpochForPeer(pair.dst.Host.ID()))
		n, err := pair.src.Packer.Pack(seq, payload, packed)
		if err != nil {
			t.Fatal(err)
		}
		if err := pair.src.Dispatcher.SendToPeer(ctx, pair.dst.Host.ID(), packed[:n]); err != nil {
			t.Fatal(err)
		}
		received := make(chan []byte, 1)
		go func() {
			buf := make([]byte, 2048)
			for {
				size, err := pair.pipe.Read(buf)
				if err != nil {
					return
				}
				// Metadata convergence can inject GARP/NA before the test ICMP.
				if bytes.Contains(buf[:size], []byte("P2PTAP_PING_V4_TEST_DATA")) {
					received <- bytes.Clone(buf[:size])
					return
				}
			}
		}()
		select {
		case got := <-received:
			if !bytes.Equal(got, payload) {
				t.Fatalf("direction %d: TAP payload differs", i)
			}
		case <-ctx.Done():
			t.Fatalf("direction %d: no TAP delivery", i)
		}
		if pair.src.isDirectlyConnected(pair.dst.Host.ID()) {
			t.Fatal("test accidentally established a direct endpoint connection")
		}
	}
	// A caller's cancellation must also reach the circuit opener.
	cancelled, stop := context.WithCancel(ctx)
	stop()
	s, err := a.openControlStream(cancelled, c.Host.ID(), EchoProtocolID)
	if s != nil {
		_ = s.Reset()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("control opener ignored caller cancellation: %v", err)
	}
}
