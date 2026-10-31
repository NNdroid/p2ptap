package node

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	ma "github.com/multiformats/go-multiaddr"
	"p2ptap/pkg/tap"
)

// TestE2EMultipathDirectLinkSingleConnection documents a necessary precondition
// for direct multipath: libp2p keeps ONE connection per (peer, address family /
// routable address). Two listeners on the SAME IPv4 interface collapse onto a
// single connection — even WithForceDirectDial only force-reconnects the existing
// one, it does NOT create a parallel second connection. So two single-homed peers
// (each with one IPv4 address) yield exactly ONE physical path and the multipath
// strategy can never obtain a second path to split over; it falls back to the
// single-stream synchronous write (see writePackedBatchLocked: len(streams)>1
// gate) and provides ZERO multi-path benefit. The contrast — a genuinely
// dual-homed peer reachable over IPv4 AND IPv6 (or TCP AND QUIC) — IS now able
// to yield two connections, exercised by TestE2EMultipathMultiProtocolDirectLink
// (which relies on the DialPeerToAddr bypass of the Host.Connect short-circuit).
// This test pins the single-homed reality so a future change that expects
// single-interface multipath to multi-path is caught.
func TestE2EMultipathDirectLinkSingleConnection(t *testing.T) {
	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "multipath")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "multipath")
	// Two listeners each: even with two advertised addresses and two explicit
	// dials (one forced), libp2p still settles on a single connection.
	cfgA.ListenAddrs = []string{"/ip4/0.0.0.0/tcp/0", "/ip4/0.0.0.0/tcp/0"}
	cfgB.ListenAddrs = []string{"/ip4/0.0.0.0/tcp/0", "/ip4/0.0.0.0/tcp/0"}

	nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create NodeB: %v", err)
	}
	nodes := []*Node{nodeA, nodeB}
	defer func() {
		for _, n := range nodes {
			n.Close()
		}
	}()
	nodeA.Start()
	nodeB.Start()

	bAddrs := nodeB.Host.Addrs()
	if len(bAddrs) < 2 {
		t.Fatalf("NodeB did not expose 2 listeners (got %d): %v", len(bAddrs), bAddrs)
	}
	dial := func(ctx context.Context, addr ma.Multiaddr) error {
		ti := nodeB.Host.Peerstore().PeerInfo(nodeB.Host.ID())
		ti.Addrs = []ma.Multiaddr{addr}
		return nodeA.Host.Connect(ctx, ti)
	}
	if err := dial(nodeA.ctx, bAddrs[0]); err != nil {
		t.Fatalf("connect A->B addr0: %v", err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel2()
	if err := dial(network.WithForceDirectDial(ctx2, "p2ptap-mp-test"), bAddrs[1]); err != nil {
		t.Fatalf("force-connect A->B addr1: %v", err)
	}

	// libp2p collapses both dials onto ONE connection.
	deadline := time.Now().Add(8 * time.Second)
	var conns []network.Conn
	for time.Now().Before(deadline) {
		conns = nodeA.Host.Network().ConnsToPeer(nodeB.Host.ID())
		if len(conns) >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(conns) != 1 {
		t.Fatalf("expected libp2p to keep exactly 1 connection on a direct link (regardless of listener count / forced dial), got %d", len(conns))
	}
	t.Logf("DIRECT LINK between two hosts yields %d libp2p connection(s) -> multipath has only 1 path (no multi-path benefit)", len(conns))

	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)
	time.Sleep(300 * time.Millisecond)
	_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")

	reader := newFrameReader(pipeB)
	t.Cleanup(reader.Close)

	const frames = 32
	var wireFrames [][]byte
	var payloads [][]byte
	for i := 0; i < frames; i++ {
		tag := fmt.Sprintf("MP_DIRECT_%d", i)
		payloads = append(payloads, []byte(tag))
		wireFrames = append(wireFrames, constructICMPv4PacketWithData(
			testMACA, testMACB, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 7200+i, 1, []byte(tag)))
	}
	coll := newConcurrentPayloadCollector(reader, payloads)
	for i := 0; i < frames; i++ {
		if _, werr := pipeA.Write(wireFrames[i]); werr != nil {
			t.Fatalf("write %d failed: %v", i, werr)
		}
	}
	coll.wait(t, pipeA, wireFrames, payloads, 16*time.Second, "A->B(multipath direct link)")
	if got := countSeen(coll, payloads); got != frames {
		t.Fatalf("direct-link multipath delivered %d/%d frames", got, frames)
	}
	t.Logf("direct-link multipath: %d/%d frames delivered intact (but over a SINGLE path — multipath is a no-op here)", frames, frames)
}

func countSeen(c *concurrentPayloadCollector, want [][]byte) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, w := range want {
		if c.seen[string(w)] {
			n++
		}
	}
	return n
}
