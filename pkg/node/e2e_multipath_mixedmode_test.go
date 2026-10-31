package node

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"p2ptap/pkg/tap"
)

// TestE2EMultipathMixedModeInterop is the interop guard between STRATEGIES: the
// node in "multipath" mode talks to a node in a different mode over the same
// wire protocol, in both directions.
//
// This is worth pinning because the multipath mode is the one that (a) holds
// several data streams per peer, (b) spreads frames over all of them, and (c)
// may emit the optional FEC envelope. All three are purely EGRESS decisions: the
// frame format the receiver parses does not depend on its own strategy. A peer
// running best_path has no idea it is being fed by a multipath sender, and it
// must still (1) read every inbound stream the multipath peer opened, (2)
// reassemble frames whose fragments rode different links, and (3) accept frames
// from a path it would not itself have chosen.
//
// The test does not require asymmetric setups to be *equivalent* — a one-path
// peer legitimately sends everything over one link. What it pins is that nothing
// multipath-specific makes the frame unreadable on either side.
func TestE2EMultipathMixedModeInterop(t *testing.T) {
	if testing.Short() {
		t.Skip("skips NIC-binding mixed-mode e2e in -short mode")
	}

	tapA, pipeA := tap.NewMemTAPPair("mmA", "mm-pipeA")
	tapB, pipeB := tap.NewMemTAPPair("mmB", "mm-pipeB")

	nics, err := physicalNICIPs()
	if err != nil {
		t.Skipf("physicalNICIPs failed: %v", err)
	}
	var v4, v6 string
	for _, ip := range nics {
		if ip.To4() != nil && v4 == "" {
			v4 = ip.String()
		} else if ip.To4() == nil && v6 == "" {
			v6 = ip.String()
		}
	}
	if v4 == "" {
		t.Skip("host has no non-loopback IPv4 NIC; cannot bind the multipath-capable peer")
	}

	// A is multipath (it must be able to hold >=2 paths), B is the default
	// strategy — the asymmetry is the point of the test.
	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "multipath")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
	bAddrs := []string{
		fmt.Sprintf("/ip4/%s/tcp/0", v4),
		fmt.Sprintf("/ip4/%s/udp/0/quic-v1", v4),
	}
	if v6 != "" && !manet.IsIP6LinkLocal(ma.StringCast("/ip6/"+v6)) {
		bAddrs = append(bAddrs, fmt.Sprintf("/ip6/%s/tcp/0", v6))
	}
	cfgB.ListenAddrs = bAddrs

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

	gotTCP, gotQUIC := false, false
	deadline0 := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline0) {
		for _, la := range nodeB.Host.Network().ListenAddresses() {
			s := la.String()
			if strings.Contains(s, "/tcp/") && strings.Contains(s, v4) {
				gotTCP = true
			}
			if strings.Contains(s, "/quic-v1") && strings.Contains(s, v4) {
				gotQUIC = true
			}
		}
		if gotTCP && gotQUIC {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !gotTCP || !gotQUIC {
		t.Skipf("NodeB did not bind both a TCP and a QUIC listener on %s (tcp=%v quic=%v)", v4, gotTCP, gotQUIC)
	}

	bInfo := peer.AddrInfo{ID: nodeB.Host.ID(), Addrs: nodeB.Host.Network().ListenAddresses()}
	nodeA.Host.Peerstore().AddAddrs(bInfo.ID, bInfo.Addrs, peerstore.PermanentAddrTTL)

	// A (multipath) drives path repair; B, being best_path, never does.
	repairDeadline := time.Now().Add(30 * time.Second)
	for len(nodeA.Host.Network().ConnsToPeer(nodeB.Host.ID())) < 2 {
		if time.Now().After(repairDeadline) {
			conns := nodeA.Host.Network().ConnsToPeer(nodeB.Host.ID())
			t.Fatalf("multipath A established only %d connection(s) to a best_path peer (expected >=2): %v", len(conns), conns)
		}
		nodeA.repairMultipathPaths(nodeB.Host.ID())
		time.Sleep(100 * time.Millisecond)
	}
	conns := nodeA.Host.Network().ConnsToPeer(nodeB.Host.ID())
	t.Logf("mixed-mode: multipath A holds %d connections to best_path B", len(conns))

	nodeA.Dispatcher.EnsureStreamsOnAllConns(nodeB.Host.ID())
	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)
	time.Sleep(300 * time.Millisecond)
	_ = pipeA.ConfigureIP("10.0.0.1/24", "fd00::1/64")
	_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")

	// A->B: multipath sender, best_path receiver. Frames arrive interleaved from
	// several links, so the receiver's reassembly/dedup must be path-agnostic.
	readerB := newFrameReader(pipeB)
	t.Cleanup(readerB.Close)

	const frames = 32
	payloads := make([][]byte, frames)
	wireAB := make([][]byte, frames)
	for i := 0; i < frames; i++ {
		tag := fmt.Sprintf("MM_AB_%d", i)
		payloads[i] = []byte(tag)
		wireAB[i] = constructICMPv4PacketWithData(testMACA, testMACB,
			net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 8600+i, 1, []byte(tag))
	}
	collB := newConcurrentPayloadCollector(readerB, payloads)
	for i := 0; i < frames; i++ {
		if _, werr := pipeA.Write(wireAB[i]); werr != nil {
			t.Fatalf("A->B write %d failed: %v", i, werr)
		}
	}
	collB.wait(t, pipeA, wireAB, payloads, 16*time.Second, "A(multipath)->B(best_path)")

	// B->A: best_path sender, multipath receiver. B uses the single stream it
	// considers best; A must accept it on a stream *it* opened for a different
	// path without duplicating or dropping it.
	readerA := newFrameReader(pipeA)
	t.Cleanup(readerA.Close)

	payloadsBack := make([][]byte, frames)
	wireBA := make([][]byte, frames)
	for i := 0; i < frames; i++ {
		tag := fmt.Sprintf("MM_BA_%d", i)
		payloadsBack[i] = []byte(tag)
		wireBA[i] = constructICMPv4PacketWithData(testMACB, testMACA,
			net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"), 8700+i, 1, []byte(tag))
	}
	collA := newConcurrentPayloadCollector(readerA, payloadsBack)
	for i := 0; i < frames; i++ {
		if _, werr := pipeB.Write(wireBA[i]); werr != nil {
			t.Fatalf("B->A write %d failed: %v", i, werr)
		}
	}
	collA.wait(t, pipeB, wireBA, payloadsBack, 16*time.Second, "B(best_path)->A(multipath)")

	t.Logf("mixed-mode interop: %d/%d A->B and %d/%d B->A frames delivered intact",
		countSeen(collB, payloads), frames, countSeen(collA, payloadsBack), frames)
}
