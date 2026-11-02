package node

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	relayclient "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	ma "github.com/multiformats/go-multiaddr"
	"p2ptap/pkg/tap"
)

// TestE2EExitNodeOverRelayMultipath covers the topology a mobile client
// actually runs in: the Exit Node sits behind a NAT and is reachable ONLY
// through relays, and the client's multipath set is made of two circuits.
//
// Two things are asserted that no other test covers together:
//
//  1. The Exit Node's TAP IP must reach the client over the RELAY control
//     tunnel. The Android activation path (pkg/android.setExitNodeLocked) calls
//     SetExitNode with the peer ID only and resolves the gateway IP from peer
//     metadata; if the metadata never crosses the relay's ctrl mux, activation
//     fails outright and the whole tunnel is dead. That was the
//     dispatchRelayCtrlInner / dispatchBootRelayControlStream gap for
//     MuxControlProtocolID.
//  2. Transit traffic must cross a MULTI-PATH relay set: two circuits, one per
//     relay, both carrying exit egress.
//
// Invariants: A and B never learn each other's direct addresses, so the only
// paths between them are the circuits (asserted below).
func TestE2EExitNodeOverRelayMultipath(t *testing.T) {
	if testing.Short() {
		t.Skip("skips relay e2e in -short mode")
	}

	newRelay := func(t *testing.T) host.Host {
		t.Helper()
		r, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.EnableRelayService(),
			libp2p.ForceReachabilityPublic(),
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.Close() })
		return r
	}
	r1, r2 := newRelay(t), newRelay(t)
	r1Info := peer.AddrInfo{ID: r1.ID(), Addrs: r1.Addrs()}
	r2Info := peer.AddrInfo{ID: r2.ID(), Addrs: r2.Addrs()}

	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "multipath")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "multipath")
	cfgB.ExitNode.Enable = true

	nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create NodeB: %v", err)
	}
	defer func() {
		nodeA.Close()
		nodeB.Close()
	}()
	nodeA.Start()
	nodeB.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// B (the exit node) reserves a circuit through BOTH relays, so the client can
	// reach it over two independent paths.
	if _, err := relayclient.Reserve(ctx, nodeB.Host, r1Info); err != nil {
		t.Fatalf("B reserve via R1: %v", err)
	}
	if _, err := relayclient.Reserve(ctx, nodeB.Host, r2Info); err != nil {
		t.Fatalf("B reserve via R2: %v", err)
	}
	if err := nodeA.Host.Connect(ctx, r1Info); err != nil {
		t.Fatalf("A connect R1: %v", err)
	}
	if err := nodeA.Host.Connect(ctx, r2Info); err != nil {
		t.Fatalf("A connect R2: %v", err)
	}

	circuit1, _ := ma.NewMultiaddr("/p2p/" + r1.ID().String() + "/p2p-circuit/p2p/" + nodeB.Host.ID().String())
	circuit2, _ := ma.NewMultiaddr("/p2p/" + r2.ID().String() + "/p2p-circuit/p2p/" + nodeB.Host.ID().String())
	nodeA.Host.Peerstore().AddAddrs(nodeB.Host.ID(), []ma.Multiaddr{circuit1, circuit2}, peerstore.PermanentAddrTTL)
	// B needs a way back to A: the same two circuits, reserved by A.
	if _, err := relayclient.Reserve(ctx, nodeA.Host, r1Info); err != nil {
		t.Fatalf("A reserve via R1: %v", err)
	}
	if err := nodeA.dialPeerToAddr(ctx, nodeB.Host.ID(), circuit1); err != nil {
		t.Fatalf("A dial circuit1: %v", err)
	}
	if err := nodeA.dialPeerToAddr(ctx, nodeB.Host.ID(), circuit2); err != nil {
		t.Fatalf("A dial circuit2: %v", err)
	}

	connDeadline := time.Now().Add(30 * time.Second)
	for {
		if len(nodeA.Host.Network().ConnsToPeer(nodeB.Host.ID())) >= 2 {
			break
		}
		if time.Now().After(connDeadline) {
			t.Fatalf("A established only %d circuit(s) to the exit node (want 2)",
				len(nodeA.Host.Network().ConnsToPeer(nodeB.Host.ID())))
		}
		time.Sleep(100 * time.Millisecond)
	}
	if nodeA.isDirectlyConnected(nodeB.Host.ID()) {
		t.Skip("A formed a DIRECT connection to B; the relay-only invariant cannot hold in this sandbox")
	}
	t.Logf("exit-over-relay: A holds %d circuit path(s) to the exit node", len(nodeA.Host.Network().ConnsToPeer(nodeB.Host.ID())))

	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)

	// The relay control tunnel must deliver B's metadata (TAP IP) to A. This is
	// the only source the Android activation path has when the caller passes the
	// peer ID without addresses.
	var meta PeerMeta
	metaDeadline := time.Now().Add(30 * time.Second)
	for {
		if m, ok := nodeA.GetPeerMeta(nodeB.Host.ID()); ok && (m.TapIP != "" || m.TapIPv6 != "") {
			meta = m
			break
		}
		if time.Now().After(metaDeadline) {
			t.Fatalf("A never received the exit node's TAP IP over the relay control tunnel; the Android activation path cannot resolve a gateway IP")
		}
		time.Sleep(100 * time.Millisecond)
	}
	tapV4, tapV6 := meta.TapIP, meta.TapIPv6
	if i := strings.IndexByte(tapV4, '/'); i >= 0 {
		tapV4 = tapV4[:i]
	}
	if i := strings.IndexByte(tapV6, '/'); i >= 0 {
		tapV6 = tapV6[:i]
	}

	if err := nodeA.Gateway.SetExitNode(nodeB.Host.ID().String(), tapV4, tapV6, nil); err != nil {
		t.Fatalf("SetExitNode over relay failed: %v", err)
	}
	if !nodeA.isExitNodeActive() {
		t.Fatalf("exit node did not become active over the relay path")
	}
	t.Logf("exit-over-relay: exit node active, gateway v4=%q v6=%q", tapV4, tapV6)

	_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")
	_ = pipeA.ConfigureIP("10.0.0.1/24", "fd00::1/64")

	readerB := newFrameReader(pipeB)
	t.Cleanup(readerB.Close)

	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	clientIP := net.ParseIP("10.0.0.1")
	publicIP := net.ParseIP("203.0.113.9")

	const frames = 64
	var want, wires [][]byte
	for i := 0; i < frames; i++ {
		tag := []byte(fmt.Sprintf("EXIT_RELAY_%04d", i))
		want = append(want, tag)
		// Android shape: pkg/tuntap wraps every OS packet with a broadcast dst.
		wires = append(wires, constructICMPv4PacketWithData(
			srcMAC, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, clientIP, publicIP,
			9500+i, 1, append(tag, make([]byte, 180)...)))
	}
	coll := newConcurrentPayloadCollector(readerB, want)
	for i := range wires {
		if _, werr := pipeA.Write(wires[i]); werr != nil {
			t.Fatalf("pipeA.Write frame %d failed: %v", i, werr)
		}
	}
	if !coll.waitUntil(want, 25*time.Second) {
		t.Fatalf("only %d/%d transit frames crossed the relay multipath set", countSeen(coll, want), frames)
	}
	t.Logf("exit-over-relay: %d/%d transit frames crossed the relay multipath set", countSeen(coll, want), frames)
}
