package node

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	relayClient "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	ma "github.com/multiformats/go-multiaddr"

	"p2ptap/pkg/routing"
	"p2ptap/pkg/tap"
)

// testBootRelayProtocolID mirrors cmd/p2ptap-boot's BootRelayProtocolID.
const testBootRelayProtocolID protocol.ID = "/p2ptap/boot-relay/1.0.0"

// testBootRelayHandler is a minimal, faithful re-implementation of the boot's
// relayRouter.route forward logic: read a length-prefixed frame, unpack the
// boot-relay envelope, and deliver to the destination's own uplink stream.
type testBootRelayHandler struct {
	mu      sync.RWMutex
	streams map[peer.ID]network.Stream // clientID -> its uplink (server side)
}

func (h *testBootRelayHandler) handle(s network.Stream) {
	remote := s.Conn().RemotePeer()
	h.mu.Lock()
	h.streams[remote] = s
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		if h.streams[remote] == s {
			delete(h.streams, remote)
		}
		h.mu.Unlock()
		s.Close()
	}()
	buf := make([]byte, 66000)
	for {
		if err := s.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			return
		}
		n, err := readFrameTest(s, buf)
		if err != nil || n == 0 {
			return
		}
		_, _, _, finalDst, _, _, _, uerr := routing.UnpackBootRelayFrame(buf[:n])
		if uerr != nil {
			continue
		}
		if finalDst == s.Conn().RemotePeer() {
			continue // heartbeat, don't loop
		}
		h.mu.RLock()
		dst := h.streams[finalDst]
		h.mu.RUnlock()
		if dst == nil {
			continue
		}
		// length-prefix + write (mirrors boot's runRelayWriter).
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(n))
		if _, err := dst.Write(lenBuf[:]); err != nil {
			continue
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			continue
		}
	}
}

func readFrameTest(r io.Reader, buf []byte) (int, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, err
	}
	ln := int(binary.BigEndian.Uint32(lenBuf[:]))
	if ln < 0 || ln > len(buf) {
		return 0, io.ErrUnexpectedEOF
	}
	if _, err := io.ReadFull(r, buf[:ln]); err != nil {
		return 0, err
	}
	return ln, nil
}

// TestE2EBootRelayTapDataTransit reproduces the reported "boot-relay cannot
// carry TAP data" symptom: two nodes whose ONLY shared connectivity is a
// p2ptap-boot (with both the overlay boot-relay uplink AND Circuit Relay v2)
// must exchange a real TAP frame end-to-end. This is the data-plane path the
// boot-relay is supposed to provide but users report as unusable.
func TestE2EBootRelayTapDataTransit(t *testing.T) {
	// 1. In-process boot: libp2p host with Circuit Relay v2 service + the
	//    application boot-relay uplink handler. Force public so the circuit
	//    relay service actually mounts.
	bootHost, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.EnableRelayService(),
		libp2p.ForceReachabilityPublic(),
	)
	if err != nil {
		t.Fatalf("create boot host: %v", err)
	}
	defer bootHost.Close()
	// Note: EnableRelayService already mounts the Circuit Relay v2 service; the
	// /hop handler activates because ForceReachabilityPublic makes the loopback
	// host read as publicly reachable (mirrors boot_relay_test.go).
	bh := &testBootRelayHandler{streams: make(map[peer.ID]network.Stream)}
	bootHost.SetStreamHandler(testBootRelayProtocolID, bh.handle)
	bootMa := bootHost.Addrs()[0]
	bootBootstrap := bootMa.String() + "/p2p/" + bootHost.ID().String()
	t.Logf("boot relay at %s", bootBootstrap)

	// 2. Two p2ptap nodes, both using ONLY the boot as bootstrap (no direct link
	//    between them; no mDNS, no static peers).
	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgA.BootstrapPeers = []string{bootBootstrap}
	cfgA.StaticPeers = nil
	cfgA.EnableMDNS = false
	cfgA.DiscoverBootMesh = false

	cfgC := createTestNodeConfig("10.0.0.3/24", "fd00::3/64", "best_path")
	cfgC.BootstrapPeers = []string{bootBootstrap}
	cfgC.StaticPeers = nil
	cfgC.EnableMDNS = false
	cfgC.DiscoverBootMesh = false

	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapC, pipeC := tap.NewMemTAPPair("tapC", "pipeC")

	aNode, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	defer aNode.Close()
	cNode, err := NewNodeWithTAP(cfgC, tapC, nil)
	if err != nil {
		t.Fatalf("create NodeC: %v", err)
	}
	defer cNode.Close()

	aNode.Start()
	cNode.Start()

	// 3. Both nodes connect to the boot and open their boot-relay uplinks.
	waitConnectedTo(t, aNode.Host, bootHost.ID(), "A->boot")
	waitConnectedTo(t, cNode.Host, bootHost.ID(), "C->boot")
	waitBootUplink(t, aNode, bootHost.ID(), "A")
	waitBootUplink(t, cNode, bootHost.ID(), "C")

	// 3b. Reserve a Circuit Relay v2 slot on the boot for BOTH nodes so the
	//     circuit dial in step 7 has a reservation to traverse. In production
	//     libp2p AutoRelay does this automatically once the boot is a static
	//     relay; here we drive the client API directly (as boot_relay_test.go
	//     does) so the reservation exists deterministically before the dial.
	bootInfo := &peer.AddrInfo{ID: bootHost.ID(), Addrs: bootHost.Addrs()}
	rctx, rcancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer rcancel()
	if _, err := relayClient.Reserve(rctx, aNode.Host, *bootInfo); err != nil {
		t.Fatalf("NodeA failed to reserve circuit slot on boot relay: %v", err)
	}
	if _, err := relayClient.Reserve(rctx, cNode.Host, *bootInfo); err != nil {
		t.Fatalf("NodeC failed to reserve circuit slot on boot relay: %v", err)
	}
	t.Log("✓ both nodes reserved Circuit Relay v2 slots on the boot")

	// 4. Teach A that C exists via the boot, the way a REAL peek-map broadcast
	//    from the boot hub does it (meta.go applyPeerMetaFromLSA): the boot
	//    announces C, A records an indirect circuit-class edge boot<->C and
	//    remembers that C was discovered VIA the boot. This is the only path a
	//    relay-only mesh uses to route to C through the boot — A never learns a
	//    DIRECT edge to C because the two are not connected.
	aNode.Router.UpdateDirectLink(bootHost.ID(), 10, routing.LinkDirect)
	aNode.Router.SetEdge(bootHost.ID(), cNode.Host.ID(), 25, routing.LinkCircuit)
	aNode.recordPeekMapOrigin(cNode.Host.ID(), bootHost.ID(), 1, true)
	aNode.invalidateRouteCache()

	// 5. Confirm A has no direct connection to C and that its route to C goes
	//    through the boot.
	if aNode.Host.Network().Connectedness(cNode.Host.ID()) != network.NotConnected {
		t.Fatalf("A unexpectedly has a connection to C; the relay-only invariant cannot hold")
	}
	routes := aNode.Router.ComputeRoutes()
	rc, ok := routes[cNode.Host.ID()]
	if !ok || rc.IsDirect || rc.NextHop != bootHost.ID() {
		t.Fatalf("NodeA route to C not through boot: ok=%v isDirect=%v nextHop=%v", ok, rc.IsDirect, rc.NextHop)
	}

	// 6. Drain C's TAP and send a real ICMP frame A -> C (must transit boot).
	readerC := newFrameReader(pipeC)
	readerA := newFrameReader(pipeA)
	defer readerA.Close()

	_ = pipeA.ConfigureIP("10.0.0.1/24", "fd00::1/64")
	_ = pipeC.ConfigureIP("10.0.0.3/24", "fd00::3/64")

	// Use the nodes' REAL TAP MACs (not the synthetic testMACA/testMACC): the
	// receiver's L2 filter drops frames whose Dst MAC is not its own interface
	// MAC, and the MAC-rewrite that would fix a synthetic Dst MAC only runs on
	// the boot-relay path — NOT on the circuit/direct path.
	pingFrame := constructICMPv4Packet(aNode.localMAC, cNode.localMAC,
		net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.3"), 5151, 1)
	writeAndExpectWithRetry(t, pipeA, readerC, pingFrame,
		[]byte("P2PTAP_PING_V4_TEST_DATA"), "IPv4 A -> boot-relay -> C")

	t.Log("✓ boot-relay transited a real TAP frame A -> boot -> C")
	// readerC must stop reading pipeC: two frameReaders on the same mem-TAP
	// compete for every frame, so a still-alive readerC would steal the
	// circuit-path frame from readerC2 below.
	readerC.Close()

	// 7. Circuit-relay data path: A dials C THROUGH the boot's Circuit Relay v2
	//    and must carry a real TAP frame over the circuit stream. This is the
	//    other reported failure mode ("circuit relay cannot carry TAP data").
	relayMa := bootHost.Addrs()[0]
	circuitComp, _ := ma.NewMultiaddr(
		"/p2p/" + bootHost.ID().String() + "/p2p-circuit/p2p/" + cNode.Host.ID().String())
	targetCircuit := relayMa.Encapsulate(circuitComp)

	dctx, dcancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer dcancel()
	if err := aNode.dialPeerToAddr(dctx, cNode.Host.ID(), targetCircuit); err != nil {
		t.Fatalf("A dial C through boot circuit: %v", err)
	}
	// Wait for the application data stream to come up over the circuit.
	waitStreamReady(t, aNode, cNode)
	waitStreamReady(t, cNode, aNode)

	// Drain fresh (the reader above already consumed the boot-relay frame).
	readerC2 := newFrameReader(pipeC)
	defer readerC2.Close()

	pingFrame2 := constructICMPv4Packet(aNode.localMAC, cNode.localMAC,
		net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.3"), 5152, 2)
	writeAndExpectWithRetry(t, pipeA, readerC2, pingFrame2,
		[]byte("P2PTAP_PING_V4_TEST_DATA"), "IPv4 A -> circuit-relay(boot) -> C")
	t.Log("✓ circuit-relay transited a real TAP frame A -> boot(circuit) -> C")
}

// waitBootUplink blocks until the node reports a live boot-relay uplink to boot.
func waitBootUplink(t *testing.T, n *Node, boot peer.ID, label string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if n.hasBootRelayUplink(boot) {
			t.Logf("✓ %s boot-relay uplink to %s open", label, boot.ShortString())
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s boot-relay uplink to %s", label, boot.ShortString())
		}
		time.Sleep(200 * time.Millisecond)
	}
}
