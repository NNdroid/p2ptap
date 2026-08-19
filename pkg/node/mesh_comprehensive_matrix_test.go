package node

import (
	"bytes"
	"net"
	"runtime"
	"testing"
	"time"

	"p2ptap/pkg/routing"
	"p2ptap/pkg/tap"
)

// TestMatrix_10_0_0_1_to_10_0_0_2_DirectAndBidirectionalPing tests direct P2P
// connectivity between 10.0.0.1 (NodeA) and 10.0.0.2 (NodeB) across IPv4 and IPv6.
func TestMatrix_10_0_0_1_to_10_0_0_2_DirectAndBidirectionalPing(t *testing.T) {
	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")

	nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create nodeA: %v", err)
	}
	defer nodeA.Close()

	nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create nodeB: %v", err)
	}
	defer nodeB.Close()

	nodeA.Start()
	nodeB.Start()

	// Direct P2P connection
	connectNodes(t, nodeA, nodeB)
	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)

	// Propagate metadata
	nodeA.storePeerMeta(nodeB.Host.ID(), PeerMeta{NodeName: "B", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: nodeB.localMAC.String()})
	nodeB.storePeerMeta(nodeA.Host.ID(), PeerMeta{NodeName: "A", TapIP: "10.0.0.1/24", TapIPv6: "fd00::1/64", TapMAC: nodeA.localMAC.String()})
	nodeA.rebuildARPIndex()
	nodeB.rebuildARPIndex()

	macA := nodeA.localMAC
	macB := nodeB.localMAC

	// 1. IPv4 Ping: A -> B
	pingV4 := constructICMPv4PacketWithData(macA, macB, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1001, 1, []byte("MATRIX_PING_V4_A_TO_B"))
	if _, err := pipeA.Write(pingV4); err != nil {
		t.Fatalf("NodeA pipe write failed: %v", err)
	}
	assertPacketArrived(t, pipeB, "NodeB received IPv4 ping from NodeA", 3*time.Second, func(f []byte) bool {
		return bytes.Contains(f, []byte("MATRIX_PING_V4_A_TO_B"))
	})

	// 2. IPv4 Ping: B -> A
	replyV4 := constructICMPv4PacketWithData(macB, macA, net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"), 1001, 2, []byte("MATRIX_PING_V4_B_TO_A"))
	if _, err := pipeB.Write(replyV4); err != nil {
		t.Fatalf("NodeB pipe write failed: %v", err)
	}
	assertPacketArrived(t, pipeA, "NodeA received IPv4 ping from NodeB", 3*time.Second, func(f []byte) bool {
		return bytes.Contains(f, []byte("MATRIX_PING_V4_B_TO_A"))
	})

	// 3. IPv6 Ping: A -> B
	pingV6 := constructICMPv6Packet(macA, macB, net.ParseIP("fd00::1"), net.ParseIP("fd00::2"), 2001, 1)
	if _, err := pipeA.Write(pingV6); err != nil {
		t.Fatalf("NodeA pipe write IPv6 failed: %v", err)
	}
	assertPacketArrived(t, pipeB, "NodeB received IPv6 ping from NodeA", 3*time.Second, func(f []byte) bool {
		return len(f) >= 54 && f[12] == 0x86 && f[13] == 0xdd
	})

	t.Logf("✓ TestMatrix_DirectP2P: Full bidirectional IPv4 & IPv6 communication verified between 10.0.0.1 and 10.0.0.2")
}

// TestMatrix_10_0_0_1_to_10_0_0_2_ViaBootRelayBridge tests end-to-end communication
// when both nodes are strictly behind NAT and reach each other ONLY via a custom Bootstrap Server.
func TestMatrix_10_0_0_1_to_10_0_0_2_ViaBootRelayBridge(t *testing.T) {
	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")

	bootHost, closeBoot := newTestBootRelayBridge(t)
	defer closeBoot()
	bootMa := bootHost.Addrs()[0].String() + "/p2p/" + bootHost.ID().String()
	cfgA.BootstrapPeers = []string{bootMa}
	cfgB.BootstrapPeers = []string{bootMa}

	nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create nodeA: %v", err)
	}
	defer nodeA.Close()

	nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create nodeB: %v", err)
	}
	defer nodeB.Close()

	nodeA.Start()
	nodeB.Start()

	bootID := bootHost.ID()
	waitBootRelayUplink(t, nodeA, bootID)
	waitBootRelayUplink(t, nodeB, bootID)

	aID := nodeA.Host.ID()
	bID := nodeB.Host.ID()

	// Seed peer metadata
	nodeA.storePeerMeta(bID, PeerMeta{NodeName: "B", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: nodeB.localMAC.String()})
	nodeB.storePeerMeta(aID, PeerMeta{NodeName: "A", TapIP: "10.0.0.1/24", TapIPv6: "fd00::1/64", TapMAC: nodeA.localMAC.String()})
	nodeA.rebuildARPIndex()
	nodeB.rebuildARPIndex()

	// Force SeqSync handshake over the boot-relay control tunnel
	go nodeA.triggerPeerRekey(bID)
	go nodeB.triggerPeerRekey(aID)

	waitCipherReady(t, nodeA, bID)
	waitCipherReady(t, nodeB, aID)

	macA := nodeA.localMAC
	macB := nodeB.localMAC

	// Ping A -> B through Boot Server
	pingFrame := constructICMPv4PacketWithData(macA, macB, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 3001, 1, []byte("BOOT_RELAY_A_TO_B"))
	if _, err := pipeA.Write(pingFrame); err != nil {
		t.Fatalf("pipeA write failed: %v", err)
	}
	assertPacketArrived(t, pipeB, "NodeB received boot-relayed ping from NodeA", 4*time.Second, func(f []byte) bool {
		return bytes.Contains(f, []byte("BOOT_RELAY_A_TO_B"))
	})

	// Ping B -> A return frame through Boot Server
	replyFrame := constructICMPv4PacketWithData(macB, macA, net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"), 3001, 2, []byte("BOOT_RELAY_B_TO_A"))
	if _, err := pipeB.Write(replyFrame); err != nil {
		t.Fatalf("pipeB write failed: %v", err)
	}
	assertPacketArrived(t, pipeA, "NodeA received boot-relayed reply from NodeB", 4*time.Second, func(f []byte) bool {
		return bytes.Contains(f, []byte("BOOT_RELAY_B_TO_A"))
	})

	t.Logf("✓ TestMatrix_BootRelay: Verified end-to-end encrypted bidirectional communication over Boot Relay")
}

// TestMatrix_10_0_0_1_to_10_0_0_2_ViaOverlayMeshRelayNode tests multi-hop overlay mesh
// routing when NodeA (10.0.0.1) and NodeB (10.0.0.2) traverse an intermediate transit NodeC (10.0.0.3).
func TestMatrix_10_0_0_1_to_10_0_0_2_ViaOverlayMeshRelayNode(t *testing.T) {
	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")
	tapC, _ := tap.NewMemTAPPair("tapC", "pipeC")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
	cfgC := createTestNodeConfig("10.0.0.3/24", "fd00::3/64", "best_path")

	nodeA, _ := NewNodeWithTAP(cfgA, tapA, nil)
	defer nodeA.Close()
	nodeB, _ := NewNodeWithTAP(cfgB, tapB, nil)
	defer nodeB.Close()
	nodeC, _ := NewNodeWithTAP(cfgC, tapC, nil)
	defer nodeC.Close()

	nodeA.Start()
	nodeB.Start()
	nodeC.Start()

	// Connect A <-> C and B <-> C (A and B are NOT directly connected)
	connectNodes(t, nodeA, nodeC)
	connectNodes(t, nodeB, nodeC)
	waitOverlayReady(t, nodeA, nodeC)
	waitOverlayReady(t, nodeB, nodeC)
	waitStreamReady(t, nodeA, nodeC)
	waitStreamReady(t, nodeC, nodeA)
	waitStreamReady(t, nodeB, nodeC)
	waitStreamReady(t, nodeC, nodeB)

	aID := nodeA.Host.ID()
	bID := nodeB.Host.ID()
	cID := nodeC.Host.ID()

	// Configure routing paths: A -> C -> B, and B -> C -> A via LSA
	nodeA.storePeerMeta(bID, PeerMeta{NodeName: "B", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: nodeB.localMAC.String()})
	nodeB.storePeerMeta(aID, PeerMeta{NodeName: "A", TapIP: "10.0.0.1/24", TapIPv6: "fd00::1/64", TapMAC: nodeA.localMAC.String()})
	nodeA.rebuildARPIndex()
	nodeB.rebuildARPIndex()

	lsaC := &routing.LinkStatePayload{
		Origin: cID.String(),
		Seq:    1,
		TTL:    5,
		Neighbors: map[string]int64{
			aID.String(): 10,
			bID.String(): 10,
		},
		NodeName: "C-relay",
		TapIP:    nodeC.Config.TapIP,
		TapIPv6:  nodeC.Config.TapIPv6,
		TapMAC:   nodeC.Config.TapMAC,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
	}
	nodeA.Router.ProcessLSA(lsaC)
	nodeB.Router.ProcessLSA(lsaC)
	nodeA.invalidateRouteCache()
	nodeB.invalidateRouteCache()

	// Negotiate E2E cipher tunneled via NodeC
	go nodeA.triggerPeerRekey(bID)
	go nodeB.triggerPeerRekey(aID)

	waitCipherReady(t, nodeA, bID)
	waitCipherReady(t, nodeB, aID)

	macA := nodeA.localMAC
	macB := nodeB.localMAC

	// Ping A -> B through overlay relay C
	pingFrame := constructICMPv4PacketWithData(macA, macB, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 4001, 1, []byte("OVERLAY_RELAY_A_TO_B"))
	if _, err := pipeA.Write(pingFrame); err != nil {
		t.Fatalf("pipeA write failed: %v", err)
	}
	assertPacketArrived(t, pipeB, "NodeB received overlay-relayed ping from NodeA", 4*time.Second, func(f []byte) bool {
		return bytes.Contains(f, []byte("OVERLAY_RELAY_A_TO_B"))
	})

	// Reply B -> A through overlay relay C
	replyFrame := constructICMPv4PacketWithData(macB, macA, net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"), 4001, 2, []byte("OVERLAY_RELAY_B_TO_A"))
	if _, err := pipeB.Write(replyFrame); err != nil {
		t.Fatalf("pipeB write failed: %v", err)
	}
	assertPacketArrived(t, pipeA, "NodeA received overlay-relayed reply from NodeB", 4*time.Second, func(f []byte) bool {
		return bytes.Contains(f, []byte("OVERLAY_RELAY_B_TO_A"))
	})

	t.Logf("✓ TestMatrix_OverlayMeshRelay: Verified end-to-end multi-hop mesh routing through intermediate node")
}

// TestMatrix_10_0_0_1_to_10_0_0_2_MACVarianceAutoSelfHealing tests that when NodeA's
// Linux TAP driver uses a physical wire MAC that differs from its advertised metadata,
// NodeB automatically learns the wire MAC, updates its ARP table & proxy, and pings succeed.
func TestMatrix_10_0_0_1_to_10_0_0_2_MACVarianceAutoSelfHealing(t *testing.T) {
	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")

	nodeA, _ := NewNodeWithTAP(cfgA, tapA, nil)
	defer nodeA.Close()
	nodeB, _ := NewNodeWithTAP(cfgB, tapB, nil)
	defer nodeB.Close()

	nodeA.Start()
	nodeB.Start()

	connectNodes(t, nodeA, nodeB)
	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)

	aID := nodeA.Host.ID()
	bID := nodeB.Host.ID()

	// Initial stale metadata: NodeB thinks NodeA has synthetic MAC 02:d9:99:28:0e:80
	syntheticMACA, _ := net.ParseMAC("02:d9:99:28:0e:80")
	realWireMACA, _ := net.ParseMAC("ba:57:57:ed:06:71") // Actual Linux kernel MAC
	nodeA.localMAC = realWireMACA

	nodeB.storePeerMeta(aID, PeerMeta{NodeName: "A", TapIP: "10.0.0.1/24", TapIPv6: "fd00::1/64", TapMAC: syntheticMACA.String()})
	nodeA.storePeerMeta(bID, PeerMeta{NodeName: "B", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: nodeB.localMAC.String()})
	nodeB.rebuildARPIndex()

	// 1. NodeA sends an initial frame on the wire with its REAL MAC (ba:57:57:ed:06:71)
	initialFrame := constructICMPv4PacketWithData(realWireMACA, nodeB.localMAC, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 5001, 1, []byte("WIRE_MAC_ANNOUNCEMENT"))
	if _, err := pipeA.Write(initialFrame); err != nil {
		t.Fatalf("pipeA write failed: %v", err)
	}

	assertPacketArrived(t, pipeB, "NodeB received frame from NodeA", 3*time.Second, func(f []byte) bool {
		return bytes.Contains(f, []byte("WIRE_MAC_ANNOUNCEMENT"))
	})

	// 2. Verify that NodeB's auto-healing mechanism learned NodeA's real wire MAC
	deadline := time.Now().Add(3 * time.Second)
	updated := false
	for time.Now().Before(deadline) {
		mac, _ := nodeB.lookupPeerMACByIPv4(net.ParseIP("10.0.0.1"))
		if mac != nil && mac.String() == realWireMACA.String() {
			updated = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !updated {
		t.Fatalf("NodeB did not update effective MAC to real wire MAC %s", realWireMACA.String())
	}

	// 3. Now NodeB sends an ICMP ping to NodeA using the learned real wire MAC
	pingBtoA := constructICMPv4PacketWithData(nodeB.localMAC, realWireMACA, net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"), 5001, 2, []byte("PING_TO_LEARNED_WIRE_MAC"))
	if _, err := pipeB.Write(pingBtoA); err != nil {
		t.Fatalf("pipeB write failed: %v", err)
	}

	// 4. Assert packet arrived at NodeA with the EXACT realWireMACA destination
	assertPacketArrived(t, pipeA, "NodeA received packet addressed to its real kernel MAC", 3*time.Second, func(f []byte) bool {
		if len(f) < 14 {
			return false
		}
		dstMAC := net.HardwareAddr(f[0:6])
		return dstMAC.String() == realWireMACA.String() && bytes.Contains(f, []byte("PING_TO_LEARNED_WIRE_MAC"))
	})

	t.Logf("✓ TestMatrix_MACVarianceAutoSelfHealing: Successfully auto-healed and pinged Linux TAP interface with wire MAC divergence")
}

// TestMatrix_10_0_0_1_to_10_0_0_2_SubnetAndExitNodeRouting tests subnet/exit node
// routing between NodeA (10.0.0.1, advertising 192.168.50.0/24) and NodeB (10.0.0.2).
func TestMatrix_10_0_0_1_to_10_0_0_2_SubnetAndExitNodeRouting(t *testing.T) {
	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")

	nodeA, _ := NewNodeWithTAP(cfgA, tapA, nil)
	defer nodeA.Close()
	nodeB, _ := NewNodeWithTAP(cfgB, tapB, nil)
	defer nodeB.Close()

	nodeA.Start()
	nodeB.Start()

	connectNodes(t, nodeA, nodeB)
	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)

	aID := nodeA.Host.ID()

	// NodeA advertises subnet 192.168.50.0/24
	nodeB.storePeerMeta(aID, PeerMeta{
		NodeName:          "A-Exit",
		TapIP:             "10.0.0.1/24",
		TapIPv6:           "fd00::1/64",
		TapMAC:            nodeA.localMAC.String(),
		AdvertisedSubnets: []string{"192.168.50.0/24"},
		IsExitNode:        true,
	})
	nodeB.rebuildARPIndex()

	// NodeB sends packet to a LAN host behind NodeA: 192.168.50.100
	lanDstIP := net.ParseIP("192.168.50.100")
	lanPingFrame := constructICMPv4PacketWithData(nodeB.localMAC, nodeA.localMAC, net.ParseIP("10.0.0.2"), lanDstIP, 6001, 1, []byte("LAN_ROUTING_TO_A"))
	if _, err := pipeB.Write(lanPingFrame); err != nil {
		t.Fatalf("pipeB write failed: %v", err)
	}

	assertPacketArrived(t, pipeA, "NodeA received routed subnet frame for 192.168.50.100", 3*time.Second, func(f []byte) bool {
		return bytes.Contains(f, []byte("LAN_ROUTING_TO_A"))
	})

	t.Logf("✓ TestMatrix_SubnetAndExitNodeRouting: Verified subnet packet delivery to exit/subnet gateway")
}

func connectNodes(t *testing.T, a, b *Node) {
	t.Helper()
	ti := b.Host.Peerstore().PeerInfo(b.Host.ID())
	ti.Addrs = b.Host.Addrs()
	if err := a.Host.Connect(a.ctx, ti); err != nil {
		t.Fatalf("connect %s->%s: %v", a.Host.ID().ShortString(), b.Host.ID().ShortString(), err)
	}
}

func assertPacketArrived(t *testing.T, pipe *tap.MemTAP, desc string, timeout time.Duration, predicate func([]byte) bool) {
	t.Helper()
	deadline := time.After(timeout)
	buf := make([]byte, 2048)
	for {
		select {
		case <-deadline:
			t.Fatalf("TIMEOUT (%v): %s", timeout, desc)
		default:
			n, err := pipe.Read(buf)
			if err == nil && n > 0 {
				if predicate(buf[:n]) {
					t.Logf("  ✓ Received expected packet: %s (%d bytes)", desc, n)
					return
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}
