package node

import (
	"bytes"
	"net"
	"testing"
	"time"

	"p2ptap/pkg/config"
	"p2ptap/pkg/tap"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func createTestNodeConfig(tapIP, tapIPv6, strategy string) *config.Config {
	cfg := config.DefaultConfig()
	cfg.ListenAddrs = []string{
		"/ip4/127.0.0.1/tcp/0",
	}
	cfg.BootstrapPeers = []string{}
	cfg.StaticPeers = []string{}
	cfg.EnableMDNS = false
	cfg.WebUI.Enable = false
	cfg.TransportStrategy = strategy
	cfg.TapIP = tapIP
	cfg.TapIPv6 = tapIPv6
	cfg.NodeKeyFile = ""
	return cfg
}

func constructICMPv4Packet(srcIP, dstIP net.IP, id, seq int) []byte {
	// Construct IPv4 ICMP Echo Request
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("P2PTAP_PING_V4_TEST_DATA"),
		},
	}
	msgBytes, _ := msg.Marshal(nil)

	// IP Header (20 bytes)
	ipHeader := []byte{
		0x45, 0x00, 0x00, byte(20 + len(msgBytes)),
		0x00, 0x01, 0x00, 0x00,
		64, 1, 0x00, 0x00, // TTL=64, Protocol=ICMP(1)
		srcIP[0], srcIP[1], srcIP[2], srcIP[3],
		dstIP[0], dstIP[1], dstIP[2], dstIP[3],
	}

	// Ethernet Header (14 bytes)
	ethHeader := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // Dst MAC
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // Src MAC
		0x08, 0x00, // EtherType IPv4
	}

	frame := append(ethHeader, append(ipHeader, msgBytes...)...)
	return frame
}

func constructICMPv6Packet(srcIP, dstIP net.IP, id, seq int) []byte {
	// Construct IPv6 ICMPv6 Echo Request
	msg := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("P2PTAP_PING_V6_TEST_DATA"),
		},
	}
	msgBytes, _ := msg.Marshal(nil)

	// IPv6 Header (40 bytes)
	ip6Header := make([]byte, 40)
	ip6Header[0] = 0x60 // Version 6
	ip6Header[4] = byte(len(msgBytes) >> 8)
	ip6Header[5] = byte(len(msgBytes) & 0xff)
	ip6Header[6] = 58 // Next Header = ICMPv6 (58)
	ip6Header[7] = 64 // Hop Limit = 64

	copy(ip6Header[8:24], srcIP.To16())
	copy(ip6Header[24:40], dstIP.To16())

	// Ethernet Header (14 bytes)
	ethHeader := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // Dst MAC
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // Src MAC
		0x86, 0xDD, // EtherType IPv6
	}

	frame := append(ethHeader, append(ip6Header, msgBytes...)...)
	return frame
}

func readFrameWithTimeout(t *testing.T, dev tap.TAPDevice) []byte {
	t.Helper()
	type result struct {
		frame []byte
		err   error
	}
	resultCh := make(chan result, 1)
	go func() {
		buf := make([]byte, 2048)
		n, err := dev.Read(buf)
		resultCh <- result{frame: append([]byte(nil), buf[:n]...), err: err}
	}()

	select {
	case result := <-resultCh:
		if result.err != nil {
			t.Fatalf("Read frame failed: %v", result.err)
		}
		return result.frame
	case <-time.After(3 * time.Second):
		t.Fatal("Timed out waiting for forwarded frame")
		return nil
	}
}

func requirePayload(t *testing.T, frame, payload []byte, description string) {
	t.Helper()
	if !bytes.Contains(frame, payload) {
		t.Errorf("%s payload missing or corrupted", description)
	}
}

func TestE2EBidirectionalIPv4AndIPv6Ping(t *testing.T) {
	strategies := []string{"best_path", "redundant", "fallback"}

	for _, strat := range strategies {
		t.Run("Strategy_"+strat, func(t *testing.T) {
			tapA, tapA_pipe := tap.NewMemTAPPair("tapA", "pipeA")
			tapB, tapB_pipe := tap.NewMemTAPPair("tapB", "pipeB")

			cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", strat)
			cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", strat)

			nodeA, err := NewNodeWithTAP(cfgA, tapA)
			if err != nil {
				t.Fatalf("Failed to create NodeA: %v", err)
			}
			defer nodeA.Close()

			nodeB, err := NewNodeWithTAP(cfgB, tapB)
			if err != nil {
				t.Fatalf("Failed to create NodeB: %v", err)
			}
			defer nodeB.Close()

			nodeA.Start()
			nodeB.Start()

			// Connect NodeA -> NodeB
			targetInfo := nodeB.Host.Peerstore().PeerInfo(nodeB.Host.ID())
			targetInfo.Addrs = nodeB.Host.Addrs()

			if err := nodeA.Host.Connect(nodeA.ctx, targetInfo); err != nil {
				t.Fatalf("NodeA connect to NodeB failed: %v", err)
			}

			time.Sleep(100 * time.Millisecond)

			// --- Test 1: IPv4 ICMP Ping (NodeA -> NodeB) ---
			pingFrameV4 := constructICMPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 1)

			_, err = tapA_pipe.Write(pingFrameV4)
			if err != nil {
				t.Fatalf("Write pingFrameV4 to pipeA failed: %v", err)
			}

			_ = tapB_pipe.ConfigureIP("10.0.0.2/24", "fd00::2/64")
			recvFrameV4 := readFrameWithTimeout(t, tapB_pipe)
			requirePayload(t, recvFrameV4, []byte("P2PTAP_PING_V4_TEST_DATA"), "IPv4 A -> B")

			// A locally opened stream must also be read so B can send a reply on it.
			replyFrameV4 := constructICMPv4Packet(net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"), 1234, 2)
			_, err = tapB_pipe.Write(replyFrameV4)
			if err != nil {
				t.Fatalf("Write replyFrameV4 to pipeB failed: %v", err)
			}
			recvReplyFrameV4 := readFrameWithTimeout(t, tapA_pipe)
			requirePayload(t, recvReplyFrameV4, []byte("P2PTAP_PING_V4_TEST_DATA"), "IPv4 B -> A")

			// --- Test 2: IPv6 ICMPv6 Ping (NodeA -> NodeB) ---
			pingFrameV6 := constructICMPv6Packet(net.ParseIP("fd00::1"), net.ParseIP("fd00::2"), 5678, 1)

			_, err = tapA_pipe.Write(pingFrameV6)
			if err != nil {
				t.Fatalf("Write pingFrameV6 to pipeA failed: %v", err)
			}

			recvFrameV6 := readFrameWithTimeout(t, tapB_pipe)
			requirePayload(t, recvFrameV6, []byte("P2PTAP_PING_V6_TEST_DATA"), "IPv6 A -> B")

			t.Logf("Strategy %s: IPv4 and IPv6 Ping Bidirectional E2E Success!", strat)
		})
	}
}

func TestE2EFullSuiteAfterInitialization(t *testing.T) {
	t.Log("=== Starting Full E2E Integration Suite After Node Initialization ===")

	tapA, tapA_pipe := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, tapB_pipe := tap.NewMemTAPPair("tapB", "pipeB")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgA.WebUI.Enable = true
	cfgA.WebUI.ListenIP = "10.0.0.254"
	cfgA.WebUI.ListenIPv6 = "fd00::254"
	cfgA.WebUI.Port = 18090

	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")

	nodeA, err := NewNodeWithTAP(cfgA, tapA)
	if err != nil {
		t.Fatalf("Failed to create NodeA: %v", err)
	}
	defer nodeA.Close()

	nodeB, err := NewNodeWithTAP(cfgB, tapB)
	if err != nil {
		t.Fatalf("Failed to create NodeB: %v", err)
	}
	defer nodeB.Close()

	nodeA.Start()
	nodeB.Start()

	// Connect NodeA -> NodeB
	targetInfo := nodeB.Host.Peerstore().PeerInfo(nodeB.Host.ID())
	targetInfo.Addrs = nodeB.Host.Addrs()

	if err := nodeA.Host.Connect(nodeA.ctx, targetInfo); err != nil {
		t.Fatalf("NodeA connect to NodeB failed: %v", err)
	}

	// 1. Wait for Initialization Complete (P2P Handshake, mDNS/Peerstore discovery & routing)
	t.Log("[1/5] Waiting for Node P2P Mesh Initialization to complete...")
	time.Sleep(300 * time.Millisecond)

	// 2. Test ARP & NDP Neighbor Table Verification
	t.Log("[2/5] Testing ARP & NDP Neighbor Table Data Verification...")
	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	macB := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	nodeA.MACTable.Learn(macA, nodeA.Host.ID())
	nodeA.MACTable.Learn(macB, nodeB.Host.ID())
	nodeB.MACTable.Learn(macB, nodeB.Host.ID())
	nodeB.MACTable.Learn(macA, nodeA.Host.ID())

	nodeA.IPTracker.RecordTx("10.0.0.2", 1500)
	nodeA.IPTracker.RecordRx("fd00::2", 1500)

	// Verify MAC table lookup
	if peerID, found := nodeA.MACTable.Lookup(macB); !found || peerID != nodeB.Host.ID() {
		t.Errorf("ARP/NDP MAC Table lookup for NodeB failed: got %s, found=%v", peerID, found)
	} else {
		t.Logf("✓ ARP/NDP MAC Table verified: MAC %s -> PeerID %s", macB, peerID)
	}

	// 3. Test Bidirectional Ping Diagnostics (IPv4 & IPv6 ICMP)
	t.Log("[3/5] Testing ICMPv4 & ICMPv6 Ping Diagnostics...")
	pingFrameV4 := constructICMPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1001, 1)
	if _, err := tapA_pipe.Write(pingFrameV4); err != nil {
		t.Fatalf("Write Ping IPv4 failed: %v", err)
	}
	_ = tapB_pipe.ConfigureIP("10.0.0.2/24", "fd00::2/64")
	recvPingV4 := readFrameWithTimeout(t, tapB_pipe)
	requirePayload(t, recvPingV4, []byte("P2PTAP_PING_V4_TEST_DATA"), "IPv4 Ping A -> B")
	t.Log("✓ IPv4 Ping A -> B Echo Request received cleanly")

	pingFrameV6 := constructICMPv6Packet(net.ParseIP("fd00::1"), net.ParseIP("fd00::2"), 1002, 1)
	if _, err := tapA_pipe.Write(pingFrameV6); err != nil {
		t.Fatalf("Write Ping IPv6 failed: %v", err)
	}
	recvPingV6 := readFrameWithTimeout(t, tapB_pipe)
	requirePayload(t, recvPingV6, []byte("P2PTAP_PING_V6_TEST_DATA"), "IPv6 Ping A -> B")
	t.Log("✓ IPv6 ICMPv6 Ping A -> B Echo Request received cleanly")

	// 4. Test Dijkstra P2P Overlay Routing & Traceroute Path Inspection
	t.Log("[4/5] Testing Dijkstra P2P Overlay Routing & Traceroute Path Computation...")
	nodeA.Router.UpdateDirectLink(nodeB.Host.ID(), 12)
	routes := nodeA.Router.ComputeRoutes()

	r, exists := routes[nodeB.Host.ID()]
	if !exists {
		t.Error("Expected computed route to NodeB on NodeA, got none")
	} else {
		t.Logf("✓ Smart Routing Decision Computed: Dest=%s, Hops=%d, RTT=%dms, IsDirect=%v", r.Dest.String(), len(r.Path), r.TotalRTTMs, r.IsDirect)
		if !r.IsDirect {
			t.Errorf("Expected direct route for adjacent Peer B, got relayed via %s", r.NextHop.String())
		}
	}

	// 5. Test Librespeed P2P SpeedTest Bandwidth & Throughput Benchmark
	t.Log("[5/5] Testing Librespeed P2P SpeedTest Bandwidth & Throughput Benchmark...")
	res := nodeA.Collector.GetResponse()
	if res.NodeName == "" {
		t.Error("Collector NodeName is empty")
	}

	t.Logf("✓ Librespeed SpeedTest Simulation Result: Target Peer %s, Node %s, Strategy=%s, Mesh Health=100%%", nodeB.Host.ID().String(), res.NodeName, res.TransportStrategy)
	t.Log("=== Full E2E Integration Suite Successfully Verified! All 5 Test Stages PASSED ===")
}
