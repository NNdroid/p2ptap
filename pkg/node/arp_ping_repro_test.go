package node

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"p2ptap/pkg/tap"
)

// buildARPRequest crafts a minimal ARP "who-has" request frame: A's OS asking
// for B's IP. eth dst = broadcast, target MAC = zero, target IP = the queried
// peer (B). 60-byte minimum Ethernet frame.
func buildARPRequest(senderMAC net.HardwareAddr, senderIP, targetIP net.IP) []byte {
	f := make([]byte, 60)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // dst MAC broadcast
	copy(f[6:12], senderMAC)                                   // src MAC
	binary.BigEndian.PutUint16(f[12:14], 0x0806)               // EtherType ARP
	binary.BigEndian.PutUint16(f[14:16], 1)                   // HW type Ethernet
	binary.BigEndian.PutUint16(f[16:18], 0x0800)              // protocol IPv4
	f[18] = 6                                                 // HW size
	f[19] = 4                                                 // proto size
	binary.BigEndian.PutUint16(f[20:22], 1)                   // opcode = request
	copy(f[22:28], senderMAC)                                 // sender MAC
	copy(f[28:32], senderIP.To4())                            // sender IP
	// target MAC left zero
	copy(f[38:42], targetIP.To4()) // target IP
	return f
}

// TestARPPingRepro reproduces the real-world "A cannot ping B" path:
//  1. A's OS emits an ARP request for B's IP (broadcast).
//  2. A's proxy-ARP must answer with B's real TAP MAC (locally, to A's TAP).
//  3. A's OS then sends an ICMP echo request unicast to B's MAC.
//  4. A's node must route it to B (MAC-learned unicast), and B must receive it.
//
// The existing e2e suites bypass ARP entirely (synthetic MACs + IP-fallback
// routing), so a defect in the ARP-discovery + MAC-learned unicast path would
// pass those suites yet still break real ping.
func TestARPPingRepro(t *testing.T) {
	tapA, tapA_pipe := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, tapB_pipe := tap.NewMemTAPPair("tapB", "pipeB")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")

	nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	defer nodeA.Close()
	nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create NodeB: %v", err)
	}
	defer nodeB.Close()

	nodeA.Start()
	nodeB.Start()

	targetInfo := nodeB.Host.Peerstore().PeerInfo(nodeB.Host.ID())
	targetInfo.Addrs = nodeB.Host.Addrs()
	if cerr := nodeA.Host.Connect(nodeA.ctx, targetInfo); cerr != nil {
		t.Fatalf("connect A->B: %v", cerr)
	}

	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)
	time.Sleep(300 * time.Millisecond)

	// Seed peer metadata BOTH ways so each node's ARP index knows the other's
	// real TAP MAC/IP — exactly what the running daemon learns via the meta
	// exchange over the control channel.
	nodeA.storePeerMeta(nodeB.Host.ID(), PeerMeta{
		NodeName: "B",
		TapIP:    nodeB.localV4IP.String() + "/24",
		TapMAC:   nodeB.localMAC.String(),
	})
	nodeB.storePeerMeta(nodeA.Host.ID(), PeerMeta{
		NodeName: "A",
		TapIP:    nodeA.localV4IP.String() + "/24",
		TapMAC:   nodeA.localMAC.String(),
	})

	readerA := newFrameReader(tapA_pipe) // captures A's locally-written frames (ARP reply)
	readerB := newFrameReader(tapB_pipe) // captures B's received ping
	defer readerA.Close()
	defer readerB.Close()

	// --- Step 1+2: ARP request then expect a proxy-ARP reply from A's node ---
	arpReq := buildARPRequest(testMACA, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"))
	if _, err := tapA_pipe.Write(arpReq); err != nil {
		t.Fatalf("write ARP request: %v", err)
	}

	var bMac net.HardwareAddr
	deadline := time.After(8 * time.Second)
	gotReply := false
	for !gotReply {
		select {
		case f := <-readerA.frames:
			// ARP reply: ethertype 0x0806, opcode 2 at [20:22].
			if len(f) >= 42 && binary.BigEndian.Uint16(f[12:14]) == 0x0806 &&
				binary.BigEndian.Uint16(f[20:22]) == 2 {
				// Accept only a reply from the IP we asked about (ARP sender
				// protocol address at f[28:32]); a stray reply for another
				// host would otherwise bind the wrong MAC.
				if !net.IP(f[28:32]).Equal(net.ParseIP("10.0.0.2").To4()) {
					continue
				}
				bMac = net.HardwareAddr(append([]byte(nil), f[22:28]...)) // sender MAC in reply = B's MAC
				t.Logf("ARP reply received on A: B's MAC=%s", bMac.String())
				gotReply = true
			}
		case <-deadline:
			t.Fatalf("no proxy-ARP reply received on A within timeout — ARP discovery broken")
		}
	}

	if len(bMac) != 6 {
		t.Fatalf("ARP reply did not carry a 6-byte B MAC: %v", bMac)
	}

	// --- Step 3+4: ICMP echo request unicast to B's MAC, expect B to receive ---
	icmp := constructICMPv4PacketWithData(testMACA, bMac, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 5000, 1, []byte("ARP_PING_REPRO"))
	if _, err := tapA_pipe.Write(icmp); err != nil {
		t.Fatalf("write ICMP: %v", err)
	}

	gotPing := false
	deadline = time.After(8 * time.Second)
	for !gotPing {
		select {
		case f := <-readerB.frames:
			if bytes.Contains(f, []byte("ARP_PING_REPRO")) {
				gotPing = true
			}
		case <-deadline:
			t.Fatalf("B never received the ICMP echo (after ARP-discovery) — A cannot ping B")
		}
	}
	t.Log("ARP-discovery + MAC-learned unicast ping path verified: A can ping B")
}
