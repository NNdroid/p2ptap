package node

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"p2ptap/pkg/logger"
	"p2ptap/pkg/tap"
)

func init() {
	// Surface the Tx-send-error / dedup / decrypt diagnostics that are emitted at
	// DEBUG so a flaky multi-peer ping failure is diagnosable.
	logger.SetGlobalLevel(logger.LevelDebug)
}

// TestARPPingThreeNode reproduces the documented "multi-peer key-rotation
// fragility": A<->B works alone, but breaks as soon as a 3rd peer (C) is
// present. We build a full mesh A-B, B-C, A-C and verify every directed ping
// (A->B, A->C, B->C) still delivers after the mesh is up. If the fragility is
// real and reproducible here, the test will show which directed link dies.
func TestARPPingThreeNode(t *testing.T) {
	mk := func(ip, ip6 string) (*Node, tap.TAPDevice, tap.TAPDevice) {
		tapDev, pipe := tap.NewMemTAPPair("tap"+ip, "pipe"+ip)
		cfg := createTestNodeConfig(ip+"/24", ip6+"/64", "best_path")
		n, err := NewNodeWithTAP(cfg, tapDev, nil)
		if err != nil {
			t.Fatalf("create node %s: %v", ip, err)
		}
		n.Start()
		return n, tapDev, pipe
	}

	nodeA, _, pipeA := mk("10.0.0.1", "fd00::1")
	nodeB, _, pipeB := mk("10.0.0.2", "fd00::2")
	nodeC, _, pipeC := mk("10.0.0.3", "fd00::3")
	defer nodeA.Close()
	defer nodeB.Close()
	defer nodeC.Close()

	connect := func(a, b *Node) {
		ti := b.Host.Peerstore().PeerInfo(b.Host.ID())
		ti.Addrs = b.Host.Addrs()
		if err := a.Host.Connect(a.ctx, ti); err != nil {
			t.Fatalf("connect %s->%s: %v", a.Host.ID().ShortString(), b.Host.ID().ShortString(), err)
		}
	}
	connect(nodeA, nodeB)
	connect(nodeB, nodeC)
	connect(nodeA, nodeC)

	// Wait for all three overlay pairs to be ready.
	for _, pr := range [][2]*Node{{nodeA, nodeB}, {nodeB, nodeC}, {nodeA, nodeC}} {
		waitOverlayReady(t, pr[0], pr[1])
		waitStreamReady(t, pr[0], pr[1])
		waitStreamReady(t, pr[1], pr[0])
	}
	time.Sleep(500 * time.Millisecond)

	// Seed all peer metadata both ways.
	all := map[*Node]PeerMeta{
		nodeA: {NodeName: "A", TapIP: "10.0.0.1/24", TapMAC: nodeA.localMAC.String()},
		nodeB: {NodeName: "B", TapIP: "10.0.0.2/24", TapMAC: nodeB.localMAC.String()},
		nodeC: {NodeName: "C", TapIP: "10.0.0.3/24", TapMAC: nodeC.localMAC.String()},
	}
	peers := []*Node{nodeA, nodeB, nodeC}
	for _, src := range peers {
		for _, dst := range peers {
			if src == dst {
				continue
			}
			src.storePeerMeta(dst.Host.ID(), all[dst])
		}
	}

	// ONE persistent reader per TAP pipe, created up front and kept alive for the
	// whole test.
	//
	// This is load-bearing, not a tidy-up. frameReader.Close() only closes its
	// stop channel while its goroutine is parked in a blocking dev.Read(); the
	// goroutine cannot notice the stop until it has ALREADY consumed a frame from
	// the device, and it then discards that frame on its way out. So a Close()d
	// reader lingers as a "zombie" competing for the very same pipe as any reader
	// created after it.
	//
	// The previous code built a fresh reader per ping (and another per ARP retry),
	// so by the time the B->C ping ran, pipeC still had the zombie left behind by
	// the A->C ping racing it. Whichever goroutine won the Read consumed the ICMP
	// frame — and when the zombie won, the frame was silently dropped and the test
	// reported "no delivery" even though the node had already written it to the
	// TAP device successfully. That was the entire cause of this test's
	// intermittent B->C failure; the data path itself was fine.
	//
	// A single long-lived reader per pipe removes the contention outright. Stale
	// frames buffered in the channel are harmless: every wait below filters by a
	// unique marker (or by ARP opcode), so it just skips whatever it does not want.
	readerA := newFrameReader(pipeA)
	defer readerA.Close()
	readerB := newFrameReader(pipeB)
	defer readerB.Close()
	readerC := newFrameReader(pipeC)
	defer readerC.Close()
	readerFor := map[tap.TAPDevice]*frameReader{
		pipeA: readerA,
		pipeB: readerB,
		pipeC: readerC,
	}

	ping := func(from, to *Node, fromPipe, toPipe tap.TAPDevice, srcIP, dstIP string) bool {
		reader := readerFor[toPipe]
		fromReader := readerFor[fromPipe]
		// Resolve dst MAC via live ARP discovery from `from`.
		bMac := net.HardwareAddr{}
		dl := time.Now().Add(6 * time.Second)
		for time.Now().Before(dl) {
			arp := buildARPRequest(testMACA, net.ParseIP(srcIP), net.ParseIP(dstIP))
			fromPipe.Write(arp)
			d := time.After(1500 * time.Millisecond)
			answered := false
			for !answered {
				select {
				case f := <-fromReader.frames:
					if len(f) >= 42 && binary.BigEndian.Uint16(f[12:14]) == 0x0806 &&
						binary.BigEndian.Uint16(f[20:22]) == 2 {
						bMac = net.HardwareAddr(append([]byte(nil), f[22:28]...))
						answered = true
					}
				case <-d:
					answered = true
				}
			}
			if len(bMac) == 6 {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		if len(bMac) != 6 {
			t.Logf("ARP discovery %s->%s FAILED (no proxy-ARP reply)", srcIP, dstIP)
			return false
		}
		// Diagnostic: surface the sender's cipher/ready state for the target peer
		// so a silent drop at the readiness gate is visible.
		neg, algo, enc := from.obfStateForPeer(to.Host.ID())
		t.Logf("DIAG %s->%s: obfState(negotiated=%v algo=%s encrypted=%v) isReady=%v arpIndexHasDst=%v",
			srcIP, dstIP, neg, algo, enc, from.isPeerReady(to.Host.ID()),
			func() bool { _, pid := from.lookupPeerMACByIPv4(net.ParseIP(dstIP)); return pid != "" }())
		marker := []byte("PING_" + srcIP + "_" + dstIP)
		icmp := constructICMPv4PacketWithData(testMACA, bMac, net.ParseIP(srcIP), net.ParseIP(dstIP), 7000, 1, marker)
		fromPipe.Write(icmp)
		d := time.After(6 * time.Second)
		for {
			select {
			case f := <-reader.frames:
				if bytes.Contains(f, marker) {
					t.Logf("PING %s->%s OK", srcIP, dstIP)
					return true
				}
			case <-d:
				t.Logf("PING %s->%s FAILED (no delivery)", srcIP, dstIP)
				return false
			}
		}
	}

	ok := true
	ok = ping(nodeA, nodeB, pipeA, pipeB, "10.0.0.1", "10.0.0.2") && ok
	ok = ping(nodeA, nodeC, pipeA, pipeC, "10.0.0.1", "10.0.0.3") && ok
	ok = ping(nodeB, nodeC, pipeB, pipeC, "10.0.0.2", "10.0.0.3") && ok
	if !ok {
		t.Errorf("multi-peer mesh: at least one directed ping failed")
	}
}
