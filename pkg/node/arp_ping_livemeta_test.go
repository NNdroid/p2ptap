package node

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"p2ptap/pkg/tap"
)

// TestARPPingLiveMeta exercises the REAL discovery path: NO manual metadata
// seeding. A and B must learn each other's TAP MAC/IP purely through the
// production meta-exchange control channel. If that exchange fails to populate
// arpIndex, A's proxy-ARP never answers and A cannot ping B — exactly the
// reported symptom. This isolates "meta exchange broken" from "data plane broken"
// (the latter is already proven working by TestARPPingRepro).
func TestARPPingLiveMeta(t *testing.T) {
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

	// Give the meta-exchange control channel time to propagate B's TapMAC/IP to A
	// and rebuild A's ARP index.
	deadline := time.Now().Add(10 * time.Second)
	bMacKnown := false
	var bMac net.HardwareAddr
	for time.Now().Before(deadline) {
		// Probe A's ARP index for B's IP by sending an ARP request and watching
		// for a proxy-ARP reply (which only happens if arpIndex knows B).
		readerA := newFrameReader(tapA_pipe)
		arpReq := buildARPRequest(testMACA, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"))
		if _, err := tapA_pipe.Write(arpReq); err != nil {
			t.Fatalf("write ARP request: %v", err)
		}
		d := time.After(2 * time.Second)
		answered := false
		for !answered {
			select {
			case f := <-readerA.frames:
				if len(f) >= 42 && binary.BigEndian.Uint16(f[12:14]) == 0x0806 &&
					binary.BigEndian.Uint16(f[20:22]) == 2 {
					// Accept only a reply from the IP we asked about (ARP
					// sender protocol address at f[28:32]); a stray reply for
					// another host would otherwise bind the wrong MAC.
					if !net.IP(f[28:32]).Equal(net.ParseIP("10.0.0.2").To4()) {
						continue
					}
					bMac = net.HardwareAddr(append([]byte(nil), f[22:28]...))
					bMacKnown = true
					answered = true
				}
			case <-d:
				answered = true
			}
		}
		readerA.Close()
		if bMacKnown {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !bMacKnown {
		t.Fatalf("A never learned B's MAC via live meta exchange — arpIndex not populated, A cannot ping B")
	}
	t.Logf("A learned B's MAC via live meta exchange: %s", bMac.String())

	readerB := newFrameReader(tapB_pipe)
	defer readerB.Close()
	icmp := constructICMPv4PacketWithData(testMACA, bMac, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 6000, 1, []byte("LIVE_META_PING"))
	if _, err := tapA_pipe.Write(icmp); err != nil {
		t.Fatalf("write ICMP: %v", err)
	}
	d := time.After(8 * time.Second)
	for {
		select {
		case f := <-readerB.frames:
			if bytes.Contains(f, []byte("LIVE_META_PING")) {
				t.Log("A pinged B via live meta exchange + ARP discovery")
				return
			}
		case <-d:
			t.Fatalf("B never received ICMP after live meta exchange — A cannot ping B")
		}
	}
}
