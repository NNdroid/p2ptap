package node

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"p2ptap/pkg/tap"
)

// TestE2ELargeFrameFragmentation proves that a TAP frame whose size EXCEEDS the
// per-fragment payload (maxFragPayload ≈ 1118 bytes, derived from the tunnel MTU
// minus obfuscation + fragment overhead) is correctly split, transmitted,
// reassembled and delivered intact at the peer. This is the end-to-end guard for
// the "large packets fail but small packets work" class of frame-delivery bug
// (Risk #4): it exercises
//
//	fragmentFrame -> per-fragment re-obfuscation -> P2P send
//	             -> reassemble -> decrypt -> tapWrite
//
// in one shot, using real Nodes + a real libp2p overlay (no mocks).
func TestE2ELargeFrameFragmentation(t *testing.T) {
	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	macB := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	tapA, tapA_pipe := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, tapB_pipe := tap.NewMemTAPPair("tapB", "pipeB")
	_ = tapA.SetMAC("02:00:00:00:00:01")
	_ = tapB.SetMAC("02:00:00:00:00:02")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
	cfgA.TapMAC = "02:00:00:00:00:01"
	cfgB.TapMAC = "02:00:00:00:00:02"

	nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create NodeB: %v", err)
	}
	defer nodeA.Close()
	defer nodeB.Close()
	nodeA.Start()
	nodeB.Start()

	// Connect + wait for the encrypted overlay AND both stream directions to be
	// ready, so the first large frame is not dropped on cold start.
	targetInfo := nodeB.Host.Peerstore().PeerInfo(nodeB.Host.ID())
	targetInfo.Addrs = nodeB.Host.Addrs()
	if err := nodeA.Host.Connect(nodeA.ctx, targetInfo); err != nil {
		t.Fatalf("connect A->B: %v", err)
	}
	ready := false
	for attempt := 0; attempt < 150; attempt++ {
		okA, _, encA := nodeA.obfStateForPeer(nodeB.Host.ID())
		okB, _, encB := nodeB.obfStateForPeer(nodeA.Host.ID())
		if okA && encA && okB && encB {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("overlay A<->B did not become ready in time")
	}
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)
	time.Sleep(200 * time.Millisecond)

	// Route A->B unicast: seed B's identity in A and learn B's MAC so the frame
	// is dispatched directly instead of broadcast-flooded.
	nodeA.storePeerMeta(nodeB.Host.ID(), PeerMeta{
		NodeName: "NodeB",
		TapIP:    "10.0.0.2/24",
		TapIPv6:  "fd00::2/64",
		TapMAC:   macB.String(),
	})
	nodeA.rebuildARPIndex()
	nodeA.MACTable.Learn(macB, nodeB.Host.ID())

	readerB := newFrameReader(tapB_pipe)

	// Small + large sizes. The large ones exceed maxFragPayload (~1118) and thus
	// MUST traverse the fragment/reassemble path; a bug there drops or corrupts
	// them while the small one still passes (the classic "大包不通小包通").
	cases := []struct {
		name       string
		payloadLen int
	}{
		{"small_64B", 64},
		{"large_1300B", 1300},
		{"large_1400B", 1400},
	}
	for _, c := range cases {
		marker := fmt.Sprintf("FRAGMTU_%s", c.name)
		frame := buildEthFrame(macB, macA, []byte{0x08, 0x00},
			net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"),
			[]byte(marker), c.payloadLen)

		got := false
		for attempt := 0; attempt < 3 && !got; attempt++ {
			if _, err := tapA_pipe.Write(frame); err != nil {
				t.Fatalf("write %s: %v", c.name, err)
			}
			deadline := time.After(8 * time.Second)
		loop:
			for {
				select {
				case f := <-readerB.frames:
					if bytes.Contains(f, []byte(marker)) {
						if len(f) != len(frame) {
							t.Fatalf("%s: reassembled frame length %d != sent %d (fragment reassembly truncated/duplicated?)",
								c.name, len(f), len(frame))
						}
						got = true
						break loop
					}
				case <-deadline:
					break loop
				}
			}
		}
		if !got {
			t.Errorf("FAIL: %s (len=%d) NOT delivered intact — fragmentation path broken for this size", c.name, c.payloadLen)
		} else {
			t.Logf("✓ %s delivered intact (sent len=%d)", c.name, len(frame))
		}
	}
	readerB.Close()
}
