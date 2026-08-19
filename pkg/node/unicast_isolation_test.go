package node

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/tap"
)

// TestUnicast_Isolation_OnlyTargetPeerReceives tests a 4-node cluster (10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4)
// and asserts that for every directed unicast stream (e.g. Node 1 -> Node 2):
// 1. The target peer (Node 2) reliably receives the packet.
// 2. ALL other non-target peers (Node 3, Node 4) and the sender itself receive ZERO copies (0% packet leakage).
func TestUnicast_Isolation_OnlyTargetPeerReceives(t *testing.T) {
	const numNodes = 4
	type clusterNode struct {
		node *Node
		pipe *tap.MemTAP
		ip   string
		v6   string
		mac  net.HardwareAddr
		id   peer.ID
	}

	nodes := make([]*clusterNode, numNodes)
	for i := 0; i < numNodes; i++ {
		ip := fmt.Sprintf("10.0.0.%d/24", i+1)
		v6 := fmt.Sprintf("fd00::%d/64", i+1)
		macStr := fmt.Sprintf("02:00:00:00:00:0%d", i+1)
		tapDev, pipe := tap.NewMemTAPPair(fmt.Sprintf("tap%d", i+1), fmt.Sprintf("pipe%d", i+1))
		_ = tapDev.SetMAC(macStr)
		cfg := createTestNodeConfig(ip, v6, "best_path")
		cfg.TapMAC = macStr

		n, err := NewNodeWithTAP(cfg, tapDev, nil)
		if err != nil {
			t.Fatalf("create node %d: %v", i+1, err)
		}
		defer n.Close()
		n.Start()

		nodes[i] = &clusterNode{
			node: n,
			pipe: pipe,
			ip:   fmt.Sprintf("10.0.0.%d", i+1),
			v6:   fmt.Sprintf("fd00::%d", i+1),
			mac:  n.localMAC,
			id:   n.Host.ID(),
		}
	}

	// 1. Establish full mesh P2P connections
	for i := 0; i < numNodes; i++ {
		for j := i + 1; j < numNodes; j++ {
			connectNodes(t, nodes[i].node, nodes[j].node)
			waitOverlayReady(t, nodes[i].node, nodes[j].node)
			waitStreamReady(t, nodes[i].node, nodes[j].node)
			waitStreamReady(t, nodes[j].node, nodes[i].node)
		}
	}

	// 2. Propagate peer metadata across all nodes
	for i := 0; i < numNodes; i++ {
		for j := 0; j < numNodes; j++ {
			if i == j {
				continue
			}
			nodes[i].node.storePeerMeta(nodes[j].id, PeerMeta{
				NodeName: fmt.Sprintf("Node-%d", j+1),
				TapIP:    fmt.Sprintf("%s/24", nodes[j].ip),
				TapIPv6:  fmt.Sprintf("%s/64", nodes[j].v6),
				TapMAC:   nodes[j].mac.String(),
			})
		}
		nodes[i].node.rebuildARPIndex()
	}

	// 3. Pre-seed MAC table with peer MACs so nodes dispatch unicast frames directly
	for i := 0; i < numNodes; i++ {
		for j := 0; j < numNodes; j++ {
			if i == j {
				continue
			}
			nodes[i].node.MACTable.Learn(nodes[j].mac, nodes[j].id)
		}
	}

	// 4. Background collectors for all pipes
	receivedTags := make([]map[string]int, numNodes)
	var mu sync.Mutex
	for i := 0; i < numNodes; i++ {
		receivedTags[i] = make(map[string]int)
	}

	stopReaders := make(chan struct{})
	var readerWg sync.WaitGroup
	for i := 0; i < numNodes; i++ {
		idx := i
		readerWg.Add(1)
		go func() {
			defer readerWg.Done()
			buf := make([]byte, 2048)
			for {
				select {
				case <-stopReaders:
					return
				default:
					n, err := nodes[idx].pipe.Read(buf)
					if err == nil && n > 0 {
						mu.Lock()
						for src := 0; src < numNodes; src++ {
							for dst := 0; dst < numNodes; dst++ {
								tag := fmt.Sprintf("UNICAST_ISOLATION_%d_TO_%d", src+1, dst+1)
								if bytes.Contains(buf[:n], []byte(tag)) {
									receivedTags[idx][tag]++
								}
							}
						}
						mu.Unlock()
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
		}()
	}

	// 5. Send directed unicast frames:
	// Node 1 -> Node 2
	// Node 2 -> Node 3
	// Node 3 -> Node 4
	// Node 4 -> Node 1
	type testPair struct {
		src int
		dst int
	}
	pairs := []testPair{
		{src: 0, dst: 1},
		{src: 1, dst: 2},
		{src: 2, dst: 3},
		{src: 3, dst: 0},
	}

	for _, p := range pairs {
		tag := fmt.Sprintf("UNICAST_ISOLATION_%d_TO_%d", p.src+1, p.dst+1)
		pkt := constructICMPv4PacketWithData(
			nodes[p.src].mac,
			nodes[p.dst].mac,
			net.ParseIP(nodes[p.src].ip),
			net.ParseIP(nodes[p.dst].ip),
			8800+p.src*10+p.dst,
			1,
			[]byte(tag),
		)
		if _, err := nodes[p.src].pipe.Write(pkt); err != nil {
			t.Fatalf("node %d pipe write failed: %v", p.src+1, err)
		}
	}

	// Wait 2 seconds for all unicast packets to be delivered
	time.Sleep(2 * time.Second)
	close(stopReaders)
	readerWg.Wait()

	mu.Lock()
	defer mu.Unlock()

	// 6. Assert strict unicast isolation for each test pair
	for _, p := range pairs {
		tag := fmt.Sprintf("UNICAST_ISOLATION_%d_TO_%d", p.src+1, p.dst+1)

		// Target node MUST receive the frame
		if count := receivedTags[p.dst][tag]; count == 0 {
			t.Errorf("FAIL: Target Node %d did NOT receive unicast frame %s", p.dst+1, tag)
		} else {
			t.Logf("✓ Target Node %d received %d frame(s) of %s", p.dst+1, count, tag)
		}

		// Non-target nodes and sender MUST receive 0 frames (zero leakage)
		for nodeIdx := 0; nodeIdx < numNodes; nodeIdx++ {
			if nodeIdx == p.dst {
				continue
			}
			if count := receivedTags[nodeIdx][tag]; count > 0 {
				t.Errorf("FAIL: Non-target Node %d received %d frame(s) of %s! Unicast isolation breached!",
					nodeIdx+1, count, tag)
			}
		}
	}

	t.Logf("✓ TestUnicast_Isolation_OnlyTargetPeerReceives: Complete 4-node unicast isolation verified! 0 cross-peer frame leakage.")
}
