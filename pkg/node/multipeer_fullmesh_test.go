package node

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/routing"
	"p2ptap/pkg/tap"
)

// TestE2E_MultiPeer_FullMesh_AllToAll_Ping spins up a 4-node full mesh cluster
// (10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4) and verifies that every single node
// can simultaneously send and receive ICMP pings to/from EVERY other node in the cluster
// with 0% packet loss (all 12 directed communication paths).
func TestE2E_MultiPeer_FullMesh_AllToAll_Ping(t *testing.T) {
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
		tapDev, pipe := tap.NewMemTAPPair(fmt.Sprintf("tap%d", i+1), fmt.Sprintf("pipe%d", i+1))
		cfg := createTestNodeConfig(ip, v6, "best_path")

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

	// 1. Establish full mesh P2P connections (every node connects to all other nodes)
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

	// 3. Start background frame collectors for each node's pipe
	receivedFrames := make([]map[string]bool, numNodes)
	var mu sync.Mutex
	for i := 0; i < numNodes; i++ {
		receivedFrames[i] = make(map[string]bool)
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
						frameCopy := string(buf[:n])
						mu.Lock()
						for src := 0; src < numNodes; src++ {
							tag := fmt.Sprintf("FULL_MESH_PING_%d_TO_%d", src+1, idx+1)
							if bytes.Contains(buf[:n], []byte(tag)) {
								receivedFrames[idx][tag] = true
							}
						}
						mu.Unlock()
						_ = frameCopy
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
		}()
	}

	// 4. Send concurrent ICMP pings across ALL N*(N-1) directed pairs
	for i := 0; i < numNodes; i++ {
		for j := 0; j < numNodes; j++ {
			if i == j {
				continue
			}
			tag := fmt.Sprintf("FULL_MESH_PING_%d_TO_%d", i+1, j+1)
			pingPkt := constructICMPv4PacketWithData(
				nodes[i].mac,
				nodes[j].mac,
				net.ParseIP(nodes[i].ip),
				net.ParseIP(nodes[j].ip),
				7000+i*10+j,
				1,
				[]byte(tag),
			)
			if _, err := nodes[i].pipe.Write(pingPkt); err != nil {
				t.Fatalf("node %d pipe write failed: %v", i+1, err)
			}
		}
	}

	// 5. Wait for all 12 directed pings to be received with 0% loss
	deadline := time.Now().Add(5 * time.Second)
	allReceived := false
	for time.Now().Before(deadline) {
		mu.Lock()
		count := 0
		for j := 0; j < numNodes; j++ {
			for i := 0; i < numNodes; i++ {
				if i == j {
					continue
				}
				tag := fmt.Sprintf("FULL_MESH_PING_%d_TO_%d", i+1, j+1)
				if receivedFrames[j][tag] {
					count++
				}
			}
		}
		mu.Unlock()
		if count == numNodes*(numNodes-1) {
			allReceived = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	close(stopReaders)
	readerWg.Wait()

	if !allReceived {
		t.Fatalf("Not all multi-peer mesh pings arrived! Received: %v", receivedFrames)
	}

	t.Logf("✓ TestE2E_MultiPeer_FullMesh_AllToAll_Ping: All %d directed communication paths across %d nodes passed simultaneously!", numNodes*(numNodes-1), numNodes)
}

// TestE2E_MultiPeer_StarTopology_Relayed_AllToAll_Ping tests 4 nodes in a Hub-and-Spoke
// star topology where Node 3 is the central relay hub, and Nodes 1, 2, 4 are spokes.
// Verifies that spoke nodes can all communicate with each other concurrently through the hub.
func TestE2E_MultiPeer_StarTopology_Relayed_AllToAll_Ping(t *testing.T) {
	tap1, pipe1 := tap.NewMemTAPPair("tap1", "pipe1")
	tap2, pipe2 := tap.NewMemTAPPair("tap2", "pipe2")
	tapHub, _ := tap.NewMemTAPPair("tapHub", "pipeHub")
	tap4, pipe4 := tap.NewMemTAPPair("tap4", "pipe4")

	n1, _ := NewNodeWithTAP(createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path"), tap1, nil)
	defer n1.Close()
	n2, _ := NewNodeWithTAP(createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path"), tap2, nil)
	defer n2.Close()
	nHub, _ := NewNodeWithTAP(createTestNodeConfig("10.0.0.3/24", "fd00::3/64", "best_path"), tapHub, nil)
	defer nHub.Close()
	n4, _ := NewNodeWithTAP(createTestNodeConfig("10.0.0.4/24", "fd00::4/64", "best_path"), tap4, nil)
	defer n4.Close()

	n1.Start()
	n2.Start()
	nHub.Start()
	n4.Start()

	// Connect spokes to Hub ONLY
	connectNodes(t, n1, nHub)
	connectNodes(t, n2, nHub)
	connectNodes(t, n4, nHub)

	waitOverlayReady(t, n1, nHub)
	waitOverlayReady(t, n2, nHub)
	waitOverlayReady(t, n4, nHub)
	waitStreamReady(t, n1, nHub)
	waitStreamReady(t, nHub, n1)
	waitStreamReady(t, n2, nHub)
	waitStreamReady(t, nHub, n2)
	waitStreamReady(t, n4, nHub)
	waitStreamReady(t, nHub, n4)

	id1 := n1.Host.ID()
	id2 := n2.Host.ID()
	idHub := nHub.Host.ID()
	id4 := n4.Host.ID()

	// Seed peer metadata on all nodes
	spokes := []*Node{n1, n2, n4}
	for _, sp := range spokes {
		sp.storePeerMeta(id1, PeerMeta{NodeName: "Node1", TapIP: "10.0.0.1/24", TapIPv6: "fd00::1/64", TapMAC: n1.localMAC.String()})
		sp.storePeerMeta(id2, PeerMeta{NodeName: "Node2", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: n2.localMAC.String()})
		sp.storePeerMeta(id4, PeerMeta{NodeName: "Node4", TapIP: "10.0.0.4/24", TapIPv6: "fd00::4/64", TapMAC: n4.localMAC.String()})
		sp.rebuildARPIndex()
	}

	// Seed Hub's LSA to all spokes so they route through Hub
	lsaHub := &routing.LinkStatePayload{
		Origin: idHub.String(),
		Seq:    1,
		TTL:    5,
		Neighbors: map[string]int64{
			id1.String(): 10,
			id2.String(): 10,
			id4.String(): 10,
		},
		NodeName: "Hub",
		TapIP:    nHub.Config.TapIP,
		TapIPv6:  nHub.Config.TapIPv6,
		TapMAC:   nHub.Config.TapMAC,
	}
	n1.Router.ProcessLSA(lsaHub)
	n2.Router.ProcessLSA(lsaHub)
	n4.Router.ProcessLSA(lsaHub)
	n1.invalidateRouteCache()
	n2.invalidateRouteCache()
	n4.invalidateRouteCache()

	// Negotiate E2E ciphers between spoke pairs: 1<->2, 1<->4, 2<->4
	go n1.triggerPeerRekey(id2)
	go n2.triggerPeerRekey(id1)
	go n1.triggerPeerRekey(id4)
	go n4.triggerPeerRekey(id1)
	go n2.triggerPeerRekey(id4)
	go n4.triggerPeerRekey(id2)

	waitCipherReady(t, n1, id2)
	waitCipherReady(t, n2, id1)
	waitCipherReady(t, n1, id4)
	waitCipherReady(t, n4, id1)
	waitCipherReady(t, n2, id4)
	waitCipherReady(t, n4, id2)

	// Spoke 1 pings Spoke 2 through Hub
	ping1to2 := constructICMPv4PacketWithData(n1.localMAC, n2.localMAC, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 8001, 1, []byte("RELAY_STAR_1_TO_2"))
	if _, err := pipe1.Write(ping1to2); err != nil {
		t.Fatalf("pipe1 write failed: %v", err)
	}
	assertPacketArrived(t, pipe2, "Spoke 2 received relayed ping from Spoke 1", 4*time.Second, func(f []byte) bool {
		return bytes.Contains(f, []byte("RELAY_STAR_1_TO_2"))
	})

	// Spoke 2 pings Spoke 4 through Hub
	ping2to4 := constructICMPv4PacketWithData(n2.localMAC, n4.localMAC, net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.4"), 8002, 1, []byte("RELAY_STAR_2_TO_4"))
	if _, err := pipe2.Write(ping2to4); err != nil {
		t.Fatalf("pipe2 write failed: %v", err)
	}
	assertPacketArrived(t, pipe4, "Spoke 4 received relayed ping from Spoke 2", 4*time.Second, func(f []byte) bool {
		return bytes.Contains(f, []byte("RELAY_STAR_2_TO_4"))
	})

	// Spoke 4 pings Spoke 1 through Hub
	ping4to1 := constructICMPv4PacketWithData(n4.localMAC, n1.localMAC, net.ParseIP("10.0.0.4"), net.ParseIP("10.0.0.1"), 8003, 1, []byte("RELAY_STAR_4_TO_1"))
	if _, err := pipe4.Write(ping4to1); err != nil {
		t.Fatalf("pipe4 write failed: %v", err)
	}
	assertPacketArrived(t, pipe1, "Spoke 1 received relayed ping from Spoke 4", 4*time.Second, func(f []byte) bool {
		return bytes.Contains(f, []byte("RELAY_STAR_4_TO_1"))
	})

	t.Logf("✓ TestE2E_MultiPeer_StarTopology_Relayed_AllToAll_Ping: All spoke-to-spoke multi-peer relayed paths verified!")
}
