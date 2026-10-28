package node

import (
	"fmt"
	"net"
	"testing"
	"time"

	"p2ptap/pkg/config"
	"p2ptap/pkg/routing"
	"p2ptap/pkg/tap"
)

// TestE2ECoalescedBatchDualPath exercises the TX coalescing / RX batch-split
// feature end-to-end over BOTH delivery paths:
//
//	direct: A <-> B connected directly            (deliverDirectSubFrame)
//	relay:  A -> B(relay) -> C, A NOT connected to C (deliverRelayedSubFrame)
//
// The coalescer buffers small (<400 B) unicast frames per target peer and merges
// them into a single batch frame to avoid padding; the receiver splits the batch
// back into sub-frames. Every uniquely-marked frame must arrive intact on both
// paths, which locks the batch build + split + reorder-release contract across
// the two distinct RX code paths (direct and relayed).
func TestE2ECoalescedBatchDualPath(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		runCoalesceE2E(t, false)
	})
	t.Run("relay", func(t *testing.T) {
		runCoalesceE2E(t, true)
	})
}

// runCoalesceE2E builds a small-frame burst and asserts every marker arrives on
// the destination TAP. When viaRelay is false it is a plain 2-node A<->B direct
// link; when true it is a 3-node A--B(relay)--C chain with A deliberately not
// connected to C, so every A->C frame is wrapped in an overlay-relay envelope
// and forwarded hop-by-hop through B.
func runCoalesceE2E(t *testing.T, viaRelay bool) {
	t.Helper()

	// Enough small frames to cross the coalescer's flush threshold (400 B) more
	// than once: each frame is ~63 B, so ~7 frames form the first batch and the
	// rest coalesce into a second one. Both batches are multi-frame, which is
	// what forces the receiver's batch split on each path.
	const frames = 12

	var (
		srcPipe tap.TAPDevice
		dstPipe tap.TAPDevice
		srcMAC  = testMACA
		dstMAC  net.HardwareAddr
		dstIP   string
	)
	nodes := []*Node{}
	defer func() {
		for _, n := range nodes {
			n.Close()
		}
	}()

	if !viaRelay {
		tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
		tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")
		cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
		cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
		enableCoalesce(cfgA)
		enableCoalesce(cfgB)

		nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
		if err != nil {
			t.Fatalf("create NodeA: %v", err)
		}
		nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
		if err != nil {
			t.Fatalf("create NodeB: %v", err)
		}
		nodes = append(nodes, nodeA, nodeB)
		nodeA.Start()
		nodeB.Start()

		ti := nodeB.Host.Peerstore().PeerInfo(nodeB.Host.ID())
		ti.Addrs = nodeB.Host.Addrs()
		if cerr := nodeA.Host.Connect(nodeA.ctx, ti); cerr != nil {
			t.Fatalf("connect A->B: %v", cerr)
		}
		waitOverlayReady(t, nodeA, nodeB)
		waitStreamReady(t, nodeA, nodeB)
		waitStreamReady(t, nodeB, nodeA)
		time.Sleep(300 * time.Millisecond)

		_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")

		srcPipe, dstPipe = pipeA, pipeB
		dstMAC, dstIP = testMACB, "10.0.0.2"
	} else {
		tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
		tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")
		tapC, pipeC := tap.NewMemTAPPair("tapC", "pipeC")
		cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
		cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
		cfgC := createTestNodeConfig("10.0.0.3/24", "fd00::3/64", "best_path")
		enableCoalesce(cfgA)
		enableCoalesce(cfgB)
		enableCoalesce(cfgC)

		aNode, err := NewNodeWithTAP(cfgA, tapA, nil)
		if err != nil {
			t.Fatalf("create NodeA: %v", err)
		}
		bNode, err := NewNodeWithTAP(cfgB, tapB, nil)
		if err != nil {
			t.Fatalf("create NodeB: %v", err)
		}
		cNode, err := NewNodeWithTAP(cfgC, tapC, nil)
		if err != nil {
			t.Fatalf("create NodeC: %v", err)
		}
		nodes = append(nodes, aNode, bNode, cNode)
		aNode.Start()
		bNode.Start()
		cNode.Start()

		connect := func(a, b *Node) {
			ti := b.Host.Peerstore().PeerInfo(b.Host.ID())
			ti.Addrs = b.Host.Addrs()
			if cerr := a.Host.Connect(a.ctx, ti); cerr != nil {
				t.Fatalf("connect %s->%s: %v", a.Host.ID().ShortString(), b.Host.ID().ShortString(), cerr)
			}
		}
		// Only the two real edges. A<->C is intentionally left unconnected so
		// every A->C frame is forced through the relay B.
		connect(aNode, bNode)
		connect(bNode, cNode)
		waitOverlayReady(t, aNode, bNode)
		waitOverlayReady(t, bNode, cNode)
		waitStreamReady(t, aNode, bNode)
		waitStreamReady(t, bNode, aNode)
		waitStreamReady(t, bNode, cNode)
		waitStreamReady(t, cNode, bNode)
		time.Sleep(300 * time.Millisecond)

		_ = pipeA.ConfigureIP("10.0.0.1/24", "fd00::1/64")
		_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")
		_ = pipeC.ConfigureIP("10.0.0.3/24", "fd00::3/64")

		// Seed peer metadata on every node so TAP IPs resolve to peer IDs in both
		// the egress (A resolves 10.0.0.3 -> C) and the relay-forward (B/C) paths.
		peers := map[*Node]PeerMeta{
			aNode: {NodeName: "A", TapIP: "10.0.0.1/24", TapIPv6: "fd00::1/64", TapMAC: aNode.localMAC.String()},
			bNode: {NodeName: "B-relay", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: bNode.localMAC.String()},
			cNode: {NodeName: "C", TapIP: "10.0.0.3/24", TapIPv6: "fd00::3/64", TapMAC: cNode.localMAC.String()},
		}
		for src := range peers {
			for dst, dm := range peers {
				if src == dst {
					continue
				}
				src.storePeerMeta(dst.Host.ID(), dm)
			}
		}

		// Teach NodeA that C is reachable via NodeB (deterministic, isolates the
		// relay-forward data path from LSA propagation timing).
		aNode.Router.UpdateDirectLink(bNode.Host.ID(), 10, routing.LinkDirect)
		bNode.Router.UpdateDirectLink(aNode.Host.ID(), 10, routing.LinkDirect)
		bNode.Router.UpdateDirectLink(cNode.Host.ID(), 12, routing.LinkDirect)
		lsa := buildSeedLSA(bNode, aNode)
		if !aNode.Router.ProcessLSA(lsa) {
			t.Fatalf("NodeA.ProcessLSA (from B) returned false — could not seed B-C topology")
		}
		aNode.invalidateRouteCache()

		// DIAGNOSTIC: A must have a non-direct route to C via B, else the relay
		// path is not actually exercised.
		routes := aNode.Router.ComputeRoutes()
		rc, ok := routes[cNode.Host.ID()]
		if !ok || rc.IsDirect || rc.NextHop != bNode.Host.ID() {
			t.Fatalf("NodeA route to C is not the expected non-direct relay (ok=%v IsDirect=%v nextHop=%s)",
				ok, rc.IsDirect, rc.NextHop)
		}

		srcPipe, dstPipe = pipeA, pipeC
		dstMAC, dstIP = testMACC, "10.0.0.3"
	}

	// One long-lived reader on the destination, started before the burst.
	reader := newFrameReader(dstPipe)
	t.Cleanup(reader.Close)

	// Build the uniquely-marked small frames and start the collector first.
	var wireFrames [][]byte
	var payloads [][]byte
	label := map[bool]string{true: "RELAY", false: "DIRECT"}[viaRelay]
	for i := 0; i < frames; i++ {
		tag := fmt.Sprintf("COALESCE_%s_%d", label, i)
		payloads = append(payloads, []byte(tag))
		wireFrames = append(wireFrames, constructICMPv4PacketWithData(
			srcMAC, dstMAC, net.ParseIP("10.0.0.1"), net.ParseIP(dstIP), 6000+i, 1, []byte(tag)))
	}
	coll := newConcurrentPayloadCollector(reader, payloads)

	// Burst the frames back-to-back so the coalescer merges them into batches
	// instead of padding each one individually.
	for i := 0; i < frames; i++ {
		if _, werr := srcPipe.Write(wireFrames[i]); werr != nil {
			t.Fatalf("write %d failed: %v", i, werr)
		}
	}

	dir := map[bool]string{true: "A->C(relay)", false: "A->B(direct)"}[viaRelay]
	coll.wait(t, srcPipe, wireFrames, payloads, 16*time.Second, dir)
	t.Logf("coalesced batch E2E success (%s path)", label)
}

// enableCoalesce turns on obfuscation with the default rule set (0 -> 400-600,
// coalesce on) so small frames are coalesced and the batch path is exercised.
func enableCoalesce(cfg *config.Config) {
	cfg.Obfuscation.Enable = true
	cfg.Obfuscation.PaddingRules = "0 -> 400-600"
}
