package node

import (
	"bytes"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/routing"
	"p2ptap/pkg/tap"
)

// TestRelayCtrlEstablishesEndToEndCipher reproduces the reported "cannot connect
// to other peers" failure and verifies its fix.
//
// Topology (relay in the MIDDLE, NOT an endpoint):
//
//	NodeA ── NodeB (relay) ── NodeC
//
// A and C are NEVER directly connected. They learn each other's existence via
// B's flooded LSA (B advertises its B-C edge), so A computes a route to C with
// NextHop == B. Before the fix, the control plane (SeqSync cipher + Meta
// identity) only ran over DIRECT connections, so A and C could never negotiate
// the A↔C cipher — and every A→C frame was dropped at C's AEAD gate.
//
// The fix tunnels the SeqSync / Meta handshake through B using the RelayCtrl
// protocol: A opens a relay-ctrl stream to B, B proxies the inner handshake
// bytes verbatim to C, and C runs the handler with its logical peer rewritten
// to A. The cipher is therefore anchored on the TRUE origin (A↔C), not on the
// relay (B).
//
// Regression contract:
//   - A and C are NOT directly connected (so the tunnel is mandatory).
//   - After the reconciler / explicit SyncSeqToPeer, BOTH ends hold a negotiated
//     A↔C cipher (peerObf keyed on the true counterpart).
//   - An ICMP Echo A→C is delivered on NodeC's TAP, proving end-to-end encrypted
//     relayed delivery now works.
//   - A learns C's identity via the same tunnel (Meta over relay-ctrl).
func TestRelayCtrlEstablishesEndToEndCipher(t *testing.T) {
	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")
	tapC, pipeC := tap.NewMemTAPPair("tapC", "pipeC")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
	cfgC := createTestNodeConfig("10.0.0.3/24", "fd00::3/64", "best_path")

	aNode, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	defer aNode.Close()
	bNode, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create NodeB: %v", err)
	}
	defer bNode.Close()
	cNode, err := NewNodeWithTAP(cfgC, tapC, nil)
	if err != nil {
		t.Fatalf("create NodeC: %v", err)
	}
	defer cNode.Close()

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
	connect(aNode, bNode)
	connect(bNode, cNode)
	// Deliberately do NOT connect A<->C, so the relay tunnel is mandatory.

	// The encrypted overlay must be ready on BOTH hops so each relay seal
	// (A->B, then B->C) has a usable per-hop cipher.
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

	// Deterministically teach NodeA that C is reachable via NodeB (in production
	// this arrives through B's flooded LSA).
	aNode.Router.UpdateDirectLink(bNode.Host.ID(), 10, routing.LinkDirect)
	bNode.Router.UpdateDirectLink(aNode.Host.ID(), 10, routing.LinkDirect)
	bNode.Router.UpdateDirectLink(cNode.Host.ID(), 12, routing.LinkDirect)

	lsa := bNode.Router.BuildLSA(uint64(time.Now().UnixNano())+1, routing.NodeIdentity{
		NodeName:          bNode.nodeName,
		TapIP:             bNode.Config.TapIP,
		TapIPv6:           bNode.Config.TapIPv6,
		TapMAC:            bNode.Config.TapMAC,
		OS:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		IsExitNode:        bNode.Config.ExitNode.Enable,
		AdvertisedSubnets: bNode.Config.AdvertisedSubnets,
	})
	if !aNode.Router.ProcessLSA(lsa) {
		t.Fatalf("NodeA.ProcessLSA (from B) returned false — could not seed B-C topology")
	}
	aNode.invalidateRouteCache()
	// The LEADER for a relay-only pair must itself know the route to the follower
	// (to pick the relay hop), so seed C with B's LSA as well. In production B
	// floods this LSA to every peer; without it here C would have no next-hop for
	// A and could never open the relayed handshake, masking the fix.
	if !cNode.Router.ProcessLSA(lsa) {
		t.Fatalf("NodeC.ProcessLSA (from B) returned false — could not seed B-A topology")
	}
	cNode.invalidateRouteCache()

	aID := aNode.Host.ID()
	cID := cNode.Host.ID()

	// SANITY: A and C must NOT be directly connected (the tunnel is mandatory).
	if aNode.isDirectlyConnected(cID) {
		t.Fatalf("DIAGNOSTIC: A and C are directly connected — topology is wrong, relay path not exercised")
	}
	routes := aNode.Router.ComputeRoutes()
	rc, ok := routes[cID]
	if !ok || rc.IsDirect || rc.NextHop != bNode.Host.ID() {
		t.Fatalf("DIAGNOSTIC: NodeA has no non-direct route to C via B (nextHop=%v, direct=%v)",
			rc.NextHop, rc.IsDirect)
	}
	t.Logf("✓ NodeA route to C: nextHop=B(relay), IsDirect=false")

	// SANITY: the LEADER (C) must also have a route to A via B, or it can never
	// open the relayed handshake. Verify before driving the sync.
	croutes := cNode.Router.ComputeRoutes()
	crc, cok := croutes[aID]
	if !cok || crc.IsDirect || crc.NextHop != bNode.Host.ID() {
		t.Fatalf("DIAGNOSTIC: NodeC (leader) has no non-direct route to A via B (nextHop=%v, direct=%v)",
			crc.NextHop, crc.IsDirect)
	}
	t.Logf("✓ NodeC (leader) route to A: nextHop=B(relay), IsDirect=false")

	// --- Drive the control-plane sync through the relay tunnel ---
	// Drive it from both ends via triggerPeerRekey (the production path). The
	// single-initiator (resync-leader) rule means exactly one side opens the
	// handshake while the other nudges via rekeyReq over the same relay-ctrl
	// tunnel — so both relay-only peers converge without the per-peer handshake
	// mutex deadlock that a double-SyncSeqToPeer would cause. The relay-control
	// reconciler also fires every 5s, so even a passive node converges.
	go aNode.triggerPeerRekey(cID)
	go cNode.triggerPeerRekey(aID)

	// Wait for the end-to-end A↔C cipher to be negotiated on BOTH ends.
	waitCipherReady(t, aNode, cID)
	waitCipherReady(t, cNode, aID)
	t.Logf("✓ A↔C end-to-end cipher established via relay NodeB")

	// The cipher MUST be keyed on the true counterpart (C on A's side, A on
	// C's side) — not on the relay B. If the tunnel had wrongly keyed it on B,
	// A↔B (already ready) would mask the bug, so assert the C / A slots exist.
	if po := aNode.peerObf(cID); po == nil || !po.negotiated {
		t.Fatalf("A has no negotiated cipher for C (relay tunnel failed to establish A↔C cipher)")
	}
	if po := cNode.peerObf(aID); po == nil || !po.negotiated {
		t.Fatalf("C has no negotiated cipher for A (relay tunnel failed to establish A↔C cipher)")
	}

	// --- Identity (Meta) must also propagate through the same tunnel ---
	go aNode.syncMetadataToPeer(cID)
	waitMetaReady(t, aNode, cID)
	t.Logf("✓ A learned C's identity via relay-ctrl tunnel")

	// --- Echo keepalive must ALSO survive the tunnel (regression guard) ---
	// echoPool is built on newLSAStreamPool, so it opens through
	// openControlStream and therefore gets tunnelled for relay-only peers just
	// like SeqSync/LSA/Meta. If dispatchRelayCtrlInner lacks an EchoProtocolID
	// case, the final hop closes the stream, pingPongProbePeer fails
	// pingPongMaxFailures times and calls reconnectPeer() — putting every
	// relay-only peer into a permanent forced-reconnect loop. Assert a real
	// echo round-trip A -> B(relay) -> C so that gap can never come back.
	echoPayload := []byte{0x50, 0x49, 0x4E, 0x47} // "PING"
	echoOK := false
	echoDeadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(echoDeadline) {
		reply := make([]byte, 16)
		if aNode.echoPool.WithStream(cID, func(s network.Stream) error {
			_ = s.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if err := WriteFrame(s, echoPayload); err != nil {
				return err
			}
			_ = s.SetReadDeadline(time.Now().Add(3 * time.Second))
			rn, rerr := ReadFrame(s, reply)
			if rerr != nil {
				return rerr
			}
			if rn < 4 || !bytes.Equal(reply[:4], echoPayload) {
				t.Logf("echo via tunnel returned %d bytes (unexpected payload)", rn)
			}
			return nil
		}) && bytes.Equal(reply[:4], echoPayload) {
			echoOK = true
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !echoOK {
		t.Fatalf("echo keepalive A->C did NOT survive the relay-ctrl tunnel — " +
			"dispatchRelayCtrlInner is missing the EchoProtocolID case, so relay-only " +
			"peers will keep failing ping-pong and be force-reconnected in a loop")
	}
	t.Logf("✓ Echo keepalive round-trips A -> relay(B) -> C through the relay-ctrl tunnel")

	// --- End-to-end encrypted data delivery A -> C (relayed via B) ---
	readerC := newFrameReader(pipeC)
	defer readerC.Close()
	readerA := newFrameReader(pipeA)
	defer readerA.Close()

	pingFrame := constructICMPv4Packet(testMACA, testMACC,
		net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.3"), 4242, 1)

	t.Log("Sending ICMP Echo A(10.0.0.1) -> C(10.0.0.3) — expected relayed + end-to-end encrypted through B...")
	writeAndExpectWithRetry(t, pipeA, readerC, pingFrame,
		[]byte("P2PTAP_PING_V4_TEST_DATA"), "IPv4 A -> relay(B) -> C (end-to-end encrypted)")

	t.Log("✓ RelayCtrl: A↔C control plane + end-to-end encrypted data delivery both work through relay NodeB")
}

// waitCipherReady polls until node a holds a negotiated per-peer cipher for b.
func waitCipherReady(t *testing.T, a *Node, b peer.ID) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if po := a.peerObf(b); po != nil && po.negotiated {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("cipher for %s not established within 30s (relay-ctrl tunnel failed)", b)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// waitMetaReady polls until node a has ingested identity for b via peerMeta.
func waitMetaReady(t *testing.T, a *Node, b peer.ID) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if v, ok := a.peerMeta.Load(b); ok {
			if m, ok := v.(PeerMeta); ok && m.TapIP != "" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("identity for %s not learned via relay within 30s", b)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
