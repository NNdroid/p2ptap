package node

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/routing"
	"p2ptap/pkg/tap"
)

// TestBootRelayCtrlEstablishesEndToEndCipher reproduces the exact reported
// failure: TWO NAT'd nodes behind the same boot (but with NO direct path and NO
// overlay-relay peer between them) cannot exchange a single frame — the ARP
// broadcast goes out but never comes back, and mDNS dials to private addresses
// all fail.
//
// Topology (relay-over-backbone bridge, NOT an endpoint, NOT circuitv2):
//
//	NodeA ── boot (relay-over-backbone) ── NodeB
//
// A and B are NEVER directly connected. They each open a persistent
// /p2ptap/boot-relay/1.0.0 uplink to the boot after PSK auth (open mode here, so
// auth trivially succeeds). Because the custom boot is a relay-over-backbone
// bridge and does NOT serve the libp2p relay-ctrl protocol, the SeqSync / Meta /
// Echo control handshakes MUST be multiplexed onto the boot-relay uplink as
// kind=Control frames (the bootRelayCtrlStream simulator), with the logical peer
// rewritten to the TRUE origin so the A↔B cipher is anchored on A↔B — not on the
// boot. This is the path that #351/#352 fix and that this test locks.
//
// Regression contract:
//   - A and B are NOT directly connected (the boot-relay tunnel is mandatory).
//   - Both ends hold a negotiated A↔B cipher (peerObf keyed on the true counterpart).
//   - The identity (Meta) propagates through the same kind=Control tunnel.
//   - An Echo keepalive round-trips A -> boot -> B, proving dispatchRelayCtrlInner
//     has the EchoProtocolID case (otherwise relay-only peers get force-reconnected
//     in a loop).
//   - An ICMP Echo A→B is delivered on NodeB's TAP, proving end-to-end encrypted
//     relayed delivery over the boot-relay data plane (kind=Data).
func TestBootRelayCtrlEstablishesEndToEndCipher(t *testing.T) {
	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")

	// A real libp2p host standing in for the custom boot: it ONLY bridges
	// boot-relay frames between its locally-attached clients (local-delivery),
	// exactly like a single-boot deployment. No PSK/auth handler is needed
	// because the node runs in open mode (Config.PSK == ""), and
	// authenticateWithRelay returns true without opening any stream.
	bootHost, closeBoot := newTestBootRelayBridge(t)
	defer closeBoot()
	bootMa := bootHost.Addrs()[0].String() + "/p2p/" + bootHost.ID().String()
	cfgA.BootstrapPeers = []string{bootMa}
	cfgB.BootstrapPeers = []string{bootMa}

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

	aNode.Start()
	bNode.Start()

	aID := aNode.Host.ID()
	bID := bNode.Host.ID()
	bootID := bootHost.ID()

	// The boot-relay uplinks must be alive on BOTH nodes (auth succeeded + the
	// /p2ptap/boot-relay/1.0.0 stream to the boot was registered). This is the
	// gate that canEgressToPeer and relayHopForTarget depend on for the
	// relay-over-backbone path.
	waitBootRelayUplink(t, aNode, bootID)
	waitBootRelayUplink(t, bNode, bootID)
	t.Logf("✓ Both nodes established a boot-relay uplink to the boot")

	// Teach each node about the other via peerMeta (the only way a boot-relay
	// peer is learned — the boot does not speak LSA/peek-map in this minimal
	// harness). The TapIP entry is what lets A route dst IP 10.0.0.2 -> B.
	aNode.storePeerMeta(bID, PeerMeta{NodeName: "B", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: bNode.localMAC.String()})
	bNode.storePeerMeta(aID, PeerMeta{NodeName: "A", TapIP: "10.0.0.1/24", TapIPv6: "fd00::1/64", TapMAC: aNode.localMAC.String()})

	// SANITY: A and B must NOT be directly connected (the boot-relay tunnel is
	// mandatory), and relayHopForTarget(A, B) must resolve to the boot (a
	// bootstrap peer with a live uplink), NOT "" and NOT a circuitv2 fallback.
	if aNode.isDirectlyConnected(bID) {
		t.Fatalf("DIAGNOSTIC: A and B are directly connected — topology is wrong, boot-relay path not exercised")
	}
	if h := aNode.relayHopForTarget(bID); h != bootID {
		t.Fatalf("DIAGNOSTIC: relayHopForTarget(A, B) = %v, want boot %v (one NAT'd peer behind same boot, no direct path)", h, bootID)
	}
	if !aNode.hasBootRelayUplink(bootID) {
		t.Fatalf("DIAGNOSTIC: A reports no boot-relay uplink to the boot")
	}
	t.Logf("✓ Topology correct: A⟷B only via boot-relay uplink (no direct path, no overlay relay)")

	// --- Drive the control-plane handshake through the boot-relay control
	// tunnel (kind=Control frames). Fire from both ends via triggerPeerRekey
	// (the production path; the resync-leader rule means exactly one side opens
	// the handshake, the other nudges it — no per-peer handshake-mutex deadlock).
	// The reconciler (every 5s) also drives this for boot-relay peers, but we
	// call it explicitly for deterministic convergence.
	go aNode.triggerPeerRekey(bID)
	go bNode.triggerPeerRekey(aID)

	waitCipherReady(t, aNode, bID)
	waitCipherReady(t, bNode, aID)
	t.Logf("✓ A↔B end-to-end cipher established via boot-relay control tunnel")

	// The cipher MUST be keyed on the true counterpart (B on A's side, A on
	// B's side) — not on the boot. If the tunnel had wrongly keyed it on the
	// boot, A↔boot (already ready, separate path) would mask the bug.
	if po := aNode.peerObf(bID); po == nil || !po.negotiated {
		t.Fatalf("A has no negotiated cipher for B (boot-relay control tunnel failed)")
	}
	if po := bNode.peerObf(aID); po == nil || !po.negotiated {
		t.Fatalf("B has no negotiated cipher for A (boot-relay control tunnel failed)")
	}

	// --- Identity (Meta) must ALSO propagate through the same kind=Control
	// tunnel (regression: a relay-only peer must learn its counterpart's MAC/IP).
	go aNode.syncMetadataToPeer(bID)
	waitMetaReady(t, aNode, bID)
	t.Logf("✓ A learned B's identity via boot-relay control tunnel")

	// --- Echo keepalive MUST survive the tunnel (regression guard for the
	// EchoProtocolID case in dispatchBootRelayControlStream). Without it, the
	// final hop closes the stream, ping-pong fails and every relay-only peer is
	// force-reconnected in a permanent loop.
	echoPayload := []byte{0x50, 0x49, 0x4E, 0x47} // "PING"
	echoOK := false
	echoDeadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(echoDeadline) {
		reply := make([]byte, 16)
		if aNode.echoPool.WithStream(bID, func(s network.Stream) error {
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
				t.Logf("echo via boot-relay tunnel returned %d bytes (unexpected payload)", rn)
			}
			return nil
		}) && bytes.Equal(reply[:4], echoPayload) {
			echoOK = true
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !echoOK {
		t.Fatalf("echo keepalive A->B did NOT survive the boot-relay control tunnel — " +
			"dispatchBootRelayControlStream is missing the EchoProtocolID case, so relay-only " +
			"peers will keep failing ping-pong and be force-reconnected in a loop")
	}
	t.Logf("✓ Echo keepalive round-trips A -> boot -> B through the boot-relay control tunnel")

	// --- End-to-end encrypted data delivery A -> B (relayed via boot, kind=Data).
	readerB := newFrameReader(pipeB)
	defer readerB.Close()

	pingFrame := constructICMPv4Packet(testMACA, testMACB,
		net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 4242, 1)

	t.Log("Sending ICMP Echo A(10.0.0.1) -> B(10.0.0.2) — expected relayed + end-to-end encrypted through the boot...")
	writeAndExpectWithRetry(t, pipeA, readerB, pingFrame,
		[]byte("P2PTAP_PING_V4_TEST_DATA"), "IPv4 A -> boot-relay -> B (end-to-end encrypted)")

	t.Log("✓ BootRelay: A↔B control plane + end-to-end encrypted data delivery both work through the boot relay-over-backbone bridge")
}

// newTestBootRelayBridge spins up a real libp2p host that implements JUST the
// relay-over-backbone local-delivery bridge: it keeps one uplink stream per
// connected client and forwards every boot-relay frame it receives to the
// stream owned by the frame's finalDst. This mirrors cmd/p2ptap-boot's
// relayRouter.route (local-delivery branch) with no PSK/backbone machinery.
func newTestBootRelayBridge(t *testing.T) (host.Host, func()) {
	t.Helper()
	bh, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("create test boot host: %v", err)
	}
	var mu sync.Mutex
	clients := map[peer.ID]network.Stream{}
	bh.SetStreamHandler(BootRelayProtocolID, func(s network.Stream) {
		remote := s.Conn().RemotePeer()
		mu.Lock()
		clients[remote] = s
		mu.Unlock()
		defer func() {
			mu.Lock()
			delete(clients, remote)
			mu.Unlock()
			_ = s.Close()
		}()
		buf := make([]byte, 64*1024)
		for {
			n, rerr := ReadFrame(s, buf)
			if rerr != nil || n == 0 {
				return
			}
			data := append([]byte(nil), buf[:n]...)
			// The boot is a stateless bridge: read src/dst peer IDs and the
			// in-band netID, never the inner payload (end-to-end sealed for the
			// final destination). We only need finalDst to route locally.
			_, _, _, finalDst, _, _, _, uerr := routing.UnpackBootRelayFrame(data)
			if uerr != nil {
				continue
			}
			mu.Lock()
			ls := clients[finalDst]
			mu.Unlock()
			if ls == nil {
				// Destination not attached here (would be a backbone frame in a
				// multi-boot deployment). Single-boot harness drops it.
				continue
			}
			// Write length-prefixed: the node's downlink reads with ReadFrame (4-byte
			// length prefix), so the frame must be framed exactly like the uplink.
			if werr := WriteFrame(ls, data); werr != nil {
				mu.Lock()
				delete(clients, finalDst)
				mu.Unlock()
			}
		}
	})
	return bh, func() { _ = bh.Close() }
}

// waitBootRelayUplink polls until node n holds a live boot-relay uplink to boot.
func waitBootRelayUplink(t *testing.T, n *Node, boot peer.ID) {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for {
		if n.hasBootRelayUplink(boot) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("boot-relay uplink to %s not established within 40s (auth/connect/uplink failed)", boot)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
