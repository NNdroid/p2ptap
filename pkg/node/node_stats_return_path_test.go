package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/config"
	"p2ptap/pkg/obfuscate"
	vswitch "p2ptap/pkg/switch"
)

func TestDeriveReturnPathStates(t *testing.T) {
	n := &Node{
		peerTapProbe:   make(map[peer.ID]tapProbeOutcome),
		perPeerTxSpeed: make(map[peer.ID]uint64),
		perPeerRxSpeed: make(map[peer.ID]uint64),
		arpIndex:       &arpIndex{v4: make(map[uint32]arpIndexEntry), v6: make(map[[16]byte]arpIndexEntry)},
	}

	pID := peer.ID("test-peer-1")

	// 1. Peer without TAP IP -> relay_only
	st, _, _ := n.deriveReturnPath(pID, "Peer")
	if st != "relay_only" {
		t.Fatalf("expected relay_only, got %s", st)
	}

	// Register TAP IP in metadata
	n.storePeerMeta(pID, PeerMeta{TapIP: "10.0.0.2/24"})

	// 2. Pure idle peer (no Tx, no Rx) -> idle
	st, _, _ = n.deriveReturnPath(pID, "Peer")
	if st != "idle" {
		t.Fatalf("expected idle for pure idle peer, got %s", st)
	}

	// 3. Idle peer with background broadcast noise (txBytes > 0, but txSpd == 0, lastRx == 0)
	// THIS WAS THE CRITICAL FALSE POSITIVE BUG REPORTED BY USER ("目前很多节点回程状态是单向仅发？")
	n.recordPeerTxBytes(pID, 120) // 120 bytes of broadcast ARP/mDNS
	st, _, _ = n.deriveReturnPath(pID, "Peer")
	if st != "idle" {
		t.Fatalf("expected idle for idle peer with broadcast noise (txSpd=0), got %s", st)
	}

	// 4. Actively sending traffic right now (txSpd > 0) with zero Rx -> genuinely asymmetric
	n.perPeerBytesMu.Lock()
	n.perPeerTxSpeed[pID] = 5000
	n.perPeerBytesMu.Unlock()
	st, _, _ = n.deriveReturnPath(pID, "Peer")
	if st != "asymmetric" {
		t.Fatalf("expected asymmetric when actively sending without return, got %s", st)
	}

	// 5. Inbound frame arrives (e.g. via direct or relayed traffic) -> ok
	n.notePeerRx(pID)
	st, _, _ = n.deriveReturnPath(pID, "Peer")
	if st != "ok" {
		t.Fatalf("expected ok after receiving inbound frame, got %s", st)
	}

	// 6. Explicit TAP Probe outcome takes high precedence
	pID2 := peer.ID("test-peer-2")
	n.storePeerMeta(pID2, PeerMeta{TapIP: "10.0.0.3/24"})
	n.recordTapProbe(pID2, true, true, "OK")
	st, _, _ = n.deriveReturnPath(pID2, "Peer")
	if st != "ok" {
		t.Fatalf("expected ok after successful TAP probe, got %s", st)
	}

	t.Logf("✓ TestDeriveReturnPathStates: All state transitions verified successfully")
}

func TestReturnPathRobustnessAndProvenance(t *testing.T) {
	bootA := peer.ID("boot-node-A")
	bootB := peer.ID("boot-node-B")
	target := peer.ID("nat-peer-target")

	n := &Node{
		Host:               nil,
		Config:             &config.Config{},
		MACTable:           vswitch.NewMACTable(),
		Collector:          noopCollector{},
		bootRelayConns:     make(map[peer.ID]*bootRelayConn),
		bootRelayBlacklist: make(map[peer.ID]time.Time),
		dedupPeers:         make(map[peer.ID]*obfuscate.Deduplicator),
		arpIndex:           &arpIndex{v4: make(map[uint32]arpIndexEntry), v6: make(map[[16]byte]arpIndexEntry)},
	}
	n.discoveredBoots.Store(bootA, true)
	n.discoveredBoots.Store(bootB, true)

	// Register uplinks for both boots
	n.bootRelayConns[bootA] = &bootRelayConn{boot: bootA}
	n.bootRelayConns[bootB] = &bootRelayConn{boot: bootB}

	// 1. Initially target has no provenance
	if orig, ok := n.lookupPeekMapOrigin(target); ok {
		t.Fatalf("expected no origin initially, got %v", orig)
	}

	// 2. An inbound frame arrives from target via bootB
	payload := make([]byte, 64)
	payload[12] = 0x08
	payload[13] = 0x00 // IPv4
	copy(payload[26:30], []byte{10, 0, 0, 88}) // src IP = 10.0.0.88
	srcMAC := []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}

	n.deliverRelayedFrameToTAP(payload, target, bootB, 100)

	// Verify return path is noted alive
	if !n.peerRxWithin(target, 2*time.Second) {
		t.Fatalf("expected peerRxWithin=true after deliverRelayedFrameToTAP")
	}

	// Verify provenance is recorded as bootB
	orig, ok := n.lookupPeekMapOrigin(target)
	if !ok || orig.Via != bootB {
		t.Fatalf("expected origin.Via=%s, got %s (ok=%v)", bootB, orig.Via, ok)
	}

	// Verify relayHopForTarget routes to bootB (not bootA!)
	hop := n.relayHopForTarget(target)
	if hop != bootB {
		t.Fatalf("expected relayHopForTarget to pick provenance bootB, got %s", hop)
	}

	// Verify IPv4 address was auto-learned into metadata
	val, okMeta := n.peerMeta.Load(target)
	if !okMeta {
		t.Fatalf("expected peerMeta loaded for target")
	}
	meta := val.(PeerMeta)
	if meta.TapIP != "10.0.0.88/24" {
		t.Fatalf("expected TapIP=10.0.0.88/24, got %s", meta.TapIP)
	}

	// 3. Test IPv6 auto-learning
	v6Payload := make([]byte, 80)
	v6Payload[12] = 0x86
	v6Payload[13] = 0xdd // IPv6
	copy(v6Payload[22:38], []byte{0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88})
	n.learnPeerAddressFromFrame(target, srcMAC, v6Payload)

	val2, _ := n.peerMeta.Load(target)
	meta2 := val2.(PeerMeta)
	if meta2.TapIPv6 != "fd00::88/64" {
		t.Fatalf("expected TapIPv6=fd00::88/64, got %s", meta2.TapIPv6)
	}

	t.Logf("✓ TestReturnPathRobustnessAndProvenance: Provenance routing and auto-learning verified successfully")
}
