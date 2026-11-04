package node

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	relayclient "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	ma "github.com/multiformats/go-multiaddr"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"p2ptap/pkg/packet"
	"p2ptap/pkg/tap"
)

// Padding is a TX-side, self-describing transformation: Pack always emits the
// same 15-byte obfuscate header (magic/seqID/obfType/payloadLen/paddingLen)
// regardless of whether padding is enabled or which bands apply, and Unpack
// reads the framing from the header alone — the receiver's own rule never
// participates in decoding. These tests PIN that contract end to end: two
// nodes whose obfuscation configurations DISAGREE (enable flag, band layout,
// coalescing, MaxFragSize, MTU) must interoperate bidirectionally over direct,
// boot-relay-bridged, and overlay-relayed topologies.
//
// All frame delivery is asserted through concurrent payload collectors (one
// reader per TAP pipe, started before anything is written): a sequential
// search-and-consume assertion would silently swallow frames that arrive out
// of order or coalesced, misfiring on the very batching behaviour these tests
// exist to exercise.

type paddingInteropCase struct {
	name string

	enableA bool
	ruleA   string
	fragA   int // Obfuscation.MaxFragSize on A (0 = default)

	enableB bool
	ruleB   string
	fragB   int

	// bigFrameAtoB: when > 0, an ICMP v4 frame with a payload this big is sent
	// A→B in addition to the pings (exercises fragmentation of a padded frame
	// under A's fragment cap and reassembly under B's).
	bigFrameAtoB int
}

func paddingInteropTag(caseName, dir string) []byte {
	return []byte("PINTEROP_" + strings.ToUpper(caseName) + "_" + dir)
}

func containsTag(tag []byte) func([]byte) bool {
	return func(f []byte) bool { return bytes.Contains(f, tag) }
}

// constructLargeICMPv4 builds an ICMPv4 echo frame of arbitrary payload size
// with a CORRECT 16-bit IP total-length field and IP checksum. The shared
// constructICMPv4PacketWithData helper truncates the total length to its low
// byte, which no real kernel would emit; the oversized-refragmentation paths
// under test here read that field, so the frame must be well formed.
func constructLargeICMPv4(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, id, seq int, data []byte) []byte {
	msgBytes, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: data},
	}).Marshal(nil)
	if err != nil {
		panic(err)
	}
	src4, dst4 := srcIP.To4(), dstIP.To4()
	totalLen := 20 + len(msgBytes)

	eth := make([]byte, 14)
	copy(eth[0:6], dstMAC)
	copy(eth[6:12], srcMAC)
	eth[12], eth[13] = 0x08, 0x00

	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[1] = 0x00
	ip[2] = byte(totalLen >> 8)
	ip[3] = byte(totalLen)
	ip[4], ip[5] = 0x12, 0x34 // identification
	ip[6], ip[7] = 0x00, 0x00 // no DF/MF, offset 0
	ip[8] = 64
	ip[9] = 1 // ICMP
	copy(ip[12:16], src4)
	copy(ip[16:20], dst4)
	cs := packet.IPChecksum(ip[:20]) // header checksum field is zeroed above
	ip[10], ip[11] = byte(cs>>8), byte(cs)

	return append(eth, append(ip, msgBytes...)...)
}

func TestPaddingInteropAcrossModes(t *testing.T) {
	if testing.Short() {
		t.Skip("skips padding interop mesh in -short mode")
	}
	cases := []paddingInteropCase{
		// A emits PaddingLen=0 frames; B pads everything under 400 to 400-600.
		// The RX side of each must decode the other's framing unchanged.
		{name: "disabled_vs_default_rule", enableA: false, enableB: true, ruleB: ""},
		// A pads to exactly 64; B pads anything under 900 to 900-1200.
		{name: "minimal_vs_aggressive", enableA: true, ruleA: "0 -> 64", enableB: true, ruleB: "0 -> 900-1200"},
		// Two-band rule vs one high band: band selection differs per direction.
		{name: "multiband_vs_single_highband", enableA: true,
			ruleA: "0 -> 400-600\n1024 -> 1300-1500", enableB: true, ruleB: "0 -> 1200"},
		// A never coalesces; B buffers unicast frames up to 20 ms and flushes
		// them as batch payloads — B must split A's frames and A must split
		// B's batches.
		{name: "coalesce_off_vs_slow_flush", enableA: true, ruleA: "coalesce off",
			enableB: true, ruleB: "coalesce on max_delay_ms=20"},
		// A fragments its sealed frames at 600 bytes; B reassembles them under
		// its own (default) fragment policy.
		{name: "fragcap_600_vs_default", enableA: true, ruleA: "0 -> 400-600",
			fragA: 600, enableB: true, ruleB: "", bigFrameAtoB: 2048},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tapA, pipeA := tap.NewMemTAPPair("tapA-"+tc.name, "pipeA-"+tc.name)
			tapB, pipeB := tap.NewMemTAPPair("tapB-"+tc.name, "pipeB-"+tc.name)

			cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
			cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
			cfgA.Obfuscation.Enable = tc.enableA
			cfgA.Obfuscation.PaddingRules = tc.ruleA
			cfgA.Obfuscation.MaxFragSize = tc.fragA
			cfgB.Obfuscation.Enable = tc.enableB
			cfgB.Obfuscation.PaddingRules = tc.ruleB
			cfgB.Obfuscation.MaxFragSize = tc.fragB

			nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
			if err != nil {
				t.Fatalf("create nodeA: %v", err)
			}
			defer nodeA.Close()
			nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
			if err != nil {
				t.Fatalf("create nodeB: %v", err)
			}
			defer nodeB.Close()
			nodeA.Start()
			nodeB.Start()

			connectNodes(t, nodeA, nodeB)
			waitOverlayReady(t, nodeA, nodeB)
			waitStreamReady(t, nodeA, nodeB)
			waitStreamReady(t, nodeB, nodeA)
			nodeA.storePeerMeta(nodeB.Host.ID(), PeerMeta{NodeName: "B", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: nodeB.localMAC.String()})
			nodeB.storePeerMeta(nodeA.Host.ID(), PeerMeta{NodeName: "A", TapIP: "10.0.0.1/24", TapIPv6: "fd00::1/64", TapMAC: nodeA.localMAC.String()})
			nodeA.rebuildARPIndex()
			nodeB.rebuildARPIndex()

			// Collectors start BEFORE any frame is written, one per direction.
			wantB := [][]byte{
				paddingInteropTag(tc.name, "v4_a2b"),
				paddingInteropTag(tc.name, "v6_a2b"),
			}
			for i := 0; i < 4; i++ {
				wantB = append(wantB, paddingInteropTag(tc.name, "burst"+string(rune('0'+i))))
			}
			if tc.bigFrameAtoB > 0 {
				wantB = append(wantB, paddingInteropTag(tc.name, "big_a2b"))
			}
			wantA := [][]byte{paddingInteropTag(tc.name, "v4_b2a")}
			readerA, readerB := newFrameReader(pipeA), newFrameReader(pipeB)
			t.Cleanup(func() { readerA.Close(); readerB.Close() })
			collA := newConcurrentPayloadCollector(readerA, wantA)
			collB := newConcurrentPayloadCollector(readerB, wantB)

			macA, macB := nodeA.localMAC, nodeB.localMAC
			ipA, ipB := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
			v6A, v6B := net.ParseIP("fd00::1"), net.ParseIP("fd00::2")

			// A→B: a 63-byte v4 ping sits below every case's band floor, so
			// A's TX pads (or coalesces) it per its own rule while B's RX just
			// decodes the self-describing header; a v6 ping appended with a
			// tagged payload; four rapid pings that A coalesces into batch
			// payloads when its rule coalesces (B's SplitBatchPayload must
			// hand every sub-frame through the full RX pipeline); and the
			// case's big frame when one is configured.
			if _, err := pipeA.Write(constructICMPv4PacketWithData(macA, macB, ipA, ipB, 7001, 1,
				paddingInteropTag(tc.name, "v4_a2b"))); err != nil {
				t.Fatalf("pipeA write v4: %v", err)
			}
			v6 := append(constructICMPv6Packet(macA, macB, v6A, v6B, 7002, 1),
				paddingInteropTag(tc.name, "v6_a2b")...)
			if _, err := pipeA.Write(v6); err != nil {
				t.Fatalf("pipeA write v6: %v", err)
			}
			for i := 0; i < 4; i++ {
				if _, err := pipeA.Write(constructICMPv4PacketWithData(macA, macB, ipA, ipB, 7003, i+1,
					paddingInteropTag(tc.name, "burst"+string(rune('0'+i))))); err != nil {
					t.Fatalf("pipeA write burst %d: %v", i, err)
				}
			}
			if tc.bigFrameAtoB > 0 {
				if _, err := pipeA.Write(constructLargeICMPv4(macA, macB, ipA, ipB, 7004, 1,
					append(paddingInteropTag(tc.name, "big_a2b"), bytes.Repeat([]byte{0xA5}, tc.bigFrameAtoB)...))); err != nil {
					t.Fatalf("pipeA write big frame: %v", err)
				}
			}
			if !collB.waitUntil(wantB, 8*time.Second) {
				t.Fatalf("B did not receive all of A's frames; missing=%v", collB.missing(wantB))
			}

			// B→A: the reverse direction pads per B's rule.
			if _, err := pipeB.Write(constructICMPv4PacketWithData(macB, macA, ipB, ipA, 7001, 2,
				paddingInteropTag(tc.name, "v4_b2a"))); err != nil {
				t.Fatalf("pipeB write v4: %v", err)
			}
			if !collA.waitUntil(wantA, 8*time.Second) {
				t.Fatalf("A did not receive B's frames; missing=%v", collA.missing(wantA))
			}
		})
	}
}

// TestPaddingInteropMTUMismatch pins interoperability when the two ends
// disagree on the tunnel MTU: A (MTU 9000) hands a 2.5 KB jumbo ICMP frame to
// the overlay and B (MTU 600) cannot inject a frame that size into its device,
// so its tapWrite boundary must re-fragment it to B's MTU instead of dropping
// it — while B's small replies flow back unpadded and unfragmented.
func TestPaddingInteropMTUMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skips padding interop mesh in -short mode")
	}
	tapA, pipeA := tap.NewMemTAPPair("tapA-mtu", "pipeA-mtu")
	tapB, pipeB := tap.NewMemTAPPair("tapB-mtu", "pipeB-mtu")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
	cfgA.Obfuscation.Enable = true
	cfgA.Obfuscation.PaddingRules = "0 -> 64"
	cfgA.MTU = 9000
	cfgB.Obfuscation.Enable = true
	cfgB.Obfuscation.PaddingRules = "0 -> 400-600"
	cfgB.MTU = 600

	nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create nodeA: %v", err)
	}
	defer nodeA.Close()
	nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create nodeB: %v", err)
	}
	defer nodeB.Close()
	nodeA.Start()
	nodeB.Start()

	connectNodes(t, nodeA, nodeB)
	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)
	nodeA.storePeerMeta(nodeB.Host.ID(), PeerMeta{NodeName: "B", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: nodeB.localMAC.String()})
	nodeB.storePeerMeta(nodeA.Host.ID(), PeerMeta{NodeName: "A", TapIP: "10.0.0.1/24", TapIPv6: "fd00::1/64", TapMAC: nodeA.localMAC.String()})
	nodeA.rebuildARPIndex()
	nodeB.rebuildARPIndex()

	wantB := [][]byte{paddingInteropTag("mtu", "jumbo_a2b")}
	wantA := [][]byte{paddingInteropTag("mtu", "small_b2a")}
	readerA, readerB := newFrameReader(pipeA), newFrameReader(pipeB)
	t.Cleanup(func() { readerA.Close(); readerB.Close() })
	collA := newConcurrentPayloadCollector(readerA, wantA)
	collB := newConcurrentPayloadCollector(readerB, wantB)

	macA, macB := nodeA.localMAC, nodeB.localMAC
	ipA, ipB := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")

	// A→B jumbo: a well-formed 2.5 KB payload. B's device limit is 614 bytes,
	// so the frame crosses the tunnel whole and must be re-fragmented at B's
	// TAP write boundary; the tag rides the first fragment.
	tagJumbo := paddingInteropTag("mtu", "jumbo_a2b")
	if _, err := pipeA.Write(constructLargeICMPv4(macA, macB, ipA, ipB, 7101, 1,
		append(tagJumbo, bytes.Repeat([]byte{0x5A}, 2500)...))); err != nil {
		t.Fatalf("pipeA write jumbo: %v", err)
	}
	if !collB.waitUntil(wantB, 8*time.Second) {
		t.Fatalf("B did not receive the re-fragmented jumbo frame; missing=%v", collB.missing(wantB))
	}

	// B→A small reply: B's own tiny frames are far under both MTUs.
	if _, err := pipeB.Write(constructICMPv4PacketWithData(macB, macA, ipB, ipA, 7101, 2,
		paddingInteropTag("mtu", "small_b2a"))); err != nil {
		t.Fatalf("pipeB write small: %v", err)
	}
	if !collA.waitUntil(wantA, 8*time.Second) {
		t.Fatalf("A did not receive B's small reply; missing=%v", collA.missing(wantA))
	}
}

// TestPaddingInteropOverBootRelay pins interoperability when the two ends
// cannot reach each other directly at all — both connect ONLY through a boot
// relay bridge (the NAT'd-deployment shape) — while disagreeing on padding:
// A pads aggressively (0 -> 900-1200), B runs the default bands with
// coalescing off.
func TestPaddingInteropOverBootRelay(t *testing.T) {
	if testing.Short() {
		t.Skip("skips padding interop mesh in -short mode")
	}
	tapA, pipeA := tap.NewMemTAPPair("tapA-boot", "pipeA-boot")
	tapB, pipeB := tap.NewMemTAPPair("tapB-boot", "pipeB-boot")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
	cfgA.Obfuscation.Enable = true
	cfgA.Obfuscation.PaddingRules = "0 -> 900-1200"
	cfgB.Obfuscation.Enable = true
	cfgB.Obfuscation.PaddingRules = "coalesce off"

	bootHost, closeBoot := newTestBootRelayBridge(t)
	defer closeBoot()
	bootMa := bootHost.Addrs()[0].String() + "/p2p/" + bootHost.ID().String()
	cfgA.BootstrapPeers = []string{bootMa}
	cfgB.BootstrapPeers = []string{bootMa}

	nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create nodeA: %v", err)
	}
	defer nodeA.Close()
	nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create nodeB: %v", err)
	}
	defer nodeB.Close()
	nodeA.Start()
	nodeB.Start()

	bootID := bootHost.ID()
	waitBootRelayUplink(t, nodeA, bootID)
	waitBootRelayUplink(t, nodeB, bootID)

	aID, bID := nodeA.Host.ID(), nodeB.Host.ID()
	nodeA.storePeerMeta(bID, PeerMeta{NodeName: "B", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: nodeB.localMAC.String()})
	nodeB.storePeerMeta(aID, PeerMeta{NodeName: "A", TapIP: "10.0.0.1/24", TapIPv6: "fd00::1/64", TapMAC: nodeA.localMAC.String()})
	nodeA.rebuildARPIndex()
	nodeB.rebuildARPIndex()

	wantB := [][]byte{
		paddingInteropTag("boot", "v4_a2b"),
		paddingInteropTag("boot", "big_a2b"),
	}
	wantA := [][]byte{paddingInteropTag("boot", "v4_b2a")}
	readerA, readerB := newFrameReader(pipeA), newFrameReader(pipeB)
	t.Cleanup(func() { readerA.Close(); readerB.Close() })
	collA := newConcurrentPayloadCollector(readerA, wantA)
	collB := newConcurrentPayloadCollector(readerB, wantB)

	macA, macB := nodeA.localMAC, nodeB.localMAC
	ipA, ipB := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")

	// A→B: a 63-byte ping padded by A's aggressive band, crossing the boot
	// relay bridge (boot-relay downlink → deliverRelayedFrameToTAP on B), and
	// a 1.8 KB frame at its natural size (above A's band target_min).
	if _, err := pipeA.Write(constructICMPv4PacketWithData(macA, macB, ipA, ipB, 7201, 1,
		paddingInteropTag("boot", "v4_a2b"))); err != nil {
		t.Fatalf("pipeA write v4: %v", err)
	}
	if _, err := pipeA.Write(constructLargeICMPv4(macA, macB, ipA, ipB, 7202, 1,
		append(paddingInteropTag("boot", "big_a2b"), bytes.Repeat([]byte{0xC3}, 1800)...))); err != nil {
		t.Fatalf("pipeA write big frame: %v", err)
	}
	if !collB.waitUntil(wantB, 10*time.Second) {
		t.Fatalf("B did not receive A's frames over the boot relay; missing=%v", collB.missing(wantB))
	}

	// B→A reply: B does not coalesce; the reply crosses the bridge unpadded.
	if _, err := pipeB.Write(constructICMPv4PacketWithData(macB, macA, ipB, ipA, 7201, 2,
		paddingInteropTag("boot", "v4_b2a"))); err != nil {
		t.Fatalf("pipeB write v4: %v", err)
	}
	if !collA.waitUntil(wantA, 10*time.Second) {
		t.Fatalf("A did not receive B's reply over the boot relay; missing=%v", collA.missing(wantA))
	}
}

// TestPaddingInteropOverOverlayRelay pins interoperability when the two ends
// reach each other ONLY through an overlay relay hop (the hub-and-spoke
// shape): the origin pads the end-to-end frame per its own rule and seals the
// relay envelope with the same packer, while the destination decodes with its
// own (different) rule. A pads to 400-600; B pads to exactly 64.
func TestPaddingInteropOverOverlayRelay(t *testing.T) {
	if testing.Short() {
		t.Skip("skips padding interop mesh in -short mode")
	}
	tapA, pipeA := tap.NewMemTAPPair("tapA-relay", "pipeA-relay")
	tapB, pipeB := tap.NewMemTAPPair("tapB-relay", "pipeB-relay")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "best_path")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "best_path")
	cfgA.Obfuscation.Enable = true
	cfgA.Obfuscation.PaddingRules = "0 -> 400-600"
	cfgB.Obfuscation.Enable = true
	cfgB.Obfuscation.PaddingRules = "0 -> 64"

	nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create nodeA: %v", err)
	}
	defer nodeA.Close()
	nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create nodeB: %v", err)
	}
	defer nodeB.Close()
	nodeA.Start()
	nodeB.Start()

	// Relay-only topology: B reserves on the relay, A connects to the relay,
	// A dials the circuit address. No direct A↔B connection exists at any
	// point, so every frame crosses the hop-by-hop relay envelope.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bID := nodeB.Host.ID()
	r := newTopoRelay(t)
	rInfo := peer.AddrInfo{ID: r.ID(), Addrs: r.Addrs()}
	if _, rerr := relayclient.Reserve(ctx, nodeB.Host, rInfo); rerr != nil {
		t.Fatalf("exit node reserve via relay failed: %v", rerr)
	}
	if cerr := nodeA.Host.Connect(ctx, rInfo); cerr != nil {
		t.Fatalf("client connect relay failed: %v", cerr)
	}
	circuit := "/p2p/" + r.ID().String() + "/p2p-circuit/p2p/" + bID.String()
	if derr := nodeA.dialPeerToAddr(ctx, bID, ma.StringCast(circuit)); derr != nil {
		t.Fatalf("dial circuit failed: %v", derr)
	}

	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)
	nodeA.storePeerMeta(bID, PeerMeta{NodeName: "B", TapIP: "10.0.0.2/24", TapIPv6: "fd00::2/64", TapMAC: nodeB.localMAC.String()})
	nodeB.storePeerMeta(nodeA.Host.ID(), PeerMeta{NodeName: "A", TapIP: "10.0.0.1/24", TapIPv6: "fd00::1/64", TapMAC: nodeA.localMAC.String()})
	nodeA.rebuildARPIndex()
	nodeB.rebuildARPIndex()

	wantB := make([][]byte, 0, 5)
	wantB = append(wantB, paddingInteropTag("relay", "v4_a2b"))
	for i := 0; i < 4; i++ {
		wantB = append(wantB, paddingInteropTag("relay", "burst"+string(rune('0'+i))))
	}
	wantA := [][]byte{paddingInteropTag("relay", "v4_b2a")}
	readerA, readerB := newFrameReader(pipeA), newFrameReader(pipeB)
	t.Cleanup(func() { readerA.Close(); readerB.Close() })
	collA := newConcurrentPayloadCollector(readerA, wantA)
	collB := newConcurrentPayloadCollector(readerB, wantB)

	macA, macB := nodeA.localMAC, nodeB.localMAC
	ipA, ipB := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")

	// A→B: padded by A's band, wrapped in the overlay-relay envelope (hop
	// seal + end-to-end seal), unwrapped and decoded by B's own rule — plus a
	// burst to exercise dedup/reorder over the relay under asymmetric padding.
	if _, err := pipeA.Write(constructICMPv4PacketWithData(macA, macB, ipA, ipB, 7301, 1,
		paddingInteropTag("relay", "v4_a2b"))); err != nil {
		t.Fatalf("pipeA write v4: %v", err)
	}
	for i := 0; i < 4; i++ {
		if _, err := pipeA.Write(constructICMPv4PacketWithData(macA, macB, ipA, ipB, 7302, i+1,
			paddingInteropTag("relay", "burst"+string(rune('0'+i))))); err != nil {
			t.Fatalf("pipeA write burst %d: %v", i, err)
		}
	}
	if !collB.waitUntil(wantB, 10*time.Second) {
		t.Fatalf("B did not receive A's frames over the overlay relay; missing=%v", collB.missing(wantB))
	}

	// B→A: B pads to exactly 64; A decodes with the 400-600 rule.
	if _, err := pipeB.Write(constructICMPv4PacketWithData(macB, macA, ipB, ipA, 7301, 2,
		paddingInteropTag("relay", "v4_b2a"))); err != nil {
		t.Fatalf("pipeB write v4: %v", err)
	}
	if !collA.waitUntil(wantA, 10*time.Second) {
		t.Fatalf("A did not receive B's ping over the overlay relay; missing=%v", collA.missing(wantA))
	}
}
