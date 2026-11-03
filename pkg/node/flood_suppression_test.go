package node

import (
	"net"
	"testing"
	"time"

	"p2ptap/pkg/tap"
)

// TestL3TunnelDoesNotFloodUnroutableWANFrames pins the flood-suppression guard
// for a frame shaped the way an L3 tunnel emits it.
//
// Android's VpnService exposes only a TUN fd (no ARP, no L2 neighbour), so the
// driver synthesises the Ethernet header itself. Until the destination IP is
// resolved it has no peer MAC to put there and must fall back to broadcast —
// which is precisely the shape of every packet the OS routes into a
// 0.0.0.0/0 tunnel and out to the internet.
//
// The guard that keeps such packets from being fanned out to the whole mesh
// used to test "is the destination MAC unicast?", so on Android (and on Wintun
// whenever the peer's MAC had not been learned yet) it could never fire: with
// no Exit Node selected, the entire outbound WAN stream of the device was
// flooded to every peer, burning relay bandwidth and leaking the
// destination metadata. The decision belongs on the IP destination, which the
// frame always carries; the MAC is only a hint.
func TestL3TunnelDoesNotFloodUnroutableWANFrames(t *testing.T) {
	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")

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
		t.Fatalf("NodeA connect to NodeB failed: %v", cerr)
	}
	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)

	_ = pipeA.ConfigureIP("10.0.0.1/24", "fd00::1/64")
	_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")

	// The premise of the guard: no Exit Node, so nothing can deliver a WAN
	// packet, and broadcasting it to peers only costs bandwidth.
	if nodeA.isExitNodeActive() {
		t.Fatalf("NodeA unexpectedly has an active exit node")
	}

	readerB := newFrameReader(pipeB)
	t.Cleanup(readerB.Close)

	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	l3Broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	clientIP := net.ParseIP("10.0.0.1")

	wanTag := []byte("FLOOD_WAN_DEST_UNROUTABLE")
	lanTag := []byte("FLOOD_LIMITED_BROADCAST")
	want := [][]byte{wanTag, lanTag}
	coll := newConcurrentPayloadCollector(readerB, want)

	// An unroutable internet destination, emitted the way the Android driver
	// emits it: dst MAC still broadcast because no peer owns the address.
	wan := constructICMPv4PacketWithData(
		srcMAC, l3Broadcast, clientIP, net.ParseIP("203.0.113.9"), 9500, 1, wanTag)
	if _, werr := pipeA.Write(wan); werr != nil {
		t.Fatalf("pipeA.Write(WAN frame) failed: %v", werr)
	}

	// A limited broadcast is the opposite case: it is exactly what the mesh
	// must carry (DHCP before an address exists, ARP-less L3 discovery), and
	// the same guard must not swallow it. It doubles as proof that the link
	// was live for the whole observation window.
	lan := constructICMPv4PacketWithData(
		srcMAC, l3Broadcast, clientIP, net.ParseIP("255.255.255.255"), 9501, 1, lanTag)
	if _, werr := pipeA.Write(lan); werr != nil {
		t.Fatalf("pipeA.Write(limited broadcast) failed: %v", werr)
	}

	deadline := time.Now().Add(8 * time.Second)
	for !coll.allSeen([][]byte{lanTag}) {
		if time.Now().After(deadline) {
			t.Fatalf("the limited-broadcast frame never reached peer B; the link was dead, so this test proves nothing")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Give a leaked flood time to show up: the dispatch fan-out is asynchronous,
	// so a frame that WAS flooded would arrive well inside this window.
	time.Sleep(500 * time.Millisecond)
	if coll.allSeen([][]byte{wanTag}) {
		t.Fatalf("an unroutable WAN frame (dst 203.0.113.9, dst MAC %s) was flooded to peer B with no exit node active",
			l3Broadcast)
	}
}
