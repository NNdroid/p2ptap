package node

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peerstore"
	"p2ptap/pkg/tap"
)

// TestE2EExitNodeTransitOverMultipath pins the interaction the field reports
// point at: an Exit Node tunnel carried over a genuine MULTI-PATH link.
//
// It is the only test that combines the two features:
//
//   - Node A is a VPN client with the "multipath" strategy, so every frame it
//     sends to B is distributed across B's paths and the batch writer
//     (writeBatchMultipathLocked) splits each drained batch over them;
//   - Node B is the Exit Node server (ExitNode.Enable), so transit frames it
//     receives must be rewritten to its own TAP MAC and injected into its TAP.
//
// The link is made genuinely multi-path the same way
// TestE2EMultipathMultiProtocolDirectLink does: B listens on TCP and QUIC on
// the host NIC, and the multipath repair path dials both instead of collapsing
// onto one connection.
//
// Both L2 shapes a client can produce are exercised, because they enter
// processTapFrame through DIFFERENT branches:
//
//   - unicast-unknown: a real TAP stack resolved a gateway MAC;
//   - l3-broadcast: Android has no TAP at all — pkg/tuntap wraps every OS
//     packet with dst = ff:ff:ff:ff:ff:ff, so the frame lands in the broadcast
//     block instead.
//
// Traffic is asserted in BOTH directions, because an exit tunnel is only usable
// when the reply half also crosses the multipath set.
func TestE2EExitNodeTransitOverMultipath(t *testing.T) {
	if testing.Short() {
		t.Skip("skips NIC-binding multipath e2e in -short mode")
	}
	runExitNodeOverMultipath(t, "multipath")
}

// TestE2EExitNodeTransitOverBestPath is the control for the test above: the same
// exit-node scenario on a non-multipath strategy. When only the multipath
// variant fails, the fault is in the multipath scheduler / batch writer rather
// than in the exit-node datapath itself.
func TestE2EExitNodeTransitOverBestPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skips NIC-binding multipath e2e in -short mode")
	}
	runExitNodeOverMultipath(t, "best_path")
}

func runExitNodeOverMultipath(t *testing.T, strategy string) {
	t.Helper()

	nics, err := physicalNICIPs()
	if err != nil {
		t.Skipf("physicalNICIPs failed: %v", err)
	}
	var v4 string
	for _, ip := range nics {
		if ip.To4() != nil {
			v4 = ip.String()
			break
		}
	}
	if v4 == "" {
		t.Skip("host has no non-loopback IPv4 NIC; cannot bind NodeB")
	}

	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", strategy)
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", strategy)
	// B is the Exit Node server for the tunnel A installs.
	cfgB.ExitNode.Enable = true
	cfgB.ListenAddrs = []string{
		fmt.Sprintf("/ip4/%s/tcp/0", v4),
		fmt.Sprintf("/ip4/%s/udp/0/quic-v1", v4),
	}

	nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create NodeB: %v", err)
	}
	defer func() {
		nodeA.Close()
		nodeB.Close()
	}()
	nodeA.Start()
	nodeB.Start()

	// Both a TCP and a QUIC listener on the IPv4 NIC: that is what gives the
	// multipath repair two dialable, distinct paths.
	gotTCP, gotQUIC := false, false
	deadline0 := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline0) {
		for _, la := range nodeB.Host.Network().ListenAddresses() {
			s := la.String()
			if strings.Contains(s, "/tcp/") && strings.Contains(s, v4) {
				gotTCP = true
			}
			if strings.Contains(s, "/quic-v1") && strings.Contains(s, v4) {
				gotQUIC = true
			}
		}
		if gotTCP && gotQUIC {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !gotTCP || !gotQUIC {
		t.Skipf("NodeB did not bind both TCP and QUIC on %s (tcp=%v quic=%v)", v4, gotTCP, gotQUIC)
	}

	bInfo := nodeB.Host.Peerstore().PeerInfo(nodeB.Host.ID())
	bInfo.Addrs = nodeB.Host.Network().ListenAddresses()
	nodeA.Host.Peerstore().AddAddrs(bInfo.ID, bInfo.Addrs, peerstore.PermanentAddrTTL)

	// Drive the multipath repair loop until A holds every distinct path to B.
	// best_path does not spray, so a single connection is enough there.
	wantConns := 1
	if strategy == "multipath" {
		wantConns = 2
	}
	repairDeadline := time.Now().Add(30 * time.Second)
	for {
		nodeA.repairMultipathPaths(nodeB.Host.ID())
		if len(nodeA.Host.Network().ConnsToPeer(nodeB.Host.ID())) >= wantConns {
			break
		}
		if time.Now().After(repairDeadline) {
			t.Fatalf("path repair established only %d connection(s) to B (want >=%d)",
				len(nodeA.Host.Network().ConnsToPeer(nodeB.Host.ID())), wantConns)
		}
		time.Sleep(100 * time.Millisecond)
	}
	conns := nodeA.Host.Network().ConnsToPeer(nodeB.Host.ID())
	pathKeys := make(map[string]bool)
	for _, c := range conns {
		pathKeys[multipathAddrKey(c.RemoteMultiaddr())] = true
	}
	t.Logf("%s: A holds %d connection(s) over %d distinct path(s) to the exit node",
		strategy, len(conns), len(pathKeys))

	nodeA.Dispatcher.EnsureStreamsOnAllConns(nodeB.Host.ID())
	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)
	time.Sleep(300 * time.Millisecond)

	_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")
	_ = pipeA.ConfigureIP("10.0.0.1/24", "fd00::1/64")

	// Install the exit node on A, addressed by peer ID with B's TAP IPs — the
	// same call the WebUI/Android path makes.
	// Exactly what the Android client does: peer ID only, no TAP IP. Core has
	// to resolve the TAP IP from B's peer metadata, and an empty/unresolved
	// value makes SetExitNode refuse the activation outright.
	meta, ok := nodeA.GetPeerMeta(nodeB.Host.ID())
	if !ok || (meta.TapIP == "" && meta.TapIPv6 == "") {
		t.Fatalf("A has no TAP IP metadata for the exit peer (meta=%+v ok=%v); the Android activation path cannot resolve a gateway IP", meta, ok)
	}
	tapV4, tapV6 := meta.TapIP, meta.TapIPv6
	if i := strings.IndexByte(tapV4, '/'); i >= 0 {
		tapV4 = tapV4[:i]
	}
	if i := strings.IndexByte(tapV6, '/'); i >= 0 {
		tapV6 = tapV6[:i]
	}
	if err := nodeA.Gateway.SetExitNode(nodeB.Host.ID().String(), tapV4, tapV6, nil); err != nil {
		t.Fatalf("SetExitNode on A failed: %v", err)
	}
	if !nodeA.isExitNodeActive() {
		t.Fatalf("exit node did not become active on A after SetExitNode")
	}
	if pid := nodeA.Gateway.ActiveExitPeerPID(); pid != nodeB.Host.ID() {
		t.Fatalf("A active exit peer = %s, want %s", pid, nodeB.Host.ID())
	}

	// ONE reader per pipe and ONE collector per reader for the whole test. A
	// second collector on the same frameReader would race it for frames and
	// silently discard the other's payloads — which reads exactly like packet
	// loss in the tunnel.
	readerB := newFrameReader(pipeB)
	t.Cleanup(readerB.Close)
	readerA := newFrameReader(pipeA)
	t.Cleanup(readerA.Close)

	srcMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	clientIP := net.ParseIP("10.0.0.1")
	publicIP := net.ParseIP("203.0.113.9")

	// Payloads must be unique per shape: the exit server applies content-based
	// broadcast dedup to frames arriving with a broadcast dst MAC, so replaying
	// byte-identical frames would be dropped as duplicates and look like a
	// datapath bug.
	shapes := []struct {
		name   string
		dstMAC net.HardwareAddr
	}{
		{"unicast-unknown", net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}},
		{"l3-broadcast", net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}

	const (
		transitFrames = 200
		replyFrames   = 24
	)
	type shapePlan struct {
		name    string
		wires   [][]byte
		want    [][]byte
		replies [][]byte
		repWant [][]byte
	}
	plans := make([]shapePlan, 0, len(shapes))
	var allWant, allRepWant [][]byte
	for _, shape := range shapes {
		prefix := "EXIT_MP_" + shape.name + "_"
		p := shapePlan{name: shape.name}
		// A BULK burst, not a handful of packets: that is what real exit traffic
		// looks like, and it is also what drives the dispatch worker's
		// (kind,target) batching — up to 32 packed frames per SendBatchToPeer
		// call, which is the only way the multipath BATCH writer is reached.
		for i := 0; i < transitFrames; i++ {
			tag := []byte(fmt.Sprintf("%s%04d", prefix, i))
			p.want = append(p.want, tag)
			p.wires = append(p.wires, constructICMPv4PacketWithData(
				srcMAC, shape.dstMAC, clientIP, publicIP, 9100+i, 1,
				append(tag, make([]byte, 180)...)))
		}
		// Reply direction: the exit node returns traffic to the client. This is
		// the half that makes the tunnel usable, and the exit server has to
		// resolve the client's TAP IP back to the A peer to forward it.
		for i := 0; i < replyFrames; i++ {
			tag := []byte(fmt.Sprintf("%sREPLY_%04d", prefix, i))
			p.repWant = append(p.repWant, tag)
			p.replies = append(p.replies, constructICMPv4PacketWithData(
				shape.dstMAC, srcMAC, publicIP, clientIP, 9300+i, 1, tag))
		}
		allWant = append(allWant, p.want...)
		allRepWant = append(allRepWant, p.repWant...)
		plans = append(plans, p)
	}

	coll := newConcurrentPayloadCollector(readerB, allWant)
	rcoll := newConcurrentPayloadCollector(readerA, allRepWant)

	for _, p := range plans {
		for i := range p.wires {
			if _, werr := pipeA.Write(p.wires[i]); werr != nil {
				t.Fatalf("%s: pipeA.Write frame %d failed: %v", p.name, i, werr)
			}
		}
		if !coll.waitUntil(p.want, 20*time.Second) {
			var missing []string
			coll.mu.Lock()
			for _, wgt := range p.want {
				if !coll.seen[string(wgt)] {
					missing = append(missing, string(wgt))
				}
			}
			coll.mu.Unlock()
			if len(missing) > 12 {
				missing = missing[:12]
			}
			t.Errorf("%s: %d/%d transit frames (%s) reached the exit node's TAP; missing=%v",
				strategy, countSeen(coll, p.want), len(p.want), p.name, missing)
			continue
		}
		t.Logf("%s: %d/%d transit frames (%s) reached the exit node's TAP",
			strategy, countSeen(coll, p.want), len(p.want), p.name)
	}

	for _, p := range plans {
		for i := range p.replies {
			if _, werr := pipeB.Write(p.replies[i]); werr != nil {
				t.Fatalf("%s: pipeB.Write reply %d failed: %v", p.name, i, werr)
			}
		}
		if !rcoll.waitUntil(p.repWant, 20*time.Second) {
			t.Errorf("%s: %d/%d reply frames (%s) reached the client's TAP",
				strategy, countSeen(rcoll, p.repWant), len(p.repWant), p.name)
			continue
		}
		t.Logf("%s: %d/%d reply frames (%s) reached the client's TAP",
			strategy, countSeen(rcoll, p.repWant), len(p.repWant), p.name)
	}
}
