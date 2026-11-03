package node

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	relayclient "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	ma "github.com/multiformats/go-multiaddr"

	"p2ptap/pkg/tap"
)

// mpTopology describes one physical path layout a real deployment can have
// between a VPN client and its Exit Node.
type mpTopology struct {
	name string
	// direct is the number of transport-level (TCP/QUIC) paths to the peer.
	direct int
	// relay is the number of /p2p-circuit paths, each through a DISTINCT relay.
	relay int
	// spray is how many of those paths the multipath scheduler is expected to
	// use CONCURRENTLY. It is deliberately not direct+relay: nonRelayStreams
	// keeps circuit-relay paths registered but out of the scheduling set while
	// any direct path is healthy, because a relay hop is rate-limited and adds
	// a slow hop that would tax every frame the DWRR hands it. A relay-only
	// peer has no direct path, so its whole set is relay and it does spray.
	spray int
	// relayCarries is true when relay paths are expected to carry data in the
	// STEADY state (relay-only topologies). For direct+relay it is false and
	// the circuits are failover-only; the test still asserts they are
	// REGISTERED and each has its own stream, which is what makes the failover
	// possible at all.
	relayCarries bool
}

func (tp mpTopology) wantPaths() int { return tp.direct + tp.relay }

// TestE2EMultipathTopologyMatrix runs the same Exit Node workload over the three
// path layouts that actually occur in the field, so a regression in any one of
// them is attributable to the topology rather than to "multipath" in general.
//
// The three layouts are NOT symmetric, and the asymmetry is the point:
//
//   - direct-dual      (2 direct): the classic two-link spray, e.g. Wi-Fi TCP +
//     cellular QUIC. Both paths carry traffic.
//   - direct-plus-relay (1 direct + 1 circuit): the peer is reachable directly
//     AND through a relay. The circuit stays registered for failover but the
//     scheduler sprays over the direct path only (nonRelayStreams).
//   - relay-dual       (2 circuits): a NATed Exit Node reachable only through
//     relays. This is the mobile-client case; both circuits spray.
//
// Every case drives the Android L2 shape (dst = ff:ff:ff:ff:ff:ff, which is
// what pkg/tuntap produces for every OS packet) through the Exit Node datapath
// in both directions, because a tunnel is only usable when the reply half also
// crosses the multipath set.
func TestE2EMultipathTopologyMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("skips relay/NIC-binding multipath e2e in -short mode")
	}
	cases := []mpTopology{
		{name: "direct-dual", direct: 2, relay: 0, spray: 2, relayCarries: false},
		{name: "direct-plus-relay", direct: 1, relay: 1, spray: 1, relayCarries: false},
		{name: "relay-dual", direct: 0, relay: 2, spray: 2, relayCarries: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Sequential on purpose: each case starts up to two real relays and
			// two real libp2p hosts, and the suites in this package are known to
			// starve each other when run concurrently.
			runExitNodeOverTopology(t, tc)
		})
	}
}

// topologyNICv4 returns the host's first non-loopback IPv4 address. Paths must
// use a real interface address: filterAdvertisedAddrs drops loopback from the
// advertised set and the conn gater refuses overlay (TAP) ranges, so neither
// 127.0.0.1 nor 10.0.0.0/8 can stand in for a direct link here.
func topologyNICv4(t *testing.T) string {
	t.Helper()
	nics, err := physicalNICIPs()
	if err != nil {
		t.Skipf("physicalNICIPs failed: %v", err)
	}
	for _, ip := range nics {
		if ip.To4() != nil && !ip.IsLoopback() {
			return ip.String()
		}
	}
	t.Skip("host has no non-loopback IPv4 NIC; cannot build direct multipath paths")
	return ""
}

// newTopoRelay starts a circuit-relay v2 service on loopback.
//
// The relay itself listens on loopback (its address is never advertised, it is
// a hop we dial explicitly), while the ENDPOINT paths use NIC addresses. That
// split matters: a loopback circuit address would be dropped by
// filterUndialableAddrs during peer discovery, but dialPeerToAddr issues the
// circuit dial directly and skips that filter.
func newTopoRelay(t *testing.T) host.Host {
	t.Helper()
	r, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.EnableRelayService(),
		libp2p.ForceReachabilityPublic(),
	)
	if err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// waitTopoListeners blocks until the node advertises a TCP listener on v4 (and,
// when wantQUIC is set, a QUIC one too) and returns both transport addresses
// without the /p2p suffix.
func waitTopoListeners(t *testing.T, n *Node, v4 string, wantQUIC bool) (tcpAddr, quicAddr string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		tcpAddr, quicAddr = "", ""
		for _, la := range n.Host.Network().ListenAddresses() {
			s := la.String()
			if !strings.Contains(s, v4) {
				continue
			}
			switch {
			case strings.Contains(s, "/quic-v1"):
				quicAddr = s
			case strings.Contains(s, "/tcp/"):
				tcpAddr = s
			}
		}
		if tcpAddr != "" && (!wantQUIC || quicAddr != "") {
			return tcpAddr, quicAddr
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Skipf("node never bound tcp=%v quic=%v listeners on %s", tcpAddr != "", quicAddr != "", v4)
	return "", ""
}

// classifyTopoConns splits a peer's connections into direct and relay paths
// using the SAME predicate the scheduler uses (connIsRelayForPeer), so the test
// cannot disagree with the code under test about what counts as a relay path.
func classifyTopoConns(conns []network.Conn, p peer.ID) (direct, relayed []network.Conn) {
	for _, c := range conns {
		if c == nil {
			continue
		}
		if connIsRelayForPeer(c, p) {
			relayed = append(relayed, c)
			continue
		}
		direct = append(direct, c)
	}
	return direct, relayed
}

// topologyNodes starts the client (A, multipath, no exit installed yet) and the
// Exit Node server (B, ExitNode.Enable) for one topology, binding B to the NIC
// addresses that topology needs.
func topologyNodes(t *testing.T, topo mpTopology, v4 string) (nodeA, nodeB *Node, pipeA, pipeB *tap.MemTAP) {
	t.Helper()
	tapA, pipeA := tap.NewMemTAPPair("tapA-"+topo.name, "pipeA-"+topo.name)
	tapB, pipeB := tap.NewMemTAPPair("tapB-"+topo.name, "pipeB-"+topo.name)
	t.Cleanup(func() { _ = pipeA.Close(); _ = pipeB.Close() })

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "multipath")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "multipath")
	cfgB.ExitNode.Enable = true
	cfgB.ListenAddrs = []string{fmt.Sprintf("/ip4/%s/tcp/0", v4)}
	if topo.direct >= 2 {
		cfgB.ListenAddrs = append(cfgB.ListenAddrs, fmt.Sprintf("/ip4/%s/udp/0/quic-v1", v4))
	}

	var err error
	nodeA, err = NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	nodeB, err = NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		nodeA.Close()
		t.Fatalf("create NodeB: %v", err)
	}
	t.Cleanup(func() { nodeA.Close(); nodeB.Close() })
	nodeA.Start()
	nodeB.Start()
	return nodeA, nodeB, pipeA, pipeB
}

// buildTopologyPaths dials every path the topology calls for and returns the
// resulting connections, already classified with the scheduler's own
// relay predicate. circuits is returned so a test that breaks a direct path can
// also prune the direct addresses from the peerstore and keep the repair loop
// from simply re-dialing them.
func buildTopologyPaths(t *testing.T, topo mpTopology, v4 string, nodeA, nodeB *Node) (direct, relayed []network.Conn, circuits []ma.Multiaddr) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)

	tcpAddr, quicAddr := waitTopoListeners(t, nodeB, v4, topo.direct >= 2)
	bID := nodeB.Host.ID()
	dial := func(raw, why string) {
		t.Helper()
		m, merr := ma.NewMultiaddr(raw)
		if merr != nil {
			t.Fatalf("%s: parse %q: %v", topo.name, raw, merr)
		}
		if derr := nodeA.dialPeerToAddr(ctx, bID, m); derr != nil {
			t.Fatalf("%s: dial %s (%s) failed: %v", topo.name, raw, why, derr)
		}
	}
	withPeer := func(raw string) string { return raw + "/p2p/" + bID.String() }

	// --- Direct paths first. Building them BEFORE the circuits is the stricter
	// order: it proves dialPeerToAddr still opens a relay path while a healthy
	// direct connection to the same peer already exists (the short-circuit that
	// multipath repair had to bypass). ---
	if topo.direct >= 1 {
		if isOverlayMultiaddr(ma.StringCast(tcpAddr)) {
			t.Skipf("NIC address %s is inside the overlay ranges; the conn gater refuses direct dials to it", tcpAddr)
		}
		dial(withPeer(tcpAddr), "direct tcp")
	}
	if topo.direct >= 2 {
		dial(withPeer(quicAddr), "direct quic")
	}

	// --- Relay paths. B reserves on each relay so A can reach it through that
	// hop; A connects to the relay first so the circuit dial has a hop to use.
	for i := 0; i < topo.relay; i++ {
		r := newTopoRelay(t)
		rInfo := peer.AddrInfo{ID: r.ID(), Addrs: r.Addrs()}
		if _, rerr := relayclient.Reserve(ctx, nodeB.Host, rInfo); rerr != nil {
			t.Fatalf("%s: exit node reserve via relay %d failed: %v", topo.name, i, rerr)
		}
		if cerr := nodeA.Host.Connect(ctx, rInfo); cerr != nil {
			t.Fatalf("%s: client connect relay %d failed: %v", topo.name, i, cerr)
		}
		circuit := "/p2p/" + r.ID().String() + "/p2p-circuit/p2p/" + bID.String()
		dial(circuit, fmt.Sprintf("relay circuit %d", i))
		circuits = append(circuits, ma.StringCast(circuit))
	}

	// --- Topology assertion: the required direct and relay path counts. ---
	connDeadline := time.Now().Add(30 * time.Second)
	for {
		direct, relayed = classifyTopoConns(nodeA.Host.Network().ConnsToPeer(bID), bID)
		if len(direct) >= topo.direct && len(relayed) >= topo.relay {
			break
		}
		if time.Now().After(connDeadline) {
			t.Fatalf("%s: A holds %d direct + %d relay path(s) to the exit node, want >=%d + >=%d",
				topo.name, len(direct), len(relayed), topo.direct, topo.relay)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("%s: A holds %d direct + %d relay path(s) to the exit node (%d paths total)",
		topo.name, len(direct), len(relayed), topo.wantPaths())
	return direct, relayed, circuits
}

// prepareTopologyStreams pins one application stream on every path (both
// directions) and waits for the overlay handshake to converge.
func prepareTopologyStreams(t *testing.T, topo mpTopology, nodeA, nodeB *Node) {
	t.Helper()
	bID := nodeB.Host.ID()
	nodeA.Dispatcher.EnsureStreamsOnAllConns(bID)
	nodeB.Dispatcher.EnsureStreamsOnAllConns(nodeA.Host.ID())
	streamDeadline := time.Now().Add(20 * time.Second)
	for {
		if topoPathsHaveStreams(nodeA, bID) && topoPathsHaveStreams(nodeB, nodeA.Host.ID()) {
			break
		}
		if time.Now().After(streamDeadline) {
			t.Fatalf("%s: not every path got a data stream (A sees %d stream(s), B sees %d)",
				topo.name, streamLen(nodeA.Dispatcher.GetPeerStreams(bID)),
				streamLen(nodeB.Dispatcher.GetPeerStreams(nodeA.Host.ID())))
		}
		time.Sleep(100 * time.Millisecond)
	}

	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)
	time.Sleep(300 * time.Millisecond)
}

func runExitNodeOverTopology(t *testing.T, topo mpTopology) {
	t.Helper()
	v4 := topologyNICv4(t)
	nodeA, nodeB, pipeA, pipeB := topologyNodes(t, topo, v4)
	buildTopologyPaths(t, topo, v4, nodeA, nodeB)
	prepareTopologyStreams(t, topo, nodeA, nodeB)
	bID := nodeB.Host.ID()

	// --- Activate the Exit Node exactly as the Android client does: peer ID
	// only, TAP IP resolved from peer metadata. Over a relay-only topology the
	// metadata has to cross the relay control tunnel, which is a different code
	// path from a direct link. ---
	var meta PeerMeta
	metaDeadline := time.Now().Add(30 * time.Second)
	for {
		if m, ok := nodeA.GetPeerMeta(bID); ok && (m.TapIP != "" || m.TapIPv6 != "") {
			meta = m
			break
		}
		if time.Now().After(metaDeadline) {
			t.Fatalf("%s: A never received the exit node's TAP IP; SetExitNode cannot resolve a gateway on this topology", topo.name)
		}
		time.Sleep(100 * time.Millisecond)
	}
	tapV4 := stripCIDR(meta.TapIP)
	tapV6 := stripCIDR(meta.TapIPv6)
	// CI runs non-root and without a real TAP device, so the exit node cannot
	// install a host default route; the routing orchestration is unit-tested
	// separately in gateway_test.go against the same fake.
	injectFakeRouteBackend(nodeA.Gateway)
	if serr := nodeA.Gateway.SetExitNode(bID.String(), tapV4, tapV6, nil); serr != nil {
		t.Fatalf("%s: SetExitNode failed: %v", topo.name, serr)
	}
	if !nodeA.isExitNodeActive() {
		t.Fatalf("%s: exit node did not become active", topo.name)
	}
	if pid := nodeA.Gateway.ActiveExitPeerPID(); pid != bID {
		t.Fatalf("%s: active exit peer = %s, want %s", topo.name, pid, bID)
	}

	_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")
	_ = pipeA.ConfigureIP("10.0.0.1/24", "fd00::1/64")

	// ONE reader per TAP device for the whole case: a second reader would race
	// the first for frames and silently eat them (see newFrameReader).
	readerB := newFrameReader(pipeB)
	t.Cleanup(readerB.Close)
	readerA := newFrameReader(pipeA)
	t.Cleanup(readerA.Close)

	clientMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	clientIP := net.ParseIP("10.0.0.1")
	publicIP := net.ParseIP("203.0.113.9")

	// The tag prefix is per-topology: the exit server applies content-based
	// dedup to broadcast-dst frames, so byte-identical frames would be dropped
	// as replays and read exactly like packet loss.
	prefix := "EXIT_TOPO_" + topo.name + "_"
	const (
		transitFrames = 96
		replyFrames   = 24
	)
	var want, wires [][]byte
	for i := 0; i < transitFrames; i++ {
		tag := []byte(fmt.Sprintf("%s%04d", prefix, i))
		want = append(want, tag)
		// Android L2 shape: every OS packet is wrapped with a broadcast dst.
		wires = append(wires, constructICMPv4PacketWithData(
			clientMAC, broadcast, clientIP, publicIP, 9600+i, 1, append(tag, make([]byte, 180)...)))
	}
	var repWant, replies [][]byte
	for i := 0; i < replyFrames; i++ {
		tag := []byte(fmt.Sprintf("%sREPLY_%04d", prefix, i))
		repWant = append(repWant, tag)
		replies = append(replies, constructICMPv4PacketWithData(
			broadcast, clientMAC, publicIP, clientIP, 9800+i, 1, tag))
	}

	coll := newConcurrentPayloadCollector(readerB, want)
	rcoll := newConcurrentPayloadCollector(readerA, repWant)

	for i := range wires {
		if _, werr := pipeA.Write(wires[i]); werr != nil {
			t.Fatalf("%s: pipeA.Write transit frame %d failed: %v", topo.name, i, werr)
		}
	}
	if !coll.waitUntil(want, 25*time.Second) {
		t.Fatalf("%s: only %d/%d transit frames reached the exit node's TAP; missing=%v",
			topo.name, countSeen(coll, want), transitFrames, coll.missing(want))
	}
	t.Logf("%s: %d/%d transit frames crossed the topology intact", topo.name, transitFrames, transitFrames)

	for i := range replies {
		if _, werr := pipeB.Write(replies[i]); werr != nil {
			t.Fatalf("%s: pipeB.Write reply %d failed: %v", topo.name, i, werr)
		}
	}
	if !rcoll.waitUntil(repWant, 25*time.Second) {
		t.Fatalf("%s: only %d/%d reply frames reached the client's TAP; missing=%v",
			topo.name, countSeen(rcoll, repWant), replyFrames, rcoll.missing(repWant))
	}
	t.Logf("%s: %d/%d reply frames crossed the topology intact", topo.name, replyFrames, replyFrames)

	// --- Per-path TX attribution: which paths actually carried the workload.
	// This is the assertion that separates "the topology exists" from "the
	// scheduler used it". ---
	var txDirect, txRelay int
	for _, c := range nodeA.Host.Network().ConnsToPeer(bID) {
		if c == nil || c.RemoteMultiaddr() == nil {
			continue
		}
		_, frames, ok := nodeA.pathTxStats(bID, c.RemoteMultiaddr().String())
		if !ok || frames == 0 {
			continue
		}
		if connIsRelayForPeer(c, bID) {
			txRelay++
		} else {
			txDirect++
		}
	}
	t.Logf("%s: workload landed on %d direct + %d relay path(s) (want %d concurrent)",
		topo.name, txDirect, txRelay, topo.spray)

	if txDirect+txRelay < topo.spray {
		t.Fatalf("%s: multipath spray used only %d path(s) of the %d expected (%d direct + %d relay)",
			topo.name, txDirect+txRelay, topo.spray, txDirect, txRelay)
	}
	if topo.relayCarries && txRelay < topo.relay {
		t.Fatalf("%s: a relay-only topology must spray over BOTH circuits, but only %d of %d carried traffic",
			topo.name, txRelay, topo.relay)
	}
	if !topo.relayCarries && topo.relay > 0 {
		// Circuit-relay paths are failover-only while a direct path is healthy
		// (nonRelayStreams). They are still registered and carry a stream —
		// asserted above — so a direct-path failure can fall back onto them.
		t.Logf("%s: %d relay circuit(s) stayed failover-only, as designed", topo.name, topo.relay)
	}
}

// topoPathsHaveStreams reports whether every live connection to p carries at
// least one registered application stream from n's point of view.
func topoPathsHaveStreams(n *Node, p peer.ID) bool {
	conns := n.Host.Network().ConnsToPeer(p)
	if len(conns) == 0 {
		return false
	}
	ps := n.Dispatcher.GetPeerStreams(p)
	if ps == nil {
		return false
	}
	have := make(map[string]bool, len(conns))
	for _, s := range ps.GetAllStreams() {
		if s == nil || s.Conn() == nil {
			continue
		}
		have[s.Conn().ID()] = true
	}
	for _, c := range conns {
		if c == nil || !have[c.ID()] {
			return false
		}
	}
	return true
}

// topologyStreamsAreRelayOnly reports whether every stream n still schedules for
// p rides a relay path. Used by the failover test to tell "the dead direct
// stream has been retired" apart from "the scheduler will retry it forever".
func topologyStreamsAreRelayOnly(n *Node, p peer.ID) bool {
	ps := n.Dispatcher.GetPeerStreams(p)
	if ps == nil {
		return false
	}
	streams := ps.GetAllStreams()
	if len(streams) == 0 {
		return false
	}
	for _, s := range streams {
		if !streamIsRelayForPeer(s, p) {
			return false
		}
	}
	return true
}

// TestE2EMultipathDirectPlusRelayFailover covers the only reason the
// direct+relay topology is worth having: the circuit must take over once the
// direct path dies.
//
// Its counterpart is the direct-plus-relay case in the matrix above, which pins
// the steady state — while a direct path is healthy the circuit is REGISTERED
// but not scheduled (nonRelayStreams). Together they pin the whole contract:
// idle in the steady state, carrying data on failure. Without the failover half
// "direct + relay" would be indistinguishable from a single-path link with a
// spare that never gets used, and a direct-path outage would look like a
// complete tunnel outage to the user.
func TestE2EMultipathDirectPlusRelayFailover(t *testing.T) {
	if testing.Short() {
		t.Skip("skips relay/NIC-binding multipath e2e in -short mode")
	}
	topo := mpTopology{name: "direct-plus-relay-failover", direct: 1, relay: 1, spray: 1}
	v4 := topologyNICv4(t)
	nodeA, nodeB, pipeA, pipeB := topologyNodes(t, topo, v4)
	directConns, _, circuits := buildTopologyPaths(t, topo, v4, nodeA, nodeB)
	prepareTopologyStreams(t, topo, nodeA, nodeB)

	bID := nodeB.Host.ID()
	_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")
	_ = pipeA.ConfigureIP("10.0.0.1/24", "fd00::1/64")

	// Activate the Exit Node on A exactly as the Android client does: peer ID
	// only, TAP IP resolved from peer metadata. The burst below is addressed to
	// a PUBLIC address, so without an active exit node the core is right to
	// suppress it from the mesh flood (nothing in the mesh can deliver it — see
	// TestL3TunnelDoesNotFloodUnroutableWANFrames, which pins that). This test
	// measured flood delivery before, not relay failover, and only passed
	// because an L3-shaped frame with a broadcast destination MAC slipped past
	// the flood guard.
	var exitMeta PeerMeta
	exitMetaDeadline := time.Now().Add(30 * time.Second)
	for {
		if m, ok := nodeA.GetPeerMeta(bID); ok && (m.TapIP != "" || m.TapIPv6 != "") {
			exitMeta = m
			break
		}
		if time.Now().After(exitMetaDeadline) {
			t.Fatalf("%s: A never received the exit node's TAP IP; SetExitNode cannot resolve a gateway", topo.name)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// CI runs non-root and without a real TAP device, so the exit node cannot
	// install a host default route; the routing orchestration is unit-tested
	// separately in gateway_test.go against the same fake.
	injectFakeRouteBackend(nodeA.Gateway)
	if serr := nodeA.Gateway.SetExitNode(bID.String(), stripCIDR(exitMeta.TapIP), stripCIDR(exitMeta.TapIPv6), nil); serr != nil {
		t.Fatalf("%s: SetExitNode failed: %v", topo.name, serr)
	}
	if !nodeA.isExitNodeActive() {
		t.Fatalf("%s: exit node did not become active", topo.name)
	}

	readerB := newFrameReader(pipeB)
	t.Cleanup(readerB.Close)

	clientMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	clientIP := net.ParseIP("10.0.0.1")
	publicIP := net.ParseIP("203.0.113.9")
	prefix := "EXIT_TOPO_FAILOVER_"

	// --- Break the direct path. ---
	// Pin the peerstore to the circuit address only: identify seeded the direct
	// address, and leaving it there would let the multipath repair loop simply
	// re-dial the path this test just destroyed.
	nodeA.Host.Peerstore().SetAddrs(bID, circuits, peerstore.PermanentAddrTTL)
	for _, c := range directConns {
		if c != nil {
			_ = c.Close()
		}
	}
	// A dead stream stays registered until a write fails on it, so probe with
	// disposable frames until the scheduler's set is relay-only. Without this
	// the measured burst would burn a write deadline per frame on a stream that
	// can never deliver, which reads like a tunnel stall instead of a failover.
	probeDeadline := time.Now().Add(20 * time.Second)
	for !topologyStreamsAreRelayOnly(nodeA, bID) {
		if time.Now().After(probeDeadline) {
			t.Fatalf("the dead direct stream was never retired from the multipath set (%d stream(s) still scheduled)",
				streamLen(nodeA.Dispatcher.GetPeerStreams(bID)))
		}
		tag := []byte(fmt.Sprintf("%sPROBE_%d", prefix, time.Now().UnixNano()))
		_, _ = pipeA.Write(constructICMPv4PacketWithData(clientMAC, broadcast, clientIP, publicIP, 9700, 1, tag))
		time.Sleep(150 * time.Millisecond)
	}
	t.Logf("failover: direct path closed (%d conn(s)), scheduler set is relay-only", len(directConns))

	// --- The circuit must now carry the whole workload, intact. ---
	const frames = 48
	var want, wires [][]byte
	for i := 0; i < frames; i++ {
		tag := []byte(fmt.Sprintf("%s%04d", prefix, i))
		want = append(want, tag)
		wires = append(wires, constructICMPv4PacketWithData(
			clientMAC, broadcast, clientIP, publicIP, 9900+i, 1, append(tag, make([]byte, 180)...)))
	}
	coll := newConcurrentPayloadCollector(readerB, want)
	for i := range wires {
		if _, werr := pipeA.Write(wires[i]); werr != nil {
			t.Fatalf("pipeA.Write frame %d failed: %v", i, werr)
		}
	}
	if !coll.waitUntil(want, 25*time.Second) {
		t.Fatalf("after the direct path died only %d/%d frames crossed the surviving circuit; missing=%v",
			countSeen(coll, want), frames, coll.missing(want))
	}
	t.Logf("failover: %d/%d frames crossed the surviving relay circuit", frames, frames)

	// Confirm the circuit — not a re-dialed direct path — did the work.
	_, relayConns := classifyTopoConns(nodeA.Host.Network().ConnsToPeer(bID), bID)
	if len(relayConns) == 0 {
		t.Fatal("the relay circuit itself disappeared")
	}
	var relayFrames uint64
	for _, c := range relayConns {
		if _, fr, ok := nodeA.pathTxStats(bID, c.RemoteMultiaddr().String()); ok {
			relayFrames += fr
		}
	}
	if relayFrames == 0 {
		t.Fatal("no frame was attributed to the surviving relay circuit")
	}
	t.Logf("failover: the relay circuit carried %d frames after the direct path died", relayFrames)
}

// TestE2EMultipathRelayDualFailover is the relay-only counterpart of
// TestE2EMultipathDirectPlusRelayFailover. The exit node sits behind a NAT
// reachable ONLY through two independent circuit-relay paths; when ONE circuit
// dies — the radio path it rides dropping away — the surviving circuit must
// carry the whole workload. That is the mobile scenario the client actually
// runs, and the steady-state relay-dual case in the matrix above does not cover
// the failover half.
func TestE2EMultipathRelayDualFailover(t *testing.T) {
	if testing.Short() {
		t.Skip("skips relay/NIC-binding multipath e2e in -short mode")
	}
	topo := mpTopology{name: "relay-dual-failover", direct: 0, relay: 2, spray: 2}
	v4 := topologyNICv4(t)
	nodeA, nodeB, pipeA, pipeB := topologyNodes(t, topo, v4)
	_, relayed, _ := buildTopologyPaths(t, topo, v4, nodeA, nodeB)
	prepareTopologyStreams(t, topo, nodeA, nodeB)
	bID := nodeB.Host.ID()

	// Activate the Exit Node exactly as the Android client does: peer ID only,
	// TAP IP resolved from peer metadata crossing the relay control tunnel.
	var meta PeerMeta
	metaDeadline := time.Now().Add(30 * time.Second)
	for {
		if m, ok := nodeA.GetPeerMeta(bID); ok && (m.TapIP != "" || m.TapIPv6 != "") {
			meta = m
			break
		}
		if time.Now().After(metaDeadline) {
			t.Fatalf("%s: A never received the exit node's TAP IP", topo.name)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// CI runs non-root and without a real TAP device; the routing orchestration
	// is unit-tested separately in gateway_test.go against the same fake.
	injectFakeRouteBackend(nodeA.Gateway)
	if serr := nodeA.Gateway.SetExitNode(bID.String(), stripCIDR(meta.TapIP), stripCIDR(meta.TapIPv6), nil); serr != nil {
		t.Fatalf("%s: SetExitNode failed: %v", topo.name, serr)
	}
	if !nodeA.isExitNodeActive() {
		t.Fatalf("%s: exit node did not become active", topo.name)
	}

	_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")
	_ = pipeA.ConfigureIP("10.0.0.1/24", "fd00::1/64")
	readerB := newFrameReader(pipeB)
	t.Cleanup(readerB.Close)

	clientMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	clientIP := net.ParseIP("10.0.0.1")
	publicIP := net.ParseIP("203.0.113.9")
	prefix := "EXIT_TOPO_RELAY_FAILOVER_"

	// --- Break ONE of the two relay circuits. ---
	if len(relayed) < 2 {
		t.Fatalf("%s: expected 2 relay circuits, got %d", topo.name, len(relayed))
	}
	victim, survivor := relayed[0], relayed[1]
	// Pin the peerstore to the surviving circuit address only: identify seeded
	// both circuit addresses, and leaving the dead one there would let the
	// multipath repair loop simply re-dial the circuit this test just destroyed
	// (both relays are still up; only the circuit CONN through one of them died).
	nodeA.Host.Peerstore().SetAddrs(bID, []ma.Multiaddr{survivor.RemoteMultiaddr()}, peerstore.PermanentAddrTTL)
	_ = victim.Close()
	t.Logf("%s: closed one circuit (conn %s); the surviving circuit (conn %s) must carry the workload",
		topo.name, victim.ID(), survivor.ID())

	// --- The surviving circuit must now carry the whole workload, intact. ---
	const frames = 48
	var want, wires [][]byte
	for i := 0; i < frames; i++ {
		tag := []byte(fmt.Sprintf("%s%04d", prefix, i))
		want = append(want, tag)
		wires = append(wires, constructICMPv4PacketWithData(
			clientMAC, broadcast, clientIP, publicIP, 9900+i, 1, append(tag, make([]byte, 180)...)))
	}
	coll := newConcurrentPayloadCollector(readerB, want)
	for i := range wires {
		if _, werr := pipeA.Write(wires[i]); werr != nil {
			t.Fatalf("%s: pipeA.Write frame %d failed: %v", topo.name, i, werr)
		}
	}
	if !coll.waitUntil(want, 25*time.Second) {
		t.Fatalf("%s: after one circuit died only %d/%d frames crossed the surviving circuit; missing=%v",
			topo.name, countSeen(coll, want), frames, coll.missing(want))
	}
	t.Logf("%s: %d/%d frames crossed the surviving circuit after one circuit died", topo.name, frames, frames)

	// Confirm the surviving circuit — not a re-dialed dead one — did the work.
	if got := len(nodeA.Host.Network().ConnsToPeer(bID)); got != 1 {
		t.Fatalf("%s: A re-dialed the dead circuit; now %d conn(s) to the exit node", topo.name, got)
	}
	var survivorFrames uint64
	if _, fr, ok := nodeA.pathTxStats(bID, survivor.RemoteMultiaddr().String()); ok {
		survivorFrames = fr
	}
	if survivorFrames == 0 {
		t.Fatalf("%s: no frame was attributed to the surviving circuit", topo.name)
	}
	t.Logf("%s: the surviving circuit carried %d frames after the other died", topo.name, survivorFrames)
}
