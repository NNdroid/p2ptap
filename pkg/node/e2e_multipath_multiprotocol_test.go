package node

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/test"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"p2ptap/pkg/tap"
)

// splitAddrsByFamily partitions listen/peer multiaddrs into IPv4 and IPv6 lists,
// dropping loopback and IPv6 link-local (fe80::) addresses — those are exactly
// the ones filterUndialableAddrs would throw away, so they can never become a
// multipath path anyway.
func splitAddrsByFamily(addrs []ma.Multiaddr) (v4, v6 []ma.Multiaddr) {
	for _, a := range addrs {
		if a == nil {
			continue
		}
		if manet.IsIPLoopback(a) || manet.IsIP6LinkLocal(a) {
			continue
		}
		if _, err := a.ValueForProtocol(ma.P_IP6); err == nil {
			v6 = append(v6, a)
		} else if _, err := a.ValueForProtocol(ma.P_IP4); err == nil {
			v4 = append(v4, a)
		}
	}
	return v4, v6
}

// TestE2EMultipathMultiProtocolDirectLink proves the user's correction to the
// earlier "direct-link multipath can never get a 2nd path" conclusion: a direct
// (non-relay) link CAN carry multiple parallel paths, because the two peers may
// be reachable over DIFFERENT transports (TCP and QUIC) and/or over MULTIPLE IP
// families (IPv4 and IPv6). libp2p keeps one connection per (peer, address), so a
// dual-protocol / dual-stack peer naturally yields >1 connection, and the
// multipath scheduler can split traffic across them.
//
// The previous code could never OPEN that 2nd path, because Host.Connect (and
// swarm.dialPeer) short-circuits on the existing connection and returns it
// instead of dialing the 2nd address. The fix adds Node.dialPeerToAddr ->
// swarm.DialPeerToAddr which bypasses the short-circuit and dials the specific
// missing address. This test asserts the end-to-end behaviour:
//
//   - Node B binds TCP and QUIC listeners on its IPv4 NIC (and a TCP listener on
//     its IPv6 NIC when one is present), so B is reachable over distinct paths;
//   - multipath path-repair establishes >=2 connections from A to B;
//   - those connections are on DISTINCT paths (different transport or family);
//   - each connection gets its own data stream (EnsureStreamsOnAllConns);
//   - a frame burst flows intact across the 2+ path multipath set.
//
// The sandbox has no IPv6 NIC, so the TCP+QUIC-on-IPv4 case is what actually
// runs here; it is sufficient to prove the multi-path point (协议可以不同).
func TestE2EMultipathMultiProtocolDirectLink(t *testing.T) {
	if testing.Short() {
		t.Skip("skips NIC-binding multipath e2e in -short mode")
	}

	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")

	// Bind B to explicit NIC IPs so the advertised/dialable addresses are real
	// interface addresses (not 0.0.0.0 / :: wildcards, which filterUndialableAddrs
	// drops as undialable). The IPv4 NIC is always required; an IPv6 NIC (if the
	// host has one) adds a second address family, exercising the multi-IP case.
	nics, err := physicalNICIPs()
	if err != nil {
		t.Skipf("physicalNICIPs failed: %v", err)
	}
	var v4, v6 string
	for _, ip := range nics {
		if ip.To4() != nil && v4 == "" {
			v4 = ip.String()
		} else if ip.To4() == nil && v6 == "" {
			v6 = ip.String()
		}
	}
	if v4 == "" {
		t.Skip("host has no non-loopback IPv4 NIC; cannot bind NodeB")
	}

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "multipath")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "multipath")
	// Explicit per-NIC listeners. TCP + QUIC on the IPv4 NIC prove the
	// "协议可以不同" (different transport) case; an extra TCP listener on the IPv6
	// NIC (when present and not link-local) proves the "多ip / ipv4+ipv6" case.
	bAddrs := []string{
		fmt.Sprintf("/ip4/%s/tcp/0", v4),
		fmt.Sprintf("/ip4/%s/udp/0/quic-v1", v4),
	}
	if v6 != "" && !manet.IsIP6LinkLocal(ma.StringCast("/ip6/" + v6)) {
		bAddrs = append(bAddrs, fmt.Sprintf("/ip6/%s/tcp/0", v6))
	}
	cfgB.ListenAddrs = bAddrs

	nodeA, err := NewNodeWithTAP(cfgA, tapA, nil)
	if err != nil {
		t.Fatalf("create NodeA: %v", err)
	}
	nodeB, err := NewNodeWithTAP(cfgB, tapB, nil)
	if err != nil {
		t.Fatalf("create NodeB: %v", err)
	}
	nodes := []*Node{nodeA, nodeB}
	defer func() {
		for _, n := range nodes {
			n.Close()
		}
	}()
	nodeA.Start()
	nodeB.Start()

	// Wait until B has bound BOTH a TCP and a QUIC listener on the IPv4 NIC.
	deadline0 := time.Now().Add(15 * time.Second)
	gotTCP, gotQUIC := false, false
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
		t.Skipf("NodeB did not bind both a TCP and a QUIC listener on the IPv4 NIC (tcp=%v quic=%v); cannot run multi-protocol multipath e2e", gotTCP, gotQUIC)
	}
	t.Logf("NodeB multi-protocol listeners on %s: tcp=%v quic=%v", v4, gotTCP, gotQUIC)

	// Make A aware of ALL of B's addresses. In a real deployment Identify would
	// populate this; here we seed it explicitly so the test does not depend on
	// Identify timing.
	bInfo := peer.AddrInfo{ID: nodeB.Host.ID(), Addrs: nodeB.Host.Network().ListenAddresses()}
	nodeA.Host.Peerstore().AddAddrs(bInfo.ID, bInfo.Addrs, peerstore.PermanentAddrTTL)

	// Drive multipath repair until A holds >=2 connections to B. This is the exact
	// code path that was previously short-circuited by Host.Connect.
	repairDeadline := time.Now().Add(30 * time.Second)
	for {
		nodeA.repairMultipathPaths(nodeB.Host.ID())
		if len(nodeA.Host.Network().ConnsToPeer(nodeB.Host.ID())) >= 2 {
			break
		}
		if time.Now().After(repairDeadline) {
			conns := nodeA.Host.Network().ConnsToPeer(nodeB.Host.ID())
			t.Fatalf("multi-protocol multipath repair established only %d connection(s) to B (expected >=2): %v", len(conns), conns)
		}
		time.Sleep(100 * time.Millisecond)
	}
	conns := nodeA.Host.Network().ConnsToPeer(nodeB.Host.ID())
	t.Logf("multi-protocol multipath: A holds %d connections to B", len(conns))
	if len(conns) < 2 {
		t.Fatalf("expected >=2 connections to multi-protocol peer, got %d", len(conns))
	}

	// Sanity: the connections must be on DISTINCT paths. Two connections on the
	// same (IP, transport) key would be a libp2p dedupe bug, not a multipath win.
	pathKeys := make(map[string]bool)
	hasTCP, hasQUIC := false, false
	for _, c := range conns {
		ra := c.RemoteMultiaddr()
		pathKeys[multipathAddrKey(ra)] = true
		s := ra.String()
		if strings.Contains(s, "/tcp/") {
			hasTCP = true
		}
		if strings.Contains(s, "/quic-v1") {
			hasQUIC = true
		}
	}
	if len(pathKeys) < 2 {
		t.Fatalf("the %d connections collapse to fewer than 2 distinct multipath paths: %v", len(conns), conns)
	}
	// At minimum the dual-protocol case must yield a TCP path AND a QUIC path.
	if !hasTCP || !hasQUIC {
		t.Fatalf("expected both a TCP and a QUIC connection to B, got tcp=%v quic=%v (conns=%v)", hasTCP, hasQUIC, conns)
	}

	// Each connection must get its own data stream (EnsureStreamsOnAllConns).
	nodeA.Dispatcher.EnsureStreamsOnAllConns(nodeB.Host.ID())
	streamDeadline := time.Now().Add(15 * time.Second)
	for {
		allHave := true
		for _, c := range nodeA.Host.Network().ConnsToPeer(nodeB.Host.ID()) {
			if len(c.GetStreams()) == 0 {
				allHave = false
				break
			}
		}
		if allHave {
			break
		}
		if time.Now().After(streamDeadline) {
			t.Fatalf("not all multi-protocol connections got a data stream within timeout")
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("multi-protocol multipath: all %d connections carry a data stream", len(conns))

	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeB, nodeA)
	time.Sleep(300 * time.Millisecond)
	_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")

	reader := newFrameReader(pipeB)
	t.Cleanup(reader.Close)

	const frames = 48
	var wireFrames [][]byte
	var payloads [][]byte
	for i := 0; i < frames; i++ {
		tag := fmt.Sprintf("MP_MULTI_%d", i)
		payloads = append(payloads, []byte(tag))
		wireFrames = append(wireFrames, constructICMPv4PacketWithData(
			testMACA, testMACB, net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 8300+i, 1, []byte(tag)))
	}
	coll := newConcurrentPayloadCollector(reader, payloads)
	for i := 0; i < frames; i++ {
		if _, werr := pipeA.Write(wireFrames[i]); werr != nil {
			t.Fatalf("write %d failed: %v", i, werr)
		}
	}
	coll.wait(t, pipeA, wireFrames, payloads, 16*time.Second, "A->B(multi-protocol multipath 2-path)")
	if got := countSeen(coll, payloads); got != frames {
		t.Fatalf("multi-protocol multipath delivered %d/%d frames", got, frames)
	}
	t.Logf("multi-protocol multipath: %d/%d frames delivered intact across the 2-path set", frames, frames)
}

// TestMultipathAddrKey locks down the normalization used to decide whether two
// addresses represent the SAME multipath path. The two easy-to-get-wrong cases
// are: (1) a peerstore address carries a trailing /p2p/<id> that a transport
// address does not, so the two forms must compare equal; (2) it must NOT blindly
// strip the last component, or it would also drop /tcp or /quic and collapse
// distinct paths. Different address families and different transports must yield
// distinct keys so each becomes its own parallel path.
func TestMultipathAddrKey(t *testing.T) {
	base := ma.StringCast("/ip4/1.2.3.4/tcp/4001")
	// A real, valid peer ID so peer.IDFromP2PAddr succeeds and the /p2p component
	// is actually stripped (a malformed id makes IDFromP2PAddr fail and the
	// component would wrongly survive).
	pid, pidErr := test.RandPeerID()
	if pidErr != nil {
		t.Fatalf("RandPeerID: %v", pidErr)
	}
	withP2P := ma.StringCast("/ip4/1.2.3.4/tcp/4001/p2p/" + pid.String())

	if got := multipathAddrKey(base); got != "/ip4/1.2.3.4/tcp/4001" {
		t.Fatalf("base key = %q, want /ip4/1.2.3.4/tcp/4001", got)
	}
	// The /p2p component must be stripped so peerstore and conn forms match.
	if got := multipathAddrKey(withP2P); got != "/ip4/1.2.3.4/tcp/4001" {
		t.Fatalf("/p2p form key = %q, want /ip4/1.2.3.4/tcp/4001 (p2p component must be stripped)", got)
	}
	// The trailing /tcp must NOT be stripped.
	if got := multipathAddrKey(withP2P); got == "/ip4/1.2.3.4" {
		t.Fatalf("BUG: /tcp was stripped from %q", withP2P)
	}

	// Different address family => distinct path.
	v6 := ma.StringCast("/ip6/fd00::1/tcp/4001")
	if multipathAddrKey(base) == multipathAddrKey(v6) {
		t.Fatalf("IPv4 and IPv6 addresses must be distinct multipath paths")
	}
	// Different transport on same IP => distinct path. quic-v1 is layered on
	// UDP, so the canonical form is /udp/<port>/quic-v1.
	quic := ma.StringCast("/ip4/1.2.3.4/udp/4001/quic-v1")
	if multipathAddrKey(base) == multipathAddrKey(quic) {
		t.Fatalf("tcp and quic must be distinct multipath paths")
	}
	// Same family/transport with a different port => distinct path.
	otherPort := ma.StringCast("/ip4/1.2.3.4/tcp/4002")
	if multipathAddrKey(base) == multipathAddrKey(otherPort) {
		t.Fatalf("different ports must be distinct multipath paths")
	}
}
