package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	relayclient "github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	ma "github.com/multiformats/go-multiaddr"

	"p2ptap/pkg/packet"
	"p2ptap/pkg/tap"
)

// TestE2EExitNodeReturnPath covers the HALF of the Exit Node that no other test
// touches: the RETURN path, from the Exit server's kernel back into the client's
// TUN device.
//
// The existing exit-node e2e suites (e2e_exit_node_relay_test.go,
// e2e_exit_node_multipath_test.go) only assert that client egress frames reach
// the Exit server's TAP. That is the easy direction: the client resolves the
// Exit peer by peer ID and pushes a packed frame down a stream. The direction
// that actually breaks a phone — and the one whose failure looks exactly like
// "the Exit Node says it is active but nothing on the phone works" — is the way
// back:
//
//  1. The Exit server's kernel has an IP packet for the client's TAP address.
//     It needs a link-layer address for it, so it emits an ARP request into the
//     TAP device.
//  2. The node must PROXY-ANSWER that ARP. The TUN device at the other end
//     belongs to a phone: it never answers ARP itself, because an L3 VpnService
//     TUN has no ARP stack at all. If the proxy does not answer, the server's
//     kernel never transmits the packet and every reply is lost.
//  3. The proxied ARP reply must name the CLIENT's MAC, not the server's own.
//     If it names the server's local MAC, the kernel sends the reply to itself,
//     the node resolves it back to "me", and the packet is dropped.
//  4. The server must then resolve the client's TAP IP to the client's peer and
//     push the frame back over whatever path exists — here, a relay-only
//     circuit, which is the deployment the phone actually runs.
//
// Steps 1-4 are asserted individually so a failure names the broken stage
// instead of only "no delivery".
func TestE2EExitNodeReturnPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skips relay e2e in -short mode")
	}

	r, err := libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.EnableRelayService(),
		libp2p.ForceReachabilityPublic(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	rInfo := peer.AddrInfo{ID: r.ID(), Addrs: r.Addrs()}

	tapA, pipeA := tap.NewMemTAPPair("tapA", "pipeA")
	tapB, pipeB := tap.NewMemTAPPair("tapB", "pipeB")

	cfgA := createTestNodeConfig("10.0.0.1/24", "fd00::1/64", "multipath")
	cfgB := createTestNodeConfig("10.0.0.2/24", "fd00::2/64", "multipath")
	cfgB.ExitNode.Enable = true
	// The Exit server has to masquerade. On the CI host this backend is a no-op,
	// but the flag still decides whether the manager considers itself an Exit
	// server, which is what rewriteRxDstMAC consults on the receive path.
	cfgB.ExitNode.NATMasquerade = true

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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := relayclient.Reserve(ctx, nodeB.Host, rInfo); err != nil {
		t.Fatalf("B reserve: %v", err)
	}
	if err := nodeA.Host.Connect(ctx, rInfo); err != nil {
		t.Fatalf("A connect relay: %v", err)
	}
	circuit, _ := ma.NewMultiaddr("/p2p/" + r.ID().String() + "/p2p-circuit/p2p/" + nodeB.Host.ID().String())
	nodeA.Host.Peerstore().AddAddrs(nodeB.Host.ID(), []ma.Multiaddr{circuit}, peerstore.PermanentAddrTTL)
	if _, err := relayclient.Reserve(ctx, nodeA.Host, rInfo); err != nil {
		t.Fatalf("A reserve: %v", err)
	}
	if err := nodeA.dialPeerToAddr(ctx, nodeB.Host.ID(), circuit); err != nil {
		t.Fatalf("A dial circuit: %v", err)
	}
	if nodeA.isDirectlyConnected(nodeB.Host.ID()) {
		t.Skip("A formed a DIRECT connection to B; the relay-only invariant cannot hold in this sandbox")
	}

	waitOverlayReady(t, nodeA, nodeB)
	waitStreamReady(t, nodeA, nodeB)
	// Deliberately NOT calling waitStreamReady(nodeB, nodeA): in production the
	// Exit server never receives a TAP frame from the client until it has one,
	// so nothing guarantees an outbound data stream from the server to the
	// client exists. The return path must therefore bootstrap that stream on
	// demand. Priming it here would hide exactly the failure this test is for.

	// --- Activate the Exit Node on the client, exactly like the Android API. ---
	var meta PeerMeta
	metaDeadline := time.Now().Add(30 * time.Second)
	for {
		if m, ok := nodeA.GetPeerMeta(nodeB.Host.ID()); ok && (m.TapIP != "" || m.TapIPv6 != "") {
			meta = m
			break
		}
		if time.Now().After(metaDeadline) {
			t.Fatalf("A never received the exit node's TAP IP over the relay control tunnel")
		}
		time.Sleep(100 * time.Millisecond)
	}
	tapV4, tapV6 := meta.TapIP, meta.TapIPv6
	if i := strings.IndexByte(tapV4, '/'); i >= 0 {
		tapV4 = tapV4[:i]
	}
	if i := strings.IndexByte(tapV6, '/'); i >= 0 {
		tapV6 = tapV6[:i]
	}
	injectFakeRouteBackend(nodeA.Gateway)
	if err := nodeA.Gateway.SetExitNode(nodeB.Host.ID().String(), tapV4, tapV6, nil); err != nil {
		t.Fatalf("SetExitNode over relay failed: %v", err)
	}
	if !nodeA.isExitNodeActive() {
		t.Fatalf("exit node did not become active over the relay path")
	}

	// The Exit server must know the client's TAP address to route replies to it.
	// In production that comes from the client's own metadata; wait for it so the
	// ARP-proxy stage below is tested against a populated ARP index rather than a
	// race.
	reverseMetaDeadline := time.Now().Add(30 * time.Second)
	for {
		if m, ok := nodeB.GetPeerMeta(nodeA.Host.ID()); ok && m.TapIP != "" {
			t.Logf("exit-return: server knows client metadata (tap=%s mac=%s)", m.TapIP, m.TapMAC)
			break
		}
		if time.Now().After(reverseMetaDeadline) {
			t.Fatalf("the Exit server never received the client's metadata; it cannot resolve a reply destination, so every return packet would be dropped")
		}
		time.Sleep(100 * time.Millisecond)
	}

	_ = pipeB.ConfigureIP("10.0.0.2/24", "fd00::2/64")
	_ = pipeA.ConfigureIP("10.0.0.1/24", "fd00::1/64")

	readerB := newFrameReader(pipeB)
	t.Cleanup(readerB.Close)
	readerA := newFrameReader(pipeA)
	t.Cleanup(readerA.Close)

	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")
	publicIP := net.ParseIP("203.0.113.9")

	// --- Stage 1-3: the Exit server's kernel ARPs for the client. ---
	// A real Linux box emits this ARP request the moment it has a reply to
	// deliver to an address with no neighbour entry. Nothing else in the test
	// suite exercises it, and a phone's TUN can never answer it itself.
	serverMAC, err := net.ParseMAC(cfgB.TapMAC)
	if err != nil {
		t.Fatalf("parse server TapMAC %q: %v", cfgB.TapMAC, err)
	}
	arpReq := buildARPRequest(serverMAC, serverIP, clientIP)
	if _, werr := pipeB.Write(arpReq); werr != nil {
		t.Fatalf("pipeB.Write ARP request failed: %v", werr)
	}

	clientMAC := waitARPReplyFor(t, readerB, clientIP, 10*time.Second)
	if clientMAC == nil {
		t.Fatalf("the Exit server never proxy-answered the ARP request for the client TAP IP %s; "+
			"the server kernel has no link-layer address to send replies to, so no return packet can ever leave the tunnel "+
			"(this is exactly what an Android client sees as \"exit node active but nothing works\")", clientIP)
	}
	if bytes.Equal(clientMAC, serverMAC) {
		t.Fatalf("the Exit server answered the ARP request for %s with its OWN MAC %s; "+
			"replies are then addressed to the server itself and never reach the client", clientIP, serverMAC)
	}
	t.Logf("exit-return: server proxied client %s -> %s", clientIP, clientMAC)

	// --- Stage 4: the reply itself must cross the relay into the client's TUN. ---
	const frames = 32
	var want [][]byte
	for i := 0; i < frames; i++ {
		tag := []byte(fmt.Sprintf("EXIT_RETURN_%04d", i))
		want = append(want, tag)
		reply := constructICMPv4PacketWithData(
			serverMAC, clientMAC, publicIP, clientIP, 9700+i, 1, append(tag, make([]byte, 120)...))
		if _, werr := pipeB.Write(reply); werr != nil {
			t.Fatalf("pipeB.Write reply %d failed: %v", i, werr)
		}
	}
	coll := newConcurrentPayloadCollector(readerA, want)
	if !coll.waitUntil(want, 25*time.Second) {
		got := countSeen(coll, want)
		t.Fatalf("only %d/%d return frames reached the client's TUN; "+
			"the Exit server accepted the packet from its kernel but the frame never came back over the overlay", got, frames)
	}
	if !nodeA.isExitNodeActive() {
		t.Fatalf("the exit node was cleared while return traffic was flowing")
	}
	t.Logf("exit-return: %d/%d return frames reached the client TUN over the relay", frames, frames)
}

// waitARPReplyFor drains frames from the Exit server's TAP side until it finds an
// ARP reply that answers for targetIP, and returns the MAC that was advertised
// in the reply's sender field. Returns nil when the deadline expires.
//
// Expected shapes (RFC 826, Ethernet/IPv4, 28-byte ARP body):
//
//	[0:6]   dst MAC
//	[6:12]  src MAC
//	[12:14] 0x0806
//	[14:16] htype = 1
//	[16:18] ptype = 0x0800
//	[18]    hlen = 6
//	[19]    plen = 4
//	[20:22] oper = 2 (reply)
//	[22:28] sender MAC
//	[28:32] sender IP
//	[32:38] target MAC
//	[38:42] target IP
func waitARPReplyFor(t *testing.T, fr *frameReader, targetIP net.IP, timeout time.Duration) net.HardwareAddr {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case f := <-fr.frames:
			if len(f) < 42 || binary.BigEndian.Uint16(f[12:14]) != packet.EtherTypeARP {
				continue
			}
			if binary.BigEndian.Uint16(f[20:22]) != 2 {
				continue // not a reply
			}
			if !bytes.Equal(net.IP(f[38:42]), targetIP.To4()) {
				continue
			}
			return net.HardwareAddr(f[22:28])
		case <-deadline:
			return nil
		}
	}
}
