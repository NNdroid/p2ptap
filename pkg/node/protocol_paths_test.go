package node

import (
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

// A bare Node with only the subnet fields populated is enough for isMeshLocalIP:
// lookupPeerIDByAdvertisedSubnet and lookupPeerMACByIPv6 both tolerate a nil
// arpIndex, so the index is built directly rather than through storePeerMeta
// (which also rebuilds the whole index and needs a live config).
func bareMeshNode(t *testing.T) *Node {
	t.Helper()
	n := &Node{}
	var err error
	_, n.localV4Net, err = net.ParseCIDR("10.9.9.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, n.localV6Net, err = net.ParseCIDR("fd00:99::/64")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// installAdvertisedSubnet puts a peer's advertised prefixes straight into the
// read index, bypassing the config gate that rebuildARPIndex applies.
func installAdvertisedSubnet(t *testing.T, n *Node, p peer.ID, cidr string) {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	n.arpIndexMu.Lock()
	idx := n.arpIndex
	if idx == nil {
		idx = &arpIndex{}
	}
	idx.subnets = append(idx.subnets, arpSubnetEntry{net: ipNet, pid: p})
	n.arpIndex = idx
	n.arpIndexMu.Unlock()
}

func testMA(s string) multiaddr.Multiaddr {
	m, err := multiaddr.NewMultiaddr(s)
	if err != nil {
		panic(err)
	}
	return m
}

// The port STUN reports belongs to the throwaway socket the binder probed with
// — nothing is listening on it. Only the observed IP is usable, paired with
// our own listener ports.
func TestReflexiveUDPAddrsUsesListenerPorts(t *testing.T) {
	stun := []multiaddr.Multiaddr{testMA("/ip4/203.0.113.7/udp/54321/quic-v1")}
	listeners := []multiaddr.Multiaddr{
		testMA("/ip4/192.168.1.50/udp/40000/quic-v1"),
		testMA("/ip4/192.168.1.50/udp/41000/webrtc-direct"),
		testMA("/ip4/192.168.1.50/udp/41001/quic-v1"),
		testMA("/ip4/192.168.1.50/udp/42000/quic-v1/webtransport"),
		testMA("/ip4/192.168.1.50/tcp/43000"),
		testMA("/ip4/192.168.1.50/udp/0/quic-v1"),
	}

	got := reflexiveUDPAddrs(stun, listeners)
	gotStr := []string{}
	for _, m := range got {
		gotStr = append(gotStr, m.String())
	}

	want := []string{
		"/ip4/203.0.113.7/udp/40000/quic-v1",
		"/ip4/203.0.113.7/udp/41000/webrtc-direct",
		"/ip4/203.0.113.7/udp/41001/quic-v1",
		"/ip4/203.0.113.7/udp/42000/quic-v1/webtransport",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d addr(s) %v, want %d: %v", len(got), gotStr, len(want), want)
	}
	for _, w := range want {
		if !slices.Contains(gotStr, w) {
			t.Errorf("missing %q in %v", w, gotStr)
		}
	}
	for _, g := range gotStr {
		// The probe socket's port is never dialable: advertising it only burns a
		// peer's dial budget and feeds the black hole counter.
		if strings.Contains(g, ":54321") {
			t.Errorf("advertised the STUN probe port, which no listener uses: %s", g)
		}
		// Neither may the local NIC's IP leak into a server-reflexive address.
		if strings.Contains(g, "192.168.1.50") {
			t.Errorf("kept the listener's private IP: %s", g)
		}
	}
}

func TestReflexiveUDPAddrsNoListenersYieldsNothing(t *testing.T) {
	// With no UDP listener there is no dialable port, so nothing should be
	// advertised rather than a dead address.
	if got := reflexiveUDPAddrs(
		[]multiaddr.Multiaddr{testMA("/ip4/203.0.113.7/udp/54321/quic-v1")},
		[]multiaddr.Multiaddr{testMA("/ip4/192.168.1.50/tcp/43000")},
	); len(got) != 0 {
		t.Fatalf("expected no addresses, got %v", got)
	}
}

// A frame the same peer resends must reach TAP; the duplicate-suppression ring
// is only for the same frame arriving over a different path.
func TestBcastDedupAllowsSameSourceRetransmit(t *testing.T) {
	r := bcastDedupRing{}
	a, b := peer.ID("peerA"), peer.ID("peerB")
	h := fnvHash64([]byte("identical broadcast payload"))

	if r.isDuplicate(a, h) {
		t.Fatal("the first copy was suppressed")
	}
	if !r.isDuplicate(b, h) {
		t.Fatal("the same content from another peer was not deduplicated")
	}
	if r.isDuplicate(a, h) {
		t.Fatal("a retransmit from the original source was suppressed — this is " +
			"exactly when Router Solicitation, MLD Report and ARP retries matter")
	}
	if !r.isDuplicate(b, h) {
		t.Fatal("cross-peer suppression stopped working after the refresh")
	}
}

func TestBcastDedupZeroHashNeverDedups(t *testing.T) {
	r := bcastDedupRing{}
	a := peer.ID("peerA")
	for i := 0; i < 3; i++ {
		if r.isDuplicate(a, 0) {
			t.Fatalf("zero hash was treated as a duplicate on attempt %d", i)
		}
	}
}

// isMeshLocalIP is the shared predicate for the Exit-Node hijack and the
// unroutable-frame suppression. The suppression path used to use a narrower
// one, which dropped a DHCP server's unicast-to-255.255.255.255 reply.
func TestIsMeshLocalIP(t *testing.T) {
	n := bareMeshNode(t)

	present := []string{
		"255.255.255.255", // DHCP "unicast broadcast": no address assigned yet
		"169.254.9.9",     // IPv4 link-local
		"10.9.9.9",        // our own TAP subnet
		"fd00:99::5",      // our own TAP subnet
		"fe80::5",         // IPv6 link-local
		"ff02::1",         // all-nodes: NDP / all-routers
		"ff02::ff:0:2",    // solicited-node multicast
	}
	for _, s := range present {
		if !n.isMeshLocalIP(net.ParseIP(s)) {
			t.Errorf("isMeshLocalIP(%s) = false, want true", s)
		}
	}

	absent := []string{
		"8.8.8.8", // public internet
		"2001:4860:4860::8888",
		"192.168.1.255", // a LAN we are not on and no peer advertises
		"10.9.8.9",      // adjacent subnet, not ours
		"ff0e::8002",    // internet multicast belongs to the Exit Node path
	}
	for _, s := range absent {
		if n.isMeshLocalIP(net.ParseIP(s)) {
			t.Errorf("isMeshLocalIP(%s) = true, want false", s)
		}
	}

	if n.isMeshLocalIP(nil) {
		t.Error("nil IP must not be mesh-local")
	}
}

// Every path the Exit-Node block would have hijacked is checked against the
// same predicate now.
func TestIsMeshLocalIPMatchesAdvertisedSubnets(t *testing.T) {
	n := bareMeshNode(t)
	p := peer.ID("subnet-peer")
	installAdvertisedSubnet(t, n, p, "172.16.0.0/16")
	installAdvertisedSubnet(t, n, p, "2001:db8::/48")

	present := []string{"172.16.0.77", "10.9.9.5", "fd00:99::5", "2001:db8::77"}
	for _, s := range present {
		if !n.isMeshLocalIP(net.ParseIP(s)) {
			t.Errorf("isMeshLocalIP(%s) = false, want true (advertised by %s)", s, p.ShortString())
		}
	}
	if n.isMeshLocalIP(net.ParseIP("172.17.0.1")) {
		t.Error("172.17.0.1 is outside the advertised 172.16.0.0/16")
	}
}
