package node

import (
	"bytes"
	"net"
	"strconv"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
)

// newTestNodeWithIndex builds a minimal Node and populates the read-optimized
// ARP index through the same storePeerMeta path production code uses, so the
// tests exercise index build + lookup exactly as the running daemon does.
func newTestNodeWithIndex(t *testing.T, peers []PeerMeta) *Node {
	t.Helper()
	n := &Node{}
	for i, m := range peers {
		pID := peer.ID("peer-" + string(rune('A'+i)))
		n.storePeerMeta(pID, m)
	}
	return n
}

func TestResolvePeerIDByIndex(t *testing.T) {
	peerA := peer.ID("peer-A")
	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	peerB := peer.ID("peer-B")
	macB := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x03}

	n := newTestNodeWithIndex(t, []PeerMeta{
		{
			NodeName:          "A",
			TapIP:             "10.0.0.2/24",
			TapIPv6:           "fd00::2/64",
			TapMAC:            macA.String(),
			AdvertisedSubnets: []string{"192.168.101.0/24"},
		},
		{
			NodeName:          "B",
			TapIP:             "10.0.0.3/24",
			TapIPv6:           "fd00::3/64",
			TapMAC:            macB.String(),
			AdvertisedSubnets: []string{"192.168.102.0/24"},
		},
	})

	tests := []struct {
		name    string
		ip      net.IP
		wantPID peer.ID
		wantMAC net.HardwareAddr
	}{
		{"direct v4 TapIP", net.ParseIP("10.0.0.2"), peerA, macA},
		{"direct v6 TapIP", net.ParseIP("fd00::2"), peerA, macA},
		{"advertised subnet v4", net.ParseIP("192.168.101.5"), peerA, macA},
		{"advertised subnet v6 host", net.ParseIP("192.168.102.9"), peerB, macB},
		{"unknown ip", net.ParseIP("203.0.113.7"), "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPID, gotMAC := n.resolvePeerIDByIP(tt.ip)
			if gotPID != tt.wantPID {
				t.Errorf("resolvePeerIDByIP(%v).pid = %q, want %q", tt.ip, gotPID, tt.wantPID)
			}
			if tt.wantMAC == nil {
				if gotMAC != nil {
					t.Errorf("resolvePeerIDByIP(%v).mac = %v, want nil", tt.ip, gotMAC)
				}
				return
			}
			if gotMAC == nil || !bytes.Equal(gotMAC, tt.wantMAC) {
				t.Errorf("resolvePeerIDByIP(%v).mac = %v, want %v", tt.ip, gotMAC, tt.wantMAC)
			}
		})
	}
}

func TestARPLookupsUseIndex(t *testing.T) {
	peerA := peer.ID("peer-A")
	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	n := newTestNodeWithIndex(t, []PeerMeta{
		{
			NodeName:          "A",
			TapIP:             "10.0.0.2/24",
			TapIPv6:           "fd00::2/64",
			TapMAC:            macA.String(),
			AdvertisedSubnets: []string{"192.168.101.0/24"},
		},
	})

	// Direct IPv4 / IPv6 must resolve from the O(1) maps.
	if mac, pid := n.lookupPeerMACByIPv4(net.ParseIP("10.0.0.2")); pid != peerA || !bytes.Equal(mac, macA) {
		t.Errorf("lookupPeerMACByIPv4 = (%v,%v), want (%v,%v)", mac, pid, macA, peerA)
	}
	if mac, pid := n.lookupPeerMACByIPv6(net.ParseIP("fd00::2")); pid != peerA || !bytes.Equal(mac, macA) {
		t.Errorf("lookupPeerMACByIPv6 = (%v,%v), want (%v,%v)", mac, pid, macA, peerA)
	}
	// Advertised subnet resolves to the peer ID (and MAC).
	if pid := n.lookupPeerIDByAdvertisedSubnet(net.ParseIP("192.168.101.5")); pid != peerA {
		t.Errorf("lookupPeerIDByAdvertisedSubnet = %v, want %v", pid, peerA)
	}
	if mac := n.lookupPeerMACByAdvertisedSubnet(net.ParseIP("192.168.101.5")); !bytes.Equal(mac, macA) {
		t.Errorf("lookupPeerMACByAdvertisedSubnet mac = %v, want %v", mac, macA)
	}
	// An IP that is neither a direct TapIP nor inside an advertised subnet
	// must resolve to nothing on every path.
	if mac, pid := n.lookupPeerMACByIPv4(net.ParseIP("10.9.9.9")); pid != "" || mac != nil {
		t.Errorf("lookupPeerMACByIPv4(unknown) = (%v,%v), want (nil,'')", mac, pid)
	}
	if pid := n.lookupPeerIDByAdvertisedSubnet(net.ParseIP("10.9.9.9")); pid != "" {
		t.Errorf("lookupPeerIDByAdvertisedSubnet(unknown) = %v, want ''", pid)
	}
}

// TestARPResolverNilIndexSafe guards against a nil index dereference before the
// first peerMeta write (e.g. during early startup).
func TestARPResolverNilIndexSafe(t *testing.T) {
	n := &Node{} // arpIndex left nil
	if pid, mac := n.resolvePeerIDByIP(net.ParseIP("10.0.0.2")); pid != "" || mac != nil {
		t.Errorf("resolvePeerIDByIP on nil index = (%v,%v), want (nil,'')", mac, pid)
	}
}

// benchNode builds a node with sz peers, each advertising one /24 subnet, to
// model a realistic mesh for the lookup benchmarks.
func benchNode(sz int) *Node {
	n := &Node{}
	for i := 0; i < sz; i++ {
		last := byte(2 + i)
		n.storePeerMeta(
			peer.ID("peer-"+string(rune('A'+i))),
			PeerMeta{
				TapIP:             net.IPv4(10, 0, 0, last).String() + "/24",
				TapIPv6:           "fd00::" + string(rune('2'+i)) + "/64",
				TapMAC:            net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, last}.String(),
				AdvertisedSubnets: []string{net.IPv4(192, 168, byte(i), 0).String() + "/24"},
			},
		)
	}
	return n
}

func BenchmarkResolvePeerIDByIP(b *testing.B) {
	sizes := []int{8, 64, 256}
	for _, sz := range sizes {
		n := benchNode(sz)
		direct := net.ParseIP("10.0.0.5")      // resolves via O(1) v4 map
		subnet := net.ParseIP("192.168.3.50")  // resolves via O(subnets) scan
		unknown := net.ParseIP("203.0.113.99") // miss (scans everything)
		b.Run("direct/sz="+strconv.Itoa(sz), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _ = n.resolvePeerIDByIP(direct)
			}
		})
		b.Run("subnet/sz="+strconv.Itoa(sz), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _ = n.resolvePeerIDByIP(subnet)
			}
		})
		b.Run("miss/sz="+strconv.Itoa(sz), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _ = n.resolvePeerIDByIP(unknown)
			}
		})
	}
}

// TestNDPProxyResolution drives the unified four-stage ARP/NDP decision
// (resolveProxyMAC) through the IPv6 lookup path, mirroring the IPv4 ARP
// branch in processTapFrame. It pins down each outcome: peer direct, advertised
// subnet, local TAP / WebUI virtual, and unknown (no active Exit Node).
func TestNDPProxyResolution(t *testing.T) {
	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	n := newTestNodeWithIndex(t, []PeerMeta{
		{
			NodeName:          "A",
			TapIP:             "10.0.0.2/24",
			TapIPv6:           "fd00::2/64",
			TapMAC:            macA.String(),
			AdvertisedSubnets: []string{"192.168.101.0/24"},
		},
	})
	n.localV6IP = net.ParseIP("fd00::1")
	n.virtualWebUIV6IP = net.ParseIP("fd00::fe")
	n.localMAC = net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}

	isLocal := func(ip net.IP) bool {
		return ip.Equal(n.localV6IP) || (n.virtualWebUIV6IP != nil && ip.Equal(n.virtualWebUIV6IP))
	}

	tests := []struct {
		name    string
		target  net.IP
		wantVia proxyVia
		wantMAC net.HardwareAddr
	}{
		{"peer direct v6 TapIP", net.ParseIP("fd00::2"), proxyViaPeer, macA},
		{"advertised subnet (IPv4 LAN)", net.ParseIP("192.168.101.5"), proxyViaSubnet, macA},
		{"local TAP v6", net.ParseIP("fd00::1"), proxyViaLocal, n.localMAC},
		{"WebUI virtual v6", net.ParseIP("fd00::fe"), proxyViaLocal, n.localMAC},
		{"unknown (no Exit active)", net.ParseIP("2001:db8::5"), proxyViaNone, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := n.resolveProxyMAC(tt.target, n.lookupPeerMACByIPv6, n.lookupPeerMACByAdvertisedSubnet, isLocal)
			if res.via != tt.wantVia {
				t.Errorf("via = %v, want %v", res.via, tt.wantVia)
			}
			if tt.wantMAC == nil {
				if res.mac != nil {
					t.Errorf("mac = %v, want nil", res.mac)
				}
				return
			}
			if res.mac == nil || !bytes.Equal(res.mac, tt.wantMAC) {
				t.Errorf("mac = %v, want %v", res.mac, tt.wantMAC)
			}
		})
	}
}

// BenchmarkLookupPeerMACByIPv6 asserts the direct IPv6 resolve stays allocation
// free (the [16]byte index key avoids ip.String() on the hot path).
func BenchmarkLookupPeerMACByIPv6(b *testing.B) {
	sizes := []int{8, 64, 256}
	for _, sz := range sizes {
		n := benchNode(sz)
		target := net.ParseIP("fd00::2") // resolves via O(1) v6 map
		b.Run("sz="+strconv.Itoa(sz), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _ = n.lookupPeerMACByIPv6(target)
			}
		})
	}
}
