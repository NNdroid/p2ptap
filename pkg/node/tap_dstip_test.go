package node

import (
	"encoding/binary"
	"net"
	"strconv"
	"testing"
)

// buildIPFrame wraps a bare IP packet in the 14-byte Ethernet header the TAP
// path always sees, so the dst-IP parsers can be exercised on both shapes.
func buildIPFrame(ethType uint16, pkt []byte) []byte {
	frame := make([]byte, 14+len(pkt))
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	binary.BigEndian.PutUint16(frame[12:14], ethType)
	copy(frame[14:], pkt)
	return frame
}

// ipv4Packet returns a minimal IPv4 packet whose destination is dst.
func ipv4Packet(dst net.IP) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	copy(pkt[16:20], dst.To4())
	return pkt
}

// ipv6Packet returns a minimal IPv6 packet whose destination is dst.
func ipv6Packet(dst net.IP) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x60
	copy(pkt[24:40], dst.To16())
	return pkt
}

// truncatedFrame builds a frame of exactly n bytes carrying ethType, so the
// length guards in both dst-IP parsers can be checked at their boundaries.
func truncatedFrame(n int, ethType uint16) []byte {
	frame := make([]byte, n)
	if n >= 14 {
		binary.BigEndian.PutUint16(frame[12:14], ethType)
	}
	return frame
}

// TestFrameDstIPMatchesExtractFrameDstIP pins the zero-copy parser to the
// owning one it replaced on the TAP hot path. frameDstIP aliases the frame
// (used for the 2-3 duplicate parses per frame that used to allocate), so any
// divergence in offset or length handling would silently mis-resolve a peer.
func TestFrameDstIPMatchesExtractFrameDstIP(t *testing.T) {
	arpFrame := func() []byte {
		f := make([]byte, 42)
		binary.BigEndian.PutUint16(f[12:14], 0x0806)
		copy(f[38:42], net.IPv4(192, 168, 1, 1).To4())
		return f
	}
	cases := []struct {
		name  string
		frame []byte
	}{
		{"ipv4", buildIPFrame(0x0800, ipv4Packet(net.IPv4(10, 0, 0, 7)))},
		{"ipv6", buildIPFrame(0x86DD, ipv6Packet(net.ParseIP("fd00::7")))},
		{"arp", arpFrame()},
		{"non-ip ethertype", buildIPFrame(0x88CC, make([]byte, 40))},
		{"runt 20 bytes", make([]byte, 20)},
		{"short ipv4 (33 bytes)", truncatedFrame(33, 0x0800)},
		{"short ipv6 (53 bytes)", truncatedFrame(53, 0x86DD)},
		{"short arp (41 bytes)", truncatedFrame(41, 0x0806)},
		{"empty", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := frameDstIP(tc.frame)
			want := extractFrameDstIP(tc.frame)
			if (got == nil) != (want == nil) {
				t.Fatalf("frameDstIP = %v, extractFrameDstIP = %v (nil mismatch)", got, want)
			}
			if got != nil && !got.Equal(want) {
				t.Fatalf("frameDstIP = %v, extractFrameDstIP = %v", got, want)
			}
		})
	}
}

// TestFrameDstIPAliasesTheFrame documents the contract the hot path relies on:
// frameDstIP returns a view, not a copy, so it must still track the frame's
// bytes and it must not allocate. extractFrameDstIP stays the owning variant.
func TestFrameDstIPAliasesTheFrame(t *testing.T) {
	frame := buildIPFrame(0x0800, ipv4Packet(net.IPv4(10, 0, 0, 7)))

	allocs := testing.AllocsPerRun(100, func() {
		_ = frameDstIP(frame)
	})
	if allocs != 0 {
		t.Errorf("frameDstIP allocated %v times per call, want 0", allocs)
	}

	// A view sees later mutations of the same buffer; a copy does not. This is
	// why the owning wrapper must be used by anything that stores the address.
	copy(frame[30:34], net.IPv4(10, 0, 0, 99).To4())
	if got := frameDstIP(frame); !got.Equal(net.IPv4(10, 0, 0, 99)) {
		t.Errorf("frameDstIP did not alias the frame: got %v", got)
	}
	if got := extractFrameDstIP(frame); !got.Equal(net.IPv4(10, 0, 0, 99)) {
		t.Errorf("extractFrameDstIP = %v, want the current bytes", got)
	}
}

// TestIsMeshLocalAddressIsSubsetOfIsMeshLocalIP guards the split: the Exit Node
// branch calls isMeshLocalAddress because it has already established that no
// peer owns the destination, so anything it reports as mesh-local MUST also be
// mesh-local to the full predicate. The converse is not true (a peer's TAP IP
// is mesh-local to isMeshLocalIP but not to isMeshLocalAddress), and that
// difference is exactly what the call site relies on.
func TestIsMeshLocalAddressIsSubsetOfIsMeshLocalIP(t *testing.T) {
	n := benchNode(4)
	n.localV4Net = mustCIDR(t, "10.99.0.0/24")
	n.localV6Net = mustCIDR(t, "fd00:1::/64")

	addresses := []string{
		"255.255.255.255", // limited broadcast (DHCP unicast-to-broadcast)
		"224.0.0.251",     // mDNS
		"239.255.255.250", // SSDP
		"169.254.1.1",     // pre-DHCP link-local
		"10.99.0.9",       // our own TAP subnet
		"10.0.2.1",        // peer A's direct TAP IP (peer-owned)
		"192.16.0.5",      // peer A's advertised LAN subnet (peer-owned)
		"232.1.1.1",       // global multicast -> exit path
		"203.0.113.99",    // plain WAN
		"ff02::fb",        // IPv6 link-local multicast
		"ff05::1:3",       // IPv6 site-local multicast (DHCPv6)
		"ff0e::1",         // IPv6 global multicast -> exit path
		"fd00:1::9",       // our own TAP v6 subnet
		"fd00::2",         // peer A's direct TAP IPv6 (peer-owned)
		"2001:db8::5",     // plain WAN v6
	}
	for _, s := range addresses {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test address %q", s)
		}
		if n.isMeshLocalAddress(ip) && !n.isMeshLocalIP(ip) {
			t.Errorf("isMeshLocalAddress(%s) = true but isMeshLocalIP = false; the cheap predicate must be a subset", s)
		}
	}
}

// TestIsMeshLocalAddressIgnoresPeerOwnership asserts the property that makes
// the Exit Node branch able to skip the two peer lookups: for an address no
// peer owns, the cheap predicate must agree with the full one.
func TestIsMeshLocalAddressIgnoresPeerOwnership(t *testing.T) {
	n := benchNode(4)
	n.localV4Net = mustCIDR(t, "10.99.0.0/24")
	n.localV6Net = mustCIDR(t, "fd00:1::/64")

	// The predicate split is only worth anything if the index really is holding
	// advertised subnets to scan; assert the fixture actually built some.
	n.arpIndexMu.RLock()
	advertised := len(n.arpIndex.subnets)
	n.arpIndexMu.RUnlock()
	if advertised != 4 {
		t.Fatalf("fixture built %d advertised subnets, want 4", advertised)
	}

	// Peer-owned: the full predicate must say yes, the cheap one must say no,
	// because at the call site that state has already been ruled out.
	for _, s := range []string{"10.0.2.1", "192.16.0.5", "fd00::2"} {
		ip := net.ParseIP(s)
		if !n.isMeshLocalIP(ip) {
			t.Errorf("isMeshLocalIP(%s) = false, want true (peer-owned)", s)
		}
		if n.isMeshLocalAddress(ip) {
			t.Errorf("isMeshLocalAddress(%s) = true; it must not consult peer ownership", s)
		}
	}
	// Not peer-owned: the two must agree, in both directions.
	for _, s := range []string{"255.255.255.255", "224.0.0.251", "169.254.1.1", "10.99.0.9", "203.0.113.99", "ff02::fb", "fd00:1::9", "2001:db8::5"} {
		ip := net.ParseIP(s)
		if got, want := n.isMeshLocalAddress(ip), n.isMeshLocalIP(ip); got != want {
			t.Errorf("disagree for unowned %s: isMeshLocalAddress = %v, isMeshLocalIP = %v", s, got, want)
		}
	}
	if n.isMeshLocalAddress(nil) || n.isMeshLocalIP(nil) {
		t.Error("nil destination must be reported as not mesh-local by both predicates")
	}
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("bad CIDR %q: %v", s, err)
	}
	return n
}

// These benchmarks quantify the two costs the change removed. Run with
// -bench 'BenchmarkFrameDstIP|BenchmarkExtractFrameDstIP|BenchmarkIsMeshLocal'
func BenchmarkFrameDstIP(b *testing.B) {
	frame := buildIPFrame(0x0800, ipv4Packet(net.IPv4(203, 0, 113, 99)))
	b.ReportAllocs()
	for b.Loop() {
		_ = frameDstIP(frame)
	}
}

func BenchmarkExtractFrameDstIP(b *testing.B) {
	frame := buildIPFrame(0x0800, ipv4Packet(net.IPv4(203, 0, 113, 99)))
	b.ReportAllocs()
	for b.Loop() {
		_ = extractFrameDstIP(frame)
	}
}

// BenchmarkIsMeshLocalMiss models the Exit Node egress decision for a WAN
// destination in a mesh where every peer advertises one LAN subnet: the full
// predicate walks all of them, the cheap one does not.
func BenchmarkIsMeshLocalMiss(b *testing.B) {
	for _, sz := range []int{8, 64, 256} {
		n := benchNode(sz)
		wan := net.ParseIP("203.0.113.99")
		b.Run("isMeshLocalIP/sz="+strconv.Itoa(sz), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = n.isMeshLocalIP(wan)
			}
		})
		b.Run("isMeshLocalAddress/sz="+strconv.Itoa(sz), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = n.isMeshLocalAddress(wan)
			}
		})
	}
}
