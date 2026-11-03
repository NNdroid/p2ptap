package node

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
)

// linearSubnetMatch is the reference implementation the prefilter must agree
// with: the plain longest-prefix scan over idx.subnets.
func linearSubnetMatch(idx *arpIndex, ip net.IP) bool {
	for _, s := range idx.subnets {
		if s.net != nil && s.net.Contains(ip) {
			return true
		}
	}
	return false
}

// TestSubnetCoverPrefilterAgreesWithScan is the correctness contract for the
// O(log n) coverage prefilter: mayMatchAdvertisedSubnet may be conservative
// (report a possible match the scan then rejects) but it must NEVER report a
// miss for an address the scan would have matched. A prefilter that is too
// aggressive does not slow anything down - it silently blackholes traffic.
func TestSubnetCoverPrefilterAgreesWithScan(t *testing.T) {
	n := newTestNodeWithIndex(t, []PeerMeta{
		{
			NodeName: "wide",
			TapIP:    "10.0.0.2/24",
			TapIPv6:  "fd00::2/64",
			TapMAC:   "02:00:00:00:00:02",
			// A /16 that CONTAINS another peer's /24, and a /32 that is the
			// reason a coarse negative cache would be wrong: 172.16.5.9 is
			// owned, but 172.16.5.10 in the same /24 is not.
			AdvertisedSubnets: []string{"10.9.0.0/16", "172.16.5.9/32", "fd00:aa::/48"},
		},
		{
			NodeName:          "narrow",
			TapIP:             "10.0.0.3/24",
			TapIPv6:           "fd00::3/64",
			TapMAC:            "02:00:00:00:00:03",
			AdvertisedSubnets: []string{"10.9.1.0/24", "fd00:aa:bb::1/128"},
		},
		{
			NodeName:          "wan-ish",
			TapIP:             "10.0.0.4/24",
			TapIPv6:           "fd00::4/64",
			TapMAC:            "02:00:00:00:00:04",
			AdvertisedSubnets: []string{"0.0.0.0/0"},
		},
	})
	n.rebuildARPIndex()

	n.arpIndexMu.RLock()
	idx := n.arpIndex
	n.arpIndexMu.RUnlock()
	if idx == nil {
		t.Fatal("index not built")
	}

	probes := []string{
		// inside 10.9.0.0/16 (and 10.9.1.0/24 for the narrow one)
		"10.9.0.1", "10.9.1.7", "10.9.255.254",
		// same /16 prefix but OUTSIDE 10.9.0.0/16
		"10.10.0.1", "10.8.255.255",
		// the /32 case
		"172.16.5.9", "172.16.5.10", "172.16.5.0", "172.16.6.9",
		// IPv6 /48 and /128
		"fd00:aa::1", "fd00:aa:bb::1", "fd00:aa:bb::2", "fd00:ab::1",
		"fd00::99", "2001:db8::1",
		// ordinary WAN destinations
		"8.8.8.8", "203.0.113.99", "1.1.1.1",
	}
	for _, p := range probes {
		ip := net.ParseIP(p)
		got := idx.mayMatchAdvertisedSubnet(ip)
		want := linearSubnetMatch(idx, ip)
		if !want && got {
			// 0.0.0.0/0 is advertised below, so these all fall through to the
			// scan; only assert the dangerous direction for this block.
			continue
		}
		if want && !got {
			t.Fatalf("prefilter claimed %s is covered by no subnet, but the scan matched it", p)
		}
	}
}

// TestSubnetCoverPrefilterFalseNegatives pins the prefilter against the scan on
// an index WITHOUT a catch-all route, so both "match" and "miss" verdicts are
// compared exactly rather than only the dangerous direction.
func TestSubnetCoverPrefilterFalseNegatives(t *testing.T) {
	n := newTestNodeWithIndex(t, []PeerMeta{
		{
			NodeName:          "wide",
			TapIP:             "10.0.0.2/24",
			TapIPv6:           "fd00::2/64",
			TapMAC:            "02:00:00:00:00:02",
			AdvertisedSubnets: []string{"10.9.0.0/16", "172.16.5.9/32", "fd00:aa::/48"},
		},
		{
			NodeName:          "narrow",
			TapIP:             "10.0.0.3/24",
			TapIPv6:           "fd00::3/64",
			TapMAC:            "02:00:00:00:00:03",
			AdvertisedSubnets: []string{"10.9.1.0/24", "fd00:aa:bb::1/128"},
		},
	})
	n.rebuildARPIndex()

	n.arpIndexMu.RLock()
	idx := n.arpIndex
	n.arpIndexMu.RUnlock()

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.9.0.1", true},
		{"10.9.1.7", true},
		{"10.10.0.1", false},
		{"172.16.5.9", true},
		{"172.16.5.10", false}, // same /24 as the /32, must NOT be cached as a hit
		{"fd00:aa::1", true},
		{"fd00:aa:bb::1", true},
		{"fd00:aa:bb::2", false},
		{"fd00:ab::1", false},
		{"8.8.8.8", false},
		{"2001:db8::1", false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if got := idx.mayMatchAdvertisedSubnet(ip); got != tc.want {
			t.Errorf("mayMatchAdvertisedSubnet(%s) = %v, want %v", tc.ip, got, tc.want)
		}
		if got := linearSubnetMatch(idx, ip); got != tc.want {
			t.Fatalf("reference scan(%s) = %v, want %v - the test's expectation is wrong", tc.ip, got, tc.want)
		}
		// And the public entry points must agree end to end.
		if pid, _ := n.ResolvePeerIDByIP(ip); (pid != "") != tc.want {
			t.Errorf("ResolvePeerIDByIP(%s) matched=%v, want %v", tc.ip, pid != "", tc.want)
		}
	}
}

// TestSubnetCoverDegradesWhenSpanUnbuildable: a subnet that cannot be expressed
// as a span must switch the prefilter off instead of letting it claim misses.
func TestSubnetCoverDegradesWhenSpanUnbuildable(t *testing.T) {
	// A non-contiguous mask has Size() == (0, 0), so it cannot be turned into a
	// range. ParseCIDR never produces one, but the index is built from data
	// that travels over the network, so the fallback must exist.
	bad := &net.IPNet{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.IPMask{0xff, 0x00, 0xff, 0x00}}
	_, _, exact := buildSubnetCover([]arpSubnetEntry{{net: bad, pid: "x"}})
	if exact {
		t.Fatal("buildSubnetCover reported an exact cover for a non-contiguous mask")
	}

	idx := &arpIndex{
		subnets:    []arpSubnetEntry{{net: bad, pid: "x", mac: net.HardwareAddr{2, 0, 0, 0, 0, 1}}},
		coverExact: false,
	}
	// Unknown coverage must mean "let the scan decide", never "definitely no".
	if !idx.mayMatchAdvertisedSubnet(net.ParseIP("203.0.113.99")) {
		t.Fatal("prefilter claimed a miss while its cover was inexact")
	}
	empty := &arpIndex{coverExact: false}
	if empty.mayMatchAdvertisedSubnet(net.ParseIP("203.0.113.99")) {
		t.Fatal("prefilter matched with no subnets at all")
	}
}

// TestSubnetCoverSpansAreMerged documents that overlapping advertisements (a
// /16 from one peer containing a /24 from another) collapse into a single span,
// which is what keeps the binary search sound.
func TestSubnetCoverSpansAreMerged(t *testing.T) {
	_, ip16, err := net.ParseCIDR("10.9.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	_, ip24, err := net.ParseCIDR("10.9.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	_, ipOther, err := net.ParseCIDR("10.20.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	v4, _, exact := buildSubnetCover([]arpSubnetEntry{
		{net: ip24}, {net: ip16}, {net: ipOther},
	})
	if !exact {
		t.Fatal("cover unexpectedly inexact")
	}
	if len(v4) != 2 {
		t.Fatalf("got %d spans, want 2 (the /24 must merge into the /16): %+v", len(v4), v4)
	}
	if v4[0].lo != 0x0a090000 || v4[0].hi != 0x0a09ffff {
		t.Fatalf("first span = %08x-%08x, want 0a090000-0a09ffff", v4[0].lo, v4[0].hi)
	}
}

// TestSubnetCoverDifferentialRandom hammers the prefilter with random
// addresses against the reference scan over a randomly generated prefix set,
// which is the only practical way to cover the nested/disjoint orderings.
func TestSubnetCoverDifferentialRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(20261103))
	var subnets []arpSubnetEntry
	for i := 0; i < 300; i++ {
		var cidr string
		switch i % 4 {
		case 0:
			cidr = fmt.Sprintf("10.%d.0.0/16", i%256)
		case 1:
			cidr = fmt.Sprintf("10.%d.%d.0/24", i%64, rng.Intn(256))
		case 2:
			cidr = fmt.Sprintf("192.168.%d.%d/32", rng.Intn(256), rng.Intn(256))
		default:
			cidr = fmt.Sprintf("fd00:%x::/48", i)
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("%s: %v", cidr, err)
		}
		subnets = append(subnets, arpSubnetEntry{net: ipnet, pid: "p", mac: net.HardwareAddr{2, 0, 0, 0, 0, 1}})
	}
	v4, v6, exact := buildSubnetCover(subnets)
	if !exact {
		t.Fatal("cover unexpectedly inexact")
	}
	idx := &arpIndex{subnets: subnets, v4Cover: v4, v6Cover: v6, coverExact: true}

	for i := 0; i < 200000; i++ {
		var ip net.IP
		if i%5 == 0 {
			ip = net.IP([]byte{0xfd, 0x00, byte(rng.Intn(256)), byte(rng.Intn(256)),
				byte(rng.Intn(256)), byte(rng.Intn(256)), 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		} else {
			ip = net.IP([]byte{10, byte(rng.Intn(80)), byte(rng.Intn(256)), byte(rng.Intn(256))})
			if i%7 == 0 {
				ip = net.IP([]byte{192, 168, byte(rng.Intn(256)), byte(rng.Intn(256))})
			}
		}
		if want := linearSubnetMatch(idx, ip); want && !idx.mayMatchAdvertisedSubnet(ip) {
			t.Fatalf("prefilter missed %s which the scan matched", ip)
		}
	}
}
