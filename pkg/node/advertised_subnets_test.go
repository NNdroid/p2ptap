package node

import (
	"net"
	"testing"

	"p2ptap/pkg/config"
)

func TestParseAdvertisedSubnetsDropsInvalid(t *testing.T) {
	got := parseAdvertisedSubnets([]string{"192.168.1.0/24", "not-a-cidr", "", "2001:db8::/64"})
	if len(got) != 2 {
		t.Fatalf("want 2 parsed subnets, got %d: %v", len(got), got)
	}
	if got[0].String() != "192.168.1.0/24" || got[1].String() != "2001:db8::/64" {
		t.Fatalf("wrong parsed subnets: %v", got)
	}
	if got := parseAdvertisedSubnets(nil); len(got) != 0 {
		t.Fatalf("nil input must give no subnets, got %v", got)
	}
	if got := parseAdvertisedSubnets([]string{"", "also bad"}); len(got) != 0 {
		t.Fatalf("all-invalid input must give no subnets, got %v", got)
	}
}

func TestIsLocalAdvertisedSubnetBareNode(t *testing.T) {
	// A bare &Node{} has no seeded cache slot, so this also covers the lazy
	// advertisedNetsSlot fallback path.
	n := &Node{Config: &config.Config{AdvertisedSubnets: []string{"192.168.1.0/24", "not-a-cidr"}}}
	for _, tc := range []struct {
		ip   net.IP
		want bool
	}{
		{net.ParseIP("192.168.1.1"), true},
		{net.ParseIP("192.168.1.254"), true},
		{net.ParseIP("192.168.2.1"), false},
		{net.ParseIP("2001:db8::1"), false},
	} {
		if got := n.isLocalAdvertisedSubnet(tc.ip); got != tc.want {
			t.Errorf("isLocalAdvertisedSubnet(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if n.isLocalAdvertisedSubnet(nil) {
		t.Error("nil IP must not match")
	}
}

func TestIsLocalAdvertisedSubnetEmptyAndNilConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    *Node
		ip   net.IP
	}{
		{"no advertised subnets", &Node{Config: &config.Config{}}, net.ParseIP("192.168.1.1")},
		{"nil config", &Node{}, net.ParseIP("192.168.1.1")},
	} {
		if tc.n.isLocalAdvertisedSubnet(tc.ip) {
			t.Errorf("%s: expected no match", tc.name)
		}
	}
}

func TestAdvertisedSubnetCacheInvalidatesOnReload(t *testing.T) {
	n := &Node{Config: &config.Config{AdvertisedSubnets: []string{"10.0.0.0/8"}}}

	// Populate the cache and confirm it is what the lookup used.
	if got := n.parsedAdvertisedSubnets(); len(got) != 1 {
		t.Fatalf("cache not populated: %v", got)
	}
	if !n.isLocalAdvertisedSubnet(net.ParseIP("10.1.2.3")) {
		t.Fatal("initial advertised subnet must match")
	}

	// A hot reload publishes a new *config.Config, so the cache key must
	// change with it — otherwise the node keeps answering for the subnet it
	// no longer advertises (and stops answering for the new one).
	n.SetConfig(&config.Config{AdvertisedSubnets: []string{"172.16.0.0/12"}})
	if n.isLocalAdvertisedSubnet(net.ParseIP("10.1.2.3")) {
		t.Error("superseded advertised subnet must not match after reload")
	}
	if !n.isLocalAdvertisedSubnet(net.ParseIP("172.20.1.1")) {
		t.Error("newly advertised subnet must match after reload")
	}

	// Reloading back to an empty list must also invalidate.
	n.SetConfig(&config.Config{})
	if n.isLocalAdvertisedSubnet(net.ParseIP("172.20.1.1")) {
		t.Error("advertised subnet must not match once the list is emptied")
	}
}
