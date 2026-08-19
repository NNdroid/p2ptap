package node

import (
	"net"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func TestPrioritizeMultiaddrs(t *testing.T) {
	raw := []string{
		"/ip4/192.168.1.100/tcp/4001",                   // Private RFC1918 TCP
		"/ip4/192.168.1.100/udp/4001/quic-v1",           // Private RFC1918 QUIC
		"/ip4/1.2.3.4/tcp/45123",                        // Public IPv4 TCP
		"/ip4/1.2.3.4/udp/45123/quic-v1",                // Public IPv4 QUIC
		"/ip6/2408:8000::1/udp/4001/quic-v1",            // Public IPv6 QUIC
		"/ip6/2408:8000::1/tcp/4001",                    // Public IPv6 TCP
		"/ip4/127.0.0.1/tcp/4001",                       // Loopback (should be filtered out)
	}

	var addrs []multiaddr.Multiaddr
	for _, s := range raw {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("NewMultiaddr(%q): %v", s, err)
		}
		addrs = append(addrs, ma)
	}

	sorted := prioritizeMultiaddrs(addrs)

	// Loopback should have been excluded
	for _, a := range sorted {
		if a.String() == "/ip4/127.0.0.1/tcp/4001" {
			t.Errorf("Loopback address was not filtered out: %s", a.String())
		}
	}

	if len(sorted) != 6 {
		t.Fatalf("Expected 6 non-loopback addresses, got %d", len(sorted))
	}

	// 1st must be Public IPv6 QUIC (score 130)
	if sorted[0].String() != "/ip6/2408:8000::1/udp/4001/quic-v1" {
		t.Errorf("Expected rank 1 to be Public IPv6 QUIC, got %s", sorted[0].String())
	}
	// 2nd must be Public IPv6 TCP (score 110)
	if sorted[1].String() != "/ip6/2408:8000::1/tcp/4001" {
		t.Errorf("Expected rank 2 to be Public IPv6 TCP, got %s", sorted[1].String())
	}
	// 3rd must be Public IPv4 QUIC (score 90)
	if sorted[2].String() != "/ip4/1.2.3.4/udp/45123/quic-v1" {
		t.Errorf("Expected rank 3 to be Public IPv4 QUIC, got %s", sorted[2].String())
	}
	// 4th must be Public IPv4 TCP (score 70)
	if sorted[3].String() != "/ip4/1.2.3.4/tcp/45123" {
		t.Errorf("Expected rank 4 to be Public IPv4 TCP, got %s", sorted[3].String())
	}
}

func TestDynamicSubnetAuthorization(t *testing.T) {
	n := &Node{}
	n.manuallyAuthSubnets = make(map[string]bool)

	sub := "192.168.100.0/24"
	if n.isSubnetManuallyAuthorized(sub) {
		t.Errorf("expected subnet %s to NOT be authorized initially", sub)
	}

	n.manuallyAuthorizeSubnet(sub)
	if !n.isSubnetManuallyAuthorized(sub) {
		t.Errorf("expected subnet %s to be authorized after manuallyAuthorizeSubnet", sub)
	}

	n.manuallyRevokeSubnet(sub)
	if n.isSubnetManuallyAuthorized(sub) {
		t.Errorf("expected subnet %s to NOT be authorized after manuallyRevokeSubnet", sub)
	}
}

func TestFindSubnetGateway(t *testing.T) {
	dummyRemoteID, err := peer.Decode("12D3KooWHMeyHkLHidjN9rDp5xepj6MF69FEuiJHvu7HcGf5aG4i")
	if err != nil {
		t.Fatalf("failed to decode dummy remote peer ID: %v", err)
	}

	n := &Node{}
	// Store remote peer metadata
	n.peerMeta.Store(dummyRemoteID, PeerMeta{
		NodeName:          "RemoteNode",
		TapIP:             "10.0.0.5/24",
		TapMAC:            "02:00:0a:00:00:05",
		AdvertisedSubnets: []string{"192.168.88.0/24"},
	})

	gw, pid := n.findSubnetGateway("192.168.88.0/24")
	if gw != "10.0.0.5" {
		t.Errorf("Expected gateway 10.0.0.5, got %q", gw)
	}
	if pid != dummyRemoteID {
		t.Errorf("Expected peer ID %s, got %s", dummyRemoteID, pid)
	}

	// Non-existent subnet
	gwNone, pidNone := n.findSubnetGateway("10.99.99.0/24")
	if gwNone != "" || pidNone != "" {
		t.Errorf("Expected empty result for non-existent subnet, got gw=%q pid=%v", gwNone, pidNone)
	}
}

func parseHWMacTest(s string) net.HardwareAddr {
	hw, _ := net.ParseMAC(s)
	return hw
}
