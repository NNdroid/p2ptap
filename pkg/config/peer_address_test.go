package config

import (
	"strings"
	"testing"
)

const testPeerID = "QmNnooDu7bfjPFoTmoXMY5PeBKyy1EicV2g7HQ1b18423b"

func TestPeerAddressesRejectNonDialableEntries(t *testing.T) {
	for _, address := range []string{
		"", "192.0.2.1", testPeerID, "/p2p/" + testPeerID,
		"/ip4/192.0.2.1/tcp/4001", "/ip4/192.0.2.1/p2p/" + testPeerID,
		"/ip4/192.0.2.1/tcp/4001/p2p/not-a-peer-id",
	} {
		t.Run(address, func(t *testing.T) {
			for _, field := range []string{"static_peers", "bootstrap_peers"} {
				cfg := DefaultConfig()
				if field == "static_peers" {
					cfg.StaticPeers = []string{address}
				} else {
					cfg.BootstrapPeers = []string{address}
				}
				if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), field+"[0]") {
					t.Fatalf("%s accepted %q or lost its field/index: %v", field, address, err)
				}
			}
		})
	}
}

func TestPeerAddressesNormalizeAndPreserveStaticOnlyMesh(t *testing.T) {
	addresses := []string{
		"/ip4/192.0.2.1/tcp/4001/p2p/" + testPeerID,
		"/ip6/2001:db8::1/udp/4001/quic-v1/p2p/" + testPeerID,
		"/dnsaddr/bootstrap.libp2p.io/p2p/" + testPeerID,
		"/ip4/192.0.2.2/tcp/4001/p2p/" + testPeerID + "/p2p-circuit/p2p/" + testPeerID,
	}
	cfg := DefaultConfig()
	cfg.BootstrapPeers = []string{}
	cfg.StaticPeers = append(append([]string{}, addresses...), "  "+addresses[0]+"  ")
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.StaticPeers) != len(addresses) || len(cfg.BootstrapPeers) != 0 {
		t.Fatalf("normalization changed mesh intent: static=%v bootstrap=%v", cfg.StaticPeers, cfg.BootstrapPeers)
	}
}
