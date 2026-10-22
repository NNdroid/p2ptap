package web

import (
	"testing"

	"github.com/multiformats/go-multiaddr"

	"p2ptap/pkg/observer"
	"p2ptap/pkg/routing"
)

func mustTestMaddr(s string) multiaddr.Multiaddr {
	ma, err := multiaddr.NewMultiaddr(s)
	if err != nil {
		panic(err)
	}
	return ma
}

func TestClassifyTransportAddrsPrefersDirect(t *testing.T) {
	relayID := "12D3KooWEKwbArMjvrtryUt57BWy5NSXa6yZehX9ffP56M6St7bZ"
	relayID2 := "12D3KooWM3wrbKuSf2mG3qm6Godd1s1e1irP6da3VwHMC2nxkTNu"
	destID := "12D3KooWHMeyHkLHidjN9rDp5xepj6MF69FEuiJHvu7HcGf5aG4i"

	circuit := "/ip4/203.0.113.10/tcp/4001/p2p/" + relayID + "/p2p-circuit/p2p/" + destID
	chained := "/ip4/203.0.113.10/tcp/4001/p2p/" + relayID + "/p2p-circuit/p2p/" + relayID2 +
		"/p2p-circuit/p2p/" + destID
	direct := "/ip4/198.51.100.20/udp/4001/quic-v1"

	tests := []struct {
		name     string
		addrs    []multiaddr.Multiaddr
		expected string
		relays   []string
	}{
		{name: "none", expected: "unknown"},
		{name: "circuit only", addrs: []multiaddr.Multiaddr{mustTestMaddr(circuit)}, expected: "circuit-relay", relays: []string{relayID}},
		{
			name:     "chained relays exclude the destination",
			addrs:    []multiaddr.Multiaddr{mustTestMaddr(chained)},
			expected: "circuit-relay",
			relays:   []string{relayID, relayID2},
		},
		{name: "direct only", addrs: []multiaddr.Multiaddr{mustTestMaddr(direct)}, expected: "direct"},
		{
			name:     "mixed relay first",
			addrs:    []multiaddr.Multiaddr{mustTestMaddr(circuit), mustTestMaddr(direct)},
			expected: "direct",
		},
		{
			name:     "mixed direct first",
			addrs:    []multiaddr.Multiaddr{mustTestMaddr(direct), mustTestMaddr(circuit)},
			expected: "direct",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, _, gotRelays := classifyTransportAddrs(tt.addrs)
			if got != tt.expected {
				t.Fatalf("classifyTransportAddrs() = %q, want %q", got, tt.expected)
			}
			if len(gotRelays) != len(tt.relays) {
				t.Fatalf("classifyTransportAddrs() relays = %v, want %v", gotRelays, tt.relays)
			}
			for i := range gotRelays {
				if gotRelays[i] != tt.relays[i] {
					t.Fatalf("classifyTransportAddrs() relays[%d] = %q, want %q", i, gotRelays[i], tt.relays[i])
				}
			}
		})
	}
}

func TestTracerouteTransportPathUsesLegEvidence(t *testing.T) {
	directRoute := &routing.RouteInfo{IsDirect: true}
	if got := tracerouteTransportPath(directRoute, nil); got != "unknown" {
		t.Fatalf("route without leg evidence = %q, want unknown", got)
	}
	if got := tracerouteTransportPath(directRoute, []observer.TracerouteHop{{}, {LinkClass: "direct"}}); got != "direct" {
		t.Fatalf("direct leg = %q, want direct", got)
	}
	if got := tracerouteTransportPath(directRoute, []observer.TracerouteHop{{}, {LinkClass: "circuit-relay", IsRelayedLeg: true}}); got != "circuit-relay" {
		t.Fatalf("circuit leg = %q, want circuit-relay", got)
	}
	if got := tracerouteTransportPath(&routing.RouteInfo{IsDirect: false}, nil); got != "overlay-relay" {
		t.Fatalf("overlay route = %q, want overlay-relay", got)
	}
}
