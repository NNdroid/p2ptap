package web

import (
	"testing"

	"p2ptap/pkg/observer"
	"p2ptap/pkg/routing"
)

func TestClassifyTransportAddrsPrefersDirect(t *testing.T) {
	circuit := "/ip4/203.0.113.10/tcp/4001/p2p/relay/p2p-circuit/p2p/dest"
	direct := "/ip4/198.51.100.20/udp/4001/quic-v1"

	tests := []struct {
		name     string
		addrs    []string
		expected string
	}{
		{name: "none", expected: "unknown"},
		{name: "circuit only", addrs: []string{circuit}, expected: "circuit-relay"},
		{name: "direct only", addrs: []string{direct}, expected: "direct"},
		{name: "mixed relay first", addrs: []string{circuit, direct}, expected: "direct"},
		{name: "mixed direct first", addrs: []string{direct, circuit}, expected: "direct"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, _ := classifyTransportAddrs(tt.addrs)
			if got != tt.expected {
				t.Fatalf("classifyTransportAddrs() = %q, want %q", got, tt.expected)
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
