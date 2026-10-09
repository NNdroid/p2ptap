package node

import "testing"

// TestRelayPeerIDs pins the circuit-relay peer-ID extraction contract used
// by the transport-path diagnostics. A relayed connection's remote multiaddr
// looks like /ip4/<relayIP>/tcp/<port>/p2p/<relayPeerID>/p2p-circuit/p2p/<dest>,
// and we surface the relay peer IDs in logs/WebUI so a hidden high-latency
// relay hop is no longer invisible.
func TestRelayPeerIDs(t *testing.T) {
	relayID := "12D3KooWEKwbArMjvrtryUt57BWy5NSXa6yZehX9ffP56M6St7bZ"
	destID := "12D3KooWM3wrbKuSf2mG3qm6Godd1s1e1irP6da3VwHMC2nxkTNu"
	directID := "12D3KooWHMeyHkLHidjN9rDp5xepj6MF69FEuiJHvu7HcGf5aG4i"

	cases := []struct {
		name string
		addr string
		want []string
	}{
		{
			name: "typical circuit relay with dest",
			addr: "/ip4/1.2.3.4/tcp/4001/p2p/" + relayID + "/p2p-circuit/p2p/" + destID,
			want: []string{relayID, destID},
		},
		{
			name: "circuit relay without trailing dest peer",
			addr: "/ip4/1.2.3.4/tcp/4001/p2p/" + relayID + "/p2p-circuit",
			want: []string{relayID},
		},
		{
			name: "plain direct connection — no circuit",
			addr: "/ip4/1.2.3.4/tcp/4001/p2p/" + directID,
			want: []string{directID},
		},
		{
			name: "quic direct — no circuit",
			addr: "/ip4/1.2.3.4/udp/4001/quic-v1/p2p/" + directID,
			want: []string{directID},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			ma := mustMaddr(t, c.addr)
			got := RelayPeerIDs(ma)
			gotStrs := make([]string, len(got))
			for i, id := range got {
				gotStrs[i] = id.String()
			}
			if len(gotStrs) != len(c.want) {
				t.Fatalf("RelayPeerIDs(%q) = %v, want %v", c.addr, gotStrs, c.want)
			}
			for i := range gotStrs {
				if gotStrs[i] != c.want[i] {
					t.Fatalf("RelayPeerIDs(%q)[%d] = %q, want %q", c.addr, i, gotStrs[i], c.want[i])
				}
			}
		})
	}
}

// TestIsCircuitRelay verifies the protocol-code-based circuit-relay detection.
func TestIsCircuitRelay(t *testing.T) {
	relayID := "12D3KooWEKwbArMjvrtryUt57BWy5NSXa6yZehX9ffP56M6St7bZ"
	destID := "12D3KooWM3wrbKuSf2mG3qm6Godd1s1e1irP6da3VwHMC2nxkTNu"
	directID := "12D3KooWHMeyHkLHidjN9rDp5xepj6MF69FEuiJHvu7HcGf5aG4i"

	cases := []struct {
		addr string
		want bool
	}{
		{"/ip4/1.2.3.4/tcp/4001/p2p/" + relayID + "/p2p-circuit/p2p/" + destID, true},
		{"/ip4/1.2.3.4/tcp/4001/p2p/" + relayID + "/p2p-circuit", true},
		{"/ip4/1.2.3.4/tcp/4001/p2p/" + directID, false},
		{"/ip4/1.2.3.4/udp/4001/quic-v1/p2p/" + directID, false},
	}
	for _, c := range cases {
		if got := IsCircuitRelay(mustMA(c.addr)); got != c.want {
			t.Errorf("IsCircuitRelay(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}
