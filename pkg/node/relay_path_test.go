package node

import "testing"

// TestRelayPeerIDOf pins the circuit-relay relay-peer extraction contract used
// by the transport-path diagnostics. A relayed connection's remote multiaddr
// looks like /ip4/<relayIP>/tcp/<port>/p2p/<relayPeerID>/p2p-circuit/p2p/<dest>,
// and we surface <relayPeerID> in logs/WebUI so a hidden high-latency relay
// hop is no longer invisible.
func TestRelayPeerIDOf(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want string
	}{
		{
			name: "typical circuit relay with dest",
			addr: "/ip4/1.2.3.4/tcp/4001/p2p/QmRelayAAAA/p2p-circuit/p2p/QmDestZZZZ",
			want: "QmRelayAAAA",
		},
		{
			name: "circuit relay without trailing dest peer",
			addr: "/ip4/1.2.3.4/tcp/4001/p2p/QmRelayAAAA/p2p-circuit",
			want: "QmRelayAAAA",
		},
		{
			name: "dnsaddr relay with dest",
			addr: "/dnsaddr/relay.example.com/p2p/12D3KooRelay/p2p-circuit/p2p/12D3KooDest",
			want: "12D3KooRelay",
		},
		{
			name: "plain direct connection — no circuit",
			addr: "/ip4/1.2.3.4/tcp/4001/p2p/QmDirectOnly",
			want: "",
		},
		{
			name: "quic direct — no circuit",
			addr: "/ip4/1.2.3.4/udp/4001/quic-v1/p2p/QmDirectOnly",
			want: "",
		},
		{
			name: "empty string",
			addr: "",
			want: "",
		},
		{
			name: "circuit token but no preceding p2p tag",
			addr: "/ip4/1.2.3.4/tcp/4001/p2p-circuit",
			want: "",
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got := relayPeerIDOf(c.addr)
			if got != c.want {
				t.Fatalf("relayPeerIDOf(%q) = %q, want %q", c.addr, got, c.want)
			}
		})
	}
}
