package node

import (
	"testing"

	"github.com/multiformats/go-multiaddr"
)

const circuitRelayPeerID = "QmdXGaeGiVA745XorV1jr11RHxB9z4fqykm6xCUPX1aTJo"

func addrsFromStrings(t *testing.T, ss ...string) []multiaddr.Multiaddr {
	t.Helper()
	out := make([]multiaddr.Multiaddr, 0, len(ss))
	for _, s := range ss {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("NewMultiaddr(%q): %v", s, err)
		}
		out = append(out, ma)
	}
	return out
}

func TestDirectCandidatesDropsCircuitAddrs(t *testing.T) {
	got := directCandidates(addrsFromStrings(t,
		"/ip4/10.0.0.7/tcp/41741",
		"/ip4/185.199.108.153/p2p/"+circuitRelayPeerID+"/udp/4001/quic-v1/p2p-circuit",
		"/ip6/::ffff:169.254.1.2/tcp/41741",
		"/dns4/boot.example.com/tcp/443/p2p/"+circuitRelayPeerID+"/p2p-circuit",
	))
	want := []string{
		"/ip4/10.0.0.7/tcp/41741",
		"/ip6/::ffff:169.254.1.2/tcp/41741",
	}
	if len(got) != len(want) {
		t.Fatalf("kept %d addr(s), want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Fatalf("addr %d = %s, want %s (order must be preserved)", i, got[i].String(), w)
		}
	}
}

func TestDirectCandidatesEmpty(t *testing.T) {
	if got := directCandidates(nil); len(got) != 0 {
		t.Fatalf("nil input yielded %d addr(s)", len(got))
	}
	onlyCircuit := addrsFromStrings(t,
		"/ip4/185.199.108.153/p2p/"+circuitRelayPeerID+"/udp/4001/quic-v1/p2p-circuit")
	if got := directCandidates(onlyCircuit); len(got) != 0 {
		t.Fatalf("circuit-only input yielded %d addr(s): %v", len(got), got)
	}
}
