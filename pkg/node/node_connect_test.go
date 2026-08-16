package node

import (
	"testing"

	"github.com/multiformats/go-multiaddr"
)

// TestIsLocalAddr locks the LAN-classification contract that decides whether a
// discovered peer's addresses are "directly reachable without a relay hop". A peer
// whose every address is local must skip the circuit-relay race in dialInParallel;
// a public or circuit address must NOT be classified as local.
func TestIsLocalAddr(t *testing.T) {
	cases := []struct {
		ma  string
		got bool
	}{
		{"/ip4/127.0.0.1/tcp/4001", true},                              // loopback
		{"/ip4/10.0.0.5/tcp/4001", true},                              // private RFC1918
		{"/ip4/192.168.1.10/udp/4001/quic-v1", true},                 // private RFC1918 (QUIC)
		{"/ip4/172.16.0.5/tcp/4001", true},                           // private RFC1918
		{"/ip6/fe80::1/tcp/4001", true},                              // link-local
		{"/ip6/fd00::1/tcp/4001", true},                              // ULA (IsPrivate)
		{"/ip4/8.8.8.8/tcp/4001", false},                             // public
		{"/ip6/2001:db8::1/tcp/4001", false},                         // public (documentation range)
		{"/ip4/1.2.3.4/tcp/4001/p2p-circuit/p2p/12D3KooWM9cRwmQq9a7hvbgsJ19wSeRAUkAJ5j6u84jTFvFrwX3a", false}, // circuit addr has no IP
	}
	for _, c := range cases {
		ma, err := multiaddr.NewMultiaddr(c.ma)
		if err != nil {
			t.Fatalf("NewMultiaddr(%q): %v", c.ma, err)
		}
		if got := isLocalAddr(ma); got != c.got {
			t.Errorf("isLocalAddr(%q) = %v, want %v", c.ma, got, c.got)
		}
	}
}

// TestAllAddrsLocal ensures the all-local verdict (which suppresses the relay
// race entirely) is only true when EVERY address is local, and that an empty set
// is treated as "not local" so we still attempt the relay fallback.
func TestAllAddrsLocal(t *testing.T) {
	mk := func(s string) multiaddr.Multiaddr {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("NewMultiaddr(%q): %v", s, err)
		}
		return ma
	}

	cases := []struct {
		name string
		in   []multiaddr.Multiaddr
		want bool
	}{
		{"empty", nil, false},
		{"all local", []multiaddr.Multiaddr{
			mk("/ip4/10.0.0.5/tcp/4001"),
			mk("/ip4/192.168.1.10/udp/4001/quic-v1"),
		}, true},
		{"mixed", []multiaddr.Multiaddr{
			mk("/ip4/10.0.0.5/tcp/4001"),
			mk("/ip4/8.8.8.8/tcp/4001"),
		}, false},
		{"circuit only", []multiaddr.Multiaddr{
			mk("/ip4/1.2.3.4/tcp/4001/p2p-circuit/p2p/12D3KooWM9cRwmQq9a7hvbgsJ19wSeRAUkAJ5j6u84jTFvFrwX3a"),
		}, false},
	}
	for _, c := range cases {
		if got := allAddrsLocal(c.in); got != c.want {
			t.Errorf("%s: allAddrsLocal = %v, want %v", c.name, got, c.want)
		}
	}
}
