package node

import (
	"testing"

	"github.com/multiformats/go-multiaddr"
)

func TestIsVirtualIP(t *testing.T) {
	cases := []struct {
		webUI string
		tapIP string
		want  bool
		desc  string
	}{
		{"", "10.0.0.2", false, "empty webUI is non-virtual"},
		{"0.0.0.0", "10.0.0.2", false, "0.0.0.0 is non-virtual"},
		{"127.0.0.1", "10.0.0.2", false, "loopback is non-virtual"},
		{"auto", "10.0.0.2", false, "auto is non-virtual"},
		{"garbage", "10.0.0.2", false, "unparseable webUI is non-virtual"},
		{"10.0.0.1", "10.0.0.1", false, "same IP as tap is non-virtual"},
		{"fd00::1", "fd00::1", false, "same IPv6 as tap is non-virtual"},
		{"10.0.0.5", "10.0.0.2/24", true, "IP inside tap subnet is virtual"},
		{"192.168.99.1", "10.0.0.2", true, "different valid IP is treated virtual"},
	}
	for _, c := range cases {
		if got := IsVirtualIP(c.webUI, c.tapIP); got != c.want {
			t.Errorf("IsVirtualIP(%q,%q) = %v, want %v (%s)", c.webUI, c.tapIP, got, c.want, c.desc)
		} else {
			t.Logf("[is-virtual] IsVirtualIP(webUI=%q, tap=%q) = %v (%s)", c.webUI, c.tapIP, got, c.desc)
		}
	}
}

func TestContainsSub(t *testing.T) {
	cases := []struct {
		s    string
		sub  string
		want bool
	}{
		{"hello world", "world", true},
		{"hello world", "WORLD", false}, // case-sensitive
		{"hello world", "xyz", false},
		{"", "", true},
		{"abc", "", true},
	}
	for _, c := range cases {
		if got := containsSub(c.s, c.sub); got != c.want {
			t.Errorf("containsSub(%q,%q) = %v, want %v", c.s, c.sub, got, c.want)
		}
	}
}

// TestFilterAdvertisedAddrsDropsLoopbackAndTap pins the behaviour that the
// addresses we broadcast to remote peers must NEVER include loopback
// (127.0.0.0/8, ::1) or the TAP virtual device. A peer that learns a loopback
// address would attempt (and always fail) to dial us on 127.0.0.1 / ::1, which
// is impossible across machines — so this is a hard correctness invariant, not
// a cosmetic preference.
func TestFilterAdvertisedAddrsDropsLoopbackAndTap(t *testing.T) {
	const tapIP = "10.0.0.1/24"
	const tapIPv6 = "fd00::1/64"
	const webUIPv4 = "10.0.0.1"
	const webUIPv6 = ""

	inputs := []string{
		"/ip4/127.0.0.1/tcp/4001",     // loopback v4 -> drop
		"/ip4/127.0.0.2/udp/4001/quic-v1", // loopback v4 (entire /8) -> drop
		"/ip6/::1/tcp/4001",           // loopback v6 -> drop
		"/ip4/10.0.0.1/tcp/4001",      // == TAP IP -> drop
		"/ip4/192.168.1.50/tcp/4001",  // physical NIC -> keep
		"/ip6/2001:db8::10/tcp/4001",  // physical NIC -> keep
	}
	mas := make([]multiaddr.Multiaddr, 0, len(inputs))
	for _, s := range inputs {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		mas = append(mas, ma)
	}

	got := filterAdvertisedAddrs(mas, tapIP, tapIPv6, webUIPv4, webUIPv6)
	gotStrs := make([]string, 0, len(got))
	for _, g := range got {
		gotStrs = append(gotStrs, g.String())
	}

	// Exactly the two physical addrs must survive.
	wantKeep := map[string]bool{
		"/ip4/192.168.1.50/tcp/4001": true,
		"/ip6/2001:db8::10/tcp/4001": true,
	}
	if len(got) != len(wantKeep) {
		t.Fatalf("filterAdvertisedAddrs kept %d addrs, want %d: %v", len(got), len(wantKeep), gotStrs)
	}
	for _, g := range gotStrs {
		if !wantKeep[g] {
			t.Errorf("unexpected address survived filtering: %s", g)
		}
	}
	// Loopback must be gone — this is the regression this test guards against.
	for _, bad := range []string{"/ip4/127.0.0.1/tcp/4001", "/ip4/127.0.0.2/udp/4001/quic-v1", "/ip6/::1/tcp/4001"} {
		for _, g := range gotStrs {
			if g == bad {
				t.Errorf("loopback address leaked past filter: %s", g)
			}
		}
	}

	// Mutation guard: a list containing ONLY loopback must produce an empty
	// result. If someone deletes the manet.IsIPLoopback check, this fails.
	onlyLoop := []multiaddr.Multiaddr{
		mustMA("/ip4/127.0.0.1/tcp/4001"),
		mustMA("/ip6/::1/udp/4001/quic-v1"),
	}
	if out := filterAdvertisedAddrs(onlyLoop, "", "", "", ""); len(out) != 0 {
		t.Errorf("loopback-only input should yield empty output, got %d addrs: %v", len(out), out)
	}
}

func mustMA(s string) multiaddr.Multiaddr {
	ma, err := multiaddr.NewMultiaddr(s)
	if err != nil {
		panic(err)
	}
	return ma
}

// TestFilterLoopbackAddrsReceiveSide guards the receive-side loopback guard:
// peer addresses learned from a remote node (or lingering in the peerstore)
// that point at loopback (127.0.0.0/8, ::1) must never surface to the UI or
// be dialed. This is the complement to TestFilterAdvertisedAddrsDropsLoopbackAndTap
// which guards the broadcast side.
func TestFilterLoopbackAddrsReceiveSide(t *testing.T) {
	inputs := []string{
		"/ip4/192.168.1.50/tcp/4001",
		"/ip6/2001:db8::10/udp/4001/quic-v1",
		"/ip4/127.0.0.1/tcp/4001",         // loopback v4
		"/ip4/127.0.0.2/udp/4001/quic-v1", // loopback v4 alt
		"/ip6/::1/tcp/4001",               // loopback v6
		"/ip4/10.0.0.3/tcp/62151",         // private, must keep
	}
	mas := make([]multiaddr.Multiaddr, 0, len(inputs))
	for _, s := range inputs {
		ma, err := multiaddr.NewMultiaddr(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		mas = append(mas, ma)
	}

	got := filterLoopbackAddrs(mas)
	gotStrs := make([]string, 0, len(got))
	for _, g := range got {
		gotStrs = append(gotStrs, g.String())
	}

	wantKeep := map[string]bool{
		"/ip4/192.168.1.50/tcp/4001":         true,
		"/ip6/2001:db8::10/udp/4001/quic-v1": true,
		"/ip4/10.0.0.3/tcp/62151":            true,
	}
	if len(got) != len(wantKeep) {
		t.Fatalf("filterLoopbackAddrs kept %d addrs, want %d: %v", len(got), len(wantKeep), gotStrs)
	}
	for _, g := range gotStrs {
		if !wantKeep[g] {
			t.Errorf("unexpected address survived loopback filtering: %s", g)
		}
	}
	// Loopback must be gone.
	for _, bad := range []string{"/ip4/127.0.0.1/tcp/4001", "/ip4/127.0.0.2/udp/4001/quic-v1", "/ip6/::1/tcp/4001"} {
		for _, g := range gotStrs {
			if g == bad {
				t.Errorf("loopback address leaked past receive-side filter: %s", g)
			}
		}
	}

	// Mutation guard: a list containing ONLY loopback must produce an empty
	// result. If someone deletes the manet.IsIPLoopback check, this fails.
	onlyLoop := []multiaddr.Multiaddr{
		mustMA("/ip4/127.0.0.1/tcp/4001"),
		mustMA("/ip6/::1/udp/4001/quic-v1"),
	}
	if out := filterLoopbackAddrs(onlyLoop); len(out) != 0 {
		t.Errorf("loopback-only input should yield empty output, got %d addrs: %v", len(out), out)
	}

	// Empty and nil inputs must be safe (returned unchanged / empty).
	if out := filterLoopbackAddrs(nil); out == nil {
		// a nil slice is acceptable; just ensure no panic above
		_ = out
	}
	if out := filterLoopbackAddrs([]multiaddr.Multiaddr{}); out == nil {
		t.Errorf("empty input should return non-nil slice (or at least not nil)")
	}
}
