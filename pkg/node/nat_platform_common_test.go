package node

import (
	"strings"
	"testing"
)

// TestNatPrefixV4: WinNat and pf both key NAT on a network prefix, never on a
// host address. Handing either of them "10.0.0.1/24" must produce 10.0.0.0/24
// (or be rejected), because a host address silently matches nothing and the
// exit node would install rules that never fire.
func TestNatPrefixV4(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"10.0.0.1/24", "10.0.0.0/24", true},
		{"10.0.0.0/24", "10.0.0.0/24", true},
		{" 192.168.50.3/16 ", "192.168.0.0/16", true},
		{"172.16.5.9/32", "172.16.5.9/32", true},
		{"0.0.0.0/0", "0.0.0.0/0", true},
		{"", "", false},
		{"10.0.0.1", "", false},      // no prefix length
		{"fd00::1/64", "", false},    // wrong family
		{"not-a-cidr/24", "", false}, // unparseable
	}
	for _, tc := range cases {
		got, ok := natPrefixV4(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("natPrefixV4(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestNatPrefixV6 is the IPv6 twin.
func TestNatPrefixV6(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"fd00::1/64", "fd00::/64", true},
		{"fd00:aa:bb::1/48", "fd00:aa:bb::/48", true},
		{"10.0.0.1/24", "", false},
		{"", "", false},
		{"fd00::1", "", false},
	}
	for _, tc := range cases {
		got, ok := natPrefixV6(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("natPrefixV6(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestPowerShellQuote: the quoted value is pasted into an inline -Command, so a
// single quote in an interface name must not be able to end the string.
func TestPowerShellQuote(t *testing.T) {
	cases := map[string]string{
		"ptap0":     "'ptap0'",
		"":          "''",
		"a'b":       "'a''b'",
		"'; rm -rf": "'''; rm -rf'",
	}
	for in, want := range cases {
		if got := powerShellQuote(in); got != want {
			t.Errorf("powerShellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestPFNatAnchor: pf has no "default route" token, so an unresolved WAN must
// produce no rules at all rather than a rule that matches nothing.
func TestPFNatAnchor(t *testing.T) {
	rules := pfNatAnchor("en0", "10.0.0.1/24", "fd00::1/64")
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2 (inet + inet6): %v", len(rules), rules)
	}
	if want := "nat on en0 inet from 10.0.0.0/24 to any -> (en0)"; rules[0] != want {
		t.Errorf("v4 rule = %q, want %q", rules[0], want)
	}
	if want := "nat on en0 inet6 from fd00::/64 to any -> (en0)"; rules[1] != want {
		t.Errorf("v6 rule = %q, want %q", rules[1], want)
	}

	// No usable interface: nothing may be emitted.
	for _, wan := range []string{"", "auto", "  "} {
		if got := pfNatAnchor(wan, "10.0.0.1/24", "fd00::1/64"); got != nil {
			t.Errorf("pfNatAnchor(%q) = %v, want none", wan, got)
		}
	}
	// IPv4-only host: still one rule, no phantom inet6 line.
	if got := pfNatAnchor("en0", "10.0.0.1/24", ""); len(got) != 1 {
		t.Errorf("IPv4-only anchor produced %v, want one rule", got)
	}
	// IPv6-only host: the mirror case, and the one the subnet-router path used
	// to make impossible by hard-coding "" as the IPv6 network.
	if got := pfNatAnchor("en0", "", "fd00::1/64"); len(got) != 1 || !strings.Contains(got[0], "inet6") {
		t.Errorf("IPv6-only anchor produced %v, want one inet6 rule", got)
	}
	// Malformed TAP address: nothing to match.
	if got := pfNatAnchor("en0", "", ""); len(got) != 0 {
		t.Errorf("anchor with no TAP network produced %v, want none", got)
	}
}

// TestSubnetRouterAnchorIncludesIPv6 is the regression for the reported defect:
// SetupSubnetRouterNAT used to take only the IPv4 network, so pf got "" for the
// IPv6 half and an advertised IPv6 subnet was never masqueraded. This pins the
// exact rule set the subnet-router path now loads on macOS.
func TestSubnetRouterAnchorIncludesIPv6(t *testing.T) {
	rules := pfNatAnchor("en0", "10.9.0.1/24", "fd00:9::1/64")
	if len(rules) != 2 {
		t.Fatalf("subnet-router anchor = %v, want inet and inet6 rules", rules)
	}
	var sawV4, sawV6 bool
	for _, r := range rules {
		if strings.Contains(r, "inet6 from fd00:9::/64") {
			sawV6 = true
		}
		if strings.Contains(r, "inet from 10.9.0.0/24") {
			sawV4 = true
		}
	}
	if !sawV4 || !sawV6 {
		t.Fatalf("anchor missing a family (v4=%v v6=%v): %v", sawV4, sawV6, rules)
	}
}

// TestNatIPv6GapReason: a backend without IPv6 must say so, and must never make
// the caller fail — an IPv4 exit node that works is strictly better than one
// that refuses to start over a secondary family.
func TestNatIPv6GapReason(t *testing.T) {
	// Nothing configured: no noise on the common IPv4-only host.
	if got := natIPv6GapReason("exit-node", "WinNat", false, ""); got != "" {
		t.Errorf("empty tap_ipv6 produced %q, want no warning", got)
	}
	if got := natIPv6GapReason("exit-node", "WinNat", false, "   "); got != "" {
		t.Errorf("blank tap_ipv6 produced %q, want no warning", got)
	}
	// Backend covers IPv6 and the value is usable: still no noise.
	if got := natIPv6GapReason("exit-node", "pf", true, "fd00::1/64"); got != "" {
		t.Errorf("usable IPv6 on an IPv6-capable backend produced %q", got)
	}
	// Backend without IPv6 must name itself and the consequence.
	got := natIPv6GapReason("subnet-router", "WinNat", false, "fd00::1/64")
	for _, want := range []string{"subnet-router", "WinNat", "fd00::1/64", "dropped", "IPv4 forwarding is unaffected"} {
		if !strings.Contains(got, want) {
			t.Errorf("gap reason %q does not mention %q", got, want)
		}
	}
	// IPv6-capable backend with a malformed value must also be reported: pf
	// would just skip the inet6 rule and the host would look IPv6-ready.
	got = natIPv6GapReason("subnet-router", "pf", true, "fd00::1")
	for _, want := range []string{"pf", "fd00::1", "not an IPv6 network"} {
		if !strings.Contains(got, want) {
			t.Errorf("malformed-value reason %q does not mention %q", got, want)
		}
	}
	// An IPv4 value in tap_ipv6 is a configuration mistake, not a silent skip.
	if got := natIPv6GapReason("exit-node", "pf", true, "10.0.0.1/24"); got == "" {
		t.Error("an IPv4 CIDR in tap_ipv6 must be reported")
	}
}

// TestPFConfAnchorIsNatTyped is the subtle one: pf tags anchors by type, so NAT
// rules loaded into a plain "anchor" are loaded and then never evaluated. Only a
// nat-anchor reference makes them live.
func TestPFConfAnchorIsNatTyped(t *testing.T) {
	base := "scrub-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\nload anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n"

	if pfConfHasAnchor(base, pfAnchor) {
		t.Fatal("reported our anchor present in a config that never mentions it")
	}
	updated := pfConfWithAnchor(base, pfAnchor)
	if !pfConfHasAnchor(updated, pfAnchor) {
		t.Fatalf("anchor still missing after update:\n%s", updated)
	}
	if !strings.HasPrefix(updated, "nat-anchor \""+pfAnchor+"\"\n") {
		t.Fatalf("anchor must be added as a nat-anchor on the first line, got:\n%s", updated)
	}
	// The original ruleset must survive verbatim, or we would be silently
	// disabling whatever the host already configured.
	if !strings.Contains(updated, base) {
		t.Fatalf("existing pf.conf content was modified:\n%s", updated)
	}

	// A plain anchor line must NOT count: it loads the rules and ignores them.
	plain := "anchor \"" + pfAnchor + "\"\n"
	if pfConfHasAnchor(plain, pfAnchor) {
		t.Fatal("a plain anchor line was accepted as a nat-anchor reference")
	}

	// Idempotent.
	once := pfConfWithAnchor(base, pfAnchor)
	if twice := pfConfWithAnchor(once, pfAnchor); twice != once {
		t.Fatalf("second application changed the config:\n%q\nvs\n%q", once, twice)
	}

	// A config without a trailing newline must not get its last line glued to
	// the anchor.
	noNL := "block in all"
	got := pfConfWithAnchor(noNL, pfAnchor)
	if !strings.Contains(got, "\nnat-anchor") && strings.HasPrefix(got, noNL) {
		t.Fatalf("missing newline handling: %q", got)
	}
}

// TestNatUnsupportedError: a platform with no backend must never be able to
// report success, and the message has to name the platform and the consequence
// so an operator does not go hunting for a config problem.
func TestNatUnsupportedError(t *testing.T) {
	err := natUnsupportedError("freebsd", "exit-node", "peers will get no connectivity")
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for _, want := range []string{"freebsd", "exit-node", "no NAT implementation", "no connectivity"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
}

// TestFirstLine: node logs get one actionable line, not a tool backtrace.
func TestFirstLine(t *testing.T) {
	cases := map[string]string{
		"":                         "",
		"\n\n  \n":                 "",
		"first\nsecond":            "first",
		"\n\n  actual error  \nxx": "actual error",
	}
	for in, want := range cases {
		if got := firstLine(in); got != want {
			t.Errorf("firstLine(%q) = %q, want %q", in, got, want)
		}
	}
}
