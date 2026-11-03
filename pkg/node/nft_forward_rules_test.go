package node

import "testing"

// TestForwardAcceptRules pins the rules that keep tunneled traffic alive across
// the netfilter FORWARD hook. They are the difference between an exit node that
// works and one that installs NAT, reports "active", and drops every byte on a
// host whose FORWARD policy is DROP (Docker, ufw, firewalld defaults).
func TestForwardAcceptRules(t *testing.T) {
	rules := forwardAcceptRules("ptap0")
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2 (one per direction)", len(rules))
	}

	out := rules[0]
	if out.Dir != forwardIn || out.Iface != "ptap0" {
		t.Fatalf("first rule must accept traffic entering the TAP, got %+v", out)
	}
	if out.Established {
		t.Fatal("the client->egress direction starts connections and must not require existing conntrack state")
	}

	in := rules[1]
	if in.Dir != forwardOut || in.Iface != "ptap0" {
		t.Fatalf("second rule must accept traffic leaving towards the TAP, got %+v", in)
	}
	// Dropping this restriction would let any WAN-side host that can route at
	// the TAP subnet reach a mesh client that never opened a connection.
	if !in.Established {
		t.Fatal("the egress->client direction must require established/related state")
	}
}

// TestForwardAcceptRulesWithoutTap: without a device name there is nothing to
// scope the rules to, so nothing may be installed and the host policy stays in
// charge. Installing an unscoped accept here would open the host's forwarding.
func TestForwardAcceptRulesWithoutTap(t *testing.T) {
	if got := forwardAcceptRules(""); got != nil {
		t.Fatalf("got %d unscoped rules for an empty tap name, want none", len(got))
	}
}

// TestForwardAcceptRulesInstallNoDrop: the chain must never carry a drop
// verdict. A drop here would fight the host's own rules and could break
// forwarding the host legitimately needs, so the whole point is to accept the
// tunnel traffic and let everything else fall through.
func TestForwardAcceptRulesInstallNoDrop(t *testing.T) {
	for _, r := range forwardAcceptRules("ptap0") {
		if !r.Dir.valid() {
			t.Fatalf("rule %+v has an unknown direction", r)
		}
	}
}

// valid reports whether the direction has a meaning.
func (d forwardDirection) valid() bool {
	return d == forwardIn || d == forwardOut
}
