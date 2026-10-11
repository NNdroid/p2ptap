package node

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/test"

	"p2ptap/pkg/config"
)

// --- relay-transit ACL ------------------------------------------------------
//
// checkRelayTransitACL runs at the RELAY node, so it is the only check standing
// between a peer that is blocked on the direct path and reaching the destination
// through a third party. Anything it lets through that MatchACL would have
// denied locally is a policy bypass.

func transitNode(acl *config.ACLConfig) *Node {
	return &Node{Config: &config.Config{ACL: *acl}}
}

func TestCheckRelayTransitACLWildcardHonoured(t *testing.T) {
	src := test.RandPeerIDFatal(t)
	dst := test.RandPeerIDFatal(t)
	srcStr := src.String()

	cases := []struct {
		name string
		acl  *config.ACLConfig
		want bool
	}{
		{
			name: "wildcard deny blocks transit even when the default action allows",
			acl: &config.ACLConfig{
				Enable:        true,
				DefaultAction: "accept",
				Rules:         []config.ACLRule{{RuleID: "deny-all", Direction: "both", PeerID: "*", Action: "deny"}},
			},
			want: false,
		},
		{
			name: "wildcard accept allows transit when the default action denies",
			acl: &config.ACLConfig{
				Enable:        true,
				DefaultAction: "drop",
				Rules:         []config.ACLRule{{RuleID: "allow-all", Direction: "both", PeerID: "*", Action: "accept"}},
			},
			want: true,
		},
		{
			name: "wildcard deny placed before a specific accept wins, matching MatchACL's first-match order",
			acl: &config.ACLConfig{
				Enable:        true,
				DefaultAction: "drop",
				Rules: []config.ACLRule{
					{RuleID: "deny-all", Direction: "both", PeerID: "*", Action: "deny"},
					{RuleID: "allow-one", Direction: "both", PeerID: srcStr, Action: "accept"},
				},
			},
			want: false,
		},
		{
			name: "specific accept before the wildcard allows",
			acl: &config.ACLConfig{
				Enable:        true,
				DefaultAction: "drop",
				Rules: []config.ACLRule{
					{RuleID: "allow-one", Direction: "both", PeerID: srcStr, Action: "accept"},
					{RuleID: "deny-all", Direction: "both", PeerID: "*", Action: "deny"},
				},
			},
			want: true,
		},
		{
			name: "specific deny without any wildcard blocks",
			acl: &config.ACLConfig{
				Enable:        true,
				DefaultAction: "accept",
				Rules:         []config.ACLRule{{RuleID: "deny-one", Direction: "both", PeerID: srcStr, Action: "deny"}},
			},
			want: false,
		},
		{
			name: "no matching rule falls back to the default action",
			acl: &config.ACLConfig{
				Enable:        true,
				DefaultAction: "drop",
				Rules:         []config.ACLRule{{RuleID: "other", Direction: "both", PeerID: "Qmaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Action: "accept"}},
			},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := transitNode(tc.acl)
			if got := n.checkRelayTransitACL(src, dst); got != tc.want {
				t.Fatalf("checkRelayTransitACL = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCheckRelayTransitACLDisabled(t *testing.T) {
	n := transitNode(&config.ACLConfig{Enable: false, DefaultAction: "drop"})
	if !n.checkRelayTransitACL(test.RandPeerIDFatal(t), test.RandPeerIDFatal(t)) {
		t.Fatal("ACL disabled must allow transit unconditionally")
	}
}

// TestCheckRelayTransitACLMatchesMatchACL cross-checks the relay-transit verdict
// against the direct-path evaluator on the same ruleset. A divergence in the
// direction of "relay allows, direct denies" is exactly the bounce bypass the
// transit check exists to prevent.
func TestCheckRelayTransitACLMatchesMatchACL(t *testing.T) {
	src := test.RandPeerIDFatal(t)
	frame := buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 6, 80)
	ruleSets := []config.ACLConfig{
		{Enable: true, DefaultAction: "drop",
			Rules: []config.ACLRule{{Direction: "both", PeerID: "*", Action: "deny"}}},
		{Enable: true, DefaultAction: "accept",
			Rules: []config.ACLRule{{Direction: "both", PeerID: "*", Action: "accept"}}},
		{Enable: true, DefaultAction: "drop",
			Rules: []config.ACLRule{{Direction: "both", PeerID: src.String(), Action: "accept"}}},
		{Enable: true, DefaultAction: "accept",
			Rules: []config.ACLRule{{Direction: "both", PeerID: src.String(), Action: "deny"}}},
		{Enable: true, DefaultAction: "drop",
			Rules: []config.ACLRule{
				{Direction: "both", PeerID: src.String(), Action: "accept"},
				{Direction: "both", PeerID: "*", Action: "deny"},
			}},
	}
	for i, acl := range ruleSets {
		n := transitNode(&acl)
		gotTransit := n.checkRelayTransitACL(src, test.RandPeerIDFatal(t))
		gotDirect, _ := MatchACL(&acl, frame, src.String(), false)
		if gotTransit != gotDirect {
			t.Fatalf("ruleSet #%d: transit=%v but direct-path MatchACL=%v for the same ruleset",
				i, gotTransit, gotDirect)
		}
	}
}

// --- broadcast dedup ring ---------------------------------------------------

func TestBcastDedupRingSuppressesDuplicates(t *testing.T) {
	r := &bcastDedupRing{}
	if r.isDuplicate(0) || r.isDuplicate(0) {
		t.Fatal("hash 0 must never be treated as a duplicate (empty content)")
	}
	if r.isDuplicate(42) {
		t.Fatal("first sighting of a hash must not be a duplicate")
	}
	if !r.isDuplicate(42) {
		t.Fatal("an identical broadcast arriving again within the TTL must be suppressed")
	}
}

// TestBcastDedupRingEvictsAtCapacity pins the eviction-on-every-insert fix.
//
// Before the fix the TTL sweep broke out as soon as it had removed any entry
// and had not drained below half capacity, leaving the map at or above the cap.
// When NOTHING is expirable — a sustained flood of unique-content broadcasts
// (DHCPDISCOVERs with distinct client IDs, mDNS) — the sweep removed nothing,
// so every insert succeeded and the map grew without bound. Replaying this test
// before the fix fails on the "grew past its cap" assertion.
func TestBcastDedupRingEvictsAtCapacity(t *testing.T) {
	r := &bcastDedupRing{}

	for i := 0; i < bcastDedupMaxEntries; i++ {
		if r.isDuplicate(uint64(i + 1)) {
			t.Fatalf("first insert of hash %d unexpectedly treated as a duplicate", i+1)
		}
	}
	if got := len(r.entries); got != bcastDedupMaxEntries {
		t.Fatalf("ring should hold %d entries, got %d", bcastDedupMaxEntries, got)
	}

	// Every entry was written a nanosecond ago, so the TTL sweep cannot free a
	// single slot. Each insert must therefore force an eviction.
	for i := 0; i < 500; i++ {
		r.isDuplicate(uint64(bcastDedupMaxEntries + i + 1))
	}
	if got := len(r.entries); got > bcastDedupMaxEntries {
		t.Fatalf("ring grew past its cap: %d entries (cap %d)", got, bcastDedupMaxEntries)
	}

	// The ring must still be accepting and suppressing entries after the churn,
	// i.e. the half-eviction cannot have left it in a frozen state.
	if r.isDuplicate(2000) {
		t.Fatal("ring refused a brand-new hash after the churn; inserts are stuck")
	}
	if !r.isDuplicate(2000) {
		t.Fatal("ring failed to suppress a repeat of a hash it just accepted; dedup is disabled")
	}
}
