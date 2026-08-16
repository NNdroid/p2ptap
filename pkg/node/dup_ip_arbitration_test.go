package node

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/config"
)

func pid(s string) peer.ID { return peer.ID(s) }

// pidStr returns the canonical string form of a peer ID, exactly the value that
// would appear in the real allowed_subnet_peers config list (peer.ID is a
// CID-encoded string, not the literal we construct it from).
func pidStr(s string) string { return pid(s).String() }

func TestArbitratePeers(t *testing.T) {
	tests := []struct {
		name       string
		claimants  []peer.ID
		order      []string
		wantWinner peer.ID // empty means "any claimant is acceptable" (tie-break case)
		// wantLosers is checked as a set, not an order.
		wantLosers []peer.ID
		reasonHas  []string
	}{
		{
			name:       "earlier in list wins",
			claimants:  []peer.ID{pid("peer-A"), pid("peer-B")},
			order:      []string{pidStr("peer-B"), pidStr("peer-A")},
			wantWinner: pid("peer-B"),
			wantLosers: []peer.ID{pid("peer-A")},
			reasonHas:  []string{"index 0"},
		},
		{
			name:       "reversed list flips winner",
			claimants:  []peer.ID{pid("peer-A"), pid("peer-B")},
			order:      []string{pidStr("peer-A"), pidStr("peer-B")},
			wantWinner: pid("peer-A"),
			wantLosers: []peer.ID{pid("peer-B")},
			reasonHas:  []string{"index 0"},
		},
		{
			name:       "wildcard only ties broken by lowest peer ID",
			claimants:  []peer.ID{pid("peer-Z"), pid("peer-A")},
			order:      []string{"*"},
			wantWinner: "", // deterministic but depends on CID string order
			wantLosers: nil,
			reasonHas:  []string{"no ordered preference", "lowest peer ID"},
		},
		{
			name:       "empty list ties broken by lowest peer ID",
			claimants:  []peer.ID{pid("peer-M"), pid("peer-A")},
			order:      nil,
			wantWinner: "",
			wantLosers: nil,
			reasonHas:  []string{"no ordered preference"},
		},
		{
			name:       "listed peer beats unlisted",
			claimants:  []peer.ID{pid("peer-C"), pid("peer-B")},
			order:      []string{pidStr("peer-B")},
			wantWinner: pid("peer-B"),
			wantLosers: []peer.ID{pid("peer-C")},
			reasonHas:  []string{"index 0", "not in list"},
		},
		{
			name:       "explicit entry beats wildcard-matched peer",
			claimants:  []peer.ID{pid("peer-X"), pid("peer-A"), pid("peer-C")},
			order:      []string{pidStr("peer-C"), "*", pidStr("peer-A")},
			wantWinner: pid("peer-C"),
			wantLosers: []peer.ID{pid("peer-X"), pid("peer-A")},
			reasonHas:  []string{"index 0"},
		},
		{
			name:       "single claimant no conflict",
			claimants:  []peer.ID{pid("peer-A")},
			order:      []string{pidStr("peer-B")},
			wantWinner: pid("peer-A"),
			wantLosers: nil,
			reasonHas:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			winner, losers, reason := arbitratePeers(tt.claimants, tt.order)

			// Winner must be one of the claimants and never among the losers.
			isClaimant := false
			for _, c := range tt.claimants {
				if c == winner {
					isClaimant = true
				}
			}
			if !isClaimant {
				t.Errorf("winner %s is not a claimant %v", winner, tt.claimants)
			}
			if len(losers) != len(tt.claimants)-1 {
				t.Fatalf("losers = %v (len %d), want %d", losers, len(losers), len(tt.claimants)-1)
			}
			got := map[peer.ID]bool{}
			for _, l := range losers {
				if l == winner {
					t.Errorf("winner %s also appears in losers %v", winner, losers)
				}
				got[l] = true
			}
			for _, w := range tt.wantLosers {
				if !got[w] {
					t.Errorf("loser set = %v, missing %s", losers, w)
				}
			}
			if tt.wantWinner != "" && winner != tt.wantWinner {
				t.Errorf("winner = %s, want %s", winner, tt.wantWinner)
			}
			for _, sub := range tt.reasonHas {
				if !strings.Contains(reason, sub) {
					t.Errorf("reason = %q, want it to contain %q", reason, sub)
				}
			}
			t.Logf("[arbitrate] %s -> winner=%s losers=%v | %s", tt.name, winner, losers, reason)
		})
	}
}

// newArbitrationNode builds a minimal Node with a non-nil Config so
// rebuildARPIndex can read AllowedSubnetPeers, then seeds the given peers.
func newArbitrationNode(t *testing.T, order []string, metas map[peer.ID]PeerMeta) *Node {
	t.Helper()
	n := &Node{Config: &config.Config{AllowedSubnetPeers: order}}
	for p, m := range metas {
		n.storePeerMeta(p, m)
	}
	return n
}

func TestRebuildARPIndexDuplicateIPv4Arbitration(t *testing.T) {
	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a}
	macB := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x0b}

	// peer-A appears BEFORE peer-B in the allow list → must win the duplicate.
	n := newArbitrationNode(t,
		[]string{pidStr("peer-A"), pidStr("peer-B")},
		map[peer.ID]PeerMeta{
			pid("peer-A"): {TapIP: "10.0.0.5/24", TapMAC: macA.String()},
			pid("peer-B"): {TapIP: "10.0.0.5/24", TapMAC: macB.String()},
		},
	)

	gotPID, gotMAC := n.resolvePeerIDByIP(net.ParseIP("10.0.0.5"))
	if gotPID != pid("peer-A") {
		t.Fatalf("resolvePeerIDByIP(10.0.0.5) = %s, want peer-A (earlier in allow list)", gotPID)
	}
	if !bytes.Equal(gotMAC, macA) {
		t.Errorf("winner MAC = %v, want %v", gotMAC, macA)
	}

	conflicts := n.GetDuplicateIPConflicts()
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %d, want 1", len(conflicts))
	}
	c := conflicts[0]
	if c.ResourceType != "tap_ip_v4" {
		t.Errorf("ResourceType = %q, want tap_ip_v4", c.ResourceType)
	}
	if c.Resource != "10.0.0.5" {
		t.Errorf("Resource = %q, want 10.0.0.5", c.Resource)
	}
	if c.Winner != pidStr("peer-A") {
		t.Errorf("Winner = %q, want peer-A", c.Winner)
	}
	if len(c.Losers) != 1 || c.Losers[0] != pidStr("peer-B") {
		t.Errorf("Losers = %v, want [peer-B]", c.Losers)
	}
	if !strings.Contains(c.Reason, "index 0") {
		t.Errorf("Reason = %q, want it to mention the list index", c.Reason)
	}
	t.Logf("[dup-ip] v4 conflict -> %+v", c)
}

func TestRebuildARPIndexDuplicateIPv6Arbitration(t *testing.T) {
	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a}
	macB := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x0b}

	n := newArbitrationNode(t,
		[]string{pidStr("peer-B"), pidStr("peer-A")}, // peer-B first → must win
		map[peer.ID]PeerMeta{
			pid("peer-A"): {TapIPv6: "fd00::5/64", TapMAC: macA.String()},
			pid("peer-B"): {TapIPv6: "fd00::5/64", TapMAC: macB.String()},
		},
	)

	gotPID, _ := n.resolvePeerIDByIP(net.ParseIP("fd00::5"))
	if gotPID != pid("peer-B") {
		t.Fatalf("resolvePeerIDByIP(fd00::5) = %s, want peer-B (earlier in allow list)", gotPID)
	}
	conflicts := n.GetDuplicateIPConflicts()
	if len(conflicts) != 1 || conflicts[0].ResourceType != "tap_ip_v6" || conflicts[0].Winner != pidStr("peer-B") {
		t.Fatalf("conflicts = %+v, want one tap_ip_v6 conflict won by peer-B", conflicts)
	}
	t.Logf("[dup-ip] v6 conflict -> %+v", conflicts[0])
}

func TestRebuildARPIndexDuplicateSubnetArbitration(t *testing.T) {
	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a}
	macB := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x0b}

	n := newArbitrationNode(t,
		[]string{pidStr("peer-A"), pidStr("peer-B")},
		map[peer.ID]PeerMeta{
			pid("peer-A"): {TapIP: "10.0.0.2/24", TapMAC: macA.String(), AdvertisedSubnets: []string{"192.168.1.0/24"}},
			pid("peer-B"): {TapIP: "10.0.0.3/24", TapMAC: macB.String(), AdvertisedSubnets: []string{"192.168.1.0/24"}},
		},
	)

	// The winning subnet owner's MAC must be what the index returns.
	gotMAC := n.lookupPeerMACByAdvertisedSubnet(net.ParseIP("192.168.1.50"))
	if !bytes.Equal(gotMAC, macA) {
		t.Fatalf("subnet lookup MAC = %v, want peer-A's MAC %v", gotMAC, macA)
	}
	conflicts := n.GetDuplicateIPConflicts()
	if len(conflicts) != 1 || conflicts[0].ResourceType != "advertised_subnet" {
		t.Fatalf("conflicts = %+v, want one advertised_subnet conflict", conflicts)
	}
	if conflicts[0].Winner != pidStr("peer-A") || conflicts[0].Losers[0] != pidStr("peer-B") {
		t.Fatalf("subnet conflict verdict = %+v, want peer-A beats peer-B", conflicts[0])
	}
	t.Logf("[dup-ip] subnet conflict -> %+v", conflicts[0])
}

func TestRebuildARPIndexNoConflictWhenUnique(t *testing.T) {
	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a}
	macB := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x0b}

	n := newArbitrationNode(t,
		[]string{pidStr("peer-A"), pidStr("peer-B")},
		map[peer.ID]PeerMeta{
			pid("peer-A"): {TapIP: "10.0.0.2/24", TapMAC: macA.String()},
			pid("peer-B"): {TapIP: "10.0.0.3/24", TapMAC: macB.String()},
		},
	)
	if got := n.GetDuplicateIPConflicts(); len(got) != 0 {
		t.Fatalf("conflicts = %+v, want none for unique IPs", got)
	}
	// Unique lookups must still resolve correctly.
	if gotPID, _ := n.resolvePeerIDByIP(net.ParseIP("10.0.0.3")); gotPID != pid("peer-B") {
		t.Errorf("resolve(10.0.0.3) = %s, want peer-B", gotPID)
	}
}

func TestRebuildARPIndexOverlappingSubnetArbitration(t *testing.T) {
	macA := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a}
	macB := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x0b}

	// peer-A (10.0.0.0/8) contains peer-B's subnet (10.1.0.0/16). A is earlier
	// in the allow list so it must win; B's overlapping subnet is suppressed.
	n := newArbitrationNode(t,
		[]string{pidStr("peer-A"), pidStr("peer-B")},
		map[peer.ID]PeerMeta{
			pid("peer-A"): {TapIP: "10.0.0.2/24", TapMAC: macA.String(), AdvertisedSubnets: []string{"10.0.0.0/8"}},
			pid("peer-B"): {TapIP: "10.0.0.3/24", TapMAC: macB.String(), AdvertisedSubnets: []string{"10.1.0.0/16"}},
		},
	)

	conflicts := n.GetDuplicateIPConflicts()
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %d, want 1 overlapping-subnet conflict", len(conflicts))
	}
	c := conflicts[0]
	if c.ResourceType != "advertised_subnet_overlap" {
		t.Errorf("ResourceType = %q, want advertised_subnet_overlap", c.ResourceType)
	}
	if c.Resource != "10.1.0.0/16" {
		t.Errorf("Resource = %q, want the LOSER's CIDR 10.1.0.0/16", c.Resource)
	}
	if c.Winner != pidStr("peer-A") || len(c.Losers) != 1 || c.Losers[0] != pidStr("peer-B") {
		t.Errorf("verdict = winner=%q losers=%v, want peer-A beats peer-B", c.Winner, c.Losers)
	}

	// The loser's overlapping subnet must be suppressed from the routing index:
	// an IP inside 10.1.0.0/16 resolves to the WINNER (peer-A), not peer-B.
	gotPID, gotMAC := n.resolvePeerIDByIP(net.ParseIP("10.1.5.9"))
	if gotPID != pid("peer-A") {
		t.Errorf("resolve(10.1.5.9) = %s, want peer-A (winner covers the overlap)", gotPID)
	}
	if !bytes.Equal(gotMAC, macA) {
		t.Errorf("winner MAC = %v, want peer-A's MAC %v", gotMAC, macA)
	}

	// OS route for the losing subnet must be reported as suppressed.
	if !n.isSubnetRouteSuppressed(pid("peer-B"), "10.1.0.0/16") {
		t.Errorf("isSubnetRouteSuppressed(peer-B, 10.1.0.0/16) = false, want true")
	}
	// The winning subnet is NOT suppressed.
	if n.isSubnetRouteSuppressed(pid("peer-A"), "10.0.0.0/8") {
		t.Errorf("isSubnetRouteSuppressed(peer-A, 10.0.0.0/8) = true, want false (winner)")
	}
	t.Logf("[dup-ip] overlap conflict -> %+v", c)
}

func TestIsSubnetRouteSuppressedNoConflict(t *testing.T) {
	n := newArbitrationNode(t,
		[]string{pidStr("peer-A"), pidStr("peer-B")},
		map[peer.ID]PeerMeta{
			pid("peer-A"): {TapIP: "10.0.0.2/24", TapMAC: "02:00:00:00:00:0a", AdvertisedSubnets: []string{"192.168.1.0/24"}},
			pid("peer-B"): {TapIP: "10.0.0.3/24", TapMAC: "02:00:00:00:00:0b", AdvertisedSubnets: []string{"192.168.2.0/24"}},
		},
	)
	if n.isSubnetRouteSuppressed(pid("peer-A"), "192.168.1.0/24") {
		t.Errorf("unique subnet must NOT be suppressed")
	}
	if n.isSubnetRouteSuppressed(pid("peer-B"), "192.168.2.0/24") {
		t.Errorf("unique subnet must NOT be suppressed")
	}
	if n.isSubnetRouteSuppressed(pid("peer-A"), "10.9.9.0/24") {
		t.Errorf("unrelated CIDR must NOT be suppressed")
	}
}
