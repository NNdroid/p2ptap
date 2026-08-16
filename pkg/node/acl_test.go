package node

import (
	"encoding/binary"
	"testing"
	"time"

	"p2ptap/pkg/config"
)

func buildMockIPv4Packet(srcIP, dstIP string, proto byte, dstPort uint16) []byte {
	frame := make([]byte, 14+20+8)
	// Ethernet Header (14 bytes)
	frame[12] = 0x08
	frame[13] = 0x00

	// IPv4 Header (20 bytes)
	frame[14] = 0x45 // Version 4, IHL 5
	frame[23] = proto
	copy(frame[26:30], parseIPv4(srcIP))
	copy(frame[30:34], parseIPv4(dstIP))

	// TCP/UDP Port
	binary.BigEndian.PutUint16(frame[36:38], dstPort)
	return frame
}

func parseIPv4(ipStr string) []byte {
	return []byte{10, 0, 0, 1}
}

func TestMatchACL(t *testing.T) {
	aclCfg := &config.ACLConfig{
		Enable:        true,
		DefaultAction: "drop",
		Rules: []config.ACLRule{
			{RuleID: "r1", Action: "accept", Direction: "inbound", PeerID: "peer-A", IPCIDR: "10.0.0.0/24", Protocol: "tcp", Port: "80", Comment: "Allow HTTP"},
			{RuleID: "r2", Action: "accept", Direction: "both", PeerID: "*", IPCIDR: "*", Protocol: "tcp", Port: "8000-9000", Comment: "Allow Dev Range"},
		},
	}

	frameTCP80 := buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 6, 80)
	frameTCP443 := buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 6, 443)
	frameTCP8500 := buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 6, 8500)

	// Rx (isTx = false)
	if got, rid := MatchACL(aclCfg, frameTCP80, "peer-A", false); !got {
		t.Error("Expected MatchACL to ACCEPT peer-A TCP port 80 Rx traffic")
	} else if rid != "r1" {
		t.Errorf("Expected rule id r1, got %q", rid)
	} else {
		t.Log("[acl] ✓ peer-A TCP/80 Rx ACCEPTED (rule r1 inbound)")
	}

	// Tx (isTx = true) - rule r1 is inbound only!
	if got, _ := MatchACL(aclCfg, frameTCP80, "peer-A", true); got {
		t.Error("Expected MatchACL to DROP peer-A TCP port 80 Tx traffic (r1 is inbound only)")
	} else {
		t.Log("[acl] ✓ peer-A TCP/80 Tx DROPPED (rule r1 inbound-only)")
	}

	// Port 443 -> drop (default action drop) -> matchedRuleID is ""
	if got, rid := MatchACL(aclCfg, frameTCP443, "peer-A", false); got {
		t.Error("Expected MatchACL to DROP peer-A TCP port 443 traffic")
	} else if rid != "" {
		t.Errorf("Expected empty rule id (default action), got %q", rid)
	} else {
		t.Log("[acl] ✓ peer-A TCP/443 DROPPED (default action)")
	}

	// Port Range 8000-9000 -> accept (matches r2)
	if got, rid := MatchACL(aclCfg, frameTCP8500, "peer-X", true); !got {
		t.Error("Expected MatchACL to ACCEPT port 8500 (in 8000-9000 range)")
	} else if rid != "r2" {
		t.Errorf("Expected rule id r2, got %q", rid)
	} else {
		t.Log("[acl] ✓ peer-X TCP/8500 Tx ACCEPTED (r2 range 8000-9000, wildcard peer)")
	}
}

// TestACLStats verifies the counter logic that the WebUI status card reads.
func TestACLStats(t *testing.T) {
	s := newACLStats()

	// Three accepts (two hit rules, one falls through to default).
	s.recordAccept()
	s.recordRuleHit("r1")
	s.recordAccept()
	s.recordRuleHit("r2")
	s.recordAccept()

	// Two drops (one matched rule, one default).
	s.recordDrop(ACLDropRecord{Time: timeNow(), PeerID: "p1", RuleID: "r3", Reason: "rule:r3", Proto: "tcp", DstIP: "10.0.0.5", DstPort: 22, Dir: "inbound"})
	s.recordDrop(ACLDropRecord{Time: timeNow(), PeerID: "p2", RuleID: "", Reason: "default", Proto: "udp", DstIP: "8.8.8.8", DstPort: 53, Dir: "outbound"})

	snap := s.snapshot()
	if snap.Accepted != 3 {
		t.Errorf("Accepted: got %d, want 3", snap.Accepted)
	}
	if snap.Dropped != 2 {
		t.Errorf("Dropped: got %d, want 2", snap.Dropped)
	}
	if len(snap.RuleHits) != 2 {
		t.Errorf("RuleHits len: got %d, want 2", len(snap.RuleHits))
	}
	// Sorted by hits desc: both r1 and r2 have 1, fall back to rule id order.
	if snap.RuleHits[0].RuleID != "r1" || snap.RuleHits[1].RuleID != "r2" {
		t.Errorf("RuleHits order: got %+v", snap.RuleHits)
	}
	if len(snap.RecentDrops) != 2 {
		t.Errorf("RecentDrops len: got %d, want 2", len(snap.RecentDrops))
	}
	if snap.RecentDrops[0].PeerID != "p1" {
		t.Errorf("RecentDrops[0]: got %+v", snap.RecentDrops[0])
	}
}

// timeNow is a hook for tests; in production it's just time.Now().
var timeNow = func() time.Time { return time.Now() }
