package node

import (
	"encoding/binary"
	"testing"

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
	if !MatchACL(aclCfg, frameTCP80, "peer-A", false) {
		t.Error("Expected MatchACL to ACCEPT peer-A TCP port 80 Rx traffic")
	}

	// Tx (isTx = true) - rule r1 is inbound only!
	if MatchACL(aclCfg, frameTCP80, "peer-A", true) {
		t.Error("Expected MatchACL to DROP peer-A TCP port 80 Tx traffic (r1 is inbound only)")
	}

	// Port 443 -> drop (default action drop)
	if MatchACL(aclCfg, frameTCP443, "peer-A", false) {
		t.Error("Expected MatchACL to DROP peer-A TCP port 443 traffic")
	}

	// Port Range 8000-9000 -> accept
	if !MatchACL(aclCfg, frameTCP8500, "peer-X", true) {
		t.Error("Expected MatchACL to ACCEPT port 8500 (in 8000-9000 range)")
	}
}
