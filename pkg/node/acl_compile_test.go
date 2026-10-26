package node

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"

	"p2ptap/pkg/config"
	"p2ptap/pkg/packet"
)

func TestParseACLPort(t *testing.T) {
	for _, tc := range []struct {
		port    string
		wantMin int
		wantMax int
		wantOK  bool
	}{
		{"80", 80, 80, true},
		{"0", 0, 0, true},
		{"65535", 65535, 65535, true},
		{"1024-65535", 1024, 65535, true},
		{"8000-9000", 8000, 9000, true},
		{"0-0", 0, 0, true},
		// Single ports above 65535 never matched; a range upper bound never did
		// either. Both quirks must be preserved by the compiled path.
		{"65536", 0, 0, false},
		{"-1", 0, 0, false},
		{"-5", 0, 0, false},
		{"abc", 0, 0, false},
		{"", 0, 0, false},
		{"1024-", 0, 0, false},
		{"-65535", 0, 0, false},
		{"1-2-3", 0, 0, false},
		{"10-2", 0, 0, false},
		{"1.5", 0, 0, false},
	} {
		min, max, ok := parseACLPort(tc.port)
		if ok != tc.wantOK || min != tc.wantMin || max != tc.wantMax {
			t.Errorf("parseACLPort(%q) = (%d,%d,%v), want (%d,%d,%v)",
				tc.port, min, max, ok, tc.wantMin, tc.wantMax, tc.wantOK)
		}
	}
}

// matchACLReference is the pre-compilation ACL matcher, kept verbatim so the
// precompiled path can be proven equivalent rather than merely "same as
// itself". compileACL and matchCompiledRules restructure every rule decision
// (lowercasing, port parsing and CIDR parsing all move to compile time), and
// any drift in that restructuring is invisible to the normal ACL tests because
// those were written against whichever implementation existed.
func matchACLReference(aclCfg *config.ACLConfig, frame []byte, peerID string, isTx bool) (allowed bool, matchedRuleID string) {
	if aclCfg == nil || !aclCfg.Enable {
		return true, ""
	}

	if len(frame) < 14 {
		defAct := strings.ToLower(aclCfg.DefaultAction)
		return defAct == "accept" || defAct == "allow" || defAct == "", ""
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	var dstIP net.IP
	var protoStr string
	var dstPort int
	var portsAvailable bool

	if etherType == packet.EtherTypeIPv4 {
		defAct := strings.ToLower(aclCfg.DefaultAction)
		defAllow := defAct == "accept" || defAct == "allow" || defAct == ""
		if len(frame) < 34 {
			return defAllow, ""
		}
		ipHeader := frame[14:]
		ihl := int(ipHeader[0]&0x0f) * 4
		if ihl < 20 || len(ipHeader) < ihl {
			return defAllow, ""
		}
		protocol := ipHeader[9]
		dstIP = net.IP(ipHeader[16:20])

		payload := ipHeader[ihl:]
		fragOff := int(binary.BigEndian.Uint16(ipHeader[6:8]) & 0x1FFF)
		mfFlag := (binary.BigEndian.Uint16(ipHeader[6:8]) >> 15) & 1
		switch protocol {
		case 1:
			protoStr = "icmp"
		case 6:
			protoStr = "tcp"
			if fragOff == 0 && mfFlag == 0 && len(payload) >= 4 {
				dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
				portsAvailable = true
			}
		case 17:
			protoStr = "udp"
			if fragOff == 0 && mfFlag == 0 && len(payload) >= 4 {
				dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
				portsAvailable = true
			}
		default:
			protoStr = "any"
		}
	} else if etherType == packet.EtherTypeIPv6 {
		defAct := strings.ToLower(aclCfg.DefaultAction)
		defAllow := defAct == "accept" || defAct == "allow" || defAct == ""
		if len(frame) < 54 {
			return defAllow, ""
		}
		ipHeader := frame[14:]
		dstIP = net.IP(ipHeader[24:40])
		protoStr, dstPort, portsAvailable = parseIPv6Transport(ipHeader[6], ipHeader[40:])
	} else {
		defAct := strings.ToLower(aclCfg.DefaultAction)
		defAllow := defAct == "accept" || defAct == "allow" || defAct == ""
		return defAllow, ""
	}

	for _, rule := range aclCfg.Rules {
		dir := strings.ToLower(rule.Direction)
		if dir == "inbound" && isTx {
			continue
		}
		if dir == "outbound" && !isTx {
			continue
		}

		if rule.PeerID != "" && rule.PeerID != "*" && rule.PeerID != peerID {
			continue
		}

		proto := strings.ToLower(rule.Protocol)
		if proto != "" && proto != "any" && proto != protoStr {
			continue
		}

		if rule.Port != "" && rule.Port != "0" {
			if !portsAvailable {
				continue
			}
			if strings.Contains(rule.Port, "-") {
				parts := strings.Split(rule.Port, "-")
				if len(parts) != 2 {
					continue
				}
				minP, err1 := strconv.Atoi(parts[0])
				maxP, err2 := strconv.Atoi(parts[1])
				if err1 != nil || err2 != nil || minP < 0 || maxP < 0 || minP > maxP {
					continue
				}
				if dstPort < minP || dstPort > maxP {
					continue
				}
			} else {
				pVal, err := strconv.Atoi(rule.Port)
				if err != nil || pVal < 0 || pVal > 65535 {
					continue
				}
				if dstPort != pVal {
					continue
				}
			}
		}

		if rule.IPCIDR != "" && rule.IPCIDR != "*" && dstIP != nil {
			_, cidr, err := net.ParseCIDR(rule.IPCIDR)
			if err != nil || !cidr.Contains(dstIP) {
				continue
			}
		}

		act := strings.ToLower(rule.Action)
		return act == "accept" || act == "allow", rule.RuleID
	}

	defAct := strings.ToLower(aclCfg.DefaultAction)
	return defAct == "accept" || defAct == "allow" || defAct == "", ""
}

// buildIPv6Frame returns an IPv6 frame whose extension-header chain starts at
// chainHead (header length 0) and whose transport header carries proto with the
// given destination port.
func buildIPv6Frame(chainHead, proto byte, dstPort uint16) []byte {
	frame := make([]byte, 14+40+8+8+8)
	frame[12], frame[13] = 0x86, 0xdd
	frame[14] = 0x60 // version 6
	frame[20] = chainHead
	// dst IP at frame[38:54] stays zero; only the header chain matters here.
	frame[54] = proto
	frame[55] = 0
	if proto != 0 {
		frame[62] = proto
		binary.BigEndian.PutUint16(frame[64:66], dstPort)
	}
	return frame
}

func TestMatchACLCompiledParity(t *testing.T) {
	// Rulesets exercising every compiled field, including rules that must
	// never match: malformed port specs, a single port above 65535, a
	// malformed CIDR, and a range whose upper bound is (deliberately, as the
	// reference matcher allows) above 65535.
	rulesets := []*config.ACLConfig{
		{Enable: false},
		{Enable: true},
		{Enable: true, DefaultAction: ""},
		{Enable: true, DefaultAction: "accept"},
		{Enable: true, DefaultAction: "allow"},
		{Enable: true, DefaultAction: "drop"},
		{Enable: true, DefaultAction: "deny"},
		{
			Enable:        true,
			DefaultAction: "drop",
			Rules: []config.ACLRule{
				{RuleID: "in-tcp80", Action: "accept", Direction: "inbound", PeerID: "peer-A", IPCIDR: "10.0.0.0/24", Protocol: "tcp", Port: "80"},
				{RuleID: "rng", Action: "accept", Direction: "both", PeerID: "*", IPCIDR: "*", Protocol: "tcp", Port: "8000-9000"},
				{RuleID: "udp53", Action: "accept", Direction: "outbound", Protocol: "udp", Port: "53"},
				{RuleID: "icmp", Action: "deny", Protocol: "icmp"},
				{RuleID: "any80", Action: "accept", Protocol: "any", Port: "80"},
				{RuleID: "cidr64", Action: "accept", IPCIDR: "fd00::/64"},
				{RuleID: "peerX", Action: "deny", PeerID: "peer-X"},
			},
		},
		{
			Enable:        true,
			DefaultAction: "accept",
			Rules: []config.ACLRule{
				{RuleID: "bad-port", Action: "accept", Protocol: "tcp", Port: "65536"},
				{RuleID: "bad-range", Action: "accept", Protocol: "tcp", Port: "1-2-3"},
				{RuleID: "bad-trail", Action: "accept", Protocol: "tcp", Port: "1024-"},
				{RuleID: "bad-cidr", Action: "accept", IPCIDR: "not-a-cidr"},
				{RuleID: "no-port", Action: "accept", Protocol: "tcp", Port: "0"},
				{RuleID: "wild-card", Action: "accept", PeerID: "*", IPCIDR: "*", Protocol: "any", Port: ""},
				{RuleID: "huge-range", Action: "accept", Protocol: "udp", Port: "1000-99999"},
				{RuleID: "no-dir", Action: "accept", Direction: "both", Protocol: "udp", Port: "53"},
			},
		},
	}

	frames := [][]byte{
		buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 6, 80),
		buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 6, 443),
		buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 6, 8500),
		buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 6, 0),
		buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 6, 65535),
		buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 17, 53),
		buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 17, 1000),
		buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 17, 65535),
		buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 1, 0),
		buildMockIPv4Packet("10.0.0.1", "10.0.0.2", 47, 0),
		buildIPv6Frame(0, 6, 80),
		buildIPv6Frame(0, 17, 53),
		buildIPv6Frame(0, 6, 65535),
		buildIPv6Frame(43, 17, 53),                       // Routing extension header, then UDP
		buildIPv6Frame(50, 0, 0),                         // ESP: opaque chain
		buildIPv6Frame(6, 0, 0),                          // TCP at the top level
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x06}, // ARP
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00, 0x01, 0x01},
		make([]byte, 10),                     // runt
		append(make([]byte, 30), 0x08, 0x00), // IPv4 header truncated
		append(make([]byte, 50), 0x86, 0xdd), // IPv6 header truncated
	}
	peers := []string{"", "peer-A", "peer-B", "peer-X", "*", "no-such-peer"}

	checks := 0
	for _, aclCfg := range rulesets {
		cfg := &config.Config{ACL: *aclCfg}
		// The precompiled ruleset is what the data plane uses; matchACLReference
		// is the frozen original. They must agree on every input, including the
		// rule id, so a silently widened or narrowed rule is caught.
		cmp := (&Node{Config: cfg}).compiledACLFor(cfg)

		for _, frame := range frames {
			for _, peerID := range peers {
				for _, isTx := range []bool{false, true} {
					wantAllowed, wantRule := matchACLReference(&cfg.ACL, frame, peerID, isTx)
					gotAllowed, gotRule := matchCompiledRules(cmp, frame, peerID, isTx)
					if wantAllowed != gotAllowed || wantRule != gotRule {
						t.Fatalf("parity mismatch aclCfg=%+v frameLen=%d peerID=%q isTx=%v: reference=(%v,%q) compiled=(%v,%q)",
							aclCfg, len(frame), peerID, isTx, wantAllowed, wantRule, gotAllowed, gotRule)
					}
					checks++
				}
			}
		}
	}
	if checks == 0 {
		t.Fatal("no combinations were checked")
	}
	t.Logf("checked %d combinations", checks)
}

func TestCompiledACLCacheInvalidatesOnReload(t *testing.T) {
	n := &Node{Config: &config.Config{ACL: config.ACLConfig{Enable: true, DefaultAction: "accept"}}}
	first := n.compiledACLFor(n.config())
	if first == nil {
		t.Fatal("ACL enabled but no compiled ruleset")
	}
	if second := n.compiledACLFor(n.config()); second != first {
		t.Error("same snapshot must reuse the compiled ruleset")
	}

	n.SetConfig(&config.Config{ACL: config.ACLConfig{Enable: true, DefaultAction: "drop"}})
	third := n.compiledACLFor(n.config())
	if third == first {
		t.Error("reloaded snapshot must not reuse the old compiled ruleset")
	}
	if first.defaultAllow != true || third.defaultAllow != false {
		t.Errorf("defaultAllow not honoured: first=%v third=%v", first.defaultAllow, third.defaultAllow)
	}

	// A reload to ACL-disabled must hand back nil, and flipping back on must
	// compile a fresh ruleset rather than the disabled-era one.
	n.SetConfig(&config.Config{})
	if got := n.compiledACLFor(n.config()); got != nil {
		t.Error("disabled ACL must return nil")
	}
	n.SetConfig(&config.Config{ACL: config.ACLConfig{Enable: true, DefaultAction: "allow"}})
	if got := n.compiledACLFor(n.config()); got == nil || got.cfg != n.config() {
		t.Error("re-enabled ACL must return a ruleset keyed at the new snapshot")
	}

	if got := (&Node{}).compiledACLFor(nil); got != nil {
		t.Error("nil config must return nil")
	}
}
