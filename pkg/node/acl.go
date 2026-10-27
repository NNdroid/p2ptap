package node

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync/atomic"

	"p2ptap/pkg/config"
	"p2ptap/pkg/packet"
)

// parseIPv6Transport walks the IPv6 extension-header chain (bounded at 8
// headers — the chain is attacker-sized input) starting at firstHeader and
// returns (protocolLabel, dstPort, portsAvailable). Opaque or un-walkable
// chains (AH/ESP, truncation, hop overflow) report "any" with no ports, so
// only port-less / any-proto rules can match them; fragment chains without a
// transport header likewise never satisfy a port rule.
func parseIPv6Transport(firstHeader byte, payload []byte) (string, int, bool) {
	next := firstHeader
	for i := 0; i < 8; i++ {
		switch next {
		case 6, 17:
			label := "tcp"
			if next == 17 {
				label = "udp"
			}
			if len(payload) >= 4 {
				return label, int(binary.BigEndian.Uint16(payload[2:4])), true
			}
			return label, 0, false
		case 58:
			return "icmp", 0, false
		case 44: // Fragment
			if len(payload) < 8 {
				return "any", 0, false
			}
			inner := payload[0]
			// Whether offset is 0 (first fragment, transport header present but
			// untrustworthy) or > 0 (continuation, no transport header), port-
			// based ACL matching is unsafe: the real transport header may differ
			// from what the first fragment claims. Return protocol without port.
			switch inner {
			case 6:
				return "tcp", 0, false
			case 17:
				return "udp", 0, false
			case 58:
				return "icmp", 0, false
			default:
				return "any", 0, false
			}
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if len(payload) < 8 {
				return "any", 0, false
			}
			hdrEnd := (int(payload[1]) + 1) * 8
			if len(payload) < hdrEnd {
				return "any", 0, false
			}
			next = payload[0]
			payload = payload[hdrEnd:]
		default:
			// AH/ESP/other protocol numbers: opaque or unhandled.
			return "any", 0, false
		}
	}
	return "any", 0, false
}

// MatchACL evaluates an incoming or outgoing Layer-2 Ethernet frame against the node's ACL rules (ZeroTier-style engine).
// Returns (allowed, matchedRuleID) — matchedRuleID is the RuleID of the first rule that matched, or "" if the
// default action was applied. Callers can use the second return value to attribute the decision to a specific
// rule for per-rule counters and recent-drop reporting.
func MatchACL(aclCfg *config.ACLConfig, frame []byte, peerID string, isTx bool) (allowed bool, matchedRuleID string) {
	if aclCfg == nil || !aclCfg.Enable {
		return true, ""
	}
	// The exported path has no cache to hit, so it compiles the ruleset for
	// this call. Per-frame callers must go through Node.compiledACLFor instead.
	return matchCompiledRules(compileACL(nil, aclCfg), frame, peerID, isTx)
}

// compiledACL is the parsed form of an ACLConfig. Every strings.ToLower,
// strconv.Atoi and net.ParseCIDR in matchCompiledRules is config work: the
// rules only change on a WebUI save, but the old matcher redid all of it on
// every frame for every rule — several string renders, two Atois and a
// CIDR parse apiece. compileACL does it once per config snapshot instead.
//
// cfg is the snapshot the rules were compiled from and is only used as a
// cache key; matchCompiledRules never reads it, so a ruleset compiled with
// cfg == nil (the exported MatchACL path) behaves identically.
type compiledACL struct {
	cfg          *config.Config
	defaultAllow bool
	rules        []compiledACLRule
}

// compiledACLRule is one ACL rule with every string comparison, port spec and
// CIDR already resolved. Malformed values are kept in the ruleset but marked
// as never matching, which is exactly what the old matcher did — a rule that
// cannot match must not be widened into "any port" or "any CIDR".
type compiledACLRule struct {
	ruleID string

	// directionBound marks a rule that names a single direction; then only
	// that direction may use it. directionIsTx says which one, standing in
	// for the old "inbound"/"outbound" strings.
	directionBound bool
	directionIsTx  bool

	// peerAny covers PeerID "" and "*", both of which apply to every peer.
	peerAny bool
	peerID  string

	// proto is the lowercased protocol; "" and "any" both mean "any".
	proto string

	// hasPort gates on the packet actually exposing a destination port. The
	// bounds below are the parsed single port (min == max) or range, and
	// portValid is false for a malformed spec that must never match.
	hasPort   bool
	portValid bool
	portMin   int
	portMax   int

	// ipBinds marks a rule naming a specific CIDR; ipValid is false for an
	// unparseable one, which must never match.
	ipBinds bool
	ipValid bool
	ipNet   *net.IPNet

	allow bool
}

// compileACL parses one ACLConfig into compiledACL. key is the snapshot the
// rules came from (nil when only an ACLConfig is at hand).
func compileACL(key *config.Config, aclCfg *config.ACLConfig) *compiledACL {
	c := &compiledACL{
		cfg:          key,
		defaultAllow: aclActionAllows(strings.ToLower(aclCfg.DefaultAction)),
	}
	for _, rule := range aclCfg.Rules {
		r := compiledACLRule{ruleID: rule.RuleID}

		if dir := strings.ToLower(rule.Direction); dir == "inbound" || dir == "outbound" {
			r.directionBound = true
			r.directionIsTx = dir == "outbound"
		}

		r.peerAny = rule.PeerID == "" || rule.PeerID == "*"
		r.peerID = rule.PeerID
		r.proto = strings.ToLower(rule.Protocol)

		if port := rule.Port; port != "" && port != "0" {
			r.hasPort = true
			if lo, hi, ok := parseACLPort(port); ok {
				r.portValid = true
				r.portMin = lo
				r.portMax = hi
			}
		}

		if cidr := rule.IPCIDR; cidr != "" && cidr != "*" {
			r.ipBinds = true
			if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
				r.ipValid = true
				r.ipNet = ipNet
			}
		}

		r.allow = aclActionAllows(strings.ToLower(rule.Action))
		c.rules = append(c.rules, r)
	}
	return c
}

// aclActionAllows reports whether an action string (already lowercased by the
// caller) means "let it through". The empty string allows, matching the
// default-action behaviour.
func aclActionAllows(action string) bool {
	switch action {
	case "accept", "allow", "":
		return true
	}
	return false
}

// parseACLPort parses "80" or "1024-65535" into inclusive bounds. ok is false
// for anything malformed.
//
// Deliberately mirrors the old strings.Split-based check, including its
// quirk of capping a single port at 65535 but not a range upper bound:
// changing either would change what an existing ruleset matches. The
// >2-dash case fails because Atoi rejects the leftover "2-3" fragment, which
// is the same "never match by accident" outcome Split produced via len != 2.
func parseACLPort(port string) (min, max int, ok bool) {
	if lo, hi, isRange := strings.Cut(port, "-"); isRange {
		loN, err1 := strconv.Atoi(lo)
		hiN, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil || loN < 0 || hiN < 0 || loN > hiN {
			return 0, 0, false
		}
		return loN, hiN, true
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return 0, 0, false
	}
	return p, p, true
}

// matchCompiledRules runs pre-parsed ACL rules against frame. The frame facts
// (dstIP, protocol label, dstPort, portsAvailable) are extracted once above
// the loop, so the loop itself is pure comparison and allocation-free.
//
// aclCfg == nil or disabled is the caller's fast path: matchCompiledRules
// assumes c is non-nil and that c.cfg.Enable was already checked.
func matchCompiledRules(c *compiledACL, frame []byte, peerID string, isTx bool) (allowed bool, matchedRuleID string) {
	if c == nil {
		// compiledACLFor returns nil only when the ACL is disabled or the config
		// is absent, both of which mean "no filtering", so allow.
		return true, ""
	}
	if len(frame) < 14 {
		// Non-IP/short control frame. Apply the default action rather than
		// unconditionally allowing: with DefaultAction=drop, a malformed
		// frame is a silent bypass of the deny-by-default policy.
		return c.defaultAllow, ""
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	var dstIP net.IP
	var protoStr string
	var dstPort int
	// portsAvailable: the transport header was ACTUALLY parsed from the IP
	// payload (not hidden behind continuation fragments, extension chains, or
	// opaque AH/ESP). Port-bearing rules only ever match when this is true.
	var portsAvailable bool

	if etherType == packet.EtherTypeIPv4 { // IPv4
		// Truncated IPv4 or bogus IHL: apply the default action rather than
		// unconditionally allowing (a deny-by-default policy would be bypassed).
		if len(frame) < 34 {
			return c.defaultAllow, ""
		}
		ipHeader := frame[14:]
		ihl := int(ipHeader[0]&0x0f) * 4
		// IHL < 5 (20 bytes) is invalid: the "payload" pointer would land inside
		// the IP header, letting an attacker read arbitrary IP-header bytes as
		// the transport port and bypass port-based ACL rules.
		if ihl < 20 || len(ipHeader) < ihl {
			return c.defaultAllow, ""
		}
		protocol := ipHeader[9]
		dstIP = net.IP(ipHeader[16:20])

		payload := ipHeader[ihl:]
		// Fragments beyond the FIRST carry no transport header: reading
		// "ports" from continuation bytes is attacker-chosen garbage, which
		// let a hostile peer evade port-specific drop rules by fragmenting
		// (the chain never reassembles at the victim without the offset-0
		// fragment, which IS fully matched). Ports are therefore only
		// available when the fragment offset is zero.
		fragOff := int(binary.BigEndian.Uint16(ipHeader[6:8]) & 0x1FFF)
		mfFlag := (binary.BigEndian.Uint16(ipHeader[6:8]) >> 15) & 1
		switch protocol {
		case 1: // ICMP
			protoStr = "icmp"
		case 6: // TCP
			protoStr = "tcp"
			if fragOff == 0 && mfFlag == 0 && len(payload) >= 4 {
				dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
				portsAvailable = true
			}
		case 17: // UDP
			protoStr = "udp"
			if fragOff == 0 && mfFlag == 0 && len(payload) >= 4 {
				dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
				portsAvailable = true
			}
		default:
			protoStr = "any"
		}
	} else if etherType == packet.EtherTypeIPv6 { // IPv6
		// Truncated IPv6: apply the default action (same as IPv4 above).
		if len(frame) < 54 {
			return c.defaultAllow, ""
		}
		ipHeader := frame[14:]
		dstIP = net.IP(ipHeader[24:40])
		// Walk the extension-header chain — reading only byte 6 let a peer
		// hide TCP/UDP behind a Hop-by-Hop/Routing header (protoStr="any")
		// and skip port rules entirely.
		protoStr, dstPort, portsAvailable = parseIPv6Transport(ipHeader[6], ipHeader[40:])
	} else {
		// Non-IP frame (e.g. ARP/NDP). Apply the default action rather than
		// unconditionally allowing: with DefaultAction=drop, ARP/NDP/L2-control
		// traffic must also be denied, matching the fail-closed behavior applied
		// to truncated IP frames above.
		return c.defaultAllow, ""
	}

	// Match against ACL Rules in sequential order
	for i := range c.rules {
		r := &c.rules[i]

		if r.directionBound && r.directionIsTx != isTx {
			continue
		}

		// Match Peer ID
		if !r.peerAny && r.peerID != peerID {
			continue
		}

		// Match Protocol
		if r.proto != "" && r.proto != "any" && r.proto != protoStr {
			continue
		}

		// Match Destination Port / Port Range.
		if r.hasPort {
			// An unevaluable packet must not match a port rule at all — not
			// as DROP (garbage-port evasion) nor as ACCEPT (over-matching
			// fragments that carry no ports).
			if !portsAvailable || !r.portValid {
				continue
			}
			if dstPort < r.portMin || dstPort > r.portMax {
				continue
			}
		}

		// Match IP CIDR
		if r.ipBinds && dstIP != nil && (!r.ipValid || !r.ipNet.Contains(dstIP)) {
			continue
		}

		// Rule matched!
		return r.allow, r.ruleID
	}

	// Fallback to default action if no rule matched
	return c.defaultAllow, ""
}

// compiledACLFor returns the compiled ACL ruleset for the given config
// snapshot, compiling it once per reload. Keying the cache on the snapshot
// pointer means a hot reload publishes a fresh *config.Config and therefore a
// fresh key, so no reload hook has to remember to recompile and a stale
// ruleset is impossible.
//
// nil means "ACL disabled" — callers already returned their fast path.
func (n *Node) compiledACLFor(c *config.Config) *compiledACL {
	if c == nil || !c.ACL.Enable {
		return nil
	}
	slot := n.aclRulesSlot()
	if p := slot.Load(); p != nil && p.cfg == c {
		return p
	}

	n.aclRulesMu.Lock()
	defer n.aclRulesMu.Unlock()
	if p := slot.Load(); p != nil && p.cfg == c {
		return p
	}
	cmp := compileACL(c, &c.ACL)
	slot.Store(cmp)
	return cmp
}

// aclRulesSlot returns the ACL cache slot, allocating it on first use.
// NewNode seeds nothing here: the first ACL-enabled frame takes the slow path
// once, which is exactly the cost the precompile pays for. The allocation is
// guarded by aclRulesOnce because several data-plane goroutines can hit the
// first ACL-enabled frame at once (TestConfigHotReloadVsDataPlaneReads builds
// a bare &Node{} and hammers checkACL concurrently with a hot reload), and a
// bare check-then-set here races. After the first call, Once.Do is a single
// atomic load, so the per-frame fast path stays lock-free.
func (n *Node) aclRulesSlot() *atomic.Pointer[compiledACL] {
	n.aclRulesOnce.Do(func() {
		n.aclRules = new(atomic.Pointer[compiledACL])
	})
	return n.aclRules
}
