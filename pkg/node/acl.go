package node

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"

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
			offset := binary.BigEndian.Uint16(payload[2:4]) & 0xFFF8
			if offset == 0 {
				// First fragment carries the transport header at its start.
				next = inner
				payload = payload[8:]
				continue
			}
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

	if len(frame) < 14 {
		return true, "" // Non-IP/short control frame -> allow
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
		if len(frame) < 34 {
			return true, ""
		}
		ipHeader := frame[14:]
		ihl := int(ipHeader[0]&0x0f) * 4
		if len(ipHeader) < ihl {
			return true, ""
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
		switch protocol {
		case 1: // ICMP
			protoStr = "icmp"
		case 6: // TCP
			protoStr = "tcp"
			if fragOff == 0 && len(payload) >= 4 {
				dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
				portsAvailable = true
			}
		case 17: // UDP
			protoStr = "udp"
			if fragOff == 0 && len(payload) >= 4 {
				dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
				portsAvailable = true
			}
		default:
			protoStr = "any"
		}
	} else if etherType == packet.EtherTypeIPv6 { // IPv6
		if len(frame) < 54 {
			return true, ""
		}
		ipHeader := frame[14:]
		dstIP = net.IP(ipHeader[24:40])
		// Walk the extension-header chain — reading only byte 6 let a peer
		// hide TCP/UDP behind a Hop-by-Hop/Routing header (protoStr="any")
		// and skip port rules entirely.
		protoStr, dstPort, portsAvailable = parseIPv6Transport(ipHeader[6], ipHeader[40:])
	} else {
		// Non-IP frame (e.g. ARP/NDP), allow by default
		return true, ""
	}

	// Match against ACL Rules in sequential order
	for _, rule := range aclCfg.Rules {
		// Match Direction
		dir := strings.ToLower(rule.Direction)
		if dir == "inbound" && isTx {
			continue
		}
		if dir == "outbound" && !isTx {
			continue
		}

		// Match Peer ID
		if rule.PeerID != "" && rule.PeerID != "*" && rule.PeerID != peerID {
			continue
		}

		// Match Protocol
		proto := strings.ToLower(rule.Protocol)
		if proto != "" && proto != "any" && proto != protoStr {
			continue
		}

		// Match Destination Port / Port Range.
		if rule.Port != "" && rule.Port != "0" {
			// An unevaluable packet must not match a port rule at all — not
			// as DROP (garbage-port evasion) nor as ACCEPT (over-matching
			// fragments that carry no ports).
			if !portsAvailable {
				continue
			}
			if strings.Contains(rule.Port, "-") {
				parts := strings.Split(rule.Port, "-")
				if len(parts) != 2 {
					continue // malformed range never matches by accident
				}
				minP, _ := strconv.Atoi(parts[0])
				maxP, _ := strconv.Atoi(parts[1])
				if dstPort < minP || dstPort > maxP {
					continue
				}
			} else {
				pVal, _ := strconv.Atoi(rule.Port)
				if pVal > 0 && dstPort != pVal {
					continue
				}
			}
		}

		// Match IP CIDR
		if rule.IPCIDR != "" && rule.IPCIDR != "*" && dstIP != nil {
			_, cidr, err := net.ParseCIDR(rule.IPCIDR)
			if err != nil || !cidr.Contains(dstIP) {
				continue
			}
		}

		// Rule matched!
		act := strings.ToLower(rule.Action)
		return act == "accept" || act == "allow", rule.RuleID
	}

	// Fallback to default action if no rule matched
	defAct := strings.ToLower(aclCfg.DefaultAction)
	return defAct == "accept" || defAct == "allow" || defAct == "", ""
}
