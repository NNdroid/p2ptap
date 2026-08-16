package node

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"

	"p2ptap/pkg/config"
	"p2ptap/pkg/packet"
)

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
		switch protocol {
		case 1: // ICMP
			protoStr = "icmp"
		case 6: // TCP
			protoStr = "tcp"
			if len(payload) >= 4 {
				dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
			}
		case 17: // UDP
			protoStr = "udp"
			if len(payload) >= 4 {
				dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
			}
		default:
			protoStr = "any"
		}
	} else if etherType == packet.EtherTypeIPv6 { // IPv6
		if len(frame) < 54 {
			return true, ""
		}
		ipHeader := frame[14:]
		nextHeader := ipHeader[6]
		dstIP = net.IP(ipHeader[24:40])

		payload := ipHeader[40:]
		switch nextHeader {
		case 58: // ICMPv6
			protoStr = "icmp"
		case 6: // TCP
			protoStr = "tcp"
			if len(payload) >= 4 {
				dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
			}
		case 17: // UDP
			protoStr = "udp"
			if len(payload) >= 4 {
				dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
			}
		default:
			protoStr = "any"
		}
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

		// Match Destination Port / Port Range
		if rule.Port != "" && rule.Port != "0" && dstPort > 0 {
			if strings.Contains(rule.Port, "-") {
				parts := strings.Split(rule.Port, "-")
				if len(parts) == 2 {
					minP, _ := strconv.Atoi(parts[0])
					maxP, _ := strconv.Atoi(parts[1])
					if dstPort < minP || dstPort > maxP {
						continue
					}
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
