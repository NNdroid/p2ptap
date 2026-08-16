package node

import (
	"fmt"
	"net"

	"p2ptap/pkg/packet"
)

const (
	etherTypeIPv4 = packet.EtherTypeIPv4
	etherTypeARP  = packet.EtherTypeARP
	etherTypeIPv6 = packet.EtherTypeIPv6
)

// describeEthernetFrame keeps packet logging useful without exposing payloads.
func describeEthernetFrame(frame []byte) string {
	h := packet.ParseHeader(frame)
	if h.EtherType == 0 {
		return fmt.Sprintf("ethernet=short(%d)", len(frame))
	}

	description := fmt.Sprintf("eth=%s->%s type=0x%04x", h.SrcMAC, h.DstMAC, h.EtherType)

	switch h.EtherType {
	case etherTypeARP:
		if len(frame) >= 42 {
			op := packet.ARPOp(frame)
			senderIP := net.IP(frame[28:32])
			targetIP := net.IP(frame[38:42])
			return fmt.Sprintf("%s arp-op=%d %s->%s", description, op, senderIP, targetIP)
		}
	case etherTypeIPv4:
		if len(frame) >= 34 {
			return fmt.Sprintf("%s ipv4=%s->%s proto=%d", description, net.IP(frame[26:30]), net.IP(frame[30:34]), frame[23])
		}
	case etherTypeIPv6:
		if len(frame) >= 54 {
			return fmt.Sprintf("%s ipv6=%s->%s next=%d", description, net.IP(frame[22:38]), net.IP(frame[38:54]), frame[20])
		}
	}

	return description
}
