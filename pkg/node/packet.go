package node

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	etherTypeIPv4 = 0x0800
	etherTypeARP  = 0x0806
	etherTypeIPv6 = 0x86dd
)

// describeEthernetFrame keeps packet logging useful without exposing payloads.
func describeEthernetFrame(frame []byte) string {
	if len(frame) < 14 {
		return fmt.Sprintf("ethernet=short(%d)", len(frame))
	}

	dst := net.HardwareAddr(frame[:6])
	src := net.HardwareAddr(frame[6:12])
	etherType := binary.BigEndian.Uint16(frame[12:14])
	description := fmt.Sprintf("eth=%s->%s type=0x%04x", src, dst, etherType)

	switch etherType {
	case etherTypeARP:
		if len(frame) >= 42 {
			op := binary.BigEndian.Uint16(frame[20:22])
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
