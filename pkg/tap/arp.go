package tap

import (
	"encoding/binary"
	"net"

	"p2ptap/pkg/packet"
)

const (
	ethernetMinFrameLen = 60
	ethertypeARP        = packet.EtherTypeARP
)

// ndpAllNodesMulticast is the IPv6 all-nodes multicast address (ff02::1),
// precomputed once so every Neighbor Advertisement frame we build does not
// re-parse and re-allocate it on the data path.
var ndpAllNodesMulticast = net.ParseIP("ff02::1").To16()

// isUnspecifiedIPv6 reports whether ip is the IPv6 unspecified address (::).
// A Neighbor Solicitation sent for Duplicate Address Detection uses :: as its
// source, so its corresponding NA must be sent to the all-nodes multicast with
// the Override flag rather than as a unicast Solicited NA to :: (which is
// invalid and silently dropped by the kernel).
func isUnspecifiedIPv6(ip net.IP) bool {
	v6 := ip.To16()
	if len(v6) != 16 {
		return false
	}
	for _, b := range v6 {
		if b != 0 {
			return false
		}
	}
	return true
}

func isARPPayload(packet []byte) bool {
	return len(packet) >= 8 && packet[0] == 0x00 && packet[1] == 0x01 && packet[2] == 0x08 && packet[3] == 0x00
}

func buildARPFrame(localMAC, dstMAC net.HardwareAddr, arpPayload []byte) []byte {
	frame := make([]byte, ethernetMinFrameLen)

	if len(dstMAC) == 6 {
		copy(frame[0:6], dstMAC)
	} else {
		copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	}

	if len(localMAC) == 6 {
		copy(frame[6:12], localMAC)
	} else {
		copy(frame[6:12], packet.DefaultTapMAC)
	}

	binary.BigEndian.PutUint16(frame[12:14], ethertypeARP)
	copy(frame[14:], arpPayload)
	return frame
}

func arpOpcode(frame []byte) uint16 {
	if len(frame) < 22 {
		return 0
	}
	return binary.BigEndian.Uint16(frame[20:22])
}

func BuildARPReplyFrame(localMAC, senderMAC net.HardwareAddr, targetIP, senderIP net.IP) []byte {
	reply := make([]byte, ethernetMinFrameLen)
	if len(senderMAC) == 6 {
		copy(reply[0:6], senderMAC)
	} else {
		copy(reply[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	}
	if len(localMAC) == 6 {
		copy(reply[6:12], localMAC)
	} else {
		copy(reply[6:12], packet.DefaultTapMAC)
	}
	binary.BigEndian.PutUint16(reply[12:14], ethertypeARP)

	binary.BigEndian.PutUint16(reply[14:16], 1)                    // Hardware type: Ethernet
	binary.BigEndian.PutUint16(reply[16:18], packet.EtherTypeIPv4) // Protocol type: IPv4
	reply[18] = 6                                                  // Hardware size
	reply[19] = 4                                                  // Protocol size
	binary.BigEndian.PutUint16(reply[20:22], 2)                    // Opcode: Reply (2)

	if len(localMAC) == 6 {
		copy(reply[22:28], localMAC)
	}
	if targetIP4 := targetIP.To4(); len(targetIP4) == net.IPv4len {
		copy(reply[28:32], targetIP4)
	} else if len(targetIP) == net.IPv4len {
		copy(reply[28:32], targetIP)
	}
	if len(senderMAC) == 6 {
		copy(reply[32:38], senderMAC)
	}
	if senderIP4 := senderIP.To4(); len(senderIP4) == net.IPv4len {
		copy(reply[38:42], senderIP4)
	} else if len(senderIP) == net.IPv4len {
		copy(reply[38:42], senderIP)
	}
	return reply
}

func ShouldRespondToARP(targetIP, localIP, webUIVirtualIP net.IP, localNetwork *net.IPNet) bool {
	if targetIP == nil {
		return false
	}

	targetIP4 := targetIP.To4()
	if len(targetIP4) != net.IPv4len {
		return false
	}

	// Respond if the target is our main TAP IP
	if localIP != nil && targetIP4.Equal(localIP.To4()) {
		return true
	}

	// Respond if the target is our WebUI virtual IP
	if webUIVirtualIP != nil && targetIP4.Equal(webUIVirtualIP.To4()) {
		return true
	}

	// NOTE: We must NOT proxy-ARP for other peers in our subnet (e.g. the
	// Exit Node IP 10.0.0.2). If we answered those ARPs with our own MAC,
	// the OS would resolve the Exit default-route gateway to our local TAP
	// MAC and silently blackhole all tunneled traffic until the ARP cache
	// was flushed (e.g. by disabling/re-enabling the adapter). Peer IPs are
	// resolved through the real learned MAC table (recordMAC) instead.
	return false
}

func calcICMPv6Checksum(srcIP, dstIP []byte, icmpData []byte) uint16 {
	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(srcIP[i : i+2]))
		sum += uint32(binary.BigEndian.Uint16(dstIP[i : i+2]))
	}

	length := uint32(len(icmpData))
	sum += length >> 16
	sum += length & 0xffff
	sum += 58 // Next Header = 58 (ICMPv6)

	for i := 0; i < len(icmpData)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(icmpData[i : i+2]))
	}
	if len(icmpData)%2 == 1 {
		sum += uint32(icmpData[len(icmpData)-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func BuildIPv6NeighborAdvertisementFrame(targetMAC net.HardwareAddr, targetIPv6 net.IP, dstIPv6 ...net.IP) []byte {
	return BuildIPv6NeighborAdvertisementFrameWithMAC(targetMAC, nil, targetIPv6, dstIPv6...)
}

func BuildIPv6NeighborAdvertisementFrameWithMAC(targetMAC, senderMAC net.HardwareAddr, targetIPv6 net.IP, dstIPv6 ...net.IP) []byte {
	v6IP := targetIPv6.To16()
	if len(v6IP) != 16 || len(targetMAC) != 6 {
		return nil
	}

	dstIP := ndpAllNodesMulticast
	flags := byte(0x20) // Override (unsolicited)
	if len(dstIPv6) > 0 && dstIPv6[0] != nil && len(dstIPv6[0].To16()) == 16 && !isUnspecifiedIPv6(dstIPv6[0]) {
		dstIP = dstIPv6[0].To16()
		flags = 0x60 // Solicited + Override
	}

	frame := make([]byte, 86)
	if len(senderMAC) == 6 && (flags&0x40 != 0) {
		copy(frame[0:6], senderMAC)
	} else {
		copy(frame[0:6], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01})
	}
	copy(frame[6:12], targetMAC)
	binary.BigEndian.PutUint16(frame[12:14], packet.EtherTypeIPv6)


	frame[14] = 0x60
	binary.BigEndian.PutUint16(frame[18:20], 32)
	frame[20] = 58  // Next Header: ICMPv6
	frame[21] = 255 // Hop Limit: 255
	copy(frame[22:38], v6IP)
	copy(frame[38:54], dstIP)

	icmpData := frame[54:86]
	icmpData[0] = 136 // Neighbor Advertisement
	icmpData[1] = 0
	icmpData[4] = flags

	copy(icmpData[8:24], v6IP)
	icmpData[24] = 2 // Target Link-Layer Address Option
	icmpData[25] = 1
	copy(icmpData[26:32], targetMAC)

	chksum := calcICMPv6Checksum(frame[22:38], frame[38:54], icmpData)
	binary.BigEndian.PutUint16(icmpData[2:4], chksum)

	return frame
}
