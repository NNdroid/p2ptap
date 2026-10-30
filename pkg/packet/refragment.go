package packet

import "encoding/binary"

// Refragment splits an oversized Ethernet frame into Ethernet frames that each
// carry an IP packet no larger than mtu bytes. frame must be a complete
// Ethernet frame (>= EthernetHeaderLen bytes) carrying exactly one unfragmented
// IPv4 or IPv6 packet. fragID seeds the IPv6 Fragment header identification
// (ignored for IPv4, which reuses the packet's own ID field; every fragment of
// one datagram shares that ID).
//
// It returns nil when the frame cannot be safely re-fragmented: a non-IP
// payload, a malformed/truncated packet, an already-fragmented packet, an IPv6
// packet whose payload is preceded by extension headers (the Fragment header
// insertion position is then ambiguous), or a frame that already fits under
// mtu. The caller should drop such a frame (the previous behaviour).
//
// Each returned frame is freshly allocated and independently writable. The
// function never mutates frame and does not retain any slice of it.
//
// This is the receiver-side fix for tunnel MTU asymmetry: a sender whose TAP
// MTU is larger than ours produces IP datagrams up to its own MTU, which our
// TAP device (and validateTapWrite) would otherwise reject. Re-fragmenting them
// to our MTU lets the local IP stack reassemble them transparently, exactly as
// a router with a smaller egress MTU would.
func Refragment(frame []byte, mtu int, fragID uint32) [][]byte {
	if len(frame) < EthernetHeaderLen || mtu <= 0 {
		return nil
	}
	eth := frame[:EthernetHeaderLen]
	ip := frame[EthernetHeaderLen:]
	switch EtherType(frame) {
	case EtherTypeIPv4:
		return refragmentIPv4(eth, ip, mtu)
	case EtherTypeIPv6:
		return refragmentIPv6(eth, ip, mtu, fragID)
	default:
		// ARP, VLAN, non-IP: never oversized in practice (ARP is small), and a
		// VLAN-tagged frame cannot be re-fragmented without unwrapping the tag.
		return nil
	}
}

// refragmentIPv4 splits a single unfragmented IPv4 packet (following eth) into
// fragments each of IP length <= mtu, per RFC 791. The Don't Fragment flag is
// cleared (fragmenting on behalf of the sender is exactly what a tunnel egress
// does); the identification is preserved so the local stack reassembles the
// group. Returns nil if the packet cannot be safely fragmented.
func refragmentIPv4(eth, ip []byte, mtu int) [][]byte {
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return nil
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || ihl > len(ip) {
		return nil
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl || totalLen > len(ip) {
		return nil
	}
	if totalLen <= mtu {
		return nil // already fits; the caller should not have routed here
	}
	fo := binary.BigEndian.Uint16(ip[6:8])
	if fo&0x2000 != 0 || fo&0x1fff != 0 {
		// Already a fragment (MF set or non-zero offset): re-fragmenting a
		// fragment is invalid, so fail closed.
		return nil
	}
	payload := ip[ihl:totalLen]

	// Fragment payload must be a multiple of 8 bytes and must not push the IP
	// length past mtu. Clearing the DF/reserved bits and setting MF per fragment
	// happens in the loop below.
	maxPayload := (mtu - ihl) &^ 7
	if maxPayload < 8 {
		return nil
	}
	n := (len(payload) + maxPayload - 1) / maxPayload
	if n <= 1 {
		return nil // already fits (should not be reached, but be safe)
	}

	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		start := i * maxPayload
		end := start + maxPayload
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[start:end]

		frag := make([]byte, ihl+len(chunk))
		copy(frag, ip[:ihl])
		binary.BigEndian.PutUint16(frag[2:4], uint16(ihl+len(chunk))) // total length
		// Flags(3)+offset(13): clear DF(0x4000)/reserved(0x8000), set MF on all
		// but the last, offset = byte offset / 8.
		var foNew uint16
		if i < n-1 {
			foNew |= 0x2000 // MF
		}
		foNew |= uint16(start/8) & 0x1fff
		binary.BigEndian.PutUint16(frag[6:8], foNew)
		// Identification (ip[4:6]) is preserved by the copy above.
		binary.BigEndian.PutUint16(frag[10:12], 0) // zero before checksum
		binary.BigEndian.PutUint16(frag[10:12], IPChecksum(frag[:ihl]))
		copy(frag[ihl:], chunk)

		out = append(out, wrapEthernet(eth, frag))
	}
	return out
}

// refragmentIPv6 splits a single unfragmented IPv6 packet into fragments per
// RFC 8200 by inserting a Fragment header immediately after the 40-byte base
// header. Only packets whose payload is directly an upper-layer protocol are
// handled: if extension headers (Hop-by-Hop 0, Routing 43, Destination Options
// 60, or an existing Fragment header 44) precede the payload, the correct
// insertion point is ambiguous and we fail closed. Identification is generated
// by the caller (must be unique per source+destination).
func refragmentIPv6(eth, ip []byte, mtu int, fragID uint32) [][]byte {
	if len(ip) < 40 || ip[0]>>4 != 6 {
		return nil
	}
	payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
	if len(ip) < 40+payloadLen {
		return nil
	}
	nextHdr := ip[6]
	switch nextHdr {
	case 0, 43, 44, 60:
		// Extension header preceding the payload (Hop-by-Hop / Routing /
		// Fragment / Destination Options): insertion point ambiguous, or the
		// packet is already a fragment. Fail closed.
		return nil
	}
	if 40+payloadLen <= mtu {
		return nil // already fits; the caller should not have routed here
	}
	payload := ip[40 : 40+payloadLen]

	// Fragment payload must be a multiple of 8 and keep the packet length
	// (40 base + 8 fragment header + chunk) within mtu.
	maxPayload := (mtu - 48) &^ 7
	if maxPayload < 8 {
		return nil
	}
	n := (len(payload) + maxPayload - 1) / maxPayload
	if n <= 1 {
		return nil
	}

	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		start := i * maxPayload
		end := start + maxPayload
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[start:end]

		frag := make([]byte, 48+len(chunk))
		copy(frag[0:40], ip[0:40])
		binary.BigEndian.PutUint16(frag[4:6], uint16(8+len(chunk))) // payload length
		frag[6] = 44                                                // next header = Fragment
		// hop limit (frag[7]) preserved by the copy.

		// Fragment header (8 bytes at frag[40:48]).
		frag[40] = nextHdr // next header after the fragment header
		frag[41] = 0       // reserved
		var offM uint16
		if i < n-1 {
			offM |= 1 // M flag (low bit of the 16-bit field)
		}
		offM |= uint16(start/8) << 3 // fragment offset in 8-byte units, bits 15..3
		binary.BigEndian.PutUint16(frag[42:44], offM)
		binary.BigEndian.PutUint32(frag[44:48], fragID)
		copy(frag[48:], chunk)

		out = append(out, wrapEthernet(eth, frag))
	}
	return out
}

// wrapEthernet prepends the 14-byte Ethernet header to an IP packet, producing
// a standalone TAP frame.
func wrapEthernet(eth, ip []byte) []byte {
	frame := make([]byte, EthernetHeaderLen+len(ip))
	copy(frame, eth)
	copy(frame[EthernetHeaderLen:], ip)
	return frame
}

// IPChecksum is the RFC 1071 Internet checksum, the one's-complement sum of the
// 16-bit words of b. It is exported so the re-fragmentation path and its tests
// share a single implementation.
func IPChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
