// Package packet provides read-only parsing helpers for Ethernet frames and
// shared protocol constants. It is a dependency leaf: it imports nothing from
// p2ptap other than the standard library, so node/tap/web can all share it
// without creating import cycles.
package packet

import (
	"encoding/binary"
	"net"
)

// EtherType values used across the project. Centralized here so every layer
// (node TAP handling, tap device proxy, web interceptor/capture) references the
// same named constant instead of scattering magic numbers.
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeARP  = 0x0806
	EtherTypeIPv6 = 0x86dd
	EtherTypeVLAN = 0x8100 // 802.1Q

	// EthernetHeaderLen is the fixed size of an untagged Ethernet header
	// (dstMAC 6 + srcMAC 6 + EtherType 2). A TAP (Ethernet) device carries the
	// full L2 frame, so a maximum-size L3 packet of `mtu` bytes is carried as a
	// `mtu + EthernetHeaderLen` byte frame on the wire.
	EthernetHeaderLen = 14
)

// DefaultTapMAC is the synthetic L2 address used when a node has no real TAP MAC
// (and no Exit peer MAC) yet — e.g. proxy-ARP/NDP fallback before the peer's MAC is
// learned, or ARP/NDP frame construction in the TAP device. Centralized here so the
// magic bytes live in exactly one place.
var DefaultTapMAC = net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}

// Header is the parsed 14-byte Ethernet frame header. Payload points into the
// original slice (no copy) so callers on the hot path pay nothing for parsing.
type Header struct {
	DstMAC   net.HardwareAddr
	SrcMAC   net.HardwareAddr
	EtherType uint16
	// Payload is the L3 data following the Ethernet header. Empty if the frame
	// is shorter than 14 bytes.
	Payload []byte
}

// ParseHeader extracts the Ethernet header from frame without copying the
// underlying bytes. Returns a zero Header (EtherType 0) for frames shorter than
// 14 bytes.
func ParseHeader(frame []byte) Header {
	if len(frame) < 14 {
		return Header{}
	}
	return Header{
		DstMAC:    net.HardwareAddr(frame[0:6]),
		SrcMAC:    net.HardwareAddr(frame[6:12]),
		EtherType: binary.BigEndian.Uint16(frame[12:14]),
		Payload:   frame[14:],
	}
}

// EtherType returns the 16-bit EtherType field of frame, or 0 if the frame is
// too short to carry an Ethernet header. It is the single shared replacement
// for the many `binary.BigEndian.Uint16(frame[12:14])` call sites.
func EtherType(frame []byte) uint16 {
	if len(frame) < 14 {
		return 0
	}
	return binary.BigEndian.Uint16(frame[12:14])
}

// ARPOp returns the 16-bit ARP operation code (request=1, reply=2) from an
// Ethernet-encapsulated ARP frame, or 0 if the frame is too short.
func ARPOp(frame []byte) uint16 {
	if len(frame) < 22 {
		return 0
	}
	return binary.BigEndian.Uint16(frame[20:22])
}
