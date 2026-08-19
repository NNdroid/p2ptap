// Package tuntap provides the conversion layer that lets an Android L3 TUN
// device (which only carries raw IP packets) be presented to the node's L2
// (Ethernet / TAP) switching and routing core.
//
// On Android, VpnService only exposes a TUN (layer-3) file descriptor — there
// is no TAP (layer-2) device. The p2ptap node, however, routes and switches
// Ethernet frames. This package translates between the two worlds:
//
//   - PacketToFrame: wrap an L3 IP packet coming FROM the OS TUN fd into a
//     synthetic Ethernet frame (with a fixed local source MAC and a broadcast
//     destination MAC) so the L2 pipeline can consume it.
//   - FrameToPacket: strip the Ethernet header from a frame the L2 pipeline
//     wants to WRITE to the OS, leaving the L3 IP packet to push into the TUN
//     fd.
//
// Non-IP Ethernet traffic (e.g. ARP) cannot be carried over an L3 tunnel and is
// reported via ErrNotIPPacket so the caller can safely skip it.
package tuntap

import (
	"encoding/binary"
	"errors"
	"net"
)

// Well-known EtherTypes handled by the converter.
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86DD
	EtherTypeARP  = 0x0806
)

// BroadcastMAC is used as the destination MAC for every wrapped frame. Because
// a TUN endpoint has no real L2 neighbour, all traffic is injected as if
// addressed to the local broadcast domain; the node's L2 core learns/handles
// delivery from the inner IP header.
var BroadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// ErrNotIPPacket indicates the payload is not an IP packet and therefore cannot
// be carried over the L3 TUN tunnel.
var ErrNotIPPacket = errors.New("tuntap: payload is not an IP packet")

// ErrFrameTooShort indicates the Ethernet frame is shorter than a 14-byte header.
var ErrFrameTooShort = errors.New("tuntap: frame shorter than Ethernet header")

// DefaultMAC is the synthetic local MAC used when none is supplied.
var DefaultMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

// Converter wraps/unwraps Ethernet frames to/from L3 IP packets using a fixed
// local MAC address.
type Converter struct {
	LocalMAC net.HardwareAddr
}

// NewConverter returns a Converter that uses localMAC as the source MAC for
// wrapped frames. If localMAC is not a 6-octet address, DefaultMAC is used.
func NewConverter(localMAC net.HardwareAddr) *Converter {
	if len(localMAC) != 6 {
		localMAC = DefaultMAC
	}
	return &Converter{LocalMAC: localMAC}
}

// EtherTypeOf inspects the IP version nibble and returns the corresponding
// EtherType, or 0 if the packet is not IPv4/IPv6.
func EtherTypeOf(pkt []byte) uint16 {
	if len(pkt) == 0 {
		return 0
	}
	switch pkt[0] >> 4 {
	case 4:
		return EtherTypeIPv4
	case 6:
		return EtherTypeIPv6
	default:
		return 0
	}
}

// etherTypeOf is the unexported alias for backward compatibility.
func etherTypeOf(pkt []byte) uint16 {
	return EtherTypeOf(pkt)
}

// PacketToFrame wraps an L3 IP packet (read from the TUN fd) into an Ethernet
// frame addressed to BroadcastMAC with the converter's LocalMAC as the source.
// It returns ErrNotIPPacket if pkt is not IPv4 or IPv6.
func (c *Converter) PacketToFrame(pkt []byte) ([]byte, error) {
	ethType := EtherTypeOf(pkt)
	if ethType == 0 {
		return nil, ErrNotIPPacket
	}
	frame := make([]byte, 14+len(pkt))
	copy(frame[0:6], BroadcastMAC)
	copy(frame[6:12], c.LocalMAC)
	binary.BigEndian.PutUint16(frame[12:14], ethType)
	copy(frame[14:], pkt)
	return frame, nil
}

// FrameToPacketFast strips the 14-byte Ethernet header from frame and returns a
// zero-copy subslice to the inner L3 IP packet.
func (c *Converter) FrameToPacketFast(frame []byte) ([]byte, error) {
	if len(frame) < 14 {
		return nil, ErrFrameTooShort
	}
	ethType := binary.BigEndian.Uint16(frame[12:14])
	if ethType != EtherTypeIPv4 && ethType != EtherTypeIPv6 {
		return nil, ErrNotIPPacket
	}
	return frame[14:], nil
}

// FrameToPacket strips the 14-byte Ethernet header from frame and returns the
// inner L3 IP packet as a newly allocated buffer.
func (c *Converter) FrameToPacket(frame []byte) ([]byte, error) {
	pkt, err := c.FrameToPacketFast(frame)
	if err != nil {
		return nil, err
	}
	res := make([]byte, len(pkt))
	copy(res, pkt)
	return res, nil
}

