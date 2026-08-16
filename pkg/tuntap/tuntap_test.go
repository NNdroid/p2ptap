package tuntap

import (
	"net"
	"testing"
)

func TestPacketToFrameIPv4(t *testing.T) {
	c := NewConverter(net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01})
	// Minimal IPv4 packet: version 4, header length 5 (0x45), rest arbitrary.
	pkt := []byte{0x45, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x02, 0x0a, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04}
	frame, err := c.PacketToFrame(pkt)
	if err != nil {
		t.Fatalf("PacketToFrame: %v", err)
	}
	if len(frame) != 14+len(pkt) {
		t.Fatalf("frame len = %d, want %d", len(frame), 14+len(pkt))
	}
	if frame[12] != 0x08 || frame[13] != 0x00 {
		t.Fatalf("ethertype = %02x%02x, want 0800", frame[12], frame[13])
	}
	// src MAC must equal LocalMAC
	for i := 6; i < 12; i++ {
		if frame[i] != c.LocalMAC[i-6] {
			t.Fatalf("src MAC byte %d mismatch", i)
		}
	}
	// dst MAC must be broadcast
	for i := 0; i < 6; i++ {
		if frame[i] != 0xff {
			t.Fatalf("dst MAC byte %d not broadcast", i)
		}
	}
}

func TestPacketToFrameIPv6(t *testing.T) {
	c := NewConverter(DefaultMAC)
	// IPv6: version 6 (0x60), traffic class/flow label follow.
	pkt := append([]byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 0x3a, 0x40}, make([]byte, 16)...)
	frame, err := c.PacketToFrame(pkt)
	if err != nil {
		t.Fatalf("PacketToFrame: %v", err)
	}
	if frame[12] != 0x86 || frame[13] != 0xdd {
		t.Fatalf("ethertype = %02x%02x, want 86dd", frame[12], frame[13])
	}
}

func TestPacketToFrameNonIP(t *testing.T) {
	c := NewConverter(DefaultMAC)
	// First nibble 0x0a => not IPv4/IPv6.
	if _, err := c.PacketToFrame([]byte{0x0a, 0x00, 0x00}); err != ErrNotIPPacket {
		t.Fatalf("expected ErrNotIPPacket, got %v", err)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	c := NewConverter(net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x09})
	pkt := []byte{0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00,
		0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x08, 0x00, 0xfb, 0xfd}
	frame, err := c.PacketToFrame(pkt)
	if err != nil {
		t.Fatalf("PacketToFrame: %v", err)
	}
	got, err := c.FrameToPacket(frame)
	if err != nil {
		t.Fatalf("FrameToPacket: %v", err)
	}
	if len(got) != len(pkt) {
		t.Fatalf("roundtrip len = %d, want %d", len(got), len(pkt))
	}
	for i := range pkt {
		if got[i] != pkt[i] {
			t.Fatalf("byte %d mismatch: %02x vs %02x", i, got[i], pkt[i])
		}
	}
}

func TestFrameToPacketErrors(t *testing.T) {
	c := NewConverter(DefaultMAC)
	if _, err := c.FrameToPacket([]byte{0x01, 0x02}); err != ErrFrameTooShort {
		t.Fatalf("expected ErrFrameTooShort, got %v", err)
	}
	// ARP frame (ethertype 0806) must be rejected as non-IP.
	arp := make([]byte, 60)
	arp[12], arp[13] = 0x08, 0x06
	if _, err := c.FrameToPacket(arp); err != ErrNotIPPacket {
		t.Fatalf("expected ErrNotIPPacket for ARP, got %v", err)
	}
}
