package packet

import (
	"bytes"
	"net"
	"testing"
)

func TestParseHeaderValidFrame(t *testing.T) {
	t.Log("[packet] parse a valid 34-byte IPv4 frame header")
	// Ethernet header: dst(6) + src(6) + ethertype(2) + payload
	dst := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	src := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	frame := make([]byte, 14+20)
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	frame[12] = 0x08
	frame[13] = 0x00 // IPv4

	hdr := ParseHeader(frame)
	t.Logf("[packet] parsed dst=%s src=%s ethertype=0x%04x payloadLen=%d", hdr.DstMAC, hdr.SrcMAC, hdr.EtherType, len(hdr.Payload))
	if !bytes.Equal(hdr.DstMAC, dst) {
		t.Errorf("DstMAC = %v, want %v", hdr.DstMAC, dst)
	}
	if !bytes.Equal(hdr.SrcMAC, src) {
		t.Errorf("SrcMAC = %v, want %v", hdr.SrcMAC, src)
	}
	if hdr.EtherType != EtherTypeIPv4 {
		t.Errorf("EtherType = 0x%04x, want 0x%04x", hdr.EtherType, EtherTypeIPv4)
	}
	if len(hdr.Payload) != 20 {
		t.Errorf("Payload len = %d, want 20", len(hdr.Payload))
	}
}

func TestParseHeaderShortFrame(t *testing.T) {
	t.Log("[packet] short (<14B) frame must yield zero values, not panic")
	// Frames shorter than 14 bytes must yield zero values, not panic.
	frame := make([]byte, 10)
	hdr := ParseHeader(frame)
	if len(hdr.DstMAC) != 0 {
		t.Errorf("short frame DstMAC should be empty, got %v", hdr.DstMAC)
	}
	if hdr.EtherType != 0 {
		t.Errorf("short frame EtherType should be 0, got 0x%04x", hdr.EtherType)
	}
	if hdr.Payload != nil {
		t.Errorf("short frame Payload should be nil, got %v", hdr.Payload)
	}
	t.Log("[packet] ✓ short frame handled safely (zero values)")
}

func TestParseHeaderBoundaryLength(t *testing.T) {
	t.Log("[packet] exactly 14B frame -> valid header, empty payload")
	// Exactly 14 bytes: a valid header with empty payload.
	frame := make([]byte, 14)
	frame[12] = 0x08
	frame[13] = 0x06 // ARP
	hdr := ParseHeader(frame)
	if hdr.EtherType != EtherTypeARP {
		t.Errorf("EtherType = 0x%04x, want 0x%04x", hdr.EtherType, EtherTypeARP)
	}
	if len(hdr.Payload) != 0 {
		t.Errorf("14-byte frame Payload should be empty, got len %d", len(hdr.Payload))
	}
	t.Log("[packet] ✓ 14B boundary parsed (ARP, empty payload)")
}

func TestParseHeaderVLAN(t *testing.T) {
	t.Log("[packet] 1518B frame with VLAN tag")
	// Max-sized frame with VLAN tagged ethertype preserved.
	frame := make([]byte, 1518)
	frame[12] = 0x81
	frame[13] = 0x00 // VLAN
	hdr := ParseHeader(frame)
	if hdr.EtherType != EtherTypeVLAN {
		t.Errorf("EtherType = 0x%04x, want 0x%04x", hdr.EtherType, EtherTypeVLAN)
	} else {
		t.Logf("[packet] ✓ VLAN ethertype 0x%04x preserved", hdr.EtherType)
	}
}

func TestEtherTypeHelper(t *testing.T) {
	t.Log("[packet] EtherType() helper on IPv6 + short")
	frame := make([]byte, 14)
	frame[12] = 0x86
	frame[13] = 0xdd // IPv6
	if got := EtherType(frame); got != EtherTypeIPv6 {
		t.Errorf("EtherType() = 0x%04x, want 0x%04x", got, EtherTypeIPv6)
	} else {
		t.Logf("[packet] ✓ EtherType()=0x%04x (IPv6)", got)
	}
	// too short
	if got := EtherType(make([]byte, 5)); got != 0 {
		t.Errorf("EtherType(short) = 0x%04x, want 0", got)
	} else {
		t.Log("[packet] ✓ EtherType(short) -> 0")
	}
}

func TestARPOpHelper(t *testing.T) {
	t.Log("[packet] ARPOp() helper on request + short")
	// ARP request frame, op field at bytes 20:22.
	frame := make([]byte, 22)
	frame[20] = 0x00
	frame[21] = 0x01 // request
	if got := ARPOp(frame); got != 1 {
		t.Errorf("ARPOp() = %d, want 1", got)
	} else {
		t.Logf("[packet] ✓ ARPOp()=%d (request)", got)
	}
	// too short
	if got := ARPOp(make([]byte, 21)); got != 0 {
		t.Errorf("ARPOp(short) = %d, want 0", got)
	} else {
		t.Log("[packet] ✓ ARPOp(short) -> 0")
	}
}

func TestEtherTypeConstants(t *testing.T) {
	t.Log("[packet] ethertype constants must be non-zero")
	cases := map[uint16]string{
		EtherTypeIPv4: "IPv4",
		EtherTypeIPv6: "IPv6",
		EtherTypeARP:  "ARP",
		EtherTypeVLAN: "VLAN",
	}
	for v, name := range cases {
		if v == 0 {
			t.Errorf("%s constant must not be zero", name)
		} else {
			t.Logf("[packet] ✓ %s=0x%04x", name, v)
		}
	}
}

func TestDefaultTapMAC(t *testing.T) {
	if !bytes.Equal(DefaultTapMAC, net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}) {
		t.Errorf("DefaultTapMAC = %v, unexpected value", DefaultTapMAC)
	} else {
		t.Logf("[packet] ✓ DefaultTapMAC=%s", DefaultTapMAC)
	}
}
