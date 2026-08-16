package tap

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"p2ptap/pkg/packet"
)

func TestBuildARPFrame(t *testing.T) {
	localMAC := net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	payload := []byte{0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}
	t.Logf("[arp] build ARP req: src=%s dst=%s payloadLen=%d", localMAC, dstMAC, len(payload))

	frame := buildARPFrame(localMAC, dstMAC, payload)
	if len(frame) != ethernetMinFrameLen {
		t.Fatalf("expected frame length %d, got %d", ethernetMinFrameLen, len(frame))
	}
	if got := binary.BigEndian.Uint16(frame[12:14]); got != ethertypeARP {
		t.Fatalf("expected ethertype 0x0806, got 0x%04x", got)
	}
	if !bytes.Equal(frame[0:6], dstMAC) {
		t.Fatalf("expected destination MAC %v, got %v", dstMAC, frame[0:6])
	}
	if !bytes.Equal(frame[6:12], localMAC) {
		t.Fatalf("expected source MAC %v, got %v", localMAC, frame[6:12])
	}
	if !bytes.Equal(frame[14:14+len(payload)], payload) {
		t.Fatalf("expected payload %v, got %v", payload, frame[14:14+len(payload)])
	}
	t.Logf("[arp] ✓ ARP frame %d bytes, ethertype=0x%04x, dst=%s src=%s", len(frame), ethertypeARP, dstMAC, localMAC)
}

func TestBuildARPReplyFrame(t *testing.T) {
	localMAC := net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}
	senderMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	targetIP := net.ParseIP("10.0.0.3")
	senderIP := net.ParseIP("10.0.0.1")
	t.Logf("[arp] build ARP reply: localMAC=%s senderMAC=%s targetIP=%s senderIP=%s", localMAC, senderMAC, targetIP, senderIP)

	frame := BuildARPReplyFrame(localMAC, senderMAC, targetIP, senderIP)
	if got := binary.BigEndian.Uint16(frame[12:14]); got != ethertypeARP {
		t.Fatalf("expected ethertype 0x0806, got 0x%04x", got)
	}
	if got := binary.BigEndian.Uint16(frame[20:22]); got != 2 {
		t.Fatalf("expected ARP opcode 2, got %d", got)
	}
	if !bytes.Equal(frame[22:28], localMAC) {
		t.Fatalf("expected sender MAC %v, got %v", localMAC, frame[22:28])
	}
	if !bytes.Equal(frame[28:32], targetIP.To4()) {
		t.Fatalf("expected target IP %v, got %v", targetIP.To4(), frame[28:32])
	}
	t.Logf("[arp] ✓ ARP reply opcode=2 senderMAC=%s targetIP=%s", localMAC, targetIP)
}

func TestBuildARPReplyFrameLength(t *testing.T) {
	localMAC := net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}
	senderMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	frame := BuildARPReplyFrame(localMAC, senderMAC, net.ParseIP("10.0.0.3"), net.ParseIP("10.0.0.1"))
	if len(frame) != ethernetMinFrameLen {
		t.Fatalf("expected ARP reply length %d, got %d", ethernetMinFrameLen, len(frame))
	}
	t.Logf("[arp] ✓ ARP reply length=%d (min frame)", len(frame))
}

func TestShouldRespondToARP(t *testing.T) {
	localIP := net.ParseIP("10.0.0.3")
	_, localNet, _ := net.ParseCIDR("10.0.0.0/24")
	if !ShouldRespondToARP(net.ParseIP("10.0.0.3"), localIP, nil, localNet) {
		t.Fatal("expected local IP to trigger ARP reply")
	} else {
		t.Log("[arp] ✓ local IP 10.0.0.3 triggers reply")
	}
	if !ShouldRespondToARP(net.ParseIP("10.0.0.254"), localIP, net.ParseIP("10.0.0.254"), localNet) {
		t.Fatal("expected gateway-style virtual IP to trigger ARP reply")
	} else {
		t.Log("[arp] ✓ gateway virtual IP 10.0.0.254 triggers reply")
	}
	if ShouldRespondToARP(net.ParseIP("10.0.0.4"), localIP, nil, localNet) {
		t.Fatal("must NOT proxy-ARP for other peers in the same subnet (would blackhole Exit traffic)")
	} else {
		t.Log("[arp] ✓ peer IP 10.0.0.4 correctly NOT proxied (avoids Exit blackhole)")
	}
	if ShouldRespondToARP(net.ParseIP("10.1.0.4"), localIP, nil, localNet) {
		t.Fatal("did not expect foreign subnet IP to trigger ARP reply")
	} else {
		t.Log("[arp] ✓ foreign subnet 10.1.0.4 correctly NOT replied")
	}
}

// TestBuildIPv6NeighborAdvertisementFrame exercises the NDP Neighbor
// Advertisement builder: unsolicited vs solicited, the Duplicate-Address-
// Detection (:: source) fallback to multicast, and the ICMPv6 checksum.
func TestBuildIPv6NeighborAdvertisementFrame(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}
	target := net.ParseIP("fd00::2")

	verifyNA := func(t *testing.T, frame []byte, wantDst net.IP, wantFlags byte) {
		t.Helper()
		if len(frame) != 86 {
			t.Fatalf("NA frame length = %d, want 86", len(frame))
		}
		if got := binary.BigEndian.Uint16(frame[12:14]); got != packet.EtherTypeIPv6 {
			t.Fatalf("EtherType = 0x%04x, want 0x86dd", got)
		}
		if got := frame[20]; got != 58 {
			t.Fatalf("IPv6 Next Header = %d, want 58 (ICMPv6)", got)
		}
		if got := frame[54]; got != 136 {
			t.Fatalf("ICMPv6 type = %d, want 136 (NA)", got)
		}
		if got := frame[58]; got != wantFlags {
			t.Fatalf("NA flags = 0x%02x, want 0x%02x", got, wantFlags)
		}
		if !bytes.Equal(frame[38:54], wantDst.To16()) {
			t.Fatalf("NA dst IPv6 = %v, want %v", net.IP(frame[38:54]), wantDst)
		}
		if !bytes.Equal(frame[62:78], target.To16()) {
			t.Fatalf("NA target IPv6 = %v, want %v", net.IP(frame[62:78]), target)
		}
		if !bytes.Equal(frame[80:86], mac) {
			t.Fatalf("NA TLLAO MAC = %v, want %v", net.IP(frame[80:86]), mac)
		}
		// End-to-end checksum validation: recompute over the ICMPv6 message
		// with the checksum field zeroed (as the builder does), and compare.
		icmp := make([]byte, 32)
		copy(icmp, frame[54:86])
		icmp[2], icmp[3] = 0, 0
		gotCS := binary.BigEndian.Uint16(frame[56:58])
		wantCS := calcICMPv6Checksum(frame[22:38], frame[38:54], icmp)
		if gotCS != wantCS {
			t.Fatalf("ICMPv6 checksum = 0x%04x, want 0x%04x", gotCS, wantCS)
		}
		if gotCS == 0 {
			t.Fatalf("ICMPv6 checksum must be non-zero")
		}
	}

	t.Run("unsolicited (no dst) -> multicast Override", func(t *testing.T) {
		frame := BuildIPv6NeighborAdvertisementFrame(mac, target)
		if len(frame) == 0 {
			t.Fatal("expected non-nil unsolicited NA")
		}
		verifyNA(t, frame, net.ParseIP("ff02::1"), 0x20)
	})

	t.Run("solicited (dst provided) -> unicast Solicited+Override", func(t *testing.T) {
		sender := net.ParseIP("fd00::1")
		frame := BuildIPv6NeighborAdvertisementFrame(mac, target, sender)
		if len(frame) == 0 {
			t.Fatal("expected non-nil solicited NA")
		}
		verifyNA(t, frame, sender, 0x60)
	})

	t.Run("DAD source :: falls back to multicast Override", func(t *testing.T) {
		// A Duplicate-Address-Detection NS uses :: as its source. The NA must
		// NOT be sent to :: as a Solicited NA; it must go to ff02::1 (Override).
		frame := BuildIPv6NeighborAdvertisementFrame(mac, target, net.ParseIP("::"))
		if len(frame) == 0 {
			t.Fatal("expected non-nil NA for DAD fallback")
		}
		verifyNA(t, frame, net.ParseIP("ff02::1"), 0x20)
	})

	t.Run("nil guard on bad MAC/IP", func(t *testing.T) {
		if f := BuildIPv6NeighborAdvertisementFrame(net.HardwareAddr{1, 2, 3}, target); f != nil {
			t.Fatalf("expected nil for 3-byte MAC, got %d bytes", len(f))
		}
		if f := BuildIPv6NeighborAdvertisementFrame(mac, net.IP{1, 2, 3}); f != nil {
			t.Fatalf("expected nil for 3-byte IP, got %d bytes", len(f))
		}
	})
}
