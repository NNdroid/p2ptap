package tap

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildARPFrame(t *testing.T) {
	localMAC := net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}
	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	payload := []byte{0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}

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
}

func TestBuildARPReplyFrame(t *testing.T) {
	localMAC := net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}
	senderMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	targetIP := net.ParseIP("10.0.0.3")
	senderIP := net.ParseIP("10.0.0.1")

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
}

func TestBuildARPReplyFrameLength(t *testing.T) {
	localMAC := net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}
	senderMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	frame := BuildARPReplyFrame(localMAC, senderMAC, net.ParseIP("10.0.0.3"), net.ParseIP("10.0.0.1"))
	if len(frame) != ethernetMinFrameLen {
		t.Fatalf("expected ARP reply length %d, got %d", ethernetMinFrameLen, len(frame))
	}
}

func TestShouldRespondToARP(t *testing.T) {
	localIP := net.ParseIP("10.0.0.3")
	_, localNet, _ := net.ParseCIDR("10.0.0.0/24")
	if !ShouldRespondToARP(net.ParseIP("10.0.0.3"), localIP, nil, localNet) {
		t.Fatal("expected local IP to trigger ARP reply")
	}
	if !ShouldRespondToARP(net.ParseIP("10.0.0.254"), localIP, net.ParseIP("10.0.0.254"), localNet) {
		t.Fatal("expected gateway-style virtual IP to trigger ARP reply")
	}
	if !ShouldRespondToARP(net.ParseIP("10.0.0.4"), localIP, nil, localNet) {
		t.Fatal("expected same-subnet peer IP to trigger ARP reply")
	}
	if ShouldRespondToARP(net.ParseIP("10.1.0.4"), localIP, nil, localNet) {
		t.Fatal("did not expect foreign subnet IP to trigger ARP reply")
	}
}
