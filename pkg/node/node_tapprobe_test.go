package node

import (
	"bytes"
	"net"
	"sync/atomic"
	"testing"
)

func mustMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

// craftEchoReply turns an ICMP echo request frame into the reply the peer's OS
// would produce: swap src/dst MAC & IP, flip ICMP type 8->0, recompute checksum.
func craftEchoReply(req []byte) []byte {
	reply := make([]byte, len(req))
	copy(reply, req)
	copy(reply[0:6], req[6:12])
	copy(reply[6:12], req[0:6])
	copy(reply[14+12:14+16], req[14+16:14+20])
	copy(reply[14+16:14+20], req[14+12:14+16])
	ihl := int(reply[14]&0x0f) * 4
	reply[14+ihl] = 0 // echo reply
	icmpStart := 14 + ihl
	reply[icmpStart+2] = 0
	reply[icmpStart+3] = 0
	cs := icmpChecksum(reply[icmpStart:])
	reply[icmpStart+2] = byte(cs >> 8)
	reply[icmpStart+3] = byte(cs)
	return reply
}

func TestBuildAndVerifyICMPEchoReplyRoundTrip(t *testing.T) {
	localMAC := mustMAC("02:00:0a:00:00:01")
	peerMAC := mustMAC("02:00:0a:00:00:03")
	localIP := net.ParseIP("10.0.0.1").To4()
	peerIP := net.ParseIP("10.0.0.3").To4()
	const id uint16 = 0x5A70

	req, err := buildICMPEchoRequest(localMAC, peerMAC, localIP, peerIP, id, nil)
	if err != nil {
		t.Fatalf("buildICMPEchoRequest: %v", err)
	}
	if len(req) != 42 {
		t.Fatalf("unexpected request length %d, want 42", len(req))
	}

	reply := craftEchoReply(req)
	// A genuine echo reply from the peer must validate against the peer.
	if err := verifyICMPEchoReply(reply, peerMAC, localMAC, peerIP, localIP, id, 0); err != nil {
		t.Fatalf("verifyICMPEchoReply on crafted reply failed: %v", err)
	}

	// A reply carrying a DIFFERENT identifier must be rejected (prevents a
	// normal LAN ping from being mistaken for a probe reply).
	if err := verifyICMPEchoReply(reply, peerMAC, localMAC, peerIP, localIP, 0xBEEF, 0); err == nil {
		t.Fatalf("expected identifier mismatch error, got nil")
	}
}

func TestMaybeDeliverProbeReplyDetectsProbe(t *testing.T) {
	localMAC := mustMAC("02:00:0a:00:00:01")
	peerMAC := mustMAC("02:00:0a:00:00:03")
	localIP := net.ParseIP("10.0.0.1").To4()
	peerIP := net.ParseIP("10.0.0.3").To4()
	const id uint16 = 0x5A70

	req, _ := buildICMPEchoRequest(localMAC, peerMAC, localIP, peerIP, id, nil)
	reply := craftEchoReply(req)
	// identifier check below references icmpStart+4; recompute once here.
	ihl := int(reply[14]&0x0f) * 4
	icmpStart := 14 + ihl

	// 1) Inactive probe must NOT capture anything.
	n := &Node{}
	if n.maybeDeliverProbeReply(reply) {
		t.Fatalf("captured while probe inactive")
	}

	// 2) Active probe with a buffered channel must capture and deliver.
	n = &Node{localV4IP: localIP, probeReplyCh: make(chan []byte, 1)}
	atomic.StoreInt32(&n.probeActive, 1)
	if !n.maybeDeliverProbeReply(reply) {
		t.Fatalf("did not capture genuine probe reply")
	}
	select {
	case got := <-n.probeReplyCh:
		if !bytes.Equal(got, reply) {
			t.Fatalf("delivered frame mismatch")
		}
	default:
		t.Fatalf("nothing delivered to probeReplyCh")
	}

	// 3) A normal echo reply with a different identifier must be ignored even
	//    when active (the dst-IP check still passes, so this isolates the
	//    identifier filter — the heart of avoiding false captures).
	normal := craftEchoReply(req)
	normal[icmpStart+4] = 0xBE
	normal[icmpStart+5] = 0xEF
	normal[icmpStart+2] = 0
	normal[icmpStart+3] = 0
	cs2 := icmpChecksum(normal[icmpStart:])
	normal[icmpStart+2] = byte(cs2 >> 8)
	normal[icmpStart+3] = byte(cs2)
	if n.maybeDeliverProbeReply(normal) {
		t.Fatalf("captured a non-probe echo reply (wrong identifier)")
	}
}
