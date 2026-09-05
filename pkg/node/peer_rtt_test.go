package node

import (
	"encoding/binary"
	"math"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestPeerRTTSnapshotUsesRealSamplesAndValidity(t *testing.T) {
	n := &Node{peerRTT: make(map[peer.ID]*peerRTTState)}
	pid := peer.ID("peer-rtt-test")
	base := time.Unix(1700000000, 0)

	n.recordPeerRTTProbeAt(pid, rttSourceP2PEcho, 10*time.Millisecond, true, base)
	n.recordPeerRTTProbeAt(pid, rttSourceP2PEcho, 20*time.Millisecond, true, base.Add(time.Second))
	n.recordPeerRTTProbeAt(pid, rttSourceP2PEcho, 0, false, base.Add(2*time.Second))

	snap := n.peerRTTMeasurement(pid, base.Add(3*time.Second))
	if !snap.rttMeasured || snap.rttMs != 15 {
		t.Fatalf("rolling measured RTT = %.3f (valid=%v), want 15ms", snap.rttMs, snap.rttMeasured)
	}
	if !snap.jitterMeasured || snap.jitterMs != 10 {
		t.Fatalf("jitter = %.3f (valid=%v), want 10ms", snap.jitterMs, snap.jitterMeasured)
	}
	if !snap.lossMeasured || math.Abs(snap.lossRatePercent-100.0/3.0) > 0.001 {
		t.Fatalf("loss = %.3f%% (valid=%v), want 33.333%%", snap.lossRatePercent, snap.lossMeasured)
	}
	if snap.sampleCount != 3 || snap.source != rttSourceP2PEcho {
		t.Fatalf("unexpected sample metadata: %+v", snap)
	}

	stale := n.peerRTTMeasurement(pid, base.Add(backgroundEchoFreshFor+time.Minute))
	if stale.rttMeasured || stale.lossMeasured || stale.rttMs != 0 {
		t.Fatalf("stale control-stream measurement must become unknown, got %+v", stale)
	}
}

func TestPassiveTapICMPRTTTracksRealOutOfOrderRepliesAndLoss(t *testing.T) {
	n := &Node{
		peerRTT:            make(map[peer.ID]*peerRTTState),
		tapICMPEchoPending: make(map[tapICMPEchoKey]time.Time),
	}
	pid := peer.ID("peer-tap-ping-test")
	base := time.Unix(1700001000, 0)
	localMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	peerMAC, _ := net.ParseMAC("02:00:00:00:00:02")

	request := func(seq uint16) []byte {
		frame, err := buildICMPEchoRequest(localMAC, peerMAC, net.ParseIP("10.0.0.2").To4(), net.ParseIP("10.0.0.1").To4(), 0x1234, []byte("real-os-ping"))
		if err != nil {
			t.Fatal(err)
		}
		binary.BigEndian.PutUint16(frame[40:42], seq)
		return frame
	}
	reply := func(req []byte) []byte {
		frame := append([]byte(nil), req...)
		copy(frame[0:6], req[6:12])
		copy(frame[6:12], req[0:6])
		copy(frame[26:30], req[30:34])
		copy(frame[30:34], req[26:30])
		frame[34] = 0
		return frame
	}

	req1, req2, req3 := request(1), request(2), request(3)
	n.observeTapICMPEchoRequest(pid, req1, base)
	n.observeTapICMPEchoRequest(pid, req2, base.Add(100*time.Millisecond))
	// seq=2 returns first (50ms), then seq=1 (300ms), matching real ping's
	// ability to print replies out of order without pairing the wrong packet.
	n.observeTapICMPEchoReply(pid, reply(req2), base.Add(150*time.Millisecond))
	n.observeTapICMPEchoReply(pid, reply(req1), base.Add(300*time.Millisecond))

	n.observeTapICMPEchoRequest(pid, req3, base.Add(time.Second))
	n.expireTapICMPEchoRequests(base.Add(time.Second + tapICMPEchoTimeout))

	snap := n.peerRTTMeasurement(pid, base.Add(time.Second+tapICMPEchoTimeout))
	if snap.source != rttSourceTAPICMP || !snap.rttMeasured || snap.rttMs != 175 {
		t.Fatalf("TAP RTT snapshot = %+v, want rolling mean RTT 175ms", snap)
	}
	if !snap.jitterMeasured || snap.jitterMs != 250 {
		t.Fatalf("TAP jitter = %.3f, want 250ms", snap.jitterMs)
	}
	if math.Abs(snap.lossRatePercent-100.0/3.0) > 0.001 {
		t.Fatalf("TAP loss = %.3f%%, want 33.333%%", snap.lossRatePercent)
	}
	if len(n.tapICMPEchoPending) != 0 {
		t.Fatalf("expired request leaked from pending map: %d", len(n.tapICMPEchoPending))
	}
}

func TestPassiveTapICMPRTTTracksIPv6Echo(t *testing.T) {
	n := &Node{
		peerRTT:            make(map[peer.ID]*peerRTTState),
		tapICMPEchoPending: make(map[tapICMPEchoKey]time.Time),
	}
	pid := peer.ID("peer-tap-ping-v6")
	base := time.Unix(1700001500, 0)
	request := make([]byte, 14+40+8)
	binary.BigEndian.PutUint16(request[12:14], 0x86dd)
	request[14] = 0x60
	request[20] = 58
	copy(request[22:38], net.ParseIP("fd00::2").To16())
	copy(request[38:54], net.ParseIP("fd00::1").To16())
	request[54] = 128
	binary.BigEndian.PutUint16(request[58:60], 0x4321)
	binary.BigEndian.PutUint16(request[60:62], 7)
	reply := append([]byte(nil), request...)
	copy(reply[22:38], request[38:54])
	copy(reply[38:54], request[22:38])
	reply[54] = 129

	n.observeTapICMPEchoRequest(pid, request, base)
	n.observeTapICMPEchoReply(pid, reply, base.Add(750*time.Millisecond))
	snap := n.peerRTTMeasurement(pid, base.Add(time.Second))
	if !snap.rttMeasured || snap.source != rttSourceTAPICMP || snap.rttMs != 750 {
		t.Fatalf("IPv6 TAP RTT snapshot = %+v, want 750ms", snap)
	}
}

func TestTapICMPMeasurementOverridesControlStreamTemporarily(t *testing.T) {
	n := &Node{peerRTT: make(map[peer.ID]*peerRTTState)}
	pid := peer.ID("peer-source-priority")
	base := time.Unix(1700002000, 0)
	n.recordPeerRTTProbeAt(pid, rttSourceP2PEcho, 10*time.Millisecond, true, base)
	n.recordPeerRTTProbeAt(pid, rttSourceTAPICMP, 1200*time.Millisecond, true, base.Add(time.Second))

	current := n.peerRTTMeasurement(pid, base.Add(2*time.Second))
	if current.source != rttSourceTAPICMP || current.rttMs != 1200 {
		t.Fatalf("recent TAP measurement did not win: %+v", current)
	}
	afterTapWindow := n.peerRTTMeasurement(pid, base.Add(tapRTTPreferredFor+2*time.Second))
	if afterTapWindow.rttMeasured {
		t.Fatalf("both sources are stale and must render unknown, got %+v", afterTapWindow)
	}
}
