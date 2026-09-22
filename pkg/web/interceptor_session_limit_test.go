package web

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"

	"p2ptap/pkg/config"
)

// Session keys are built from the source IP and port as they appear on the
// wire, which any forwarding peer controls. These tests pin two properties:
// that only a SYN can open a session, and that the number of tracked sessions
// is bounded — otherwise a flood of minimum-size frames is an unbounded
// memory growth primitive aimed straight at the dashboard interceptor.

func buildTCPProbeFrame(dstIP string, srcIP string, srcPort uint16, flags byte) []byte {
	frame := make([]byte, 54)
	copy(frame[0:6], InterceptorMAC)
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800) // IPv4

	frame[14] = 0x45
	binary.BigEndian.PutUint16(frame[16:18], 40)
	frame[23] = 6 // protocol TCP
	copy(frame[26:30], net.ParseIP(srcIP).To4())
	copy(frame[30:34], net.ParseIP(dstIP).To4())

	binary.BigEndian.PutUint16(frame[34:36], srcPort)
	binary.BigEndian.PutUint16(frame[36:38], 80)
	binary.BigEndian.PutUint32(frame[38:42], 100)
	frame[46] = 0x50 // data offset 5 (20 bytes)
	frame[47] = flags
	return frame
}

func countSessions(it *TAPInterceptor) int {
	n := 0
	it.sessions.Range(func(_, _ interface{}) bool {
		n++
		return true
	})
	return n
}

func TestNonSYNFramesDoNotCreateSessions(t *testing.T) {
	it := NewTAPInterceptor("10.0.0.254", "", 80, NewStatsCollector(), config.DefaultConfig(), "")
	writer := &mockWriter{}

	// Nothing here carries a SYN: a spoofing peer could emit these indefinitely
	// from distinct source addresses, each well under the size of real traffic.
	for _, flags := range []byte{0x10, 0x18, 0x01, 0x04, 0x00} { // ACK, PSH-ACK, FIN, RST, bare
		it.MatchAndHandle(buildTCPProbeFrame("10.0.0.254", "10.0.0.99", 40000, flags), writer)
	}

	if got := countSessions(it); got != 0 {
		t.Errorf("non-SYN frames created %d sessions, want 0", got)
	}
	if got := it.sessionCount.Load(); got != 0 {
		t.Errorf("sessionCount = %d, want 0", got)
	}
}

func TestSYNOpensExactlyOneSession(t *testing.T) {
	it := NewTAPInterceptor("10.0.0.254", "", 80, NewStatsCollector(), config.DefaultConfig(), "")
	writer := &mockWriter{}

	it.MatchAndHandle(buildTCPProbeFrame("10.0.0.254", "10.0.0.99", 40000, 0x02), writer)

	if got := countSessions(it); got != 1 {
		t.Fatalf("SYN created %d sessions, want 1", got)
	}
	if got := it.sessionCount.Load(); got != 1 {
		t.Errorf("sessionCount = %d, want 1", got)
	}

	// Repeat SYN for the same 4-tuple must not double-count.
	it.MatchAndHandle(buildTCPProbeFrame("10.0.0.254", "10.0.0.99", 40000, 0x02), writer)
	if got := it.sessionCount.Load(); got != 1 {
		t.Errorf("duplicate SYN bumped sessionCount to %d, want 1", got)
	}
}

// The real attack: distinct source ports, one SYN each, far past the cap.
func TestSessionCountIsBoundedByFlood(t *testing.T) {
	it := NewTAPInterceptor("10.0.0.254", "", 80, NewStatsCollector(), config.DefaultConfig(), "")
	writer := &mockWriter{}

	floodFrames := maxTrackedSessions + 512
	var emitted atomic.Int64
	for port := 0; port < floodFrames; port++ {
		src := net.IPv4(10, 0, byte(port>>8), byte(port)).String()
		it.MatchAndHandle(buildTCPProbeFrame("10.0.0.254", src, uint16(port), 0x02), writer)
		emitted.Add(1)
	}

	if got := countSessions(it); got > maxTrackedSessions {
		t.Errorf("flood of %d SYNs left %d sessions tracked (cap %d)",
			floodFrames, got, maxTrackedSessions)
	}
	if got := it.sessionCount.Load(); got > maxTrackedSessions {
		t.Errorf("sessionCount = %d after flood, must not exceed cap %d", got, maxTrackedSessions)
	}
	t.Logf("flood of %d SYNs -> %d sessions tracked, sessionCount=%d",
		floodFrames, countSessions(it), it.sessionCount.Load())

	// The counter must not have drifted away from reality, or the cap quietly
	// stops being enforced on subsequent floods.
	if got, want := it.sessionCount.Load(), int64(countSessions(it)); got != want {
		t.Errorf("sessionCount %d out of step with %d live sessions", got, want)
	}
}

func TestIPv6NonSYNFramesDoNotCreateSessions(t *testing.T) {
	it := NewTAPInterceptor("", "fd00::254", 80, NewStatsCollector(), config.DefaultConfig(), "")

	// Minimal IPv6 + TCP frame reaching handleIPv6TCP's offsets.
	frame := make([]byte, 74)
	frame[20] = 6                                   // next header TCP
	binary.BigEndian.PutUint16(frame[54:56], 40001) // source port
	binary.BigEndian.PutUint16(frame[56:58], 80)
	frame[66] = 0x50 // data offset
	frame[67] = 0x10 // ACK, not SYN

	handled := it.handleIPv6TCP(frame, &mockWriter{})
	if !handled {
		t.Logf("frame not consumed by IPv6 TCP handler (may be filtered upstream)")
	}
	if got := countSessions(it); got != 0 {
		t.Errorf("non-SYN IPv6 frame created %d sessions, want 0", got)
	}
}
