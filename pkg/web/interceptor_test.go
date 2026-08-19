package web

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"p2ptap/pkg/config"
)

type mockWriter struct {
	mu      sync.Mutex
	written [][]byte
}

func (m *mockWriter) Write(b []byte) (int, error) {
	buf := make([]byte, len(b))
	copy(buf, b)
	m.mu.Lock()
	m.written = append(m.written, buf)
	m.mu.Unlock()
	return len(b), nil
}

func (m *mockWriter) snapshot() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]byte, len(m.written))
	copy(out, m.written)
	return out
}

func (m *mockWriter) reset() {
	m.mu.Lock()
	m.written = nil
	m.mu.Unlock()
}

func TestTAPInterceptorARP(t *testing.T) {
	t.Log("[interceptor] ARP request for gateway 10.0.0.254 should be intercepted + replied")
	collector := NewStatsCollector()
	cfg := config.DefaultConfig()
	it := NewTAPInterceptor("10.0.0.254", "", 80, collector, cfg, "")

	// Construct ARP Request for 10.0.0.254 from 10.0.0.1 (MAC 02:00:00:00:00:01)
	arpReq := make([]byte, 42)
	// EtherDst: FF:FF:FF:FF:FF:FF
	copy(arpReq[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	// EtherSrc: 02:00:00:00:00:01
	copy(arpReq[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	// EtherType: ARP (0x0806)
	binary.BigEndian.PutUint16(arpReq[12:14], 0x0806)

	// ARP Fields
	binary.BigEndian.PutUint16(arpReq[14:16], 1)
	binary.BigEndian.PutUint16(arpReq[16:18], 0x0800)
	arpReq[18] = 6
	arpReq[19] = 4
	binary.BigEndian.PutUint16(arpReq[20:22], 1) // Opcode Request

	copy(arpReq[22:28], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}) // Sender MAC
	copy(arpReq[28:32], net.ParseIP("10.0.0.1").To4())              // Sender IP
	copy(arpReq[32:38], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // Target MAC
	copy(arpReq[38:42], net.ParseIP("10.0.0.254").To4())            // Target IP

	writer := &mockWriter{}
	handled := it.MatchAndHandle(arpReq, writer)
	if !handled {
		t.Fatalf("Expected ARP request for 10.0.0.254 to be intercepted")
	}

	replies := writer.snapshot()
	if len(replies) != 1 {
		t.Fatalf("Expected 1 ARP reply written, got %d", len(replies))
	}

	reply := replies[0]
	if binary.BigEndian.Uint16(reply[20:22]) != 2 { // Opcode Reply
		t.Errorf("Expected ARP Reply opcode 2, got %d", binary.BigEndian.Uint16(reply[20:22]))
	}

	senderIP := net.IP(reply[28:32])
	if !senderIP.Equal(net.ParseIP("10.0.0.254")) {
		t.Errorf("Expected ARP reply sender IP 10.0.0.254, got %s", senderIP.String())
	}
	t.Logf("[interceptor] ✓ ARP reply opcode=2 senderIP=%s", senderIP)
}

func TestTAPInterceptorHTTP(t *testing.T) {
	t.Log("[interceptor] TCP SYN + HTTP GET to gateway:80 should be intercepted (SYN-ACK + HTML)")
	collector := NewStatsCollector()
	cfg := config.DefaultConfig()
	it := NewTAPInterceptor("10.0.0.254", "", 80, collector, cfg, "")

	writer := &mockWriter{}

	// Step 1: Send TCP SYN packet to 10.0.0.254:80
	synFrame := make([]byte, 54)
	copy(synFrame[0:6], InterceptorMAC)
	copy(synFrame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	binary.BigEndian.PutUint16(synFrame[12:14], 0x0800)

	// IP Header
	synFrame[14] = 0x45
	binary.BigEndian.PutUint16(synFrame[16:18], 40)
	synFrame[23] = 6 // TCP
	copy(synFrame[26:30], net.ParseIP("10.0.0.1").To4())
	copy(synFrame[30:34], net.ParseIP("10.0.0.254").To4())

	// TCP Header
	binary.BigEndian.PutUint16(synFrame[34:36], 54321) // Src Port
	binary.BigEndian.PutUint16(synFrame[36:38], 80)    // Dst Port
	binary.BigEndian.PutUint32(synFrame[38:42], 100)   // Seq
	synFrame[46] = 0x50                                // Data offset 5
	synFrame[47] = 0x02                                // SYN Flag

	handled := it.MatchAndHandle(synFrame, writer)
	if !handled {
		t.Fatalf("Expected TCP SYN to be intercepted")
	}

	synReplies := writer.snapshot()
	if len(synReplies) != 1 {
		t.Fatalf("Expected SYN-ACK reply, got %d written frames", len(synReplies))
	}

	synAck := synReplies[0]
	tcpFlags := synAck[47]
	if tcpFlags != 0x12 { // SYN-ACK
		t.Errorf("Expected SYN-ACK flags 0x12, got 0x%02x", tcpFlags)
	} else {
		t.Logf("[interceptor] ✓ SYN-ACK flags=0x%02x", tcpFlags)
	}

	// Step 2: Send HTTP GET / Request
	writer.reset()
	httpReqData := []byte("GET / HTTP/1.1\r\nHost: 10.0.0.254\r\n\r\n")

	httpFrame := make([]byte, 54+len(httpReqData))
	copy(httpFrame[0:54], synFrame)
	binary.BigEndian.PutUint16(httpFrame[16:18], uint16(40+len(httpReqData)))
	httpFrame[47] = 0x18                              // PSH-ACK Flag
	binary.BigEndian.PutUint32(httpFrame[38:42], 101) // Seq
	copy(httpFrame[54:], httpReqData)

	handled = it.MatchAndHandle(httpFrame, writer)
	if !handled {
		t.Fatalf("Expected HTTP Request to be intercepted")
	}

	time.Sleep(50 * time.Millisecond)

	httpReplies := writer.snapshot()
	if len(httpReplies) < 1 {
		t.Fatalf("Expected HTTP response frame written")
	}

	// Verify HTTP Response Contains HTML
	httpRespFrame := httpReplies[0]
	respData := httpRespFrame[54:]
	if !bytes.Contains(respData, []byte("HTTP/1.1 200 OK")) {
		t.Errorf("Expected HTTP 200 OK response, got: %s", string(respData))
	} else {
		t.Logf("[interceptor] ✓ HTTP 200 OK response (len=%d)", len(respData))
	}
}

func TestTAPInterceptorIPv6(t *testing.T) {
	t.Log("[interceptor] IPv6 NDP + TCP SYN to gateway[fd00::254]:80 should be intercepted")
	collector := NewStatsCollector()
	cfg := config.DefaultConfig()
	it := NewTAPInterceptor("10.0.0.254", "fd00::254", 80, collector, cfg, "")

	writer := &mockWriter{}

	// Step 1: ICMPv6 Neighbor Solicitation for [fd00::254]
	ndpReq := make([]byte, 86)
	copy(ndpReq[0:6], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01})
	copy(ndpReq[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	binary.BigEndian.PutUint16(ndpReq[12:14], 0x86DD)

	// IPv6 Header
	ndpReq[14] = 0x60
	binary.BigEndian.PutUint16(ndpReq[18:20], 32)
	ndpReq[20] = 58  // ICMPv6
	ndpReq[21] = 255 // Hop limit
	copy(ndpReq[22:38], net.ParseIP("fd00::1").To16())
	copy(ndpReq[38:54], net.ParseIP("fd00::254").To16())

	// ICMPv6 NS (135)
	ndpReq[54] = 135
	copy(ndpReq[62:78], net.ParseIP("fd00::254").To16()) // Target IP

	handled := it.MatchAndHandle(ndpReq, writer)
	if !handled {
		t.Fatalf("Expected ICMPv6 NDP for fd00::254 to be intercepted")
	}

	ndpReplies := writer.snapshot()
	if len(ndpReplies) != 1 {
		t.Fatalf("Expected 1 ICMPv6 NA reply written, got %d", len(ndpReplies))
	}

	naReply := ndpReplies[0]
	if naReply[54] != 136 { // ICMPv6 NA (136)
		t.Errorf("Expected ICMPv6 NA type 136, got %d", naReply[54])
	}
	senderIP := net.IP(naReply[22:38])
	if !senderIP.Equal(net.ParseIP("fd00::254")) {
		t.Errorf("Expected ICMPv6 NA sender IP fd00::254, got %s", senderIP.String())
	}
	t.Logf("[interceptor] ✓ NDP NA type=136 senderIP=%s", senderIP)

	// Step 2: IPv6 TCP SYN to [fd00::254]:80
	writer.reset()
	synFrame := make([]byte, 74)
	copy(synFrame[0:6], InterceptorMAC)
	copy(synFrame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	binary.BigEndian.PutUint16(synFrame[12:14], 0x86DD)

	// IPv6 Header
	synFrame[14] = 0x60
	binary.BigEndian.PutUint16(synFrame[18:20], 20) // TCP Payload len
	synFrame[20] = 6                                // TCP
	copy(synFrame[22:38], net.ParseIP("fd00::1").To16())
	copy(synFrame[38:54], net.ParseIP("fd00::254").To16())

	// TCP Header
	binary.BigEndian.PutUint16(synFrame[54:56], 54321) // Src Port
	binary.BigEndian.PutUint16(synFrame[56:58], 80)    // Dst Port
	binary.BigEndian.PutUint32(synFrame[58:62], 200)   // Seq
	synFrame[66] = 0x50                                // Data offset 5
	synFrame[67] = 0x02                                // SYN Flag

	handled = it.MatchAndHandle(synFrame, writer)
	if !handled {
		t.Fatalf("Expected IPv6 TCP SYN to be intercepted")
	}

	synReplies := writer.snapshot()
	if len(synReplies) != 1 {
		t.Fatalf("Expected IPv6 SYN-ACK reply written")
	}

	synAck := synReplies[0]
	if synAck[67] != 0x12 { // SYN-ACK
		t.Errorf("Expected IPv6 SYN-ACK flags 0x12, got 0x%02x", synAck[67])
	} else {
		t.Logf("[interceptor] ✓ IPv6 SYN-ACK flags=0x%02x", synAck[67])
	}
}
