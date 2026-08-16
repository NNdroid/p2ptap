package node

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// TapProbeProtocolID is a dedicated overlay protocol used by the WebUI
// "P2P 通联排查工具 / 端到端 TAP 转发验证" feature.
//
// It verifies the *entire* TAP data path (TAP frame -> overlay encapsulation /
// relay -> remote deobfuscation -> remote frame parsing -> remote reply
// generation -> overlay return -> local reception), which is exactly the path
// that an application-layer echo (EchoProtocolID) does NOT exercise. This is the
// test that reproduces "echo works but ping (TAP packet) does not".
//
// Message wire format:
//
//	+----------------+----------------+----------------+------------------+
//	| type (1 byte)  | flags (1 byte) | seq (4 bytes)  |  payload ...     |
//	+----------------+----------------+----------------+------------------+
//
//	type 0 = prober -> responder: a full Ethernet frame containing an ICMP
//	         echo request addressed to the responder's TAP IP.
//	type 1 = responder -> prober: the same frame with the ICMP echo reply
//	         constructed from it (src/dst MAC & IP swapped, ICMP type flipped).
//
//	flags bit0 = urgent: when set, the responder injects the echo reply into
//	         its TAP device on the PRIORITY path (tapWriteUrgent) so a
//	         diagnostic probe reply is not starved behind a busy forwarding
//	         queue. This is the "urgent flag" for peer-side processing priority.
//	         The prober ALSO dispatches the real echo-request frame on the
//	         PRIORITY SEND queue (urgentDispatchCh) so the real TAP frame itself
//	         is not starved behind ordinary TAP egress — symmetric send priority.
type TapProbeProtocolID protocol.ID

const tapProbeProtocol = protocol.ID("/p2ptap/tap-probe/1.0.0")

const (
	tapProbeTypeRequest  byte   = 0
	tapProbeTypeReply    byte   = 1
	tapProbeFlagUrgent   byte   = 1 << 0
	tapProbePayloadMax   int    = 1500
	tapProbeDefaultRTT          = 3 * time.Second
	tapProbeICMPIdentify uint16 = 0x5A70 // "Zp" : identify probe-generated ICMP
)

// TapProbeResult reports the outcome of a single end-to-end TAP forwarding test.
type TapProbeResult struct {
	PeerID    string `json:"peer_id"`
	PeerName  string `json:"peer_name"`
	TapIP     string `json:"tap_ip"`
	Success   bool   `json:"success"`
	RTTMills  int64  `json:"rtt_ms"`
	SentBytes int    `json:"sent_bytes"`
	Error     string `json:"error,omitempty"`
}

// registerTapProbeHandler registers the responder side of the TAP probe protocol.
func (n *Node) registerTapProbeHandler() {
	n.Host.SetStreamHandler(tapProbeProtocol, n.handleTapProbe)
	log.Debug("Stream handler registered for TAP probe protocol: %s", tapProbeProtocol)
}

// handleTapProbe is the responder side. It reads a TAP frame from the prober,
// validates that it is an ICMP echo request to this node's TAP IP, then
// constructs an ICMP echo reply and sends it back (echoing at the frame level,
// i.e. the path a real ping reply would take).
func (n *Node) handleTapProbe(s network.Stream) {
	defer s.Close()
	remotePeer := s.Conn().RemotePeer()

	// Bounded read: a malformed/short probe must not block this goroutine
	// forever (a peer that sends fewer than the nominal 1502 bytes would
	// otherwise pin the stream until the underlying transport times out).
	_ = s.SetReadDeadline(time.Now().Add(tapProbeDefaultRTT))

	req := make([]byte, 2+tapProbePayloadMax)
	readN, err := ReadFrame(s, req)
	if err != nil {
		log.Debug("tap-probe: read error from %s: %v", remotePeer.String(), err)
		return
	}
	req = req[:readN]

	if len(req) < 6 {
		log.Debug("tap-probe: short request from %s", remotePeer.String())
		return
	}
	msgType := req[0]
	flags := req[1]
	seq := binary.BigEndian.Uint32(req[2:6])
	frame := req[6:]
	if msgType != tapProbeTypeRequest {
		log.Debug("tap-probe: unexpected msg type %d from %s", msgType, remotePeer.String())
		return
	}

	replyFrame, err := n.buildTapProbeReply(frame)
	if err != nil {
		log.Debug("tap-probe: cannot build reply for %s: %v", remotePeer.String(), err)
		// Still echo something back so the prober does not hang, but mark as error.
		replyFrame = frame
	} else if flags&tapProbeFlagUrgent != 0 {
		// Urgent: inject the echo reply into the responder's TAP on the
		// priority path so diagnostics are not starved behind forwarding.
		n.tapWriteUrgent(replyFrame)
	}

	out := make([]byte, 0, 6+len(replyFrame))
	out = append(out, tapProbeTypeReply)
	out = append(out, flags) // echo flags back (urgent preserved)
	out = append(out, byte(seq>>24), byte(seq>>16), byte(seq>>8), byte(seq))
	out = append(out, replyFrame...)

	if err := WriteFrame(s, out); err != nil {
		log.Debug("tap-probe: write reply error to %s: %v", remotePeer.String(), err)
	}
}

// ProbeTapForward runs the prober side of the TAP forwarding test against peer.
func (n *Node) ProbeTapForward(peerID peer.ID) (TapProbeResult, error) {
	res := TapProbeResult{
		PeerID: peerID.String(),
	}

	meta, ok := n.peerMeta.Load(peerID)
	if !ok {
		res.Error = "peer metadata not found (peer may be offline or not yet synced)"
		return res, fmt.Errorf("%s", res.Error)
	}
	pm := meta.(PeerMeta)
	res.PeerName = pm.NodeName
	peerTapIPStr := splitIP(pm.TapIP)
	peerTapMAC, err := net.ParseMAC(pm.TapMAC)
	if err != nil || peerTapIPStr == "" {
		res.Error = "peer TAP IP/MAC missing in metadata"
		return res, fmt.Errorf("%s", res.Error)
	}
	peerTapIP := net.ParseIP(peerTapIPStr).To4()
	if peerTapIP == nil {
		res.Error = "peer TAP IP is not a valid IPv4 address"
		return res, fmt.Errorf("%s", res.Error)
	}
	if n.localV4IP == nil || len(n.localMAC) != 6 {
		res.Error = "local TAP IP/MAC not initialized"
		return res, fmt.Errorf("%s", res.Error)
	}
	res.TapIP = peerTapIPStr

	// Build an ICMP echo request frame addressed to the peer's TAP IP.
	reqFrame, err := buildICMPEchoRequest(n.localMAC, peerTapMAC, n.localV4IP, peerTapIP, tapProbeICMPIdentify)
	if err != nil {
		res.Error = "failed to build probe frame: " + err.Error()
		return res, err
	}
	res.SentBytes = len(reqFrame)

	// SEND-side priority: the real TAP/ICMP echo-request frame is dispatched on
	// the PRIORITY SEND queue (front of the send queue), symmetric to the
	// receive-side urgent injection.  This ensures the diagnostic probe's real
	// frame is not starved behind ordinary TAP egress backlog.  The overlay
	// stream below still carries the probe handshake/reply.
	reqFrameCopy := make([]byte, len(reqFrame))
	copy(reqFrameCopy, reqFrame)
	n.DispatchUrgentFrame(peerID, reqFrameCopy, peerTapMAC, len(reqFrame))

	seq := randomUint32()
	reqMsg := make([]byte, 0, 6+len(reqFrame))
	reqMsg = append(reqMsg, tapProbeTypeRequest)
	reqMsg = append(reqMsg, tapProbeFlagUrgent) // diagnostics: peer-side priority
	reqMsg = append(reqMsg, byte(seq>>24), byte(seq>>16), byte(seq>>8), byte(seq))
	reqMsg = append(reqMsg, reqFrame...)

	start := time.Now()
	streamCtx := network.WithAllowLimitedConn(n.ctx, "tap-probe")
	s, err := n.Host.NewStream(streamCtx, peerID, tapProbeProtocol)
	if err != nil {
		res.Error = "failed to open TAP probe stream: " + err.Error()
		return res, err
	}
	defer s.Close()

	// Length-prefixed write so the responder can read exactly this frame
	// regardless of size (matches the ReadFrame protocol on the responder side).
	if err := WriteFrame(s, reqMsg); err != nil {
		res.Error = "failed to send probe frame: " + err.Error()
		return res, err
	}

	resp := make([]byte, 2+tapProbePayloadMax)
	_ = s.SetReadDeadline(time.Now().Add(tapProbeDefaultRTT))
	readN, err := ReadFrame(s, resp)
	if err != nil {
		res.Error = "no reply received (timeout): " + err.Error()
		return res, err
	}
	elapsed := time.Since(start)
	resp = resp[:readN]

	if len(resp) < 6 || resp[0] != tapProbeTypeReply || binary.BigEndian.Uint32(resp[2:6]) != seq {
		res.Error = "malformed reply"
		return res, fmt.Errorf("%s", res.Error)
	}
	replyFrame := resp[6:]

	// Validate the echoed frame is a well-formed ICMP echo reply to us.
	if err := verifyICMPEchoReply(replyFrame, peerTapMAC, n.localMAC, peerTapIP, n.localV4IP, tapProbeICMPIdentify, seq); err != nil {
		res.Error = "reply validation failed: " + err.Error()
		return res, err
	}

	res.Success = true
	res.RTTMills = elapsed.Milliseconds()
	return res, nil
}

// buildTapProbeReply turns a received ICMP echo request frame into an ICMP echo
// reply frame (swap src/dst MAC & IP, flip ICMP type 8->0, recompute checksums).
func (n *Node) buildTapProbeReply(reqFrame []byte) ([]byte, error) {
	if len(reqFrame) < 34 {
		return nil, fmt.Errorf("frame too short (%d bytes)", len(reqFrame))
	}
	etherType := binary.BigEndian.Uint16(reqFrame[12:14])
	if etherType != 0x0800 {
		return nil, fmt.Errorf("not IPv4 (ethertype 0x%04x)", etherType)
	}
	// IPv4 header length
	ihl := int(reqFrame[14]&0x0f) * 4
	if ihl < 20 || len(reqFrame) < 14+ihl+8 {
		return nil, fmt.Errorf("invalid IPv4 header")
	}
	proto := reqFrame[14+9]
	if proto != 1 { // ICMP
		return nil, fmt.Errorf("not ICMP (proto %d)", proto)
	}
	srcIP := net.IP(reqFrame[14+12 : 14+16]).To4()
	dstIP := net.IP(reqFrame[14+16 : 14+20]).To4()
	if !dstIP.Equal(n.localV4IP) {
		return nil, fmt.Errorf("echo request not addressed to this node (%s != %s)", dstIP, n.localV4IP)
	}
	icmpType := reqFrame[14+ihl]
	if icmpType != 8 { // echo request
		return nil, fmt.Errorf("not ICMP echo request (type %d)", icmpType)
	}

	// Build reply frame: swap MACs and IPs, flip ICMP type.
	reply := make([]byte, len(reqFrame))
	copy(reply, reqFrame)
	// swap Ethernet MACs
	copy(reply[0:6], reqFrame[6:12])
	copy(reply[6:12], reqFrame[0:6])
	// swap IPs
	copy(reply[14+12:14+16], dstIP)
	copy(reply[14+16:14+20], srcIP)
	// flip ICMP type request(8) -> reply(0)
	reply[14+ihl] = 0

	// Recompute ICMP checksum (IPv4 header checksum stays valid; recompute ICMP).
	icmpStart := 14 + ihl
	reply[icmpStart+2] = 0
	reply[icmpStart+3] = 0
	cs := icmpChecksum(reply[icmpStart:])
	reply[icmpStart+2] = byte(cs >> 8)
	reply[icmpStart+3] = byte(cs)

	return reply, nil
}

// ---- ICMP frame helpers ----

func buildICMPEchoRequest(localMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, identify uint16) ([]byte, error) {
	// Ethernet(14) + IPv4(20) + ICMP(8 + payload 8) = 50 bytes
	const icmpPayloadLen = 8
	frame := make([]byte, 14+20+8+icmpPayloadLen)
	// Ethernet
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], localMAC)
	frame[12] = 0x08
	frame[13] = 0x00 // IPv4

	// IPv4 header
	frame[14] = 0x45 // version 4, IHL 5
	frame[15] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(frame[16:18], uint16(len(frame)-14))
	frame[18] = 0x00
	frame[19] = 0x00 // identification
	frame[20] = 0x00
	frame[21] = 0x00                            // flags/fragment
	frame[22] = 64                              // TTL
	frame[23] = 1                               // protocol ICMP
	binary.BigEndian.PutUint16(frame[24:26], 0) // header checksum (fill later)
	copy(frame[26:30], srcIP)
	copy(frame[30:34], dstIP)
	ipCS := ipv4Checksum(frame[14:34])
	binary.BigEndian.PutUint16(frame[24:26], ipCS)

	// ICMP echo request
	icmpStart := 34
	frame[icmpStart] = 8 // type echo request
	frame[icmpStart+1] = 0
	binary.BigEndian.PutUint16(frame[icmpStart+2:icmpStart+4], 0) // checksum
	binary.BigEndian.PutUint16(frame[icmpStart+4:icmpStart+6], identify)
	binary.BigEndian.PutUint16(frame[icmpStart+6:icmpStart+8], 0x0001) // sequence
	// payload (8 bytes of zeros)
	frame[icmpStart+2] = 0
	frame[icmpStart+3] = 0
	icmpCS := icmpChecksum(frame[icmpStart:])
	binary.BigEndian.PutUint16(frame[icmpStart+2:icmpStart+4], icmpCS)

	return frame, nil
}

func verifyICMPEchoReply(frame []byte, expSrcMAC, expDstMAC net.HardwareAddr, expSrcIP, expDstIP net.IP, identify uint16, seq uint32) error {
	if len(frame) < 34+8 {
		return fmt.Errorf("reply too short (%d bytes)", len(frame))
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return fmt.Errorf("reply not IPv4")
	}
	ihl := int(frame[14]&0x0f) * 4
	if frame[14+9] != 1 {
		return fmt.Errorf("reply not ICMP")
	}
	if frame[14+ihl] != 0 {
		return fmt.Errorf("not ICMP echo reply (type %d)", frame[14+ihl])
	}
	if !bytes.Equal(frame[0:6], expSrcMAC) {
		return fmt.Errorf("reply src MAC mismatch")
	}
	if !bytes.Equal(frame[6:12], expDstMAC) {
		return fmt.Errorf("reply dst MAC mismatch")
	}
	if !net.IP(frame[14+12 : 14+16]).Equal(expSrcIP) {
		return fmt.Errorf("reply src IP mismatch")
	}
	if !net.IP(frame[14+16 : 14+20]).Equal(expDstIP) {
		return fmt.Errorf("reply dst IP mismatch")
	}
	icmpStart := 14 + ihl
	if binary.BigEndian.Uint16(frame[icmpStart+4:icmpStart+6]) != identify {
		return fmt.Errorf("reply ICMP identifier mismatch")
	}
	return nil
}

func ipv4Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func randomUint32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

func splitIP(cidr string) string {
	for i := 0; i < len(cidr); i++ {
		if cidr[i] == '/' {
			return cidr[:i]
		}
	}
	return cidr
}
