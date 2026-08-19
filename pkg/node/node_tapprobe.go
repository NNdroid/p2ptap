package node

// TAP forwarding probe — WebUI "P2P 通联排查工具 / 端到端 TAP 转发验证".
//
// REAL END-TO-END TAP PATH (current design):
//
//	The prober builds a genuine ICMP echo-request Ethernet frame addressed to
//	the peer's TAP IP/MAC (src = our TAP IP/MAC, ICMP id = tapProbeICMPIdentify)
//	and dispatches it on the PRIORITY overlay send queue (DispatchUrgentFrame)
//	toward the peer. The frame reaches the peer's real TAP device; the peer's
//	OS ICMP stack answers it; the echo reply then crosses the peer's TAP ->
//	overlay -> OUR node, where it is captured off the INBOUND overlay receive
//	path (maybeDeliverProbeReply in node_tap.go, invoked from node_streams.go
//	just before the frame is written into our TAP) and handed to the waiting
//	prober.
//
//	A TUN/TAP device does NOT re-deliver a frame written to it back to its own
//	read fd, so the capture must happen on the RECEIVE path, never on the TAP
//	read loop. The prober validates the captured reply against the peer's MAC/IP,
//	so a PASS means a real ping-style frame actually traversed BOTH TAP devices
//	and the overlay in both directions, and a FAIL means the TAP path is
//	genuinely broken — exactly what this tool exists to diagnose ("why can't I
//	ping through the TAP?").
//
// This replaced the original design, which only round-tripped the frame over a
// dedicated control stream and built the ICMP reply IN MEMORY on the responder.
// That design could neither detect a broken return path nor any TAP-device fault
// (MAC misresolution, ARP/NDP proxy bug, TAP write failure, MTU mismatch,
// one-direction stutter), yielding FALSE PASS (overlay up, TAP down) and FALSE
// FAIL (TAP fine, control stream flaps) — and the in-memory reply path was also
// a nil-TAP panic vector ("Application error 0x0").

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/obfuscate"
)


const (
	// tapProbeDefaultRTT bounds how long we wait for the echo reply to come back
	// on the real TAP path before declaring this attempt failed.
	tapProbeDefaultRTT = 3 * time.Second
	// tapProbeICMPIdentify ("Zp") marks probe-generated ICMP so our capture can
	// tell a genuine probe reply from ordinary LAN traffic (a normal OS ping
	// never uses this id).
	tapProbeICMPIdentify uint16 = 0x5A70
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

	// Transport context: a RELAYED peer reaches us (and our probe frame reaches
	// it) through an overlay-relay / circuit hop. If THAT path is down, the real
	// ICMP request never reaches the peer's TAP (or its reply never returns) and
	// the probe legitimately FAILs — which is the correct signal for "the TAP
	// data path is broken". We surface direct/relayed so the troubleshooter can
	// tell a relay-hopper problem from a same-LAN one.
	isDirect := n.isDirectlyConnected(peerID)
	relayHop := n.relayHopForTarget(peerID)
	transportNote := "direct"
	if !isDirect {
		if relayHop != "" {
			transportNote = "relayed via " + relayHop.ShortString()
		} else {
			transportNote = "indirect (no usable relay hop)"
		}
	}

	// Build an ICMP echo request frame addressed to the peer's TAP IP.
	reqFrame, err := buildICMPEchoRequest(n.localMAC, peerTapMAC, n.localV4IP, peerTapIP, tapProbeICMPIdentify)
	if err != nil {
		res.Error = "failed to build probe frame: " + err.Error()
		return res, err
	}
	res.SentBytes = len(reqFrame)

	// Serialise probes so concurrent troubleshooter calls can't steal each
	// other's echo replies off the single TAP read loop.
	n.probeMu.Lock()
	defer n.probeMu.Unlock()

	// Genuine end-to-end TAP test: the REAL ICMP echo request is dispatched over
	// the overlay (urgent send queue) and reaches the peer's TAP device; the
	// peer's OS answers it; the echo reply travels back through the peer's TAP ->
	// overlay -> OUR node's inbound receive path, where maybeDeliverProbeReply
	// captures it and hands it to waitProbeReply below. This exercises the real
	// TAP data path in BOTH directions — not a synthetic control-stream echo —
	// so a PASS means a real ping-style frame actually traversed both TAP devices
	// and the overlay, and a FAIL means the TAP path is genuinely broken.
	const probeAttempts = 2
	start := time.Now()
	var lastErr error
	for attempt := 1; attempt <= probeAttempts; attempt++ {
		// Arm the capture so maybeDeliverProbeReply starts copying matching echo
		// replies to probeReplyCh for the duration of this attempt's wait.
		atomic.StoreInt32(&n.probeActive, 1)

		// Dispatch the REAL request frame to the peer (overlay -> peer TAP).
		seqID := n.Packer.NextSeqID(n.txEpochForPeer(peerID))
		packedBuf := make([]byte, obfuscate.MaxFrameSize)
		totalLen, perr := n.Packer.Pack(seqID, reqFrame, packedBuf)

		if perr != nil {
			lastErr = fmt.Errorf("probe frame pack error: %w", perr)
			continue
		}
		reqCopy := make([]byte, totalLen)
		copy(reqCopy, packedBuf[:totalLen])
		n.DispatchUrgentFrame(peerID, reqCopy, peerTapMAC, len(reqFrame))


		// Wait for the echo reply to arrive on OUR real TAP path (captured off
		// the inbound overlay receive path).
		reply, got := n.waitProbeReply(peerTapMAC, peerTapIP, tapProbeDefaultRTT)
		atomic.StoreInt32(&n.probeActive, 0)

		if got {
			if err := verifyICMPEchoReply(reply, peerTapMAC, n.localMAC, peerTapIP, n.localV4IP, tapProbeICMPIdentify, 0); err != nil {
				lastErr = fmt.Errorf("reply validation failed: %w", err)
			} else {
				res.Success = true
				res.RTTMills = time.Since(start).Milliseconds()
				return res, nil
			}
		} else if lastErr == nil {
			lastErr = fmt.Errorf("no echo reply on local TAP within %s (%s)", tapProbeDefaultRTT, transportNote)
		}
		if attempt < probeAttempts {
			time.Sleep(300 * time.Millisecond)
		}
	}
	res.Error = fmt.Sprintf("TAP probe failed (%s): %s", transportNote, lastErr.Error())
	return res, fmt.Errorf("%s", res.Error)
}

// waitProbeReply blocks until a TAP-probe echo reply (matching the peer's MAC
// and IP) is captured off the local inbound TAP path via probeReplyCh, or the
// timeout elapses. Frames that arrive but don't match this peer are ignored, so a
// stray or out-of-order reply doesn't abort the wait.
func (n *Node) waitProbeReply(peerTapMAC net.HardwareAddr, peerTapIP net.IP, timeout time.Duration) ([]byte, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case frame := <-n.probeReplyCh:
			if verifyICMPEchoReply(frame, peerTapMAC, n.localMAC, peerTapIP, n.localV4IP, tapProbeICMPIdentify, 0) == nil {
				return frame, true
			}
			// Not ours; keep draining so a later frame can still match.
			continue
		case <-timer.C:
			return nil, false
		}
	}
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
	// Ethernet frame order: frame[0:6] is the DESTINATION MAC, frame[6:12] is
	// the SOURCE MAC (the reverse of the IPv4 header, where src IP precedes dst
	// IP). A genuine echo reply has dst == our MAC and src == the peer's MAC, so
	// frame[0:6] must match expDstMAC and frame[6:12] must match expSrcMAC.
	if !bytes.Equal(frame[0:6], expDstMAC) {
		return fmt.Errorf("reply dst MAC mismatch")
	}
	if !bytes.Equal(frame[6:12], expSrcMAC) {
		return fmt.Errorf("reply src MAC mismatch")
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

// splitIP returns the IP portion of a "ip/prefix" string (CIDR), or the whole
// string if it has no prefix.
func splitIP(cidr string) string {
	for i := 0; i < len(cidr); i++ {
		if cidr[i] == '/' {
			return cidr[:i]
		}
	}
	return cidr
}
