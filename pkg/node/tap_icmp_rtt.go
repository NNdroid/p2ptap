package node

import (
	"encoding/binary"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

const tapICMPEchoTimeout = 10 * time.Second

// tapICMPEchoKey identifies one IPv4 echo exchange as observed at the local
// TAP boundary. PeerID is part of the key so identical ICMP IDs/sequences used
// concurrently against different mesh peers cannot collide.
type tapICMPEchoKey struct {
	peerID peer.ID
	family uint8
	id     uint16
	seq    uint16
	srcIP  [16]byte
	dstIP  [16]byte
}

// observeTapICMPEchoRequest is called only after forwarding resolved the real
// destination peer. Its timestamp is therefore the same boundary at which a
// user's OS ping enters the overlay data path.
func (n *Node) observeTapICMPEchoRequest(pid peer.ID, frame []byte, now time.Time) {
	family, id, seq, srcIP, dstIP, ok := parseICMPEcho(frame, false)
	if !ok || id == tapProbeICMPIdentify || pid == "" {
		return
	}
	key := tapICMPEchoKey{peerID: pid, family: family, id: id, seq: seq, srcIP: srcIP, dstIP: dstIP}
	n.tapICMPEchoMu.Lock()
	if n.tapICMPEchoPending == nil {
		n.tapICMPEchoPending = make(map[tapICMPEchoKey]time.Time)
	}
	n.tapICMPEchoPending[key] = now
	n.tapICMPEchoMu.Unlock()
}

// observeTapICMPEchoReply runs on the inbound overlay boundary immediately
// before the frame is injected into the local TAP. A match is a genuine RTT of
// the same path seen by the originating OS ping, including queueing delay.
func (n *Node) observeTapICMPEchoReply(pid peer.ID, frame []byte, now time.Time) {
	family, id, seq, srcIP, dstIP, ok := parseICMPEcho(frame, true)
	if !ok || id == tapProbeICMPIdentify || pid == "" {
		return
	}
	key := tapICMPEchoKey{peerID: pid, family: family, id: id, seq: seq, srcIP: dstIP, dstIP: srcIP}
	n.tapICMPEchoMu.Lock()
	sentAt, found := n.tapICMPEchoPending[key]
	if found {
		delete(n.tapICMPEchoPending, key)
	}
	n.tapICMPEchoMu.Unlock()
	if !found || !now.After(sentAt) {
		return
	}
	rtt := now.Sub(sentAt)
	if rtt <= tapICMPEchoTimeout {
		n.recordPeerRTTProbeAt(pid, rttSourceTAPICMP, rtt, true, now)
	}
}

// expireTapICMPEchoRequests turns unanswered real OS pings into loss samples.
// It is called by the regular stats snapshot, keeping the packet hot path free
// from timers/goroutines while still making loss visible in the WebUI.
func (n *Node) expireTapICMPEchoRequests(now time.Time) {
	if n == nil {
		return
	}
	var expired []tapICMPEchoKey
	n.tapICMPEchoMu.Lock()
	for key, sentAt := range n.tapICMPEchoPending {
		if now.Sub(sentAt) >= tapICMPEchoTimeout {
			expired = append(expired, key)
			delete(n.tapICMPEchoPending, key)
		}
	}
	n.tapICMPEchoMu.Unlock()
	for _, key := range expired {
		n.recordPeerRTTProbeAt(key.peerID, rttSourceTAPICMP, 0, false, now)
	}
}

func parseICMPEcho(frame []byte, reply bool) (family uint8, id, seq uint16, srcIP, dstIP [16]byte, ok bool) {
	if len(frame) < 14 {
		return 0, 0, 0, srcIP, dstIP, false
	}
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case 0x0800:
		if len(frame) < 42 || frame[14]>>4 != 4 {
			return 0, 0, 0, srcIP, dstIP, false
		}
		ihl := int(frame[14]&0x0f) * 4
		// A non-initial fragment has no ICMP header at this offset.
		if ihl < 20 || len(frame) < 14+ihl+8 || frame[14+9] != 1 || binary.BigEndian.Uint16(frame[20:22])&0x1fff != 0 {
			return 0, 0, 0, srcIP, dstIP, false
		}
		icmp := 14 + ihl
		wantType := byte(8)
		if reply {
			wantType = 0
		}
		if frame[icmp] != wantType || frame[icmp+1] != 0 {
			return 0, 0, 0, srcIP, dstIP, false
		}
		copy(srcIP[:4], frame[26:30])
		copy(dstIP[:4], frame[30:34])
		return 4, binary.BigEndian.Uint16(frame[icmp+4 : icmp+6]), binary.BigEndian.Uint16(frame[icmp+6 : icmp+8]), srcIP, dstIP, true

	case 0x86dd:
		// Normal OS echo packets have no extension header. If one is present,
		// decline the sample instead of guessing offsets and pairing the wrong
		// packet; forwarding itself is unaffected.
		if len(frame) < 14+40+8 || frame[14]>>4 != 6 || frame[20] != 58 {
			return 0, 0, 0, srcIP, dstIP, false
		}
		icmp := 14 + 40
		wantType := byte(128)
		if reply {
			wantType = 129
		}
		if frame[icmp] != wantType || frame[icmp+1] != 0 {
			return 0, 0, 0, srcIP, dstIP, false
		}
		copy(srcIP[:], frame[22:38])
		copy(dstIP[:], frame[38:54])
		return 6, binary.BigEndian.Uint16(frame[icmp+4 : icmp+6]), binary.BigEndian.Uint16(frame[icmp+6 : icmp+8]), srcIP, dstIP, true
	}
	return 0, 0, 0, srcIP, dstIP, false
}
