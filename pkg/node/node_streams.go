package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"

	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/observer"
	"p2ptap/pkg/packet"
	"p2ptap/pkg/routing"
	vswitch "p2ptap/pkg/switch"
	"p2ptap/pkg/version"
)

// minEthernetFrameLen is the smallest payload accepted as a genuine Ethernet
// frame for MAC learning / observed-MAC recording: a 14-byte Ethernet header
// plus the smallest useful L3 header (20-byte IPv4). ExtractEthernetMACs only
// needs 12 bytes, so short control payloads (e.g. a 19-byte stream warm-up
// probe) still "parse" as L2 frames — their payload bytes [0:12] would be
// recorded as a bogus src MAC, poisoning the MAC table and the ARP index.
const minEthernetFrameLen = 34

// rewriteRxDstMAC applies the L2 destination-MAC fix-ups that must happen to
// every frame just before it is injected into the local TAP device. It is
// called from BOTH the direct-receive path (handleStream) and the relay-receive
// path (handleRelayStream) so the two write-back paths stay in lockstep — the
// relay path previously omitted this rewrite, so a relayed frame whose Dst MAC
// was not exactly the local interface MAC was L2-dropped by the kernel, which
// silently broke A->B ping whenever A and B were only reachable through a relay.
//
// Two complementary cases:
//  1. Frame destined for THIS node's TAP IP: rewrite Dst MAC to localMAC so the
//     OS accepts the IPv4/IPv6 unicast (otherwise the kernel drops it at L2
//     because the Dst MAC does not match the interface).
//  2. Exit Node active and the frame is transit traffic (Dst IP is not this node
//     and not any peer's advertised/mesh IP): rewrite Dst MAC to the Exit peer
//     MAC (or our own localMAC when we ARE the Exit server) so the kernel
//     forwards it instead of L2-dropping it.
//
// The copy is skipped when the relevant MAC already equals the target (no-op
// rewrite) to avoid needless per-packet work and log noise.
func (n *Node) rewriteRxDstMAC(payload []byte) {
	if len(payload) < 34 || len(n.localMAC) != 6 {
		return
	}
	// Snapshot the mutable config once so the two IPv4/IPv6 exit-transit checks
	// below observe one consistent reload (a mid-frame swap must not tear them).
	c := n.config()
	if binary.BigEndian.Uint16(payload[12:14]) == packet.EtherTypeIPv4 && n.localV4IP != nil {
		dstIP := net.IP(payload[30:34])
		if dstIP.Equal(n.localV4IP) || n.isLocalAdvertisedSubnet(dstIP) {
			if !bytes.Equal(payload[0:6], n.localMAC) {
				log.Debug("MAC rewrite IPv4 (local dst / subnet): dstIP=%s oldDstMAC=%s newDstMAC=%s", dstIP.String(), net.HardwareAddr(payload[0:6]).String(), net.HardwareAddr(n.localMAC).String())
				copy(payload[0:6], n.localMAC)
			}
			return
		}
		if (n.isExitNodeActive() || (c != nil && c.ExitNode.Enable)) &&
			func() bool { mac, _ := n.lookupPeerMACByIPv4(dstIP); return mac == nil }() &&
			n.lookupPeerMACByAdvertisedSubnet(dstIP) == nil {
			exitMAC := n.localMAC
			if !(c != nil && c.ExitNode.Enable) {
				exitMAC = n.getExitPeerMAC()
				if len(exitMAC) != 6 {
					exitMAC = n.localMAC
				}
			}
			if len(exitMAC) == 6 && !bytes.Equal(payload[0:6], exitMAC) {
				log.Debug("MAC rewrite IPv4 (exit transit): dstIP=%s oldDstMAC=%s newDstMAC=%s", dstIP.String(), net.HardwareAddr(payload[0:6]).String(), net.HardwareAddr(exitMAC).String())
				copy(payload[0:6], exitMAC)
			}
		}
		return
	}
	if binary.BigEndian.Uint16(payload[12:14]) == packet.EtherTypeARP && n.localV4IP != nil && len(payload) >= 42 {
		targetIP := net.IP(payload[38:42])
		if targetIP.Equal(n.localV4IP) || n.isLocalAdvertisedSubnet(targetIP) {
			if !isBroadcastOrMulticastMAC(payload[0:6]) && !bytes.Equal(payload[0:6], n.localMAC) {
				log.Debug("MAC rewrite ARP (local dst / subnet): dstIP=%s oldDstMAC=%s newDstMAC=%s", targetIP.String(), net.HardwareAddr(payload[0:6]).String(), net.HardwareAddr(n.localMAC).String())
				copy(payload[0:6], n.localMAC)
			}
			return
		}
	}

	if binary.BigEndian.Uint16(payload[12:14]) == packet.EtherTypeIPv6 && n.localV6IP != nil && len(payload) >= 54 {
		dstIP := net.IP(payload[38:54])
		if dstIP.Equal(n.localV6IP) || n.isLocalAdvertisedSubnet(dstIP) {
			if !bytes.Equal(payload[0:6], n.localMAC) {
				log.Debug("MAC rewrite IPv6 (local dst / subnet): dstIP=%s oldDstMAC=%s newDstMAC=%s", dstIP.String(), net.HardwareAddr(payload[0:6]).String(), net.HardwareAddr(n.localMAC).String())
				copy(payload[0:6], n.localMAC)
			}
			return
		}

		if (n.isExitNodeActive() || (c != nil && c.ExitNode.Enable)) &&
			func() bool { mac, _ := n.lookupPeerMACByIPv6(dstIP); return mac == nil }() &&
			n.lookupPeerMACByAdvertisedSubnet(dstIP) == nil {
			exitMAC := n.localMAC
			if !(c != nil && c.ExitNode.Enable) {
				exitMAC = n.getExitPeerMAC()
				if len(exitMAC) != 6 {
					exitMAC = n.localMAC
				}
			}
			if len(exitMAC) == 6 && !bytes.Equal(payload[0:6], exitMAC) {
				log.Debug("MAC rewrite IPv6 (exit transit): dstIP=%s oldDstMAC=%s newDstMAC=%s", dstIP.String(), net.HardwareAddr(payload[0:6]).String(), net.HardwareAddr(exitMAC).String())
				copy(payload[0:6], exitMAC)
			}
		}
	}
}

func (n *Node) handleStream(s network.Stream) {
	remotePeer := s.Conn().RemotePeer()
	transportName := s.Conn().RemoteMultiaddr().String()

	log.Debug("Stream active with peer %s via %s", remotePeer.String(), transportName)
	n.Dispatcher.RegisterStream(remotePeer, transportName, s)
	defer n.Dispatcher.UnregisterStream(remotePeer, transportName, s)

	buf := make([]byte, obfuscate.MaxSealedFrameSize)
	frameCount := 0

	// A read deadline may fire after io.ReadFull has consumed part of the length
	// prefix or frame body. ReadFrame cannot put those bytes back, so retrying on
	// the same stream desynchronizes every following frame. Clear any inherited
	// deadline and instead reset the stream when node shutdown is requested.
	// Reset unblocks a ReadFrame even when its peer stays silent, without turning
	// a harmless idle period into a corrupt partial-frame retry.
	if err := s.SetReadDeadline(time.Time{}); err != nil {
		log.Debug("Failed to clear stream read deadline for %s: %v", remotePeer.String(), err)
	}
	if n.ctx != nil {
		streamDone := make(chan struct{})
		defer close(streamDone)
		go func() {
			select {
			case <-n.ctx.Done():
				_ = s.Reset()
			case <-streamDone:
			}
		}()
	}

	for {
		// Read length-prefixed frame from P2P stream
		readN, err := ReadFrame(s, buf)
		if err != nil {
			var nerr net.Error
			if errors.As(err, &nerr) && nerr.Timeout() {
				// A timeout has an unknown read offset. Never reuse this framing
				// stream: if it occurred mid-frame, its next bytes cannot safely be
				// interpreted as a new length prefix.
				log.Warn("Stream read timed out from peer %s after %d frames; resetting stream to preserve frame alignment", remotePeer.String(), frameCount)
				_ = s.Reset()
				break
			}
			if err != io.EOF {
				log.Debug("Stream read error from peer %s: %v (after %d frames)", remotePeer.String(), err, frameCount)
			} else {
				log.Debug("Stream EOF from peer %s (after %d frames)", remotePeer.String(), frameCount)
			}
			break
		}

		// Track per-peer received bytes for accurate speed display.
		n.recordPeerRxBytes(remotePeer, readN)
		if n.protoTracker != nil {
			n.protoTracker.Data.RecordRx(1, uint64(readN))
		}
		// Return-path liveness: an inbound frame directly from remotePeer proves its return path is alive
		n.notePeerRx(remotePeer)

		// PERF: per-frame path. peer.String() is base58 (~930ns, 2 allocs) and
		// is evaluated at the call site regardless of log level, so guard it.
		if log.IsDebug() {
			log.Debug("Rx raw frame: len=%d from peer=%s", readN, remotePeer.String())
		}

		frameData := buf[:readN] // may be reassigned below if reassembled

		// CONCURRENCY CONTRACT: `buf` belongs exclusively to this stream-reader
		// goroutine and is reused on each iteration. The MAC-rewrite paths below
		// mutate frameData (== buf[:readN]) in place. This is safe ONLY because
		// the eventual TAP write (n.tapWrite -> n.TAP.Write) is synchronous and
		// returns before the next loop iteration reuses `buf`.
		// Do NOT let `buf`/`frameData` escape this goroutine (e.g. hand it to a
		// background send or the urgent-write channel) without copying first, or
		// a concurrent read would observe torn/overwritten frame bytes.

		if len(frameData) < obfuscate.HeaderLen {
			// PERF: malformed-traffic path — every junk frame lands here, so
			// keep the base58 peer.String() behind the level check.
			if log.IsDebug() {
				log.Debug("Short frame (%d bytes) from peer %s, skipping", len(frameData), remotePeer.String())
			}
			continue
		}

		// ── Per-peer payload DECRYPTION happens FIRST (v2 obfuscation) ──
		// decryptPeerFrame returns (plaintext, decrypted, garbage). garbage==true
		// means a cipher was negotiated but AEAD-open failed: the bytes are
		// ciphertext we cannot open, so DROP them — never forward to the TAP. A
		// successful decrypt replaces frameData with the plaintext; the no-cipher
		// case leaves frameData unchanged (legitimate plaintext).
		dec, decOK, garbage := n.decryptPeerFrame(frameData, remotePeer)
		if garbage {
			// PERF: hit on EVERY frame during a key-divergence storm — keep guarded.
			if log.IsDebug() {
				log.Debug("Rx: dropping undecryptable ciphertext frame from %s", remotePeer.String())
			}
			n.recordPeerRxDecrypt(remotePeer, false)
			// Self-heal: if this keeps failing, re-run SeqSync to re-anchor keys.
			n.maybeResyncOnDecryptFail(remotePeer)
			continue
		}
		if decOK {
			frameData = dec
		}

		// ── Deobfuscation (parse header, extract payload) ──
		seqID, payload, err := obfuscate.Unpack(frameData)
		if err != nil {
			// PERF: also a per-frame path while keys are diverged — keep guarded.
			if log.IsDebug() {
				log.Debug("Frame unpack error from peer %s: %v", remotePeer.String(), err)
			}
			// Both decrypt AND unpack failed => genuinely invalid frame. Record
			// the failure so the recent-window Decrypt-Fail signal can fire only
			// for real garbage (not benign plaintext during the handshake window).
			n.recordPeerRxDecrypt(remotePeer, false)
			// Self-heal via the throttled resync path (threshold + cooldown,
			// then ForceSyncSeq → triggerPeerRekey's single-flight guard). This
			// avoids spawning an unguarded ForceSyncSeq per failing frame, which
			// previously fanned out into many concurrent handshakes that could
			// cross ephemeral generations and diverge the two ends' keys.
			n.maybeResyncOnDecryptFail(remotePeer)
			continue
		}
		// Valid p2ptap frame (encrypted or plaintext). Recording success here
		// resets the recent-error window so a plaintext peer never sticks in
		// "Decrypt Fail", and self-heals readiness for plaintext-capable peers.
		n.recordPeerRxDecrypt(remotePeer, true)
		n.maybeMarkReadyOnDecrypt(remotePeer, true)

		// Unpack now hard-fails on a bad magic, so any frame that reaches here
		// is a valid p2ptap overlay frame. Still enforce the magic check as a
		// belt-and-suspenders guard against stray/garbage traffic leaking into
		// the TAP device.
		if len(frameData) < 2 || binary.BigEndian.Uint16(frameData[0:2]) != obfuscate.FrameMagic {
			// PERF: stray-traffic path — keep the base58 cost behind the check.
			if log.IsDebug() {
				log.Debug("Rejected non-p2ptap frame from peer %s (bad magic, len=%d)",
					remotePeer.String(), len(frameData))
			}
			continue
		}

		// ── Tunnel fragmentation reassembly ──
		// A frame may be one fragment of a larger obfuscated TAP frame. If the
		// deobfuscated outer payload is a fragment envelope, buffer it and wait
		// for the rest; once complete, re-deobfuscate the reassembled original
		// frame to obtain the real TAP payload + seqID. Non-fragment frames use
		// the payload/seqID from the first Unpack directly.
		if n.fragRX != nil && isFragPayload(payload) {
			finalPacked, complete := n.fragRX.reassemble(remotePeer, payload)
			if !complete {
				continue // more fragments pending
			}
			// ── DECRYPT the reassembled inner frame BEFORE unpacking ──
			fdec, fdecOK, fgarbage := n.decryptPeerFrame(finalPacked, remotePeer)
			if fgarbage {
				if log.IsDebug() {
					log.Debug("Rx: dropping undecryptable reassembled ciphertext from %s", remotePeer.String())
				}
				n.recordPeerRxDecrypt(remotePeer, false)
				n.maybeResyncOnDecryptFail(remotePeer)
				continue
			}
			if fdecOK {
				finalPacked = fdec
			}
			seqID, payload, err = obfuscate.Unpack(finalPacked)
			if err != nil {
				log.Debug("Reassembled frame unpack error from peer %s: %v", remotePeer.String(), err)
				continue
			}
		}

		// PERF: per-frame path — peer.String() is base58 (~930ns, 2 allocs),
		// evaluated at the call site regardless of log level. Keep guarded.
		if log.IsDebug() {
			log.Debug("Rx unpacked: seq=%d payloadLen=%d frameLen=%d from peer=%s", seqID, len(payload), len(frameData), remotePeer.String())
		}

		// Per-peer deduplication: each peer has its own seqID space,
		// so seqIDs from different peers never collide (unlike the
		// previous global dedup that could falsely discard frames from
		// peer B whose seqID happened to match peer A's).
		n.dedupPeersMu.RLock()
		peerDedup, ok := n.dedupPeers[remotePeer]
		n.dedupPeersMu.RUnlock()
		if !ok {
			n.dedupPeersMu.Lock()
			peerDedup = n.dedupPeers[remotePeer]
			if peerDedup == nil {
				peerDedup = obfuscate.NewDeduplicator()
				n.dedupPeers[remotePeer] = peerDedup
			}
			n.dedupPeersMu.Unlock()
		}
		if obfuscate.IsStructuredSeq(seqID) {
			if ep := obfuscate.ConnEpochFromSeq(seqID); ep != peerDedup.ConnEpoch() {
				peerDedup.SetConnEpoch(ep)
			}
		}
		if peerDedup.IsDuplicate(seqID) {

			n.Collector.RecordDedup()
			// PERF: cached base58 (see peer_idstr.go) — pid.String() would cost
			// ~933ns/2allocs on EVERY frame just to feed a bookkeeping call.
			n.Collector.RecordPeerDedup(n.peerIDString(remotePeer))
			log.Debug("Duplicate frame seq=%d from peer %s", seqID, remotePeer.String())
			continue
		}
		n.Collector.RecordRxSeq(n.peerIDString(remotePeer), seqID, peerDedup.MaxSeq(), peerDedup.ReplayDrops(), peerDedup.WindowResets(), peerDedup.WindowUtilization())

		// ACL Firewall Filtering check
		if !n.checkACL(payload, n.peerIDString(remotePeer), false) {
			log.Debug("🛡️ ACL Firewall blocked Rx frame seq=%d from peer %s", seqID, remotePeer.String())
			continue
		}
		if log.IsDebug() && n.config().ACL.Enable {
			log.Debug("ACL passed: seq=%d from peer=%s", seqID, remotePeer.String())
		}

		dstMAC, srcMAC, okExtract := vswitch.ExtractEthernetMACs(payload)
		// CORRECTNESS: a runt frame cannot carry trustworthy L2 addressing, so
		// it must not feed MAC learning or the observed-MAC table.
		//
		// ExtractEthernetMACs only needs 12 bytes, so a short control payload
		// (e.g. a 19-byte stream warm-up probe) still "parses": its payload
		// bytes [0:6]/[6:12] get read as dst/src MAC. Recording that bogus src
		// MAC as the peer's observed wire MAC then poisons rebuildARPIndex
		// (which prefers the observed MAC over the advertised metadata MAC), so
		// EVERY peer ends up indexed under the same garbage MAC and the ARP
		// index collapses onto it — ARP replies return the wrong MAC and frames
		// get delivered to the wrong peer. That was the root cause of the
		// three-node mesh failure (A->C and B->C "no delivery").
		//
		// Require a legal minimum: a 14-byte Ethernet header plus a minimal
		// ARP (28) or IPv4 (20) header.
		if okExtract && len(payload) >= minEthernetFrameLen {
			// Capture the RAW (pre-normalization) source MAC the peer truly
			// emits on the wire when sending from its own TAP interface.
			// Only record when the packet originated from the peer's own TapIP,
			// avoiding false-positive MAC mismatches when an exit node / router forwards
			// LAN or routed traffic.
			if rawSrc := net.HardwareAddr(srcMAC); len(rawSrc) == 6 {
				if n.isFrameFromPeerSelf(remotePeer, payload) {
					n.recordPeerObservedTapMAC(remotePeer, rawSrc)
				}
			}

			// Normalize the learned source MAC to the peer's configured TapMAC
			// when known. Some peers (e.g. Windows) emit EUI-64 / synthetic
			// MACs in the SrcMAC field; learning those verbatim would explode
			// the MAC table with one entry per distinct random MAC. See also
			// the SrcMAC fix-up below for pcap display.
			if realMAC := n.lookupPeerTapMAC(remotePeer); realMAC != nil {
				srcMAC = realMAC
			}
			n.MACTable.Learn(srcMAC, remotePeer)

			// Auto-learn peer IPv4 / IPv6 into ARP/NDP index and inject GARP/NA into local TAP
			// ensuring the local OS can immediately return unicast replies without unproxied broadcast delay.
			n.learnPeerAddressFromFrame(remotePeer, srcMAC, payload)
			if log.IsDebug() {
				log.Debug("Rx frame: seq=%d len=%d src=%s dst=%s from_peer=%s %s",
					seqID, len(payload), net.HardwareAddr(srcMAC[:]).String(), net.HardwareAddr(dstMAC[:]).String(), remotePeer.String(), describeEthernetFrame(payload))
			}

			// Content-based dedup ONLY for broadcast/multicast frames:
			// when the same L2 broadcast/multicast payload arrives via multiple peer streams or
			// redundant paths, only the first copy is written to TAP.
			// Unicast frames are handled by per-peer SeqID sliding window deduplication above.
			if isBroadcastOrMulticastMAC(dstMAC) {
				contentHash := fnvHash64(payload)
				if n.bcastDedup.isDuplicate(contentHash) {
					n.Collector.RecordDedup()
					log.Debug("Content-dup broadcast frame hash=0x%x from peer %s dropped", contentHash, remotePeer.String())
					continue
				}
			}

		} else {
			log.Debug("Rx frame: seq=%d len=%d (MAC extract failed) from_peer=%s", seqID, len(payload), remotePeer.String())
		}

		n.Collector.RecordRecv(len(payload))
		n.Collector.RecordPacketDir(payload, false)
		if n.Collector != nil {
			n.Collector.CaptureFrameWithPeers(observer.DirRx, payload, n.peerIDString(remotePeer), "self")
		}
		if len(payload) >= 14 {
			// Fix up rx frame SrcMAC: some peers (especially Windows) may send
			// frames with an EUI-64 derived synthetic MAC in the SrcMAC field
			// instead of their configured TapMAC.  Replace it with the real
			// TapMAC from peer metadata so the pcap table shows a consistent,
			// address-book MAC.
			capturePayload := payload // avoid copying for the common case
			if okExtract {
				if realMAC := n.lookupPeerTapMAC(remotePeer); realMAC != nil {
					frameSrc := net.HardwareAddr(payload[6:12])
					if frameSrc.String() != realMAC.String() {
						capturePayload = make([]byte, len(payload))
						copy(capturePayload, payload)
						copy(capturePayload[6:12], realMAC)
					}
				}
			}
			n.Collector.RecordFrame(capturePayload)
		}
		n.IPTracker.ExtractAndRecord(payload, false)

		// Data is actively flowing — reset ping-pong fail count for this peer.
		// Prevents spurious reconnects when yamux flow control delays echo streams
		// but the application-level connection is healthy.
		n.resetPingPongFailCountForPeer(remotePeer)

		frameCount++

		if n.Interceptor != nil && n.Interceptor.MatchAndHandle(payload, tapInjectionWriter{node: n}) {
			log.Debug("Frame intercepted by userspace WebUI interceptor from peer %s", remotePeer.String())
			continue
		}

		// L2 MAC fixup for frames about to be written into the local TAP device
		// (destined-for-us Dst MAC rewrite, and Exit-Node transit rewrite). Shared
		// with the relay-receive path via rewriteRxDstMAC so the two write-back
		// paths stay identical (see that function for the full rationale).
		n.rewriteRxDstMAC(payload)

		// End-to-end TAP-probe capture. The peer's ICMP echo reply (which left
		// the peer's real TAP, traversed the overlay, and is about to be injected
		// into OUR real TAP) is captured here on the inbound path. We cannot rely
		// on it looping back through the TAP read fd — a TUN/TAP device does not
		// re-deliver written frames to its own read side — so the capture must
		// happen here to make ProbeTapForward a genuine both-directions TAP-path
		// test. The OS also receives the reply (a harmless stray, since no local
		// socket originated the request).
		n.maybeDeliverProbeReply(payload)

		// 方案 B: peer-side probe ack. If this inbound frame is the genuine
		// TAP-forward probe request (real ICMP echo request with our marker id),
		// fire an out-of-band control-plane ack to the prober AFTER the frame has
		// been written into our TAP device — the ack means "physically delivered
		// to the kernel", not merely "passed our overlay boundary". The ack
		// carries a dst-IP-match flag: whether the request was addressed to an IP
		// we currently own on the TAP. A mismatch (stale prober-side metadata)
		// makes the kernel drop the frame silently, which the prober would
		// otherwise misreport as "peer firewall blocked ICMP". We still write the
		// frame to TAP below so the real end-to-end echo reply also flows back.
		if pid, tok, ok := n.isTapProbeRequest(payload); ok {
			dstIP := net.IP(payload[14+16 : 14+20])
			ackFlag := tapProbeAckFlagIPMismatch
			if n.localV4IP != nil && dstIP.Equal(n.localV4IP) {
				ackFlag = tapProbeAckFlagIPMatched
			}
			go n.sendTapProbeAckAfterTAP(pid, tok, ackFlag)
		}

		// Write unpadded payload Ethernet frame to TAP
		if n.TAP == nil {
			log.Warn("TAP device is nil, cannot write frame")
			continue
		}
		// PERF: per-frame path — MAC .String() allocs on every call. Keep guarded.
		if log.IsDebug() {
			log.Debug("TAP write: seq=%d len=%d dstMAC=%s to %s", seqID, len(payload), net.HardwareAddr(payload[0:6]).String(), n.TAP.Name())
		}
		wn, werr := n.tapWrite(payload)
		if werr != nil {
			log.Warn("TAP write error: %v", werr)
		} else {
			log.Debug("TAP write ok: %d bytes to %s", wn, n.TAP.Name())
			// Deliver the deferred probe ack(s) for THIS frame only after the
			// TAP write succeeded: "reached peer TAP" must mean the kernel got
			// it, not that we merely passed the frame along. On write failure the
			// deferred acks are dropped — the probe will report "no ack" which
			// is the truthful outcome.
			if deferred := n.takeDeferredProbeAcks(); len(deferred) > 0 {
				for _, d := range deferred {
					go n.sendTapProbeAck(d.prober, d.token, d.flag)
				}
			}
			// Gateway packet on the server side: frames received over P2P and
			// injected into the local TAP by an Exit Node server count as
			// server→client tunnel traffic. Skip if we are ALSO an Exit Node
			// client (isExitNodeActive) to avoid double-counting our own tunnel.
			//
			// Only count UNICAST frames as genuine egress. Broadcast/multicast
			// frames (ARP, DHCP, mDNS, …) are local L2 flood traffic that stays
			// on the LAN and are NOT real upstream egress — counting them here
			// double-counted them (they are already binned by RecordPacketDir)
			// and made the gateway counter balloon even when no exit-client was
			// active. A frame is unicast iff bit 0 of the first dst-MAC byte is 0.
			if cfg := n.config(); cfg != nil && cfg.ExitNode.Enable && !n.isExitNodeActive() && len(payload) >= 6 && payload[0]&1 == 0 {
				n.Collector.RecordGatewayPacket()
			}
		}
	}
}

func (n *Node) buildLocalARPEntries(nodeName string) []observer.ARPInfoDTO {
	entries := make([]observer.ARPInfoDTO, 0, 2)
	peerID := ""
	if n.Host != nil {
		peerID = n.Host.ID().String()
	}
	if n.localV4IP != nil && len(n.localMAC) == 6 {
		entries = append(entries, observer.ARPInfoDTO{
			IP:       n.localV4IP.String(),
			MAC:      n.localMAC.String(),
			PeerID:   peerID,
			NodeName: nodeName,
			Type:     "Dynamic (ARP)",
			LastSeen: "0s ago",
		})
	}
	if n.localV6IP != nil && len(n.localMAC) == 6 {
		entries = append(entries, observer.ARPInfoDTO{
			IP:       n.localV6IP.String(),
			MAC:      n.localMAC.String(),
			PeerID:   peerID,
			NodeName: nodeName,
			Type:     "Dynamic (NDP)",
			LastSeen: "0s ago",
		})
	}
	return entries
}

func (n *Node) lsaLoop() {
	defer n.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			// Use the shared monotonic counter — a local counter starting at 1
			// would be permanently rejected as stale by peers that already saw
			// a (much larger) force-push sequence. See Node.lsaSeq.
			n.broadcastLSA(n.nextLSASeq())
		}
	}
}

// nextLSASeq returns a strictly increasing LSA sequence number. Every
// broadcastLSA call site MUST obtain its sequence here so the periodic ticker
// and the event-driven force pushes share one monotonic sequence space.
func (n *Node) nextLSASeq() uint64 {
	return n.lsaSeq.Add(1)
}

func (n *Node) broadcastLSA(seq uint64) {
	c := n.config()
	lsa := n.Router.BuildLSA(seq, routing.NodeIdentity{
		NodeName:   n.nodeName,
		TapIP:      c.TapIP,
		TapIPv6:    c.TapIPv6,
		TapMAC:     c.TapMAC,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Version:    version.Version,
		IsExitNode: c.ExitNode.Enable,
		// Carry advertised subnets in the LSA broadcast so peers that learn
		// our identity via the LSA / Peek-Map channel (not just the direct
		// P2P meta stream) also receive our routed LAN subnets.
		AdvertisedSubnets: c.AdvertisedSubnets,
	})
	data, err := json.Marshal(lsa)
	if err != nil {
		return
	}

	// Gossip throttle: if the LSA content is byte-for-byte identical to the last
	// broadcast (topology + identity + links unchanged), we can throttle re-sending.
	// However, remote peers run Router.CleanStaleNodes(60s), which purges any node
	// that hasn't refreshed its LSA within 60 seconds. Therefore, we MUST re-flood
	// at least once every 20 seconds (heartbeat) even if the payload is unchanged!
	n.lastLSAMu.Lock()
	unchanged := bytes.Equal(n.lastLSAJSON, data)
	timeSinceLast := time.Since(n.lastLSABroadcastAt)
	shouldBroadcast := !unchanged || timeSinceLast >= 20*time.Second
	if !unchanged {
		n.lastLSAJSON = append(n.lastLSAJSON[:0], data...)
	}
	if shouldBroadcast {
		n.lastLSABroadcastAt = time.Now()
	}
	n.lastLSAMu.Unlock()

	if !shouldBroadcast {
		log.Debug("LSA unchanged since last broadcast (%v ago), skipping re-flood (seq=%d)", timeSinceLast, seq)
		return
	}

	// 向所有 peer 广播 LSA —— reuse one persistent stream per peer (A):
	// the old loop opened a fresh NewStream for every peer every tick
	// (O(N) handshakes per 15s), thrashing the transport at scale. lsaPool.Submit
	// lazily opens and reuses a single long-lived length-prefixed stream.
	for _, pID := range n.Host.Network().Peers() {
		if pID == n.Host.ID() {
			continue
		}
		// Skip pure circuit-relay / bootstrap nodes: they transit /p2p-circuit
		// but do not serve our LSA control protocol, so opening a stream to
		// them always fails ("unreachable") and only spams the log. LSA flood
		// targets real mesh members only.
		if n.isBootstrapPeer(pID) {
			continue
		}
		if n.lsaPool.Submit(pID, data) {
			n.recordPeerTxBytes(pID, len(data))
			if n.protoTracker != nil {
				n.protoTracker.LSA.RecordTx(1, uint64(len(data)))
			}
		} else {
			log.Debug("Failed to send LSA to peer %s (unreachable)", pID.String())
		}
	}
}

func (n *Node) handleLSAStream(s network.Stream) {
	defer s.Close()
	// Length-prefixed frame loop (matching the persistent lsaPool sender). A
	// single long-lived stream carries many periodic LSA frames, so we must read
	// them one at a time rather than assuming one write-then-close message.
	buf := make([]byte, obfuscate.MaxSealedFrameSize)
	for {
		rn, err := ReadFrame(s, buf)
		if err != nil {
			if err != io.EOF {
				log.Debug("LSA stream read error from %s: %v", s.Conn().RemotePeer().String(), err)
			}
			return
		}
		if rn == 0 {
			continue
		}
		if n.protoTracker != nil {
			n.protoTracker.LSA.RecordRx(1, uint64(rn))
		}
		data := buf[:rn]

		var lsa routing.LinkStatePayload
		if err := json.Unmarshal(data, &lsa); err != nil {
			continue
		}

		// Piggyback node identity (name/IP/MAC) onto the link-state channel so peers
		// are identifiable even when the dedicated meta stream cannot be negotiated
		// (e.g. circuit-relay sub-stream dial timeouts). lsa.Origin is the identity
		// owner even when this LSA arrived via forwarding.
		if origin, err := peer.Decode(lsa.Origin); err == nil {
			n.applyPeerMetaFromLSA(origin, lsa)
		}

		changed := n.Router.ProcessLSA(&lsa)
		if changed {
			// Retain the freshest accepted payload for this origin so we can
			// hand a FULL topology snapshot to the next peer that connects.
			// Must be captured BEFORE the TTL decrement below.
			n.cacheLSA(&lsa)
		}
		if changed && lsa.TTL > 1 {
			lsa.TTL--
			forwardData, err := json.Marshal(lsa)
			if err == nil {
				senderID := s.Conn().RemotePeer()
				// Forward over the same persistent per-peer LSA streams.
				// Done asynchronously so a single unreachable peer (whose Submit
				// may block on a reconnect timeout) cannot stall this handler's
				// ReadFrame loop and stop us processing other peers' LSA frames.
				for _, pID := range n.Host.Network().Peers() {
					if pID == n.Host.ID() || pID == senderID {
						continue
					}
					if n.isBootstrapPeer(pID) {
						continue
					}
					fwd := pID
					go func() {
						if !n.lsaPool.Submit(fwd, forwardData) {
							log.Debug("LSA forward to %s failed (unreachable)", fwd.String())
						}
					}()
				}
			}
		}
	}
}

// lsaSnapshotMaxAge bounds how long a cached third-party LSA is still worth
// replaying to a freshly connected peer. It matches the CleanStaleNodes(60s)
// liveness window used by the routing table, so we never hand out an entry the
// receiver would immediately purge as dead.
const lsaSnapshotMaxAge = 60 * time.Second

// cacheLSA stores a defensive copy of an accepted link-state payload keyed by
// its origin. The caller must pass the payload BEFORE any TTL mutation.
func (n *Node) cacheLSA(lsa *routing.LinkStatePayload) {
	origin, err := peer.Decode(lsa.Origin)
	if err != nil || origin == n.Host.ID() {
		return
	}
	// Deep-copy the maps: the caller's payload is decoded into a loop-local
	// variable that gets mutated (TTL--) and re-marshalled for forwarding.
	cp := *lsa
	if lsa.Neighbors != nil {
		cp.Neighbors = make(map[string]int64, len(lsa.Neighbors))
		for k, v := range lsa.Neighbors {
			cp.Neighbors[k] = v
		}
	}
	if lsa.NeighborClasses != nil {
		cp.NeighborClasses = make(map[string]int, len(lsa.NeighborClasses))
		for k, v := range lsa.NeighborClasses {
			cp.NeighborClasses[k] = v
		}
	}
	if lsa.AdvertisedSubnets != nil {
		cp.AdvertisedSubnets = append([]string(nil), lsa.AdvertisedSubnets...)
	}

	n.lsaCacheMu.Lock()
	n.lsaCache[origin] = &cp
	n.lsaCacheMu.Unlock()
}

// pushLSASnapshotToPeer replays every cached third-party LSA to a single peer.
//
// Why this exists: broadcastLSA only ever advertises OUR OWN links, and
// handleLSAStream only forwards an LSA when it CHANGED the local graph. In a
// steady-state mesh nothing changes, so a node that just joined received only
// our LSA — it learned our neighbours but nothing about links two or more hops
// away, leaving it with no next-hop for distant peers. Replaying the snapshot
// makes a peer converge on the full graph the moment it connects, which is what
// lets a node bootstrap the whole mesh through a single StaticPeer (no BOOT).
//
// Sequence numbers are replayed UNCHANGED: we are not the origin, so bumping
// them would poison the origin's sequence space and make its own future LSAs
// look stale. Unchanged sequences are also what makes this idempotent — a peer
// that already holds the entry rejects it in ProcessLSA and does not re-flood.
func (n *Node) pushLSASnapshotToPeer(target peer.ID) {
	if target == n.Host.ID() || n.isBootstrapPeer(target) {
		return // BOOT nodes do not serve the LSA protocol
	}

	n.lsaCacheMu.RLock()
	snapshot := make([]*routing.LinkStatePayload, 0, len(n.lsaCache))
	var expired []peer.ID
	cutoff := time.Now().Add(-lsaSnapshotMaxAge).Unix()
	for origin, lsa := range n.lsaCache {
		if lsa.Timestamp > 0 && lsa.Timestamp < cutoff {
			expired = append(expired, origin)
			continue
		}
		// Never echo a peer's own LSA back at it, and never replay the
		// snapshot's view of ourselves (broadcastLSA owns that).
		if origin == target {
			continue
		}
		snapshot = append(snapshot, lsa)
	}
	n.lsaCacheMu.RUnlock()

	if len(expired) > 0 {
		n.lsaCacheMu.Lock()
		for _, origin := range expired {
			if cached, ok := n.lsaCache[origin]; ok && cached.Timestamp < cutoff {
				delete(n.lsaCache, origin)
			}
		}
		n.lsaCacheMu.Unlock()
	}
	if len(snapshot) == 0 {
		return
	}

	sent := 0
	for _, lsa := range snapshot {
		// Refresh TTL so the snapshot can propagate onward from the receiver
		// (the cached copy may have arrived with an almost-exhausted TTL).
		replay := *lsa
		replay.TTL = routing.DefaultLSATTL
		data, err := json.Marshal(&replay)
		if err != nil {
			continue
		}
		if n.lsaPool.Submit(target, data) {
			n.recordPeerTxBytes(target, len(data))
			sent++
		}
	}
	if sent > 0 {
		log.Debug("LSA snapshot: replayed %d/%d cached origins to %s",
			sent, len(snapshot), target.String())
	}
}

func (n *Node) handleRelayStream(s network.Stream) {
	defer s.Close()
	remotePeer := s.Conn().RemotePeer()

	// Loop read: handle multiple relay frames on the same stream (consistent with handleStream)
	buf := make([]byte, obfuscate.MaxSealedFrameSize)
	for {
		readN, err := ReadFrame(s, buf)
		if err != nil || readN == 0 {
			break
		}
		if n.protoTracker != nil {
			n.protoTracker.RelayData.RecordRx(1, uint64(readN))
		}
		data := buf[:readN]

		// HOP-BY-HOP envelope decryption. The origin sealed the outer relay
		// frame with the cipher negotiated for THIS hop, so the relay decrypts
		// with the cipher for its immediate neighbor (remotePeer) — the same
		// shared ECDH key. If a cipher is negotiated but AEAD-open fails the
		// envelope is genuine ciphertext we cannot open: DROP it (garbage==true)
		// rather than letting it reach UnpackRelayFrame as garbage.
		if rdec, rdecOK, rgarbage := n.decryptPeerFrame(data, remotePeer); rgarbage {
			log.Debug("Rx: dropping undecryptable relay envelope from %s", remotePeer.String())
			n.recordPeerRxDecrypt(remotePeer, false)
			n.maybeResyncOnDecryptFail(remotePeer)
			continue
		} else if rdecOK {
			data = rdec
		}

		// ── Unwrap the obfuscate frame that CARRIES the relay envelope ──
		// The origin wraps every relay envelope in a p2ptap obfuscate frame (see
		// sealRelayEnvelopeForHop) so the envelope can be sealed hop-by-hop, and
		// the send path may additionally have fragmented that frame. Both layers
		// are peeled here to recover the bare envelope for UnpackRelayFrame.
		//
		// Two bugs are fixed relative to the previous version:
		//   1. It parsed the relay header from `data` (the still-wrapped frame)
		//      instead of the unpacked payload, so a correctly wrapped envelope
		//      could never be decoded.
		//   2. It did `continue` on ANY Unpack error, silently discarding every
		//      bare envelope. We now fall through and let UnpackRelayFrame try,
		//      which keeps interop with peers running an older build.
		envelope := data
		if _, outer, uerr := obfuscate.Unpack(data); uerr == nil {
			if n.fragRX != nil && isFragPayload(outer) {
				finalPacked, complete := n.fragRX.reassemble(remotePeer, outer)
				if !complete {
					continue // more fragments pending
				}
				// ── DECRYPT the reassembled inner frame BEFORE unpacking ──
				rfdec, rfdecOK, rfgarbage := n.decryptPeerFrame(finalPacked, remotePeer)
				if rfgarbage {
					log.Debug("Rx: dropping undecryptable reassembled relay envelope from %s", remotePeer.String())
					n.recordPeerRxDecrypt(remotePeer, false)
					n.maybeResyncOnDecryptFail(remotePeer)
					continue
				}
				if rfdecOK {
					finalPacked = rfdec
				}
				if _, reassembled, rerr := obfuscate.Unpack(finalPacked); rerr == nil {
					envelope = reassembled
				} else {
					envelope = finalPacked
				}
			} else {
				envelope = outer
			}
		} else {
			log.Debug("Relay frame from %s is not obfuscate-wrapped (%v); parsing it as a bare relay envelope",
				remotePeer.String(), uerr)
		}

		finalDst, srcPeer, ttl, innerPayload, err := routing.UnpackRelayFrame(envelope)
		if err != nil {
			log.Debug("Relay stream unpack error from %s: %v", remotePeer.String(), err)
			continue
		}
		// Return-path liveness signal: we just received a frame ORIGINATING at
		// srcPeer (even if we are merely forwarding it), so its return path to
		// us is currently alive. Recorded for the ping-pong probe's outbound-vs-
		// return distinction in an asymmetric-routing mesh.
		n.notePeerRx(srcPeer)
		// relayHopRx: the hop (remotePeer) itself just carried a frame to us. A
		// pure-forwarding hop is never srcPeer, so this is the only signal that
		// advances for it — relayStreamPool anchors its failure-streak clear on
		// this so a healthy-but-silent forwarder is not mis-blacklisted.
		if remotePeer != "" && remotePeer != srcPeer {
			n.noteRelayHopRx(remotePeer)
			n.recordPeekMapOrigin(srcPeer, remotePeer, 1, false)
		} else if remotePeer != "" {
			// Final hop where the carrier IS the origin: still counts as the hop
			// delivering to us.
			n.noteRelayHopRx(remotePeer)
		}
		if finalDst == n.Host.ID() {
			// Destination reached: the INNER payload is END-TO-END encrypted for
			// us (finalDst) by the origin (srcPeer), so decrypt it with the cipher
			// negotiated for srcPeer — NOT remotePeer (the relay hop).
			if cipher := n.obfDecryptCipherForPeer(srcPeer); cipher != nil {
				dec, derr := obfuscate.DecryptPayloadRegion(innerPayload, cipher)
				if derr != nil {
					log.Debug("Relayed frame decrypt error from origin %s (via %s): %v",
						srcPeer.String(), remotePeer.String(), derr)
					n.recordPeerRxDecrypt(srcPeer, false)
					continue
				}
				n.recordPeerRxDecrypt(srcPeer, true)
				n.maybeMarkReadyOnDecrypt(srcPeer, true)
				innerPayload = dec
			}

			// Unpack the (now decrypted) obfuscated frame back to raw Ethernet for TAP delivery.
			seqID, unpacked, uerr := obfuscate.Unpack(innerPayload)
			if uerr != nil {
				// The end-to-end decrypted inner payload did not yield a valid
				// obfuscate frame. This happens when the origin sent a malformed
				// frame or the shared (srcPeer ↔ us) cipher drifted. The payload is
				// either still-encrypted ciphertext or garbage — writing it into the
				// kernel TAP would inject corrupt packets onto the local LAN, so DROP
				// it. (Previously this fell through and wrote `innerPayload` raw.)
				log.Debug("Relay Unpack: err=%v, dropping undecodable inner payload len=%d from origin=%s (via %s)",
					uerr, len(innerPayload), srcPeer.String(), remotePeer.String())
				n.recordPeerRxDecrypt(srcPeer, false)
				continue
			}
			log.Debug("Relay Unpack: seq=%d payloadLen=%d innerLen=%d ttl=%d from=%s",
				seqID, len(unpacked), len(innerPayload), ttl, remotePeer.String())
			// Deliver through the shared relayed-frame TAP path (also used by the
			// boot-relay / relay-over-backbone downlink). Keyed on the TRUE origin
			// (srcPeer); remotePeer is the transport (via) peer.
			n.deliverRelayedFrameToTAP(unpacked, srcPeer, remotePeer, seqID)
			continue
		}

		// Destination is another peer: forward frame if TTL > 1
		if ttl > 1 {
			routes := n.getCachedRoutes()
			nextHop := finalDst
			if route, ok := routes[finalDst]; ok && route.NextHop != "" && route.NextHop != n.Host.ID() {
				nextHop = route.NextHop
			}
			// Loop guard: never hand the frame straight back to the peer that
			// just delivered it. That would form a 2-node relay cycle (bounded
			// only by TTL) that wastes bandwidth and delays delivery; if the
			// only route we know loops back to the sender, drop the frame and
			// let the source retransmit over a better path. A legitimate
			// single-hop delivery resolves to nextHop == finalDst (never the
			// sender), so this guard cannot suppress a correct forward.
			if nextHop == remotePeer {
				log.Debug("Relay forward to %s looped back to sender %s; dropping (ttl=%d)", finalDst.String(), remotePeer.String(), ttl)
				continue
			}

			// NOTE: a previous version short-circuited here when nextHop was
			// directly connected, handing innerPayload straight to
			// Dispatcher.SendToPeer(finalDst, ...). That path was doubly broken
			// and silently corrupted every frame it touched:
			//
			//  1. WRONG KEY OWNERSHIP. innerPayload is END-TO-END sealed with the
			//     cipher of the pair (srcPeer ↔ finalDst). Delivering it over our
			//     own direct stream makes finalDst's RX path treat US as the
			//     sender, so it opens the frame with the (us ↔ finalDst) cipher —
			//     a key that cannot possibly open it. Only the relay envelope
			//     carries srcPeer, which is exactly what finalDst needs to pick
			//     the right key (see the finalDst == n.Host.ID() branch above).
			//  2. DOUBLE ENCRYPTION. SendToPeer seals whatever it is given with
			//     the target's cipher, so the already-sealed inner frame got a
			//     second AEAD layer. finalDst peels exactly one, leaving
			//     ciphertext in the payload region; Unpack still succeeds (magic
			//     and length live in the cleartext header), so the garbage was
			//     written to the TAP device as if it were a valid Ethernet frame.
			//     No error was logged anywhere — the classic "link looks healthy
			//     but ping never replies" failure.
			//
			// Keeping the envelope is also not a performance loss: when
			// nextHop == finalDst the envelope is delivered in a single hop and
			// unwrapped by handleRelayStream on arrival.
			repacked, err := routing.PackRelayFrame(finalDst, srcPeer, ttl-1, innerPayload)
			if err == nil {
				// HOP-BY-HOP re-encryption: seal the forwarded envelope for the
				// NEXT hop, mirroring what the origin did for the first hop. The
				// relay never touches the inner frame (it stays end-to-end
				// encrypted for finalDst), only the outer envelope, so each hop
				// opens exactly the envelope addressed to it.
				//
				// This MUST go through sealRelayEnvelopeForHop: a bare relay
				// envelope is NOT an obfuscate frame, so calling
				// EncryptPayloadRegion on it directly (as this code used to)
				// reads the PayloadLen field out of the middle of the base58
				// destination PeerID and fails with ErrFrameCorrupted every
				// single time. The old `if eerr == nil` guard then swallowed that
				// error and forwarded the envelope in PLAINTEXT, which the hop
				// dropped at its AEAD gate. sealRelayEnvelopeForHop packs the
				// envelope into a real obfuscate frame first, and is shared with
				// the two origin-side call sites so the three paths cannot drift.
				sealed, serr := n.sealRelayEnvelopeForHop(nextHop, repacked)
				if serr != nil {
					log.Warn("Relay forward to %s via %s aborted: %v",
						finalDst.String(), nextHop.String(), serr)
					continue
				}
				// Use persistent relay pool instead of per-frame NewStream.
				// onSent=nil: forwarding does not double-count RecordSent (origin already counted).
				// onFail: silently drop; source will retransmit.
				n.relayPool.Submit(nextHop, sealed,
					nil, // onSent — no double-counting
					func() {
						log.Debug("Relay forward to %s via %s permanently failed",
							finalDst.String(), nextHop.String())
					},
				)
			}
		}
	}
}

// EchoProtocolID is a dedicated stream protocol for real end-to-end P2P echo testing.
const EchoProtocolID protocol.ID = "/p2ptap/echo/1.0.0"

// TapProbeAckProtocolID carries the peer-side TAP-probe acknowledgement (方案 B).
// When a node receives a TAP-forward probe request frame at its TAP write
// boundary, it opens this control stream back to the prober (through relay-ctrl /
// boot-circuit when needed) to confirm the frame physically reached the peer's
// TAP — distinguishing "arrived but OS didn't answer" from "never arrived"
// without logging onto the peer machine.
const TapProbeAckProtocolID protocol.ID = "/p2ptap/tapprobe-ack/1.0.0"

// handleEcho responds to P2P echo probe streams by echoing back the exact payload
// of each length-prefixed frame. It loops over ReadFrame so a single long-lived
// echo stream can serve many periodic probes (the client reuses the same stream
// via echoPool instead of opening a fresh NewStream every tick).
func (n *Node) handleEcho(s network.Stream) {
	defer s.Close()
	buf := make([]byte, obfuscate.MaxFrameSize)
	for {
		rn, err := ReadFrame(s, buf)
		if err != nil {
			if err != io.EOF {
				log.Debug("Echo stream read error from %s: %v", s.Conn().RemotePeer().String(), err)
			}
			return
		}
		if rn == 0 {
			continue
		}
		if n.protoTracker != nil {
			n.protoTracker.Echo.RecordRx(1, uint64(rn))
		}
		// Echo the exact payload bytes back as a length-prefixed frame.
		if err := WriteFrame(s, buf[:rn]); err != nil {
			return
		}
		if n.protoTracker != nil {
			n.protoTracker.Echo.RecordTx(1, uint64(rn))
		}
	}
}

// tapProbeAckMagic marks the embedded payload of a TAP-probe request frame and
// the control-plane ack so we can tell a genuine probe from stray ICMP traffic.
const tapProbeAckMagic uint16 = 0x5A51

// isTapProbeRequest inspects an inbound TAP payload and, if it is a TAP-forward
// probe request (real ICMP echo request carrying our marker id), returns the
// prober's peer ID and the per-probe token embedded in the ICMP payload. The
// prober stamps both so the peer can route the ack back to the right origin
// even when the probe was relayed (the immediate remotePeer would then be the
// relay hop, not the prober).
func (n *Node) isTapProbeRequest(payload []byte) (peer.ID, uint64, bool) {
	if len(payload) < 42 {
		return "", 0, false
	}
	if binary.BigEndian.Uint16(payload[12:14]) != 0x0800 { // IPv4
		return "", 0, false
	}
	ihl := int(payload[14]&0x0f) * 4
	if ihl < 20 || len(payload) < 14+ihl+8 {
		return "", 0, false
	}
	if payload[14+9] != 1 { // ICMP
		return "", 0, false
	}
	icmpStart := 14 + ihl
	if payload[icmpStart] != 8 { // echo request
		return "", 0, false
	}
	if binary.BigEndian.Uint16(payload[icmpStart+4:icmpStart+6]) != tapProbeICMPIdentify {
		return "", 0, false
	}
	icmpPayload := payload[icmpStart+8:]
	if len(icmpPayload) < 3+8 {
		return "", 0, false
	}
	if binary.BigEndian.Uint16(icmpPayload[0:2]) != tapProbeAckMagic {
		return "", 0, false
	}
	pidLen := int(icmpPayload[2])
	if pidLen <= 0 || len(icmpPayload) < 3+pidLen+8 {
		return "", 0, false
	}
	pid := peer.ID(icmpPayload[3 : 3+pidLen])
	if pid == "" {
		return "", 0, false
	}
	tok := binary.BigEndian.Uint64(icmpPayload[3+pidLen : 3+pidLen+8])
	return pid, tok, true
}

// deferredProbeAck is a probe request detected on the RX path whose ack is
// HELD until the frame has been written into the local TAP device. Acking
// before the TAP write made "reached peer TAP" a lie whenever the write
// failed (TAP down, oversized frame) or the frame was destined to an IP we
// no longer own (stale prober metadata) — both looked identical to "peer OS
// firewall blocked ICMP" on the prober side.
type deferredProbeAck struct {
	prober peer.ID
	token  uint64
	flag   uint8 // tapProbeAckFlag* diagnostic
}

// sendTapProbeAck fires the peer-side acknowledgement for a received TAP-forward
// probe request. It runs in its own goroutine (off the receive loop) and opens a
// control stream back to the prober via openControlStream, which transparently
// tunnels through relay-ctrl / boot-circuit when the prober is relay-only — so
// the ack reaches the prober even on a fully relayed mesh. The ack carries the
// prober-supplied token it matches against its in-flight probe, plus the
// dst-IP-match diagnostic flag for the prober's failure message.
func (n *Node) sendTapProbeAck(prober peer.ID, tok uint64, flag uint8) {
	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	defer cancel()
	s, err := n.openControlStream(ctx, prober, TapProbeAckProtocolID)
	if err != nil {
		log.Debug("tapProbeAck: open control stream to %s: %v", prober, err)
		return
	}
	defer s.Close()
	buf := make([]byte, 2+8+1)
	binary.BigEndian.PutUint16(buf[0:2], tapProbeAckMagic)
	binary.BigEndian.PutUint64(buf[2:10], tok)
	buf[10] = flag
	if err := WriteFrame(s, buf); err != nil {
		log.Debug("tapProbeAck: write to %s: %v", prober, err)
	}
}

// queueDeferredProbeAck parks a pending probe ack until the frame's TAP write
// succeeds. The queue is tiny and consumed by the same receive-loop iteration
// that wrote the frame, so it never grows beyond one entry per in-flight probe.
func (n *Node) queueDeferredProbeAck(d deferredProbeAck) {
	n.deferredProbeAcksMu.Lock()
	n.deferredProbeAcks = append(n.deferredProbeAcks, d)
	n.deferredProbeAcksMu.Unlock()
}

// takeDeferredProbeAcks drains and returns acks queued for the frame that was
// just written into the TAP device (called only on write success).
func (n *Node) takeDeferredProbeAcks() []deferredProbeAck {
	n.deferredProbeAcksMu.Lock()
	defer n.deferredProbeAcksMu.Unlock()
	if len(n.deferredProbeAcks) == 0 {
		return nil
	}
	out := n.deferredProbeAcks
	n.deferredProbeAcks = nil
	return out
}

// sendTapProbeAckAfterTAP queues the ack so it is sent only if/when the frame
// is written into the TAP device. This shim keeps the detect site (RX loop)
// free of locking concerns.
func (n *Node) sendTapProbeAckAfterTAP(prober peer.ID, tok uint64, flag uint8) {
	n.queueDeferredProbeAck(deferredProbeAck{prober: prober, token: tok, flag: flag})
}

// handleTapProbeAck is the TapProbeAckProtocolID stream handler on the PROBER
// side. It reads the peer-supplied token and, if it matches the in-flight probe
// token, signals probeAckCh with the peer's dst-IP-match diagnostic flag so
// ProbeTapForward can report WHY the peer OS did not answer (stale metadata vs
// firewall). Token matching discards stale acks from a previous probe that may
// still be in flight. Backward compatible: a peer running an older build sends
// a 10-byte frame with no flag byte, which decodes as tapProbeAckFlagUnknown.
func (n *Node) handleTapProbeAck(s network.Stream) {
	defer s.Close()
	buf := make([]byte, 64)
	rn, err := ReadFrame(s, buf)
	if err != nil || rn < 10 {
		return
	}
	if binary.BigEndian.Uint16(buf[0:2]) != tapProbeAckMagic {
		return
	}
	tok := binary.BigEndian.Uint64(buf[2:10])
	if tok != atomic.LoadUint64(&n.probeAckToken) {
		return
	}
	flag := uint8(tapProbeAckFlagUnknown)
	if rn >= 11 {
		flag = buf[10]
	}
	select {
	case n.probeAckCh <- flag:
	default:
	}
}

// ProbePeerEcho executes a real end-to-end P2P echo test over a dedicated libp2p stream.
// Sends random payload, measures round-trip time, and verifies payload byte integrity.
func (n *Node) ProbePeerEcho(targetStr string) *observer.PeerEchoResultDTO {
	res := &observer.PeerEchoResultDTO{
		PeerID:    targetStr,
		Timestamp: time.Now(),
	}

	var pid peer.ID
	var targetPeerInfo *observer.PeerInfoDTO

	// Resolve target (PeerID, TAP IP, or Node Name)
	decodedPID, err := peer.Decode(targetStr)
	if err == nil {
		pid = decodedPID
	} else if n.Collector != nil {
		for _, p := range n.getActivePeers() {
			if p.PeerID == targetStr || p.TapIP == targetStr || p.TapIPv6 == targetStr || strings.EqualFold(p.NodeName, targetStr) {
				if parsed, err := peer.Decode(p.PeerID); err == nil {
					pid = parsed
					targetPeerInfo = &p
					break
				}
			}
		}
	}

	if pid == "" {
		res.Error = fmt.Sprintf("cannot resolve target '%s' to a connected peer ID", targetStr)
		return res
	}

	if targetPeerInfo != nil {
		res.NodeName = targetPeerInfo.NodeName
		res.PeerID = targetPeerInfo.PeerID
	}

	// Generate 32 bytes of random test payload
	sentPayload := make([]byte, 32)
	_, _ = rand.Read(sentPayload)
	res.BytesSent = len(sentPayload)

	ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	defer cancel()

	streamCtx := network.WithAllowLimitedConn(ctx, "echo-probe")
	s, err := n.Host.NewStream(streamCtx, pid, EchoProtocolID)
	if err != nil {
		res.Error = fmt.Sprintf("failed to open echo stream to %s: %v", pid.String(), err)
		return res
	}
	defer s.Close()

	// Start the RTT timer AFTER the stream is established so the reported
	// latency reflects only the data-plane echo round-trip. Measuring from
	// before NewStream would also include the libp2p handshake (and any
	// hole-punch / relay-circuit negotiation), making cold-path RTT meaningless
	// and inconsistent with ProbePeerEchoAddr, which already times from here.
	start := time.Now()

	if s.Conn() != nil {
		remoteAddr := s.Conn().RemoteMultiaddr().String()
		res.TransportAddr = remoteAddr
		res.IsRelayed = strings.Contains(remoteAddr, "/p2p-circuit")
	}

	_ = s.SetDeadline(time.Now().Add(4 * time.Second))

	// Send echo payload as a length-prefixed frame (matches handleEcho's ReadFrame loop).
	if err := WriteFrame(s, sentPayload); err != nil {
		res.Error = fmt.Sprintf("echo write failed: %v", err)
		return res
	}

	// Read echoed frame back
	recvBuf := make([]byte, 1024)
	readN, err := ReadFrame(s, recvBuf)
	rttDuration := time.Since(start)

	res.RTTMs = float64(rttDuration.Microseconds()) / 1000.0 // high precision in ms
	res.BytesRecv = readN

	if err != nil && err != io.EOF {
		res.Error = fmt.Sprintf("echo read error: %v", err)
		return res
	}

	if readN == len(sentPayload) && bytes.Equal(sentPayload, recvBuf[:readN]) {
		res.PayloadMatched = true
		res.Success = true
		res.Error = ""
	} else {
		res.Error = fmt.Sprintf("payload mismatch: sent %d bytes, received %d bytes", len(sentPayload), readN)
	}

	return res
}

// ProbePeerEchoAddr executes a targeted P2P stream echo test over a specific multiaddr path.
//
// CRITICAL: libp2p's Host.NewStream will reuse ANY existing connection to the
// peer if one is alive, regardless of what the peerstore currently contains —
// the peerstore only feeds DialPeer when no live conn exists. This means a
// caller asking us to "test echo over /ip4/X:41756/quic-v1" may silently get a
// stream opened over the peer's pre-existing circuit-relay connection (or a
// different direct transport), returning a 5 ms RTT that doesn't actually
// exercise the requested path. To make the diagnostic honest we (a) fail fast
// when the requested multiaddr is not reachable (Connect must succeed before
// we trust NewStream) and (b) verify, after NewStream, that the resulting
// stream's RemoteMultiaddr matches the requested multiaddr (prefix match to
// tolerate libp2p's trailing `/p2p/<peerID>` suffix). If it doesn't match we
// return success=false with a clear error so the WebUI shows the discrepancy
// instead of a misleading "Echo SUCCESS! 5 ms" toast.
func (n *Node) ProbePeerEchoAddr(targetStr string, targetAddrStr string) *observer.PeerEchoResultDTO {
	if targetAddrStr == "" {
		return n.ProbePeerEcho(targetStr)
	}

	res := &observer.PeerEchoResultDTO{
		PeerID:        targetStr,
		RequestedAddr: targetAddrStr, // surface what was asked for even on error paths
		Timestamp:     time.Now(),
	}

	var pid peer.ID
	decodedPID, err := peer.Decode(targetStr)
	if err == nil {
		pid = decodedPID
	} else if n.Collector != nil {
		for _, p := range n.getActivePeers() {
			if p.PeerID == targetStr || p.TapIP == targetStr || p.TapIPv6 == targetStr || strings.EqualFold(p.NodeName, targetStr) {
				if parsed, err := peer.Decode(p.PeerID); err == nil {
					pid = parsed
					res.NodeName = p.NodeName
					res.PeerID = p.PeerID
					break
				}
			}
		}
	}

	if pid == "" {
		res.Error = fmt.Sprintf("cannot resolve target '%s'", targetStr)
		return res
	}

	targetMA, err := multiaddr.NewMultiaddr(targetAddrStr)
	if err != nil {
		res.Error = fmt.Sprintf("invalid multiaddr '%s': %v", targetAddrStr, err)
		return res
	}

	// Force a fresh dial of the explicit target multiaddr: clear any dial
	// backoff so the attempt isn't suppressed, then temporarily scope the
	// peer's address book to targetMA so the subsequent NewStream exercises
	// exactly this path. We restore the original address set in a defer so this
	// diagnostic NEVER permanently destroys the peer's other (possibly
	// better/direct) addresses or its live relay path — the old code's
	// ClearAddrs-without-restore could downgrade routing until rediscovery.
	savedAddrs := n.Host.Peerstore().Addrs(pid)
	n.clearSwarmBackoff(pid)
	n.Host.Peerstore().ClearAddrs(pid)
	n.Host.Peerstore().AddAddr(pid, targetMA, 2*time.Hour)
	defer func() {
		n.Host.Peerstore().ClearAddrs(pid)
		for _, a := range savedAddrs {
			n.Host.Peerstore().AddAddr(pid, a, 2*time.Hour)
		}
	}()

	ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	defer cancel()

	// (a) Fail fast when the requested multiaddr is not reachable. Without
	// this, NewStream would silently fall back to a pre-existing connection
	// (e.g. a circuit relay) and report a meaningless "success" with the
	// wrong transport's RTT.
	if cerr := n.Host.Connect(ctx, peer.AddrInfo{ID: pid, Addrs: []multiaddr.Multiaddr{targetMA}}); cerr != nil {
		res.TransportAddr = targetMA.String()
		res.Error = fmt.Sprintf("requested multiaddr %s is not currently reachable: %v — the peer is not answering on that pathway (likely dial timeout, refusing connection, or wrong transport); the most-recent successful probe was via a different connection, not this one", targetAddrStr, cerr)
		return res
	}

	streamCtx := network.WithAllowLimitedConn(ctx, "echo-probe")
	s, err := n.Host.NewStream(streamCtx, pid, EchoProtocolID)
	if err != nil {
		res.Error = fmt.Sprintf("failed to open echo stream to %s via %s: %v", pid.String(), targetAddrStr, err)
		return res
	}
	defer s.Close()

	// (b) Defence in depth: even with Connect succeeding above, NewStream
	// can reuse a previously established connection that is NOT over
	// targetMA. Compare prefixes so libp2p's trailing `/p2p/<peerID>`
	// suffix (which it always appends to RemoteMultiaddr) is allowed.
	actualAddr := targetAddrStr
	if s.Conn() != nil {
		actualAddr = s.Conn().RemoteMultiaddr().String()
	}
	if !strings.HasPrefix(actualAddr, targetMA.String()+"/") {
		res.TransportAddr = actualAddr
		res.Success = false
		res.PayloadMatched = false
		res.Error = fmt.Sprintf("echo stream was opened over a DIFFERENT transport than the requested multiaddr: requested <%s>, actually used <%s>; the RTT below is for the OTHER transport and is NOT a measurement of the path you were probing", targetAddrStr, actualAddr)
		return res
	}
	res.TransportAddr = actualAddr
	res.IsRelayed = strings.Contains(actualAddr, "/p2p-circuit")

	sentPayload := make([]byte, 32)
	_, _ = rand.Read(sentPayload)
	res.BytesSent = len(sentPayload)

	_ = s.SetDeadline(time.Now().Add(4 * time.Second))
	start := time.Now()
	// Send echo payload as a length-prefixed frame (matches handleEcho's ReadFrame loop).
	if err := WriteFrame(s, sentPayload); err != nil {
		res.Error = fmt.Sprintf("echo write error: %v", err)
		return res
	}

	recvBuf := make([]byte, 1024)
	readN, err := ReadFrame(s, recvBuf)
	elapsed := time.Since(start)

	res.RTTMs = float64(elapsed.Microseconds()) / 1000.0
	res.BytesRecv = readN

	if err != nil && err != io.EOF {
		res.Error = fmt.Sprintf("echo read error: %v", err)
		return res
	}

	if readN == len(sentPayload) && bytes.Equal(sentPayload, recvBuf[:readN]) {
		res.PayloadMatched = true
		res.Success = true
		res.Error = ""

		// Aggressive Promotion: record latency in libp2p Peerstore and update router path.
		// Use UpdateLinkRTT so the edge's transport class (direct vs circuit) is
		// preserved — a re-measured RTT must not silently re-classify a circuit
		// relay as direct.
		n.Host.Peerstore().RecordLatency(pid, elapsed)
		if res.RTTMs > 0 {
			n.Router.UpdateLinkRTT(pid, int64(res.RTTMs))
		}
	} else {
		res.Error = fmt.Sprintf("payload mismatch: sent %d, got %d", len(sentPayload), readN)
	}

	return res
}

// ProbePeerSpeedTest executes a real multi-burst throughput and latency benchmark
// over an end-to-end stream to the specified peer.
// Transmits real bursts of payload data, measures actual transfer time and bytes,
// and computes genuine Mbps throughput, RTT metrics, jitter, and loss.
func (n *Node) ProbePeerSpeedTest(targetStr string) *observer.SpeedTestResultDTO {
	res := &observer.SpeedTestResultDTO{
		PeerID: targetStr,
	}

	var pid peer.ID
	var targetPeerInfo *observer.PeerInfoDTO

	// Resolve target (PeerID, TAP IP, or Node Name)
	decodedPID, err := peer.Decode(targetStr)
	if err == nil {
		pid = decodedPID
	} else if n.Collector != nil {
		for _, p := range n.getActivePeers() {
			pTapIP := strings.Split(p.TapIP, "/")[0]
			pTapIPv6 := strings.Split(p.TapIPv6, "/")[0]
			if p.PeerID == targetStr || pTapIP == targetStr || pTapIPv6 == targetStr || strings.EqualFold(p.NodeName, targetStr) {
				if parsed, err := peer.Decode(p.PeerID); err == nil {
					pid = parsed
					targetPeerInfo = &p
					break
				}
			}
		}
	}

	if pid == "" {
		res.QualityGrade = "UNREACHABLE"
		res.MeasurementNote = fmt.Sprintf("cannot resolve target '%s' to a connected peer ID", targetStr)
		res.PacketLoss = 1.0
		return res
	}

	if targetPeerInfo != nil {
		res.NodeName = targetPeerInfo.NodeName
		res.PeerID = targetPeerInfo.PeerID
		res.IsRelayed = targetPeerInfo.IsRelayed
	}

	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	defer cancel()

	streamCtx := network.WithAllowLimitedConn(ctx, "speedtest-probe")
	s, err := n.Host.NewStream(streamCtx, pid, EchoProtocolID)
	if err != nil {
		res.QualityGrade = "UNREACHABLE"
		res.MeasurementNote = fmt.Sprintf("failed to open benchmark stream to %s: %v", pid.String(), err)
		res.PacketLoss = 1.0
		return res
	}
	defer s.Close()

	if s.Conn() != nil {
		remoteAddr := s.Conn().RemoteMultiaddr().String()
		res.IsRelayed = strings.Contains(remoteAddr, "/p2p-circuit")
	}

	_ = s.SetDeadline(time.Now().Add(8 * time.Second))

	// Benchmark configuration: 5 bursts of 32KB payload = 160 KB payload data (320 KB roundtrip)
	const (
		numBursts = 5
		burstSize = 32 * 1024 // 32 KB per burst
	)

	testPayload := make([]byte, burstSize)
	for i := range testPayload {
		testPayload[i] = byte(i % 251)
	}

	recvBuf := make([]byte, burstSize+1024)
	rtts := make([]float64, 0, numBursts)
	var totalBytesTransferred int64
	var totalElapsed time.Duration
	successCount := 0

	for i := 0; i < numBursts; i++ {
		start := time.Now()
		if err := WriteFrame(s, testPayload); err != nil {
			break
		}
		readN, err := ReadFrame(s, recvBuf)
		elapsed := time.Since(start)
		if err != nil || readN != burstSize {
			break
		}
		rttMs := float64(elapsed.Microseconds()) / 1000.0
		rtts = append(rtts, rttMs)
		totalElapsed += elapsed
		totalBytesTransferred += int64(burstSize * 2) // Tx + Rx
		successCount++
	}

	if successCount == 0 {
		res.QualityGrade = "FAILED"
		res.MeasurementNote = "Stream established but data transfer timed out or failed"
		res.PacketLoss = 1.0
		return res
	}

	// Calculate RTT metrics
	minRTT := rtts[0]
	maxRTT := rtts[0]
	sumRTT := 0.0
	for _, r := range rtts {
		if r < minRTT {
			minRTT = r
		}
		if r > maxRTT {
			maxRTT = r
		}
		sumRTT += r
	}
	avgRTT := sumRTT / float64(len(rtts))

	// Jitter calculation (mean deviation)
	jitterSum := 0.0
	for i := 1; i < len(rtts); i++ {
		diff := rtts[i] - rtts[i-1]
		if diff < 0 {
			diff = -diff
		}
		jitterSum += diff
	}
	jitter := 0.0
	if len(rtts) > 1 {
		jitter = jitterSum / float64(len(rtts)-1)
	}

	loss := float64(numBursts-successCount) / float64(numBursts)

	// Calculate real measured Mbps: (total bits) / (total seconds) / 1,000,000
	var mbps float64
	if totalElapsed.Seconds() > 0 {
		mbps = float64(totalBytesTransferred*8) / (totalElapsed.Seconds() * 1_000_000.0)
	}

	// Round values for clean display
	res.Mbps = math.Round(mbps*100) / 100.0
	res.RTTMin = math.Round(minRTT*10) / 10.0
	res.RTTAvg = math.Round(avgRTT*10) / 10.0
	res.RTTMax = math.Round(maxRTT*10) / 10.0
	res.Jitter = math.Round(jitter*10) / 10.0
	res.PacketLoss = math.Round(loss*100) / 100.0

	// Quality rating based on real metrics
	switch {
	case loss > 0.3:
		res.QualityGrade = "POOR (High Packet Loss)"
	case res.IsRelayed && avgRTT > 100:
		res.QualityGrade = "FAIR (High Latency Relay Link)"
	case res.IsRelayed:
		res.QualityGrade = "GOOD (Circuit Relay Link)"
	case avgRTT > 100:
		res.QualityGrade = "FAIR (High Latency Direct Link)"
	case avgRTT > 40:
		res.QualityGrade = "GOOD (Direct P2P Link)"
	default:
		res.QualityGrade = "EXCELLENT (Ultra-Low Latency P2P)"
	}

	res.MeasurementNote = fmt.Sprintf("Real stream benchmark: %d KB transferred in %d ms (%d/%d bursts ok)",
		totalBytesTransferred/1024, totalElapsed.Milliseconds(), successCount, numBursts)

	return res
}

// isFrameFromPeerSelf returns true if an inbound Ethernet frame's source IP
// corresponds directly to the peer's own virtual TAP IP or ARP sender IP,
// rather than forwarded LAN / NAT traffic from behind an exit node / gateway router.
func (n *Node) isFrameFromPeerSelf(p peer.ID, frame []byte) bool {
	if len(frame) < 14 {
		return false
	}
	val, ok := n.peerMeta.Load(p)
	if !ok {
		return true
	}
	meta := val.(PeerMeta)
	peerTapIP := strings.Split(meta.TapIP, "/")[0]
	peerTapIPv6 := strings.Split(meta.TapIPv6, "/")[0]

	etherType := uint16(frame[12])<<8 | uint16(frame[13])
	if etherType == 0x0800 && len(frame) >= 34 { // IPv4
		srcIP := net.IP(frame[26:30]).String()
		if peerTapIP != "" && srcIP == peerTapIP {
			return true
		}
		if meta.IsExitNode || (peerTapIP != "" && srcIP != peerTapIP) {
			return false
		}
	} else if etherType == 0x86dd && len(frame) >= 54 { // IPv6
		srcIP := net.IP(frame[22:38]).String()
		if peerTapIPv6 != "" && srcIP == peerTapIPv6 {
			return true
		}
		if meta.IsExitNode || (peerTapIPv6 != "" && srcIP != peerTapIPv6) {
			return false
		}
	} else if etherType == 0x0806 && len(frame) >= 42 { // ARP
		arpSenderIP := net.IP(frame[28:32]).String()
		if peerTapIP != "" && arpSenderIP == peerTapIP {
			return true
		}
	}
	return true
}
