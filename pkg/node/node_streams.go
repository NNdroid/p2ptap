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
	manet "github.com/multiformats/go-multiaddr/net"

	"p2ptap/pkg/maddrutil"
	"p2ptap/pkg/mux"
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
// isLocalSubnetIP reports whether dstIP is for THIS node or for a host on the
// LAN this node fronts — i.e. a destination that must be rewritten to localMAC
// so the kernel accepts it. It is deliberately narrower than isMeshLocalIP:
// that one also covers 169.254/16, 255.255.255.255, group addresses and any IP
// another mesh peer owns, all of which are mesh destinations and must NOT be
// pulled into our own TAP. isLocalSubnetIP covers only the addresses we are
// responsible for answering to.
func (n *Node) isLocalSubnetIP(dstIP net.IP) bool {
	if dstIP == nil {
		return false
	}
	if ip4 := dstIP.To4(); ip4 != nil {
		if n.localV4IP != nil && dstIP.Equal(n.localV4IP) {
			return true
		}
		if n.localV4Net != nil && n.localV4Net.Contains(ip4) {
			return true
		}
		return n.isLocalAdvertisedSubnet(dstIP)
	}
	if n.localV6IP != nil && dstIP.Equal(n.localV6IP) {
		return true
	}
	if n.localV6Net != nil && n.localV6Net.Contains(dstIP) {
		return true
	}
	return n.isLocalAdvertisedSubnet(dstIP)
}

// rewriteDstMACForExit picks the MAC a transit frame must be rewritten to while
// Exit Node is configured, falling back to localMAC when no Exit peer MAC is
// known (which is also the correct answer when we ARE the Exit server).
func (n *Node) rewriteDstMACForExit(payload []byte, exitConfigured bool) {
	exitMAC := n.localMAC
	if !exitConfigured {
		exitMAC = n.getExitPeerMAC()
		if len(exitMAC) != 6 {
			exitMAC = n.localMAC
		}
	}
	if len(exitMAC) == 6 && !bytes.Equal(payload[0:6], exitMAC) {
		copy(payload[0:6], exitMAC)
	}
}

func (n *Node) rewriteRxDstMAC(payload []byte) {
	if len(payload) < 34 || len(n.localMAC) != 6 {
		return
	}
	// Snapshot the mutable config once so the two IPv4/IPv6 exit-transit checks
	// below observe one consistent reload (a mid-frame swap must not tear them).
	c := n.config()
	exitConfigured := c != nil && c.ExitNode.Enable
	exitOn := n.isExitNodeActive() || exitConfigured

	if ethType := binary.BigEndian.Uint16(payload[12:14]); ethType == packet.EtherTypeIPv4 || ethType == packet.EtherTypeARP {
		// ARP carries its target at offset 38 with no 20-byte IP header in
		// front; a reply echoes the requester's address there, so target == our
		// IP means the reply is for us.
		var dstIP net.IP
		if ethType == packet.EtherTypeARP {
			if len(payload) < 42 {
				return
			}
			dstIP = net.IP(payload[38:42])
		} else {
			dstIP = net.IP(payload[30:34])
		}
		if dstIP == nil {
			return
		}
		kind := "IPv4"
		if ethType == packet.EtherTypeARP {
			kind = "ARP"
		}
		if n.isLocalSubnetIP(dstIP) {
			if !bytes.Equal(payload[0:6], n.localMAC) && !(ethType == packet.EtherTypeARP && isBroadcastOrMulticastMAC(payload[0:6])) {
				// Guarded: the args render an IP and two MACs, and this runs on
				// every locally-destined frame of a LAN-gateway node.
				if log.IsDebug() {
					log.Debug("MAC rewrite %s (local dst / subnet): dstIP=%s oldDstMAC=%s newDstMAC=%s", kind, dstIP.String(), net.HardwareAddr(payload[0:6]).String(), net.HardwareAddr(n.localMAC).String())
				}
				copy(payload[0:6], n.localMAC)
			}
			return
		}
		// isMeshLocalIP, not the old ad-hoc "no peer owns this IP" test: that
		// test handed 169.254/16, 255.255.255.255 and every group address to the
		// Exit Node whenever one was active, so a pre-DHCP link-local host and a
		// DHCP unicast-broadcast reply were pulled out of the mesh entirely.
		// Frames to another peer's TAP IP are handled first by the MAC table
		// lookup above, so nothing that belongs to a peer is ever Exit-hijacked.
		if exitOn && !n.isMeshLocalIP(dstIP) {
			// Guarded: on an Exit Node this branch is every frame heading outside
			// the mesh, and the args render an IP and two MACs per call.
			if log.IsDebug() {
				log.Debug("MAC rewrite %s (exit transit): dstIP=%s oldDstMAC=%s newDstMAC=%s", kind, dstIP.String(), net.HardwareAddr(payload[0:6]).String(), net.HardwareAddr(n.localMAC).String())
			}
			n.rewriteDstMACForExit(payload, exitConfigured)
		}
		return
	}

	if binary.BigEndian.Uint16(payload[12:14]) == packet.EtherTypeIPv6 && len(payload) >= 54 {
		dstIP := net.IP(payload[38:54])
		if n.isLocalSubnetIP(dstIP) {
			if !bytes.Equal(payload[0:6], n.localMAC) {
				// Guarded: same per-frame cost as the IPv4 twin above.
				if log.IsDebug() {
					log.Debug("MAC rewrite IPv6 (local dst / subnet): dstIP=%s oldDstMAC=%s newDstMAC=%s", dstIP.String(), net.HardwareAddr(payload[0:6]).String(), net.HardwareAddr(n.localMAC).String())
				}
				copy(payload[0:6], n.localMAC)
			}
			return
		}
		if exitOn && !n.isMeshLocalIP(dstIP) {
			if log.IsDebug() {
				log.Debug("MAC rewrite IPv6 (exit transit): dstIP=%s oldDstMAC=%s newDstMAC=%s", dstIP.String(), net.HardwareAddr(payload[0:6]).String(), net.HardwareAddr(n.localMAC).String())
			}
			n.rewriteDstMACForExit(payload, exitConfigured)
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
	// Per-stream decrypt scratch: the per-peer plaintext is decrypted into this
	// buffer (rebased to its grown form after each decrypt) so steady-state
	// frames cost ZERO allocations instead of ~1.3KB/2 allocs each. Sized for
	// jumbo frames; append grows it once if ever exceeded. Same lifetime rules
	// as `buf`: the decrypted bytes are dead when the iteration ends (every
	// consumer is synchronous or copies — frag reassembly copies its chunks).
	decScratch := make([]byte, 0, 9600)
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

		// Zero-length frames indicate a broken or half-closed stream: ReadFrame
		// returned no data but no error either. Without this check the loop would
		// spin at 100% CPU on a peer that keeps the stream open but sends nothing.
		if readN == 0 {
			log.Warn("Stream zero-length read from peer %s after %d frames; resetting stream", remotePeer.String(), frameCount)
			_ = s.Reset()
			break
		}

		if n.protoTracker != nil {
			n.protoTracker.Data.RecordRx(1, uint64(readN))
		}
		// Return-path liveness: an inbound frame directly from remotePeer proves
		// its return path is alive. Annotate the transport too, so the WebUI can
		// show WHICH of possibly-several live connections carried it back.
		n.notePeerRxTransport(remotePeer, transportLabelForConn(s.Conn()), "")

		// PERF: per-frame path. peer.String() is base58 (~930ns, 2 allocs) and
		// is evaluated at the call site regardless of log level, so guard it.
		if log.IsDebug() {
			log.Debug("Rx raw frame: len=%d from peer=%s", readN, remotePeer.String())
		}

		frameData := buf[:readN]

		// CONCURRENCY CONTRACT: `frameData` (== buf[:readN]) belongs exclusively
		// to this stream-reader goroutine and may be mutated in place by the
		// MAC-rewrite paths in handleDirectFrame. Safe because enqueueTapWrite
		// copies the payload into a pooled buffer before returning.
		n.handleDirectFrame(remotePeer, frameData, &decScratch, transportName)
		frameCount++

	}
}

// handleDirectFrame processes one inbound VTP frame from a directly connected
// peer: decrypt -> unpack -> fragment reassembly -> dedup -> ACL -> MAC
// learning -> TAP write. Shared by the legacy per-peer data stream
// (handleStream) and the unified mux data channel (handleDataMuxVTP) so the
// two RX paths cannot drift.
//
// pathKey is the transport key of the stream the frame arrived on (used for
// per-path receive attribution). frameData may be mutated in place by the
// MAC-rewrite paths below, so it must belong exclusively to the calling
// goroutine: for handleStream that is the per-stream read buffer, for the mux
// path it is a private per-frame copy.
//
// decScratch is the caller's reusable decrypt scratch, rebased on each call so
// steady-state frames allocate nothing. It must not escape the call.
func (n *Node) handleDirectFrame(remotePeer peer.ID, frameData []byte, decScratch *[]byte, pathKey string) {

	if len(frameData) < obfuscate.HeaderLen {
		// PERF: malformed-traffic path — every junk frame lands here, so
		// keep the base58 peer.String() behind the level check.
		if log.IsDebug() {
			log.Debug("Short frame (%d bytes) from peer %s, skipping", len(frameData), remotePeer.String())
		}
		return
	}

	// ── Per-peer payload DECRYPTION happens FIRST (v2 obfuscation) ──
	// decryptPeerFrame returns (plaintext, decrypted, garbage). garbage==true
	// means a cipher was negotiated but AEAD-open failed: the bytes are
	// ciphertext we cannot open, so DROP them — never forward to the TAP. A
	// successful decrypt replaces frameData with the plaintext; the no-cipher
	// case leaves frameData unchanged (legitimate plaintext). The plaintext
	// lands in decScratch (rebased) — zero alloc in steady state.
	dec, decOK, garbage := n.decryptPeerFrame(*decScratch, frameData, remotePeer)
	if garbage {
		// PERF: hit on EVERY frame during a key-divergence storm — keep guarded.
		if log.IsDebug() {
			log.Debug("Rx: dropping undecryptable ciphertext frame from %s", remotePeer.String())
		}
		n.recordPeerRxDecrypt(remotePeer, false)
		// Self-heal: if this keeps failing, re-run SeqSync to re-anchor keys.
		n.maybeResyncOnDecryptFail(remotePeer)
		return
	}
	if decOK {
		frameData = dec
		*decScratch = dec
	}

	// PSK-required fail-closed (RX twin of canEgressToPeer): a plaintext frame
	// from a peer we have not negotiated an encrypted cipher with carries no
	// proof the sender knows the PSK, so it must never reach the TAP device.
	// (A wrong-PSK peer's ENCRYPTED frames already fail AEAD-open above and
	// drop as garbage; this closes the plaintext-covert-channel hole.)
	if !decOK && n.pskRequired() && !n.hasNegotiatedCipher(remotePeer) {
		if log.IsDebug() {
			log.Debug("Rx: dropping plaintext frame from %s — PSK network requires a negotiated cipher", remotePeer.String())
		}
		return
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
		return
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
		return
	}

	// ── Tunnel fragmentation reassembly ──
	// A frame may be one fragment of a larger obfuscated TAP frame. If the
	// deobfuscated outer payload is a fragment envelope, buffer it and wait
	// for the rest; once complete, re-deobfuscate the reassembled original
	// frame to obtain the real TAP payload + seqID. Non-fragment frames use
	// the payload/seqID from the first Unpack directly.
	if n.fragRX != nil && isFragPayload(payload) {
		finalPacked, complete := n.fragRX.reassemble(remotePeer, payload, reasmChannelDirect, obfuscate.ConnEpochFromSeq(seqID))
		if !complete {
			return // more fragments pending
		}
		// ── DECRYPT the reassembled inner frame BEFORE unpacking ──
		// Reuses the same scratch: the outer fragment envelope (frameData) is
		// dead here — reassemble() copied every chunk it keeps.
		fdec, fdecOK, fgarbage := n.decryptPeerFrame(*decScratch, finalPacked, remotePeer)
		if fgarbage {
			if log.IsDebug() {
				log.Debug("Rx: dropping undecryptable reassembled ciphertext from %s", remotePeer.String())
			}
			n.recordPeerRxDecrypt(remotePeer, false)
			n.maybeResyncOnDecryptFail(remotePeer)
			return
		}
		if fdecOK {
			finalPacked = fdec
			*decScratch = fdec
		}
		seqID, payload, err = obfuscate.Unpack(finalPacked)
		if err != nil {
			log.Debug("Reassembled frame unpack error from peer %s: %v", remotePeer.String(), err)
			return
		}
	}

	// PERF: render once, below. Everything in this block feeds the string to a
	// bookkeeping call or a log, and peer.ID.String() is base58 (~930ns, 2
	// allocs) evaluated at the call site regardless of log level.
	peerStr := n.peerIDString(remotePeer)
	if log.IsDebug() {
		log.Debug("Rx unpacked: seq=%d payloadLen=%d frameLen=%d from peer=%s", seqID, len(payload), len(frameData), peerStr)
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
	// Only SeqSync may change an established epoch. A delayed data frame
	// from an older session must not reset the current replay window.
	if dup, reason := peerDedup.IsDuplicateReason(seqID); dup {
		n.Collector.RecordDedup()
		n.Collector.RecordPeerDedup(peerStr)
		log.Debug("Duplicate frame seq=%d from peer %s", seqID, peerStr)
		// A SameSeq drop is redundant multi-path delivery of a frame we
		// already handed to TAP — nothing is wrong with the link. Any other
		// reason means the sender is not aligned with the window we anchored
		// for it, and unlike a decrypt failure this path used to have no
		// recovery at all: the frame was perfectly well formed and opened
		// cleanly, so every other subsystem read the link as healthy and
		// nobody ever healed it.
		if reason != obfuscate.DedupDropSameSeq {
			n.recordPeerDedupDesync(remotePeer, true)
			n.maybeResyncOnDedupDesync(remotePeer)
		}
		return
	}
	// Accepted by the dedup window: reset the peer's desync window so a
	// healed link cannot keep re-firing the resync forever.
	n.recordPeerDedupDesync(remotePeer, false)
	n.Collector.RecordRxSeq(peerStr, seqID, peerDedup.MaxSeq(), peerDedup.ReplayDrops(), peerDedup.WindowResets(), peerDedup.WindowUtilization())

	// ACL Firewall Filtering check
	if !n.checkACL(payload, peerStr, false) {
		log.Debug("🛡️ ACL Firewall blocked Rx frame seq=%d from peer %s", seqID, peerStr)
		return
	}
	if log.IsDebug() && n.config().ACL.Enable {
		log.Debug("ACL passed: seq=%d from peer=%s", seqID, peerStr)
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
				seqID, len(payload), net.HardwareAddr(srcMAC[:]).String(), net.HardwareAddr(dstMAC[:]).String(), peerStr, describeEthernetFrame(payload))
		}

		// Content-based dedup ONLY for broadcast/multicast frames:
		// when the same L2 broadcast/multicast payload arrives via multiple peer streams or
		// redundant paths, only the first copy is written to TAP.
		// Unicast frames are handled by per-peer SeqID sliding window deduplication above.
		if isBroadcastOrMulticastMAC(dstMAC) {
			contentHash := fnvHash64(payload)
			if n.bcastDedup.isDuplicate(remotePeer, contentHash) {
				n.Collector.RecordDedup()
				log.Debug("Content-dup broadcast frame hash=0x%x from peer %s dropped", contentHash, peerStr)
				return
			}
		}

	} else {
		log.Debug("Rx frame: seq=%d len=%d (MAC extract failed) from_peer=%s", seqID, len(payload), peerStr)
	}

	// Topology throughput is TAP payload, not the padded/encrypted frame read
	// from the stream. Recording here also counts a fragmented frame exactly
	// once, after reassembly, decryption, deduplication, and ACL validation.
	n.recordPeerRxBytes(remotePeer, len(payload))
	n.recordPeerRxBytesOnPath(remotePeer, pathKey, len(payload))
	n.Collector.RecordRecv(len(payload))
	n.Collector.RecordPacketDir(payload, false)
	if n.Collector != nil {
		n.Collector.CaptureFrameWithPeers(observer.DirRx, payload, peerStr, "self")
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

	if n.Interceptor != nil && n.Interceptor.MatchAndHandle(payload, tapInjectionWriter{node: n}) {
		log.Debug("Frame intercepted by userspace WebUI interceptor from peer %s", remotePeer.String())
		return
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
	n.observeTapICMPEchoReply(remotePeer, payload, time.Now())

	// Peer-side probe ack. Probe frames remain synchronous so the ack still
	// means the native TAP write has completed, while ordinary bulk traffic
	// is handed to the dedicated writer below.
	tapProbeFrame := false
	var probePID peer.ID
	var probeTok uint64
	if pid, tok, ok := n.isTapProbeRequest(payload); ok {
		tapProbeFrame = true
		probePID, probeTok = pid, tok
		dstIP := net.IP(payload[14+16 : 14+20])
		ackFlag := tapProbeAckFlagIPMismatch
		if n.localV4IP != nil && dstIP.Equal(n.localV4IP) {
			ackFlag = tapProbeAckFlagIPMatched
		}
		// Queue synchronously before the TAP write; the old goroutine could
		// race the success drain and leave a stale ack for a later frame.
		n.sendTapProbeAckAfterTAP(pid, tok, ackFlag)
	}

	if n.TAP == nil {
		log.Warn("TAP device is nil, cannot write frame")
		if tapProbeFrame {
			n.takeDeferredProbeAck(probePID, probeTok)
		}
		return
	}

	recordGateway := false
	if cfg := n.config(); cfg != nil && cfg.ExitNode.Enable && !n.isExitNodeActive() && len(payload) >= 6 && payload[0]&1 == 0 {
		recordGateway = true
	}

	if !tapProbeFrame {
		// Reorder gate: under "multipath" this delivers in counter order across
		// all paths; otherwise a zero-overhead passthrough to enqueueTapWrite.
		// Per-path RX for direct frames is attributed above with pathKey; the
		// reorder job carries no pathKey so finishTapWriteJob won't double-count.
		n.reorderTapWrite(remotePeer, seqID, payload, recordGateway, "", "")
		return
	}

	// Diagnostic probe: preserve synchronous completion semantics.
	if log.IsDebug() {
		log.Debug("TAP write: seq=%d len=%d dstMAC=%s to %s", seqID, len(payload), net.HardwareAddr(payload[0:6]).String(), n.TAP.Name())
	}
	wn, werr := n.tapWrite(payload)
	if werr != nil {
		log.Warn("TAP write error: %v", werr)
		n.takeDeferredProbeAck(probePID, probeTok)
	} else {
		log.Debug("TAP write ok: %d bytes to %s", wn, n.TAP.Name())
		if deferred := n.takeDeferredProbeAck(probePID, probeTok); len(deferred) > 0 {
			for _, d := range deferred {
				go n.sendTapProbeAck(d.prober, d.token, d.flag)
			}
		}
		if recordGateway && n.Collector != nil {
			n.Collector.RecordGatewayPacket()
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
	const period = 15 * time.Second
	// Jittered so the LSA flood does not present a fixed 15s timing signature
	// to a passive DPI observer (see jitter.go).
	timer := newJitterTimer(period)
	defer timer.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-timer.C:
			// Use the shared monotonic counter — a local counter starting at 1
			// would be permanently rejected as stale by peers that already saw
			// a (much larger) force-push sequence. See Node.lsaSeq.
			n.broadcastLSA(n.nextLSASeq())
			timer.Reset(jitterInterval(period))
		}
	}
}

// nextLSASeq returns a strictly increasing LSA sequence number. Every
// broadcastLSA call site MUST obtain its sequence here so the periodic ticker
// and the event-driven force pushes share one monotonic sequence space.
func (n *Node) nextLSASeq() uint64 {
	return n.lsaSeq.Add(1)
}

// frameLSAForMux returns the length-prefixed form of an already-marshalled LSA.
//
// handleLSAStream parses its stream one ReadFrame at a time whichever transport
// delivered it. On the legacy lsaPool path lsaStreamPool.Submit calls WriteFrame,
// so the payload is already prefixed there. The mux control channel hands the
// mux frame's payload to the handler byte-for-byte, and every other mux protocol
// (Meta at meta.go, Echo at node_connect.go) compensates by prefixing before it
// calls Send/SendRecv. LSA was the one caller that passed raw JSON, so the first
// four bytes of the payload ({"or...) were parsed as a BigEndian frame length
// (2065854322) and the whole LSA was dropped as "frame too large" — which left
// lsaCache empty and broke snapshot replay for late-joining peers.
func frameLSAForMux(data []byte) []byte {
	framed := make([]byte, frameLenSize+len(data))
	binary.BigEndian.PutUint32(framed[:frameLenSize], uint32(len(data)))
	copy(framed[frameLenSize:], data)
	return framed
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
		// Try the unified mux control channel first; fall back to the
		// legacy per-protocol stream for peers that don't support mux.
		if n.muxEngine != nil && n.muxEngine.Send(pID, mux.TagLSA, frameLSAForMux(data)) {
			if n.protoTracker != nil {
				n.protoTracker.LSA.RecordTx(1, uint64(len(data)))
			}
			continue
		}
		if n.lsaPool.Submit(pID, data) {
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
		// LSA frames are sent every 15s by each peer. A 60s deadline (4× the
		// interval) detects a dead peer and releases the goroutine/stream.
		_ = s.SetReadDeadline(time.Now().Add(60 * time.Second))
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
		//
		// TTL clamping: an attacker sets ttl:6 to bypass the first-hop origin check
		// below (which keys on exact equality with DefaultLSATTL), then
		// applyPeerMetaFromLSA runs with a forged origin — learning MACs, writing
		// GARP/NA into the local TAP, and injecting topology edges under any
		// claimed identity. Clamp to [0, DefaultLSATTL] so the origin check is
		// the only gate. Negative TTLs are dropped (they would never reach TTL 1
		// for forwarding, but they also carry no useful state).
		if lsa.TTL < 0 || lsa.TTL > routing.DefaultLSATTL {
			continue
		}

		// First-hop verification: an LSA with TTL == DefaultLSATTL was minted by
		// the sender, so lsa.Origin MUST equal the transport peer. Without this
		// check, an attacker injects topology edges under any claimed origin
		// (including making itself appear as another peer's direct neighbour,
		// enabling route hijack). Forwarded LSAs (TTL < DefaultLSATTL) trust
		// the origin — it was verified at the first hop by the forwarder.
		//
		// ROUND 8 FIX: the TTL-downgrade bypass. An attacker sets
		// ttl = DefaultLSATTL - 1 and lsa.Origin = <victim> to skip the
		// check above. We now track seen origins: the FIRST time an origin
		// is observed it MUST arrive directly with full TTL. Subsequent
		// sightings via forwarders are trusted. This closes the bypass
		// while preserving legitimate forwarding.
		remotePeer := s.Conn().RemotePeer()
		if lsa.Origin != "" {
			remoteStr := remotePeer.String()
			if val, known := n.seenOrigins.Load(lsa.Origin); known {
				entry := val.(seenOriginEntry)
				// Known origin: the frame must come from the origin itself
				// or from the peer that first introduced it. This closes
				// the TTL-downgrade bypass where an attacker sends
				// ttl < max claiming a known origin from a different peer.
				//
				// Snapshot frames take the SAME check, not a bypass: lsa.Snapshot
				// is a sender-written JSON field and proves nothing about where
				// the payload actually came from. Treating it as authoritative let
				// any directly-connected peer clobber entry.source and re-pin an
				// already-known origin to itself, after which every legitimate LSA
				// and relayed frame for that origin via any other carrier was
				// dropped for the entry's whole 5-minute lifetime.
				//
				// entry.source is deliberately never updated here. Re-pointing it
				// to the origin when a direct frame arrives would revoke the first
				// carrier, so a loss of the direct path would blackhole every
				// carrier-carried LSA for that origin until the reaper evicts the
				// entry (up to 5 minutes). The gate above already admits frames
				// from the origin itself, so nothing is blocked by keeping the pin.
				if remoteStr != lsa.Origin && remoteStr != entry.source {
					log.Debug("LSA from %s claims known origin %s (source=%s) but is not origin or source; dropping",
						remotePeer.ShortString(), lsa.Origin, entry.source)
					continue
				}
				entry.firstSeen = time.Now()
				n.seenOrigins.Store(lsa.Origin, entry)
			} else if lsa.Snapshot && lsa.TTL == routing.DefaultLSATTL {
				// First sighting via a cached snapshot. The receiver is usually
				// NOT directly connected to the origin, so the direct+full-TTL
				// rule below cannot apply, and this trust is unavoidable: LSAs
				// carry no PSK-keyed stamp the way the relay-ctrl tunnel does
				// (relay_ctrl_attest.go). Two things bound the trust:
				//   (1) pushLSASnapshotToPeer sets replay.TTL = DefaultLSATTL on
				//       every frame it replays, so a real snapshot always arrives
				//       at full TTL. Forwards that decrement TTL through an
				//       intermediate hop no longer carry the Snapshot flag (only
				//       the sender's own cache replay does), so this TTL check
				//       only admits the intended first-hop snapshot path — a peer
				//       that mints Snapshot=true on a re-forwarded frame still
				//       sets TTL itself, but a peer that merely forwards a real
				//       snapshot after decrementing it is rejected here and falls
				//       through to the strict rule below.
				//   (2) A snapshot can only pin a first-sighting; it can never
				//       re-pin an origin someone else already introduced (that
				//       is the KNOWN-origin branch above, which takes the same
				//       origin/source check).
				// The identity side effects of applyPeerMetaFromLSA —
				// learnMACFromMeta, RegisterIPMAC, processSubnetRoutes and the
				// GARP/NA writes into the local TAP — are gated further down on
				// n.hasPeerConnection(origin), so even a snapshot-minted forged
				// origin never installs MAC/IP state or writes L2 frames under
				// that identity. This branch only lets the routing graph learn
				// the edge, which is the minimal information a late-joining peer
				// needs to bootstrap the full mesh through a single StaticPeer.
				n.seenOrigins.Store(lsa.Origin, seenOriginEntry{firstSeen: time.Now(), source: remoteStr})
			} else {
				// First time seeing this origin: must come directly with full TTL.
				if lsa.Origin != remoteStr || lsa.TTL != routing.DefaultLSATTL {
					log.Debug("LSA from %s claims unseen origin %s with ttl=%d (snapshot=%v); dropping",
						remotePeer.ShortString(), lsa.Origin, lsa.TTL, lsa.Snapshot)
					continue
				}
				n.seenOrigins.Store(lsa.Origin, seenOriginEntry{firstSeen: time.Now(), source: remoteStr})
			}
		}

		// Apply the piggybacked node identity only to an LSA that ProcessLSA
		// actually accepted. Running it before ProcessLSA installed
		// attacker-chosen NodeName/TapIP/TapMAC, subnet routes and TAP IP/MAC
		// bindings keyed by a claimed origin from an LSA that was then rejected
		// (stale or absurd sequence number, TTL out of range, graph cap reached).
		accepted := n.Router.ProcessLSA(&lsa)
		if accepted && lsa.Origin != "" {
			if origin, err := peer.Decode(lsa.Origin); err == nil {
				// applyPeerMetaFromLSA runs with the CLAIMED origin identity —
				// learnMACFromMeta, RegisterIPMAC and processSubnetRoutes all
				// install state keyed by lsa.Origin, and GARP/NA writes go into
				// the local TAP from that identity. A carrier that is not
				// directly connected to the origin is only relaying a JSON
				// blob; nothing in the LSA header (including lsa.Snapshot)
				// authenticates that blob to the claimed origin. So the identity
				// channel must be direct-only: the origin's own max-TTL LSA, or
				// one from a peer this node is actively connected to. The ROUTING
				// graph still accepts forwarded LSAs through ProcessLSA above;
				// only the identity side effects are gated.
				if n.hasPeerConnection(origin) {
					n.applyPeerMetaFromLSA(origin, lsa)
				}
			}
		}
		if accepted {
			// Retain the freshest accepted payload for this origin so we can
			// hand a FULL topology snapshot to the next peer that connects.
			// Must be captured BEFORE the TTL decrement below.
			n.cacheLSA(&lsa)
		}
		if accepted && lsa.TTL > 1 {
			lsa.TTL--
			forwardData, err := json.Marshal(lsa)
			if err == nil {
				senderID := s.Conn().RemotePeer()
				// Forward over the same persistent per-peer LSA streams.
				// Done asynchronously so a single unreachable peer (whose Submit
				// may block on a reconnect timeout) cannot stall this handler's
				// ReadFrame loop and stop us processing other peers' LSA frames.
				muxForwardData := frameLSAForMux(forwardData)
				for _, pID := range n.Host.Network().Peers() {
					if pID == n.Host.ID() || pID == senderID {
						continue
					}
					if n.isBootstrapPeer(pID) {
						continue
					}
					fwd := pID
					go func() {
						if n.muxEngine != nil && n.muxEngine.Send(fwd, mux.TagLSA, muxForwardData) {
							return
						}
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
		// Mark as snapshot so the receiver may admit a FIRST sighting of an
		// origin it is not directly connected to; an origin the receiver already
		// knows still takes the strict origin/source check (see handleLSAStream).
		replay := *lsa
		replay.TTL = routing.DefaultLSATTL
		replay.Snapshot = true
		data, err := json.Marshal(&replay)
		if err != nil {
			continue
		}
		if n.muxEngine != nil && n.muxEngine.Send(target, mux.TagLSA, frameLSAForMux(data)) {
			sent++
			continue
		}
		if n.lsaPool.Submit(target, data) {
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

	// Reset the stream on node shutdown, matching handleStream. Without this
	// an idle relay stream (peer connected but not sending any frames) pins
	// the handler goroutine and its 65 KiB receive buffer for the entire
	// lifetime of the node. A read deadline is deliberately NOT set here —
	// the same reason handleStream clears the inherited one: ReadFrame has no
	// rewind, so a deadline firing mid-frame would leave the stream out of
	// sync with any further bytes the peer sends.
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

	// Loop read: handle multiple relay frames on the same stream (consistent with handleStream)
	buf := make([]byte, obfuscate.MaxSealedFrameSize)
	// Per-stream decrypt scratch (same zero-alloc pattern as handleStream):
	// plaintext relay envelopes are decrypted into this buffer and rebased each
	// iteration. Consumers are synchronous (deliverRelayedFrameToTAP) or copy
	// (fragment reassembly, repack-forward), so the buffer never escapes.
	relayDecScratch := make([]byte, 0, 9600)
	relayInnerScratch := make([]byte, 0, 9600)
	for {
		readN, err := ReadFrame(s, buf)
		if err != nil || readN == 0 {
			break
		}
		if n.protoTracker != nil {
			n.protoTracker.RelayData.RecordRx(1, uint64(readN))
		}
		n.handleRelayFrame(remotePeer, buf[:readN], &relayDecScratch, &relayInnerScratch)
	}
}

// packRelayFrame wraps inner in the overlay relay envelope, choosing the header
// version from the running config. Callers that must reach an un-upgraded peer
// keep calling routing.PackRelayFrame directly: PackBootRelayFrame in
// particular, because a boot relay has to parse the inner envelope in order to
// decide where to forward the frame.
//
// The version is read through config(), not Config, so a live config save takes
// effect without a restart. That is one atomic load on the TX path, which is
// nothing next to the two base58 encodings the v2 header used to cost per frame.
func (n *Node) packRelayFrame(finalDst, source peer.ID, ttl uint8, payload []byte) ([]byte, error) {
	if c := n.config(); c != nil && c.RelayHeaderMultihash {
		return routing.PackRelayFrameV3(finalDst, source, ttl, payload)
	}
	return routing.PackRelayFrame(finalDst, source, ttl, payload)
}

// handleRelayFrame processes one inbound overlay-relay frame: hop-by-hop
// envelope decrypt, unwrap the carrying obfuscate frame, fragment reassembly,
// envelope unpack, origin verification, then deliver or forward. Shared by the
// legacy per-peer relay stream (handleRelayStream) and the unified mux data
// channel (handleDataMuxRelay) so the two RX paths cannot drift.
//
// data may be mutated in place and must belong exclusively to the calling
// goroutine: for handleRelayStream it is the per-stream read buffer, for the mux
// path it is a private per-frame copy.
//
// relayDecScratch is the caller's reusable OUTER-envelope decrypt scratch;
// relayInnerScratch is the second, used for the end-to-end inner decrypt when
// this node is the final destination. They must be distinct buffers: the inner
// payload is a slice of the outer scratch (or of the read buffer), so opening
// it into the same buffer would be an in-place AEAD open over overlapping
// memory — the trap called out in frag.go. Both are rebased on each call so
// steady-state frames allocate nothing, and neither may escape the call.
func (n *Node) handleRelayFrame(remotePeer peer.ID, data []byte, relayDecScratch, relayInnerScratch *[]byte) {
	// HOP-BY-HOP envelope decryption. The origin sealed the outer relay
	// frame with the cipher negotiated for THIS hop, so the relay decrypts
	// with the cipher for its immediate neighbor (remotePeer) — the same
	// shared ECDH key. If a cipher is negotiated but AEAD-open fails the
	// envelope is genuine ciphertext we cannot open: DROP it (garbage==true)
	// rather than letting it reach UnpackRelayFrame as garbage.
	if rdec, rdecOK, rgarbage := n.decryptPeerFrame(*relayDecScratch, data, remotePeer); rgarbage {
		log.Debug("Rx: dropping undecryptable relay envelope from %s", remotePeer.String())
		n.relayDiag.hopGarbage()
		n.recordPeerRxDecrypt(remotePeer, false)
		n.maybeResyncOnDecryptFail(remotePeer)
		return
	} else if rdecOK {
		data = rdec
		*relayDecScratch = rdec
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
	//   2. It did `return` on ANY Unpack error, silently discarding every
	//      bare envelope. We now fall through and let UnpackRelayFrame try,
	//      which keeps interop with peers running an older build.
	envelope := data
	if outerSeq, outer, uerr := obfuscate.Unpack(data); uerr == nil {
		if n.fragRX != nil && isFragPayload(outer) {
			finalPacked, complete := n.fragRX.reassemble(remotePeer, outer, reasmChannelRelay, obfuscate.ConnEpochFromSeq(outerSeq))
			if !complete {
				return // more fragments pending
			}
			// ── DECRYPT the reassembled inner frame BEFORE unpacking ──
			// Same scratch reuse: the outer fragment envelope is dead —
			// reassemble() copied every chunk it keeps.
			rfdec, rfdecOK, rfgarbage := n.decryptPeerFrame(*relayDecScratch, finalPacked, remotePeer)
			if rfgarbage {
				log.Debug("Rx: dropping undecryptable reassembled relay envelope from %s", remotePeer.String())
				n.recordPeerRxDecrypt(remotePeer, false)
				n.maybeResyncOnDecryptFail(remotePeer)
				return
			}
			if rfdecOK {
				finalPacked = rfdec
				*relayDecScratch = rfdec
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
		n.relayDiag.envBad()
		return
	}
	n.relayDiag.recv()
	// First-hop origin verification. Every envelope carries two claims: who
	// sent it (the transport peer, authenticated by libp2p) and who
	// originated it (srcPeer, attacker-writable). Only the first is ever
	// authenticated, so what follows is a set of path-shape consistency
	// checks, not an identity proof.
	//
	//  1. Claimed origin == transport peer at full TTL: a definitive first
	//     hop. The sender is authenticated and the path length matches the
	//     claim.
	//
	//  2. Claimed origin != transport peer: a relay hop, so it must have
	//     been decremented at least once — 1 <= ttl < MaxRelayTTL. This is
	//     the ordinary shape of multi-hop traffic. In a hub-and-spoke mesh
	//     a destination spoke's very first view of a peer is through the hub,
	//     already one hop down, so demanding full TTL here breaks every such
	//     path.
	//
	//  3. Anything else — ttl == MaxRelayTTL carried by someone other than
	//     the claimed origin — advertises a zero-hop path that does not
	//     exist. Drop. This is the pre-ROUND 8 check
	//     (ttl == MaxRelayTTL && srcPeer != remotePeer).
	//
	// ROUND 8 FIX: TTL-downgrade bypass. Rule 3 alone was bypassed by
	// setting ttl = MaxRelayTTL - 1 while re-claiming an already-known
	// origin from a different carrier. seenOrigins closes that half: once an
	// origin has been observed, later sightings must come from the origin
	// itself or from the peer that first introduced it. This is the only
	// half that is decidable — the two claims are indistinguishable at the
	// first sighting, so the first sighting is shape-checked, not
	// authenticated, and the re-attribution is where the gate bites.
	// originVerified distinguishes the two branches of the gate above: a
	// sighting where srcPeer is either already known (so the carrier was
	// checked against the recorded first source) or IS the transport peer.
	// A shape-checked FIRST sighting of an otherwise-unknown srcPeer is not
	// verified — any peer ID in the right TTL range is admitted there.
	// Liveness and provenance records key on srcPeer, so they are written
	// only for verified origins: an unverified first sighting must not be able
	// to stamp a peer's return-path as alive, or re-point its peek-map origin,
	// on one frame from a hop it did not authenticate.
	originVerified := false
	if srcPeer != "" {
		// PERF: feed seenOrigins from the base58 cache. These two renders are
		// unconditional (~0.9µs and 2 allocs apiece) and then hashed again by
		// sync.Map as their keys; the rest of this file already goes through
		// peerIDString(). The key space is unchanged — the cache renders the
		// same base58 as peer.ID.String().
		srcStr := n.peerIDString(srcPeer)
		remoteStr := n.peerIDString(remotePeer)
		if val, known := n.seenOrigins.Load(srcStr); known {
			entry := val.(seenOriginEntry)
			// Known origin: the frame must come from the origin itself
			// or from the peer that first introduced it.
			//
			// entry.source is deliberately never updated here: re-pointing it
			// to the origin on a direct frame would revoke the first carrier
			// and blackhole every carrier-carried frame for that origin until
			// the reaper evicts the entry (up to 5 minutes). The gate below
			// already admits frames from the origin itself.
			if remoteStr != srcStr && remoteStr != entry.source {
				if log.IsDebug() {
					log.Debug("Relay frame from %s claims known srcPeer %s (source=%s) but is not origin or source; dropping",
						remoteStr, srcStr, entry.source)
				}
				n.relayDiag.envBad()
				return
			}
			// Throttled refresh: see seenOriginRefreshInterval.
			if time.Since(entry.firstSeen) >= seenOriginRefreshInterval {
				entry.firstSeen = time.Now()
				n.seenOrigins.Store(srcStr, entry)
			}
			originVerified = true
		} else if srcPeer == remotePeer && ttl == routing.MaxRelayTTL {
			// Direct origin at full TTL: the claimed origin IS the transport
			// peer, which libp2p authenticated, so the claim is sound.
			n.seenOrigins.Store(srcStr, seenOriginEntry{firstSeen: time.Now(), source: remoteStr})
			originVerified = true
		} else if ttl >= 1 && ttl < routing.MaxRelayTTL {
			// First sighting carried by a relay: legitimate multi-hop, with
			// at least one decrement already applied by an upstream hop.
			n.seenOrigins.Store(srcStr, seenOriginEntry{firstSeen: time.Now(), source: remoteStr})
		} else {
			// Full TTL claimed over a path that is not the claimed origin.
			log.Debug("Relay frame from %s claims unseen srcPeer %s with ttl=%d; dropping",
				remotePeer.String(), srcStr, ttl)
			n.relayDiag.envBad()
			return
		}
	}
	// Return-path liveness signal: we just received a frame ORIGINATING at
	// srcPeer (even if we are merely forwarding it), so its return path to
	// us is currently alive. Recorded for the ping-pong probe's outbound-vs-
	// return distinction in an asymmetric-routing mesh. The frame reached us
	// over the overlay envelope carried by remotePeer, so annotate that hop —
	// srcPeer may well have its own live direct connection to us unused.
	if originVerified {
		n.notePeerRxTransport(srcPeer, "overlay-relay", remotePeer)
	}
	// relayHopRx: the hop (remotePeer) itself just carried a frame to us. A
	// pure-forwarding hop is never srcPeer, so this is the only signal that
	// advances for it — relayStreamPool anchors its failure-streak clear on
	// this so a healthy-but-silent forwarder is not mis-blacklisted.
	if remotePeer != "" && remotePeer != srcPeer {
		n.noteRelayHopRx(remotePeer)
		if originVerified {
			n.recordPeekMapOrigin(srcPeer, remotePeer, 1, n.isBootstrapPeer(remotePeer))
		}
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
			// Second scratch, never relayDecScratch: innerPayload aliases the
			// outer scratch (or the read buffer), so opening into the same
			// buffer would be an in-place AEAD open over overlapping memory.
			dec, derr := obfuscate.DecryptPayloadRegionInto((*relayInnerScratch)[:0], innerPayload, cipher)
			if derr != nil {
				// Guarded: a key divergence puts every relayed frame here, and
				// the args render two peer IDs plus a NonceHex on top of the
				// failed AEAD open.
				if log.IsDebug() {
					log.Debug("Relayed frame decrypt error from origin %s (via %s): %v",
						srcPeer.String(), remotePeer.String(), derr)
				}
				n.relayDiag.finalDecFail()
				n.recordPeerRxDecrypt(srcPeer, false)
				// Self-heal parity with the direct-RX path: a persistent
				// inner-open failure here means srcPeer↔us keys diverged
				// (e.g. one side restarted). Without the throttled resync
				// nudge, relay-only peers had to wait for the reconciler's
				// next full round — minutes of one-way blackhole that
				// looked exactly like "connects but no data".
				n.maybeResyncOnDecryptFail(srcPeer)
				return
			}
			*relayInnerScratch = dec
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
			n.relayDiag.finalUnpack()
			n.recordPeerRxDecrypt(srcPeer, false)
			return
		}
		// Guarded: this is the per-relay-frame SUCCESS path, and Go evaluates
		// remotePeer.String() (a base58 encode) at the call site regardless of
		// the log level.
		if log.IsDebug() {
			log.Debug("Relay Unpack: seq=%d payloadLen=%d innerLen=%d ttl=%d from=%s",
				seqID, len(unpacked), len(innerPayload), ttl, remotePeer.String())
		}
		// Deliver through the shared relayed-frame TAP path (also used by the
		// boot-relay / relay-over-backbone downlink). Keyed on the TRUE origin
		// (srcPeer); remotePeer is the transport (via) peer.
		n.deliverRelayedFrameToTAP(unpacked, srcPeer, remotePeer, seqID)
		return
	}

	// Destination is another peer: forward frame if TTL > 1.
	// ACL check: the relay node evaluates the ACL on the (srcPeer → finalDst)
	// pair before forwarding, so a peer blocked from reaching a target by
	// local ACL cannot use a third-party relay as a bypass.
	if ttl > 1 {
		if !n.checkRelayTransitACL(srcPeer, finalDst) {
			log.Debug("Relay forward denied by ACL: %s → %s (via %s, ttl=%d)",
				srcPeer.String(), finalDst.String(), remotePeer.String(), ttl)
			return
		}
		nextHop := finalDst
		if route, ok := n.overlayRoute(finalDst, int(ttl)-1, remotePeer); ok {
			nextHop = route.NextHop
		} else if !n.routeHopUsable(finalDst, finalDst) {
			n.relayDiag.loopGuard()
			return
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
			n.relayDiag.loopGuard()
			return
		}

		// A p2ptap-boot can never be an overlay relay next hop: relayPool refuses
		// boot peers outright (it is a relay-over-backbone uplink, not an overlay
		// relay peer). Without this branch a frame whose route resolved to a boot
		// was submitted to the pool, silently rejected, and miscounted as a
		// pool-full forward drop — the relay looked healthy while every such
		// frame died here with only a debug log. routeHopUsable deliberately
		// admits boots (so the ORIGIN side can egress through them), which is
		// exactly how this route reaches the transit path. The origin-side
		// branches (node_tap.go, strategy.relayFallbackIfPossible) already take
		// the boot-relay path for the same hop; the transit path did not.
		if n.isBootstrapPeer(nextHop) {
			n.forwardRelayEnvelopeViaBootRelay(finalDst, nextHop, srcPeer, innerPayload)
			return
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
		repacked, err := n.packRelayFrame(finalDst, srcPeer, ttl-1, innerPayload)
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
				n.relayDiag.sealFail()
				return
			}
			// Use persistent relay pool instead of per-frame NewStream.
			// onSent=nil: forwarding does not double-count RecordSent (origin already counted).
			// onFail: silently drop; source will retransmit.
			if !n.relayPool.Submit(nextHop, sealed,
				nil, // onSent — no double-counting
				func() {
					log.Debug("Relay forward to %s via %s permanently failed",
						finalDst.String(), nextHop.String())
				},
			) {
				n.relayDiag.fwdPoolFull()
			}
		} else {
			log.Warn("Relay forward repack failed for dst %s src %s: %v",
				finalDst.String(), srcPeer.String(), err)
		}
		return
	}
	// Not the destination and the TTL budget is spent: the envelope dies
	// here. This is the ONLY thing that terminates an overlay-relay cycle
	// (a stale route table pointing hops at each other), so the drop has to
	// be observable. When this count sat in the PackRelayFrame error branch
	// below it was unreachable — PackRelayFrame only errors on an absurdly
	// long peer-ID string — so a live cycle left every diag counter at zero
	// and showed up nowhere in /api/relay/diag or the periodic drop summary.
	n.relayDiag.ttlExpired()
	log.Debug("Relay envelope expired at a non-destination hop: src=%s dst=%s via=%s ttl=%d; dropping",
		srcPeer.String(), finalDst.String(), remotePeer.String(), ttl)
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
		// Echo is a request/response protocol: the peer sends a probe, we
		// reply immediately. A 30s deadline detects a dead peer (echo probes
		// are sent every few seconds, so 30s is very generous).
		_ = s.SetReadDeadline(time.Now().Add(30 * time.Second))
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
		// Set a write deadline so a peer that stops reading doesn't stall us.
		_ = s.SetWriteDeadline(time.Now().Add(5 * time.Second))
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
	// Validate the claimed prober ID — a raw byte slice cast to peer.ID
	// without decoding would let an attacker specify arbitrary strings that
	// happen to resolve in the peerstore, causing the node to open control
	// streams toward uncontrolled addresses.
	rawPID := icmpPayload[3 : 3+pidLen]
	pid, err := peer.Decode(string(rawPID))
	if err != nil || pid == "" {
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
// succeeds. The queue is drained ONLY on a successful write, so a peer flooding
// probe requests while our TAP is down (n.TAP==nil, or persistent write errors)
// would otherwise grow it without bound — every entry also holds the state that
// later spawns one ack goroutine. Cap it and evict oldest: at most
// maxDeferredProbeAcks pending acks, which is far more than the handful of
// simultaneous probes the diagnostics/speedtest paths issue.
const maxDeferredProbeAcks = 32

func (n *Node) queueDeferredProbeAck(d deferredProbeAck) {
	n.deferredProbeAcksMu.Lock()
	if len(n.deferredProbeAcks) >= maxDeferredProbeAcks {
		n.deferredProbeAcks = n.deferredProbeAcks[1:] // evict oldest pending ack
	}
	n.deferredProbeAcks = append(n.deferredProbeAcks, d)
	n.deferredProbeAcksMu.Unlock()
}

// takeDeferredProbeAck returns the pending acks queued for ONE probe frame
// (matched on prober + token) and removes them from the queue.
//
// It must NOT drain the whole queue: every frame is processed in its own
// goroutine, so a blanket drain let a concurrent probe frame collect THIS
// frame's ack. If that concurrent write then failed, this frame's ack had
// already been sent for a delivery that never happened — precisely the lie the
// deferral exists to prevent ("acked a frame that was never delivered to the
// TAP"). A concurrent write that succeeded simply sends the ack a moment
// early, which is harmless; a concurrent write that failed no longer steals
// an ack it was never entitled to.
func (n *Node) takeDeferredProbeAck(prober peer.ID, token uint64) []deferredProbeAck {
	n.deferredProbeAcksMu.Lock()
	defer n.deferredProbeAcksMu.Unlock()
	var out []deferredProbeAck
	kept := n.deferredProbeAcks[:0]
	for _, d := range n.deferredProbeAcks {
		if d.prober == prober && d.token == token {
			out = append(out, d)
		} else {
			kept = append(kept, d)
		}
	}
	n.deferredProbeAcks = kept
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
	_ = s.SetReadDeadline(time.Now().Add(30 * time.Second))
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
	defer func() {
		if res.Success && res.RTTMs > 0 {
			rtt := time.Duration(res.RTTMs * float64(time.Millisecond))
			n.Host.Peerstore().RecordLatency(pid, rtt)
			n.recordPeerRTTProbe(pid, rttSourceP2PEcho, rtt, true)
		} else {
			n.recordPeerRTTProbe(pid, rttSourceP2PEcho, 0, false)
		}
	}()

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
		if ma := s.Conn().RemoteMultiaddr(); ma != nil {
			res.TransportAddr = ma.String()
			res.IsRelayed = maddrutil.IsCircuitRelay(ma)
		}
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
	defer func() {
		if res.Success && res.RTTMs > 0 {
			rtt := time.Duration(res.RTTMs * float64(time.Millisecond))
			n.recordPeerRTTProbe(pid, rttSourceP2PEcho, rtt, true)
		} else {
			n.recordPeerRTTProbe(pid, rttSourceP2PEcho, 0, false)
		}
	}()

	targetMA, err := multiaddr.NewMultiaddr(targetAddrStr)
	if err != nil {
		res.Error = fmt.Sprintf("invalid multiaddr '%s': %v", targetAddrStr, err)
		return res
	}

	// SSRF guard: reject multiaddrs pointing to loopback, link-local,
	// unspecified, multicast, or broadcast ranges. Without this, an
	// attacker-supplied multiaddr (via the WebUI or a mesh peer) could
	// force a dial to internal services. The existing overlayConnGater
	// only blocks overlay/TAP CIDRs and is DNS-blind; this check covers
	// the full SSRF surface.
	if manet.IsIPLoopback(targetMA) || isSSRFBlockedAddr(targetMA) {
		res.Error = fmt.Sprintf("multiaddr %s points to a blocked address range (loopback/link-local/multicast/broadcast); refusing to probe", targetAddrStr)
		return res
	}

	// ---- Close the DNS rebinding TOCTOU window ----
	// If the multiaddr contains a DNS component, the dialer below would
	// re-resolve it. An attacker-controlled DNS server could swap the answer
	// to an internal address between this SSRF check and the Connect call.
	// Resolve once here, validate the IPs, and dial the IP-based multiaddrs.
	if hasDNSComponent(targetMA) {
		resolvedIPs, dnsErr := lookupDNSMultiaddr(targetMA)
		if dnsErr != nil {
			res.Error = fmt.Sprintf("DNS resolution failed for %s: %v", targetAddrStr, dnsErr)
			return res
		}
		for _, ipStr := range resolvedIPs {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
				ip.IsUnspecified() || ip.IsMulticast() ||
				ip.Equal(net.IPv4bcast) {
				res.Error = fmt.Sprintf("DNS resolved to blocked address %s; refusing to probe", ipStr)
				return res
			}
		}
		// Rebuild the multiaddr with resolved IPs replacing the DNS component.
		comps := multiaddr.Split(targetMA)
		dnsIdx := -1
		for i, c := range comps {
			if c.Code() == multiaddr.P_DNS4 || c.Code() == multiaddr.P_DNS6 ||
				c.Code() == multiaddr.P_DNS || c.Code() == multiaddr.P_DNSADDR {
				dnsIdx = i
				break
			}
		}
		targetMA = nil
		if dnsIdx >= 0 && dnsIdx < len(comps)-1 {
			var suffix multiaddr.Multiaddr
			for _, c := range comps[dnsIdx+1:] {
				suffix = multiaddr.Join(suffix, c.Multiaddr())
			}
			for _, ipStr := range resolvedIPs {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					continue
				}
				var ipProto int
				if ip.To4() != nil {
					ipProto = multiaddr.P_IP4
				} else {
					ipProto = multiaddr.P_IP6
				}
				ipComp, err := multiaddr.NewComponent(multiaddr.ProtocolWithCode(ipProto).Name, ipStr)
				if err != nil {
					continue
				}
				ipMA := ipComp.Multiaddr()
				if suffix != nil {
					ipMA = multiaddr.Join(ipMA, suffix)
				}
				if targetMA == nil {
					targetMA = ipMA
				}
			}
		}
		if targetMA == nil {
			res.Error = fmt.Sprintf("DNS resolved to no valid IPs for %s", targetAddrStr)
			return res
		}
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
		res.IsRelayed = maddrutil.IsCircuitRelay(s.Conn().RemoteMultiaddr())
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
	// Cut, not Split: this runs on every direct and every relayed frame, and
	// Split allocates a slice plus a string per field for a value that only
	// ever needs its prefix. Cut allocates nothing. Both return the whole
	// string when "/" is absent, so the behaviour is identical.
	peerTapIP, _, _ := strings.Cut(meta.TapIP, "/")
	peerTapIPv6, _, _ := strings.Cut(meta.TapIPv6, "/")

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
