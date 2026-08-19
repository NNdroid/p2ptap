package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
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
	if binary.BigEndian.Uint16(payload[12:14]) == packet.EtherTypeIPv4 && n.localV4IP != nil {
		dstIP := net.IP(payload[30:34])
		if dstIP.Equal(n.localV4IP) || n.isLocalAdvertisedSubnet(dstIP) {
			if !bytes.Equal(payload[0:6], n.localMAC) {
				log.Debug("MAC rewrite IPv4 (local dst / subnet): dstIP=%s oldDstMAC=%s newDstMAC=%s", dstIP.String(), net.HardwareAddr(payload[0:6]).String(), net.HardwareAddr(n.localMAC).String())
				copy(payload[0:6], n.localMAC)
			}
			return
		}
		if (n.isExitNodeActive() || (n.Config != nil && n.Config.ExitNode.Enable)) &&
			func() bool { mac, _ := n.lookupPeerMACByIPv4(dstIP); return mac == nil }() &&
			n.lookupPeerMACByAdvertisedSubnet(dstIP) == nil {
			exitMAC := n.localMAC
			if !(n.Config != nil && n.Config.ExitNode.Enable) {
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
	if binary.BigEndian.Uint16(payload[12:14]) == packet.EtherTypeIPv6 && n.localV6IP != nil && len(payload) >= 54 {
		dstIP := net.IP(payload[38:54])
		if dstIP.Equal(n.localV6IP) || n.isLocalAdvertisedSubnet(dstIP) {
			if !bytes.Equal(payload[0:6], n.localMAC) {
				log.Debug("MAC rewrite IPv6 (local dst / subnet): dstIP=%s oldDstMAC=%s newDstMAC=%s", dstIP.String(), net.HardwareAddr(payload[0:6]).String(), net.HardwareAddr(n.localMAC).String())
				copy(payload[0:6], n.localMAC)
			}
			return
		}

		if (n.isExitNodeActive() || (n.Config != nil && n.Config.ExitNode.Enable)) &&
			func() bool { mac, _ := n.lookupPeerMACByIPv6(dstIP); return mac == nil }() &&
			n.lookupPeerMACByAdvertisedSubnet(dstIP) == nil {
			exitMAC := n.localMAC
			if !(n.Config != nil && n.Config.ExitNode.Enable) {
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
	for {
		// Respond to node shutdown: libp2p streams block indefinitely in
		// ReadFrame, so arm a short read deadline and re-check the node context
		// between frames. This lets handleStream exit promptly once Close()
		// cancels the context, instead of waiting for the underlying transport
		// to deliver EOF (which can hang on Windows / after a forced host close).
		if err := s.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			log.Debug("Failed to set stream read deadline for %s: %v", remotePeer.String(), err)
		}
		// Read length-prefixed frame from P2P stream
		readN, err := ReadFrame(s, buf)
		if err != nil {
			// A deadline-induced error means no frame arrived in the window;
			// check shutdown before giving up.
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				select {
				case <-n.ctx.Done():
					log.Debug("Stream closed for %s: node shutting down", remotePeer.String())
					return
				default:
					continue
				}
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

		log.Debug("Rx raw frame: len=%d from peer=%s", readN, remotePeer.String())

		frameData := buf[:readN] // may be reassigned below if reassembled

		// CONCURRENCY CONTRACT: `buf` is allocated per-iteration inside this
		// stream's read loop, so it is local to THIS goroutine. The MAC-rewrite
		// paths below mutate frameData (== buf[:readN]) in place. This is safe
		// ONLY because the eventual TAP write (n.tapWrite -> n.TAP.Write) is
		// synchronous and returns before the next loop iteration reuses `buf`.
		// Do NOT let `buf`/`frameData` escape this goroutine (e.g. hand it to a
		// background send or the urgent-write channel) without copying first, or
		// a concurrent read would observe torn/overwritten frame bytes.

		if len(frameData) < obfuscate.HeaderLen {
			log.Debug("Short frame (%d bytes) from peer %s, skipping", len(frameData), remotePeer.String())
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
			log.Debug("Rx: dropping undecryptable ciphertext frame from %s", remotePeer.String())
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
			log.Debug("Frame unpack error from peer %s: %v", remotePeer.String(), err)
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
			log.Debug("Rejected non-p2ptap frame from peer %s (bad magic, len=%d)",
				remotePeer.String(), len(frameData))
			continue
		}

		// ── Tunnel fragmentation reassembly ──
		// A frame may be one fragment of a larger obfuscated TAP frame. If the
		// deobfuscated outer payload is a fragment envelope, buffer it and wait
		// for the rest; once complete, re-deobfuscate the reassembled original
		// frame to obtain the real TAP payload + seqID. Non-fragment frames use
		// the payload/seqID from the first Unpack directly.
		if n.fragRX != nil && isFragPayload(payload) {
			finalPacked, complete := n.fragRX.reassemble(payload)
			if !complete {
				continue // more fragments pending
			}
			// ── DECRYPT the reassembled inner frame BEFORE unpacking ──
			fdec, fdecOK, fgarbage := n.decryptPeerFrame(finalPacked, remotePeer)
			if fgarbage {
				log.Debug("Rx: dropping undecryptable reassembled ciphertext from %s", remotePeer.String())
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

		log.Debug("Rx unpacked: seq=%d payloadLen=%d frameLen=%d from peer=%s", seqID, len(payload), len(frameData), remotePeer.String())

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
		if decOK && obfuscate.IsStructuredSeq(seqID) {
			if ep := obfuscate.ConnEpochFromSeq(seqID); ep != peerDedup.ConnEpoch() {
				peerDedup.SetConnEpoch(ep)
			}
		}
		if peerDedup.IsDuplicate(seqID) {

			n.Collector.RecordDedup()
			n.Collector.RecordPeerDedup(remotePeer.String())
			log.Debug("Duplicate frame seq=%d from peer %s", seqID, remotePeer.String())
			continue
		}
		n.Collector.RecordRxSeq(remotePeer.String(), seqID, peerDedup.MaxSeq(), peerDedup.ReplayDrops(), peerDedup.WindowResets(), peerDedup.WindowUtilization())

		// ACL Firewall Filtering check
		if !n.checkACL(payload, remotePeer.String(), false) {
			log.Debug("🛡️ ACL Firewall blocked Rx frame seq=%d from peer %s", seqID, remotePeer.String())
			continue
		}
		if n.Config.ACL.Enable {
			log.Debug("ACL passed: seq=%d from peer=%s", seqID, remotePeer.String())
		}

		dstMAC, srcMAC, errExtract := vswitch.ExtractEthernetMACs(payload)
		if !errExtract {
			// Normalize the learned source MAC to the peer's configured TapMAC
			// when known. Some peers (e.g. Windows) emit EUI-64 / synthetic
			// MACs in the SrcMAC field; learning those verbatim would explode
			// the MAC table with one entry per distinct random MAC. See also
			// the SrcMAC fix-up below for pcap display.
			if realMAC := n.lookupPeerTapMAC(remotePeer); realMAC != nil {
				srcMAC = realMAC
			}
			n.MACTable.Learn(srcMAC, remotePeer)
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
			n.Collector.CaptureFrameWithPeers(observer.DirRx, payload, remotePeer.String(), "self")
		}
		if len(payload) >= 14 {
			// Fix up rx frame SrcMAC: some peers (especially Windows) may send
			// frames with an EUI-64 derived synthetic MAC in the SrcMAC field
			// instead of their configured TapMAC.  Replace it with the real
			// TapMAC from peer metadata so the pcap table shows a consistent,
			// address-book MAC.
			capturePayload := payload // avoid copying for the common case
			if !errExtract {
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

		if n.Interceptor != nil && n.Interceptor.MatchAndHandle(payload, n.TAP) {
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

		// Write unpadded payload Ethernet frame to TAP
		if n.TAP == nil {
			log.Warn("TAP device is nil, cannot write frame")
			continue
		}
		log.Debug("TAP write: seq=%d len=%d dstMAC=%s to %s", seqID, len(payload), net.HardwareAddr(payload[0:6]).String(), n.TAP.Name())
		wn, werr := n.tapWrite(payload)
		if werr != nil {
			log.Warn("TAP write error: %v", werr)
		} else {
			log.Debug("TAP write ok: %d bytes to %s", wn, n.TAP.Name())
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
			if n.Config != nil && n.Config.ExitNode.Enable && !n.isExitNodeActive() && len(payload) >= 6 && payload[0]&1 == 0 {
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
	lsa := n.Router.BuildLSA(seq, routing.NodeIdentity{
		NodeName:   n.nodeName,
		TapIP:      n.Config.TapIP,
		TapIPv6:    n.Config.TapIPv6,
		TapMAC:     n.Config.TapMAC,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Version:    version.Version,
		IsExitNode: n.Config.ExitNode.Enable,
		// Carry advertised subnets in the LSA broadcast so peers that learn
		// our identity via the LSA / Peek-Map channel (not just the direct
		// P2P meta stream) also receive our routed LAN subnets.
		AdvertisedSubnets: n.Config.AdvertisedSubnets,
	})
	data, err := json.Marshal(lsa)
	if err != nil {
		return
	}

	// Gossip throttle: if the LSA content is byte-for-byte identical to the last
	// broadcast (topology + identity + links unchanged), skip re-sending. Neighbours
	// already hold this LSA and keep it alive via TTL, so a steady-state mesh no
	// longer re-floods the same payload every 15s.
	n.lastLSAMu.Lock()
	unchanged := bytes.Equal(n.lastLSAJSON, data)
	if !unchanged {
		n.lastLSAJSON = append(n.lastLSAJSON[:0], data...)
	}
	n.lastLSAMu.Unlock()
	if unchanged {
		log.Debug("LSA unchanged since last broadcast, skipping re-flood (seq=%d)", seq)
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
				finalPacked, complete := n.fragRX.reassemble(outer)
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

// handleEcho responds to P2P echo probe streams by echoing back the exact payload
// of each length-prefixed frame. It loops over ReadFrame so a single long-lived
// echo stream can serve many periodic probes (the client reuses the same stream
// via echoPool instead of opening a fresh NewStream every tick).
func (n *Node) handleEcho(s network.Stream) {
	defer s.Close()
	// Echo payloads in practice are tiny (32-byte probes, 4-byte "PING"
	// keepalives), but size the buffer well above that so a peer sending a
	// larger valid frame is echoed correctly instead of triggering
	// ReadFrame's "frame too large" rejection and tearing down the stream.
	buf := make([]byte, 4096)
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
		// Echo the exact payload bytes back as a length-prefixed frame.
		if err := WriteFrame(s, buf[:rn]); err != nil {
			return
		}
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
