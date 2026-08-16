package node

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/observer"
	"p2ptap/pkg/packet"
	"p2ptap/pkg/routing"
	vswitch "p2ptap/pkg/switch"
	"p2ptap/pkg/tap"
)

func (n *Node) tapReadLoop() {
	defer n.wg.Done()

	// The whole packet-parsing path hangs off this loop. A panic on a
	// malformed frame would otherwise take down the daemon and silently stop
	// all forwarding, so recover and restart the loop.
	defer func() {
		if r := recover(); r != nil {
			log.Error("TAP read loop panicked: %v\n%s", r, debug.Stack())
			if n.ctx.Err() == nil {
				n.wg.Add(1)
				go n.tapReadLoop()
			}
		}
	}()

	buf := make([]byte, obfuscate.MaxFrameSize)
	// Hold a fully-sealed on-wire frame. Pack() caps its own output at
	// MaxFrameSize (pre-AEAD), but the Node TX path then applies
	// EncryptPayloadRegion which appends a 16-byte AEAD tag, so the
	// worst-case sealed frame is MaxFrameSize + AEADTagSize — exactly
	// MaxSealedFrameSize. This must match the RX buffer sizing in
	// node_streams.go so a maximal frame is never truncated/reallocated.
	outBuf := make([]byte, obfuscate.MaxSealedFrameSize)

	// Try epoll-based event-driven I/O (Linux).  Falls back to timer-based
	// polling on non-Linux platforms transparently.
	if poller, err := tap.NewEpollPoller(n.TAP); err == nil {
		poller.NotifyOnCancel(n.ctx)
		defer poller.Close()
		n.tapReadLoopEpoll(poller, buf, outBuf)
		return
	}

	// Fallback: timer-based polling (macOS, Windows, others)
	n.tapReadLoopPoll(buf, outBuf)
}

// tapReadLoopEpoll uses epoll to block until the TAP fd is readable,
// then drains all queued frames in a batch.  Zero CPU burn when idle.
func (n *Node) tapReadLoopEpoll(poller *tap.EpollPoller, buf, outBuf []byte) {
	for {
		if err := poller.Wait(n.ctx); err != nil {
			log.Debug("TAP read loop stopped: %v", err)
			return
		}
		n.drainTapBatch(buf, outBuf)
	}
}

// tapReadLoopPoll is the fallback timer-based polling path for platforms
// without epoll (macOS, Windows).  It polls TAP.Read with a short timeout
// and batches up to 32 frames per pass.
func (n *Node) tapReadLoopPoll(buf, outBuf []byte) {
	readErrors := 0
	totalRead := 0
	lastStats := time.Now()
	for {
		select {
		case <-n.ctx.Done():
			log.Debug("TAP read loop stopped (context cancelled)")
			return
		default:
		}

		for batchIdx := 0; batchIdx < 32; batchIdx++ {
			readN, err := n.TAP.Read(buf)
			if err != nil {
				if err == io.EOF {
					log.Debug("TAP read loop stopped (EOF)")
					return
				}
				if errors.Is(err, tap.ErrReadTimeout) {
					break // No more frames available, exit batch
				}
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				readErrors++
				if readErrors == 1 || readErrors%100 == 0 {
					log.Warn("TAP read error on %s (count=%d): %v", n.TAP.Name(), readErrors, err)
				}
				break
			}
			readErrors = 0
			totalRead++

			if readN == 0 {
				continue
			}
			if readN < 14 {
				// Runt frame: drop. Capture happens only for valid frames
				// below so the collector never sees garbage.
				continue
			}
			if !n.processTapFrame(buf[:readN], outBuf) {
				return
			}
		}

		// Periodic diagnostic: show read activity every 30 seconds
		if now := time.Now(); now.Sub(lastStats) >= 30*time.Second {
			if totalRead > 0 {
				log.Debug("TAP read stats: %d frames in last 30s on %s", totalRead, n.TAP.Name())
			}
			totalRead = 0
			lastStats = now
		}
	}
}

// drainTapBatch reads up to 32 frames from TAP in a tight loop, calling
// processTapFrame for each.  It expects the fd to be readable (non-blocking
// reads succeed) and stops on the first EAGAIN / timeout.
func (n *Node) drainTapBatch(buf, outBuf []byte) {
	readErrors := 0
	totalRead := 0
	for batchIdx := 0; batchIdx < 32; batchIdx++ {
		readN, err := n.TAP.Read(buf)
		if err != nil {
			if err == io.EOF {
				log.Debug("TAP read loop stopped (EOF)")
				return
			}
			if errors.Is(err, tap.ErrReadTimeout) {
				break // No more frames available, exit batch
			}
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			readErrors++
			if readErrors == 1 || readErrors%100 == 0 {
				log.Warn("TAP read error on %s (count=%d): %v", n.TAP.Name(), readErrors, err)
			}
			break
		}
		readErrors = 0
		totalRead++

		if readN == 0 {
			continue
		}
		if readN < 14 {
			continue
		}

		// Process frame read from local TAP device
		if !n.processTapFrame(buf[:readN], outBuf) {
			log.Debug("TAP read loop terminating gracefully")
			return
		}
	}
}

// tapWrite is the single capture boundary for all frames injected into the TAP
// device (frames arriving from peers / overlay to local OS).
//
// It enforces an MTU upper bound: a frame larger than the OS device can accept
// must never be handed to it, because real TAP implementations reject oversized
// writes and the frame would be silently lost. Such oversized payloads can only
// originate from the (untrusted) overlay, so we drop and count them here.
//
// The configured MTU is the L3 MTU. A TAP (Ethernet) device carries the full
// L2 frame, so a maximum-size IP packet is carried as `mtu + EthernetHeaderLen`
// bytes on the device. Capping at exactly that real device limit (not at `mtu`)
// is essential: a tighter bound silently drops every valid full-MTU packet a
// peer sends (full 1500-byte IP datagrams arrive as 1514-byte frames), which
// breaks bulk TCP and large-payload connectivity.
func (n *Node) tapWrite(payload []byte) (int, error) {
	if len(payload) < 14 {
		log.Warn("tapWrite: dropping runt frame (len=%d < 14)", len(payload))
		return 0, nil
	}
	mtu := n.Config.MTU
	if mtu <= 0 {
		mtu = 1500
	}
	maxFrame := mtu + packet.EthernetHeaderLen
	if len(payload) > maxFrame {
		log.Warn("tapWrite: dropping oversized frame (len=%d > mtu+eth=%d)", len(payload), maxFrame)
		return 0, nil
	}
	if n.Collector != nil {
		n.Collector.CaptureFrameWithPeers(observer.DirRx, payload, "", "self")
	}
	return n.TAP.Write(payload)
}

// tapWriteUrgent injects a frame into the TAP device on the priority path.
// Used by diagnostics (TAP-probe echo reply) so a probe reply is not delayed
// behind a busy normal forwarding queue. It enqueues onto urgentWriteCh; the
// frame is drained by tapWriteUrgentLoop which owns the actual TAP.Write.
func (n *Node) tapWriteUrgent(payload []byte) {
	select {
	case n.urgentWriteCh <- payload:
	default:
		// Queue full: fall back to a direct synchronous write so the probe
		// reply is never silently dropped.
		if n.Collector != nil {
			n.Collector.CaptureFrameWithPeers(observer.DirRx, payload, "", "self")
		}
		_, _ = n.TAP.Write(payload)
	}
}

// tapWriteUrgentLoop drains the urgent TAP-write queue. The select prioritises
// urgentWriteCh over nothing else (it is the only source), but the design keeps
// the urgent path fully decoupled from the normal dispatchCh queue so a flooded
// forwarding path cannot starve diagnostic probe replies.
func (n *Node) tapWriteUrgentLoop() {
	defer n.wg.Done()
	for {
		select {
		case <-n.ctx.Done():
			return
		case payload := <-n.urgentWriteCh:
			if n.Collector != nil {
				n.Collector.CaptureFrameWithPeers(observer.DirRx, payload, "", "self")
			}
			if _, err := n.TAP.Write(payload); err != nil {
				log.Debug("urgent TAP write failed: %v", err)
			}
		}
	}
}

func (n *Node) dispatchExitTransitFrame(exitPID peer.ID, exitPeerID string, packedCopy []byte, rawPayload []byte, readN int, tag string) {
	if n.Collector != nil {
		n.Collector.CaptureFrameWithPeers(observer.DirTx, rawPayload, "self", exitPeerID)
	}
	routes := n.getCachedRoutes()
	route, hasRoute := routes[exitPID]

	if hasRoute && !route.IsDirect && route.NextHop != "" && route.NextHop != exitPID && route.NextHop != n.Host.ID() {
		log.Debug("Tx exit-transit (%s via relay %s): origLen=%d exitPeer=%s", tag, route.NextHop.String(), readN, exitPeerID)
		// END-TO-END seal for exitPID into a SEPARATE buffer; keep `packedCopy`
		// as the plaintext framed copy, because it is the direct-fallback payload
		// handed to SendToPeer, which seals it itself. Sealing it in place and
		// copying the ciphertext into the fallback would double-encrypt the frame
		// on the relay onFail path and corrupt it.
		inner := packedCopy
		if cipher := n.obfCipherForPeer(exitPID); cipher != nil {
			enc, eerr := n.sealPeerFrame(exitPID, cipher, packedCopy)
			if eerr != nil {
				log.Warn("Tx exit-transit: end-to-end seal for %s failed: %v (frame dropped rather than sent in plaintext)",
					exitPID.String(), eerr)
				releaseFrameBuf(packedCopy)
				return
			}
			inner = enc
		}
		// Wrap the relay envelope, then HOP-BY-HOP seal it for the relay hop.
		// IMPORTANT: sealRelayEnvelopeForHop Packs the bare PackRelayFrame output
		// into a real obfuscate frame FIRST and only then encrypts. Calling
		// EncryptPayloadRegion directly on the bare envelope (as this code used
		// to) read frame[11:13] inside the base58 PeerID string, always returned
		// ErrFrameCorrupted, and — with the old `if eerr==nil` guard — sent the
		// envelope in plaintext, which the hop silently dropped.
		if relayBuf, err := routing.PackRelayFrame(exitPID, n.Host.ID(), routing.MaxRelayTTL, inner); err == nil {
			sealed, serr := n.sealRelayEnvelopeForHop(route.NextHop, relayBuf)
			if serr != nil {
				log.Warn("Tx exit-transit: hop seal via %s failed: %v (frame dropped rather than sent in plaintext)",
					route.NextHop.String(), serr)
				releaseFrameBuf(packedCopy)
				return
			}
			// Direct-path fallback copy MUST stay the PLAINTEXT packed frame;
			// SendToPeer applies its own per-peer seal.
			fallbackCopy := make([]byte, len(packedCopy))
			copy(fallbackCopy, packedCopy)
			n.dispatchNonblocking(dispatchTask{
				kind:      2,
				target:    exitPID,
				relayHop:  route.NextHop,
				data:      fallbackCopy,
				relayData: sealed,
				origLen:   readN,
			})
			releaseFrameBuf(packedCopy)
			return
		}
	}
	log.Debug("Tx Pack exit-transit (%s direct): origLen=%d exitPeer=%s", tag, readN, exitPeerID)
	n.dispatchNonblocking(dispatchTask{
		kind:    0,
		target:  exitPID,
		data:    packedCopy,
		origLen: readN,
		owned:   true,
	})
}

// canEgressToPeer reports whether a TAP frame destined for peer p may be
// emitted right now (the link is "usable"). It is relay-aware:
//
//   - Direct peer: usable once the mutual "ready" handshake completed OR we
//     hold a locally-negotiated cipher for it (relaxed rule — the peer
//     self-heals its own readiness on the first frame it decrypts).
//   - Relayed (non-direct) destination: the final peer is by definition never
//     directly connected, so gating on ITS readiness would always be false and
//     blackhole every relay-only frame. Instead we gate on the RELAY HOP's
//     readiness (the hop IS directly connected, so its readiness is the correct
//     usability signal). This is what previously dropped all overlay-relay
//     traffic (the "forward through relay node" bug) and what the broadcast
//     fan-out needs so discovery frames (ARP/NDP/mDNS) reach relay-only peers.
//
// A peer with neither a usable direct link nor any relay route is genuinely
// unreachable, so we report false (caller drops the frame).
func (n *Node) canEgressToPeer(p peer.ID) bool {
	if n.isPeerReady(p) || n.obfCipherForPeer(p) != nil {
		return true
	}
	if hop := n.relayHopForTarget(p); hop != "" {
		// A boot-relay hop is a relay-over-backbone bridge, NOT a mesh peer: we
		// hold no SeqSync cipher or "ready" flag for the boot itself (it never
		// runs the handshake with us). Its reachability is purely whether the
		// persistent boot-relay uplink is alive, so gate on that. This is what
		// previously blackholed every broadcast wave AND every unicast frame to a
		// NAT'd peer reachable only through a boot: canEgressToPeer returned
		// false because the boot was never "directly connected" to the target.
		if n.isBootstrapPeer(hop) {
			return n.hasBootRelayUplink(hop)
		}
		if n.isPeerReady(hop) || n.obfCipherForPeer(hop) != nil {
			// An overlay-relay hop (a regular peer forwarding the frame
			// hop-by-hop) reaches the target directly, so hop readiness alone
			// is the correct signal (TestCanEgressToPeerRelayAware locks this
			// in for relay-only C).
			return true
		}
	}
	return false
}

// It runs ARP/NDP proxy, WebUI intercept, and dispatch to peers.
// Returns false if the read loop should terminate (unrecoverable error).
func (n *Node) processTapFrame(payload, outBuf []byte) bool {
	readN := len(payload)

	// ARP proxy handling. Require opcode == Request(1) AND protocol ==
	// IPv4 so we don't mis-read the target IP field of an ARP carrying a
	// different protocol (e.g. ARP for IPv6 / non-Ethernet HW types), which
	// would otherwise resolve the wrong address.
	if len(payload) >= 42 &&
		binary.BigEndian.Uint16(payload[12:14]) == packet.EtherTypeARP &&
		binary.BigEndian.Uint16(payload[16:18]) == packet.EtherTypeIPv4 &&
		binary.BigEndian.Uint16(payload[20:22]) == 1 {
		targetIP := net.IP(payload[38:42])
		senderIP := net.IP(payload[28:32])
		senderMAC := net.HardwareAddr(payload[22:28])

		res := n.resolveProxyMAC(targetIP, n.lookupPeerMACByIPv4, n.lookupPeerMACByAdvertisedSubnet,
			func(ip net.IP) bool {
				return tap.ShouldRespondToARP(ip, n.localV4IP, n.virtualWebUIV4IP, n.localV4Net)
			})
		if res.via != proxyViaNone {
			reply := tap.BuildARPReplyFrame(res.mac, senderMAC, targetIP, senderIP)
			if _, err := n.tapWrite(reply); err != nil {
				log.Debug("ARP proxy reply for %s write failed: %v", targetIP, err)
			}
			if res.via == proxyViaPeer {
				n.MACTable.Learn(res.mac, res.peerID)
			} else if res.via == proxyViaSubnet {
				if pid := n.lookupPeerIDByAdvertisedSubnet(targetIP); pid != "" {
					n.MACTable.Learn(res.mac, pid)
				}
			} else if res.via == proxyViaExit {
				if pid := n.Gateway.ActiveExitPeerPID(); pid != "" {
					n.MACTable.Learn(res.mac, pid)
				}
			} else if res.via != proxyViaLocal {
				log.Debug("ARP proxy: %s resolved via %v peer MAC %s", targetIP, res.via, res.mac.String())
			} else {
				log.Debug("ARP reply for local IP %s", targetIP)
			}
			return true
		}
	}

	// IPv6 NDP proxy handling — same four-stage decision as ARP above.
	// Minimum valid Neighbor Solicitation is 78 bytes (14 eth + 40 IPv6 + 24
	// NS base); the Source Link-Layer Address Option is optional, so we must
	// not require the full 86-byte frame or we silently drop legitimate NS.
	if len(payload) >= 78 &&
		binary.BigEndian.Uint16(payload[12:14]) == packet.EtherTypeIPv6 &&
		payload[20] == 58 &&
		payload[54] == 135 {

		targetIPv6 := net.IP(payload[62:78])
		senderIPv6 := net.IP(payload[22:38])

		res := n.resolveProxyMAC(targetIPv6, n.lookupPeerMACByIPv6, n.lookupPeerMACByAdvertisedSubnet,
			func(ip net.IP) bool {
				return ip.Equal(n.localV6IP) ||
					(n.virtualWebUIV6IP != nil && ip.Equal(n.virtualWebUIV6IP))
			})
		if res.via != proxyViaNone {
			naFrame := tap.BuildIPv6NeighborAdvertisementFrame(res.mac, targetIPv6, senderIPv6)
			if len(naFrame) > 0 {
				if _, err := n.tapWrite(naFrame); err != nil {
					log.Debug("NDP NA reply (%v) for %s write failed: %v", res.via, targetIPv6, err)
				}
			}
			if res.via == proxyViaPeer {
				n.MACTable.Learn(res.mac, res.peerID)
			} else if res.via == proxyViaSubnet {
				if pid := n.lookupPeerIDByAdvertisedSubnet(targetIPv6); pid != "" {
					n.MACTable.Learn(res.mac, pid)
				}
			} else if res.via == proxyViaExit {
				if pid := n.Gateway.ActiveExitPeerPID(); pid != "" {
					n.MACTable.Learn(res.mac, pid)
				}
			}
			return true
		}
	}

	if n.Interceptor != nil && n.Interceptor.MatchAndHandle(payload, n.TAP) {
		return true
	}

	if n.isLocalWebUIVirtualPacket(payload) {
		log.Debug("TAP frame involves local WebUI virtual IP/MAC, dropping from P2P overlay dispatch")
		return true
	}

	dstMAC, srcMAC, errExtract := vswitch.ExtractEthernetMACs(payload)
	if errExtract {
		log.Debug("TAP frame MAC extraction failed (len=%d) from %s", readN, n.TAP.Name())
		return true
	}
	if log.IsDebug() {
		log.Debug("TAP read: len=%d %s", readN, describeEthernetFrame(payload))
	}

	// Learn srcMAC only if it differs from our own configured TapMAC.
	// The local OS may emit frames with EUI-64 derived synthetic MACs
	// (e.g. from IPv6 link-local IID) that should NOT pollute the MAC table
	// as a second "local" entry.
	if !bytes.Equal(srcMAC, n.localMAC) {
		n.MACTable.Learn(srcMAC, n.Host.ID())
	}
	if len(payload) >= 14 {
		n.Collector.RecordFrame(payload)
	}
	n.IPTracker.ExtractAndRecord(payload, true)

	targetPeer, found := n.MACTable.Lookup(dstMAC)
	if !found {
		// Fallback: when the MAC table has no entry for dstMAC (e.g. the peer
		// hasn't sent a frame yet, so we never learned its MAC), resolve the
		// destination IP directly from the frame (direct TAP IP, advertised LAN subnet,
		// or runtime IPTracker) and look up the owning mesh peer.
		if dstIP := extractFrameDstIP(payload); dstIP != nil {
			if pid, mac := n.resolvePeerIDByIP(dstIP); pid != "" && pid != n.Host.ID() {
				targetPeer = pid
				found = true
				// Self-learn the peer's tapMAC so that subsequent frames
				// addressed to this MAC hit the direct path via MACTable.Lookup
				// instead of re-resolving through the IP fallback (which can
				// route via relay/boot and cause one-direction stutter).
				if len(mac) == 6 {
					n.MACTable.Learn(mac, pid)
				}
			}
		}
	}
	if found && targetPeer != n.Host.ID() {
		// Resolve the route up-front. For a RELAYED destination the final peer is
		// by definition never directly connected, so the "is the link usable" gate
		// below must check the RELAY HOP's readiness (route.NextHop), not the
		// final destination's. Gating on targetPeer's readiness previously dropped
		// every relay-only frame here — before it ever reached the relay branch —
		// blackholing all multi-hop / overlay-relay traffic (e.g. A -> relay ->
		// C could never deliver).
		routes := n.getCachedRoutes()
		route, hasRoute := routes[targetPeer]

		// Relay-aware usability gate (shared helper): for a relayed destination
		// the final peer is never directly connected, so canEgressToPeer gates
		// on the RELAY HOP's readiness rather than the destination's. Gating on
		// the destination's readiness previously dropped every relay-only frame
		// here — before it ever reached the relay branch — blackholing all
		// multi-hop / overlay-relay traffic (e.g. A -> relay -> C could never
		// deliver).
		if !n.canEgressToPeer(targetPeer) {
			return true
		}

		seqID := n.Packer.NextSeqID(n.txEpochForPeer(targetPeer))
		totalLen, perr := n.Packer.Pack(seqID, payload, outBuf)
		if perr != nil {
			log.Debug("Frame pack error: %v", perr)
			return true
		}
		// Copy out of the shared outBuf into a pooled buffer: the read buffer is
		// reused on the next TAP read while the worker runs in another goroutine.
		packedCopy := acquireFrameBuf(totalLen)
		copy(packedCopy, outBuf[:totalLen])
		n.Collector.RecordPacketDir(payload, true)
		n.Collector.RecordTxSeq(targetPeer.String(), seqID)
		if n.Collector != nil {
			n.Collector.CaptureFrameWithPeers(observer.DirTx, payload, "self", targetPeer.String())
		}
		log.Debug("Tx Pack: seq=%d origLen=%d packedLen=%d mode=%s dst=%s", seqID, readN, totalLen, n.Packer.Mode, targetPeer.String())

		if hasRoute && !route.IsDirect && route.NextHop != "" && route.NextHop != targetPeer && route.NextHop != n.Host.ID() {
			log.Debug("Tx overlay relay: seq=%d len=%d dst=%s via nextHop=%s (totalRTT=%dms vs directRTT=%dms)",
				seqID, readN, targetPeer.String(), route.NextHop.String(), route.TotalRTTMs, route.DirectRTTMs)
			// Direct-path fallback copy MUST remain the PLAINTEXT packed frame.
			// dispatchWorker's relay onFail handler hands task.data to SendToPeer,
			// which applies its OWN per-peer seal. Copying an already-sealed frame
			// here made that fallback double-encrypt it, and the destination — which
			// opens exactly once — dropped every such frame. Taking the copy BEFORE
			// any sealing keeps the two paths independent and correct.
			fallbackCopy := make([]byte, totalLen)
			copy(fallbackCopy, packedCopy)

			// END-TO-END seal: the inner payload is encrypted for targetPeer so the
			// relay cannot read it; only the final destination can open it. The
			// result goes into `inner`, never back into packedCopy: overwriting the
			// pooled slice with this heap allocation leaked the pooled buffer and
			// then fed the unrelated allocation to releaseFrameBuf, corrupting the
			// frame pool's size assumptions.
			inner := packedCopy
			if cipher := n.obfCipherForPeer(targetPeer); cipher != nil {
				enc, eerr := n.sealPeerFrame(targetPeer, cipher, inner)
				if eerr != nil {
					log.Warn("Tx overlay relay: end-to-end seal for %s failed: %v (frame dropped rather than sent in plaintext)",
						targetPeer.String(), eerr)
					releaseFrameBuf(packedCopy)
					return true
				}
				inner = enc
			}
			// HOP-BY-HOP: wrap the relay envelope in an obfuscate frame and seal it
			// for the relay hop, so only that hop can read the routing header. The
			// inner payload stays end-to-end encrypted for targetPeer and is never
			// readable by the relay.
			if relayBuf, rerr := routing.PackRelayFrame(targetPeer, n.Host.ID(), routing.MaxRelayTTL, inner); rerr != nil {
				log.Warn("Tx overlay relay: pack envelope for %s failed: %v", targetPeer.String(), rerr)
			} else if sealed, serr := n.sealRelayEnvelopeForHop(route.NextHop, relayBuf); serr != nil {
				log.Warn("Tx overlay relay: hop seal via %s failed: %v", route.NextHop.String(), serr)
		} else {
			n.dispatchNonblocking(dispatchTask{
					kind:      2,
					target:    targetPeer,
					relayHop:  route.NextHop,
					data:      fallbackCopy,
					relayData: sealed,
					origLen:   readN,
				})
			}
			// packedCopy is still the ORIGINAL pooled slice (the seals above wrote
			// to `inner`), and its contents now live in fallbackCopy and the relay
			// envelope. Releasing it here is therefore safe and leak-free.
			releaseFrameBuf(packedCopy)
		} else {
			n.dispatchNonblocking(dispatchTask{
				kind:    0,
				target:  targetPeer,
				dstMAC:  dstMAC,
				data:    packedCopy,
				origLen: readN,
				owned:   true,
			})
		}
	} else if !found {
		// Unknown unicast / broadcast — fall through to the broadcast handling
		// block below, which performs the Exit Node redirect when applicable.
	} else {
		// found && targetPeer == n.Host.ID(): the frame is addressed to our own
		// TAP MAC. This happens when the local OS ARPed for the Exit Node peer's
		// IP (e.g. the default-route gateway) and the Exit Node ARP proxy fell
		// back to the local MAC because the peer's real MAC was not yet learned.
		// Delivering such a frame "to ourselves" would just drop it, blackholing
		// the entire Exit Node tunnel. Redirect it to the Exit Node peer by peer
		// ID so the tunnel comes up even before the peer's MAC is discovered.
		if n.isExitNodeActive() {
			exitPeerID := n.Gateway.ActiveExitPeerID()
			if exitPeerID != "" && exitPeerID != n.Host.ID().String() {
				seqID := n.Packer.NextSeqID(n.txEpochForPeer(peer.ID(exitPeerID)))
				totalLen, perr := n.Packer.Pack(seqID, payload, outBuf)
				if perr != nil {
					log.Debug("Frame pack error: %v", perr)
					return true
				}
				packedCopy := acquireFrameBuf(totalLen)
				copy(packedCopy, outBuf[:totalLen])
				n.Collector.RecordPacketDir(payload, true)
				n.Collector.RecordTxSeq(exitPeerID, seqID)
				// Count only UNICAST frames as genuine egress; broadcast/multicast
				// (ARP/DHCP/mDNS) are local L2 and must not inflate the gateway
				// counter (they are already binned by RecordPacketDir).
				if len(payload) >= 6 && payload[0]&1 == 0 {
					n.Collector.RecordGatewayPacket()
				}
				exitPID := n.Gateway.ActiveExitPeerPID()
				log.Debug("Tx Pack exit-transit (local-MAC redirect): seq=%d origLen=%d packedLen=%d exitPeer=%s", seqID, readN, totalLen, exitPeerID)
				n.dispatchExitTransitFrame(exitPID, exitPeerID, packedCopy, payload, readN, "local-MAC redirect")
				return true
			}
		}
		// Genuinely local frame — nothing to forward.
		return true
	}

	// From here we handle broadcast / unknown-unicast frames.
	{
		// Exit Node special case — minimise broadcast:
		// When an Exit Node tunnel is active, the only sane destination for an
		// unknown/unicast-broadcast frame from the local OS is the Exit Node
		// peer (the OS is ARPing for a public IP it routed into the TAP, or
		// emitting transit traffic whose next-hop MAC it has not learned yet).
		// Flooding such frames to EVERY peer would leak the client's traffic to
		// the whole mesh and is exactly what we must avoid. So we send it ONLY
		// to the Exit Node peer (addressed by peer ID, NOT by a learned MAC, so
		// it works even before the Exit Node peer's MAC has been discovered).
		if n.isExitNodeActive() {
			// Check if target IP is a Mesh / LAN Subnet IP vs an external Internet IP:
			dstIP := extractFrameDstIP(payload)
			isMeshOrSubnet := false
			if dstIP != nil {
				if dstIP.To4() != nil {
					if n.localV4Net != nil && n.localV4Net.Contains(dstIP) {
						isMeshOrSubnet = true
					} else if pid := n.lookupPeerIDByAdvertisedSubnet(dstIP); pid != "" {
						isMeshOrSubnet = true
					}
				} else {
					if n.localV6Net != nil && n.localV6Net.Contains(dstIP) {
						isMeshOrSubnet = true
					} else if mac, _ := n.lookupPeerMACByIPv6(dstIP); mac != nil {
						isMeshOrSubnet = true
					} else if pid := n.lookupPeerIDByAdvertisedSubnet(dstIP); pid != "" {
						isMeshOrSubnet = true
					}
				}
			}
			// Only hijack to Exit Node if it's NOT a mesh/subnet IP (i.e. WAN/Internet traffic)
			if !isMeshOrSubnet {
				exitPeerID := n.Gateway.ActiveExitPeerID()
				exitPID := n.Gateway.ActiveExitPeerPID()
				if exitPeerID != "" && exitPeerID != n.Host.ID().String() {
					seqID := n.Packer.NextSeqID(n.txEpochForPeer(peer.ID(exitPeerID)))
					totalLen, perr := n.Packer.Pack(seqID, payload, outBuf)
					if perr != nil {
						log.Debug("Frame pack error: %v", perr)
						return true
					}
					packedCopy := acquireFrameBuf(totalLen)
					copy(packedCopy, outBuf[:totalLen])
					n.Collector.RecordPacketDir(payload, true)
					n.Collector.RecordTxSeq(exitPeerID, seqID)
					// Count only UNICAST frames as genuine egress (see above);
					// broadcast/multicast stay on the LAN and are not egress.
					if len(payload) >= 6 && payload[0]&1 == 0 {
						n.Collector.RecordGatewayPacket()
					}
					log.Debug("Tx Pack exit-transit (no flood): seq=%d origLen=%d packedLen=%d exitPeer=%s", seqID, readN, totalLen, exitPeerID)
					n.dispatchExitTransitFrame(exitPID, exitPeerID, packedCopy, payload, readN, "no flood")
					return true
				}
			}
		}

		// Normal mesh behaviour: flood broadcast / unknown-unicast to all peers
		// so L2 discovery (ARP/NDP for peer-advertised subnets, service
		// discovery) works across the whole overlay.
		n.Collector.RecordPacketDir(payload, true)
		if n.Collector != nil {
			n.Collector.CaptureFrameWithPeers(observer.DirTx, payload, "self", "broadcast")
		}
		// NOTE: the frame is NOT Packed here. BroadcastToAllPeers Packs it
		// PER-PEER (each peer gets its OWN anti-replay epoch baked into the
		// SeqID), so a reconnect of one peer never disturbs another. We hand the
		// raw TAP payload to the dispatcher; copy it first so the async fan-out
		// never races with the next TAP read. The per-peer Tx seq is recorded
		// inside the fan-out.
		bcastPayload := acquireFrameBuf(len(payload))
		copy(bcastPayload, payload)
		log.Debug("Tx broadcast: origLen=%d mode=%s", readN, n.Packer.Mode)
		n.dispatchNonblocking(dispatchTask{
			kind:    1,
			data:    bcastPayload,
			origLen: readN,
			owned:   true,
		})
	}
	return true
}

// lookupPeerMACByIPv6 searches peerMeta for a peer whose TapIPv6 matches the given
// IPv6 address and returns its TapMAC.  Returns nil when no matching peer is found
// or when the MAC cannot be parsed.
