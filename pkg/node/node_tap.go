package node

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"sync/atomic"
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

		batchReadCount := 0
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
			batchReadCount++

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

		// Prevent tight CPU spinning when idle or on read errors/timeouts
		if batchReadCount == 0 {
			if readErrors > 0 {
				time.Sleep(10 * time.Millisecond)
			} else {
				time.Sleep(1 * time.Millisecond)
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
const ethernetHeaderLen = 14

// tapInjectionWriter prevents optional inline services (the local WebUI
// interceptor) from bypassing the same validation, serialization and logging
// used by overlay and ARP/NDP delivery.
type tapInjectionWriter struct{ node *Node }

func (w tapInjectionWriter) Write(payload []byte) (int, error) {
	return w.node.tapWrite(payload)
}

func (n *Node) tapWrite(payload []byte) (int, error) {
	if len(payload) < 14 {
		return 0, fmt.Errorf("tap write: dropping runt frame (len=%d < %d)", len(payload), ethernetHeaderLen)
	}
	maxFrameLen := obfuscate.MaxFrameSize
	// MTU is immutable for the lifetime of the native device. Use the
	// construction-time configuration rather than the hot-reload snapshot so a
	// persisted MTU change cannot alter validation before the interface restarts.
	if n.Config != nil && n.Config.MTU > 0 {
		if mtuFrameLen := n.Config.MTU + ethernetHeaderLen; mtuFrameLen < maxFrameLen {
			maxFrameLen = mtuFrameLen
		}
	}
	if len(payload) > maxFrameLen {
		return 0, fmt.Errorf("tap write: dropping oversized frame (len=%d > limit=%d)", len(payload), maxFrameLen)
	}
	if n.TAP == nil {
		return 0, errors.New("tap write: no TAP device")
	}

	n.tapWriteMu.Lock()
	defer n.tapWriteMu.Unlock()
	nn, err := n.TAP.Write(payload)
	if err == nil && nn != len(payload) {
		err = io.ErrShortWrite
	}
	if err != nil {
		log.Warn("TAP inject failed on %s: len=%d wrote=%d err=%v", n.TAP.Name(), len(payload), nn, err)
		return nn, err
	}
	if log.IsDebug() {
		log.Debug("TAP inject: device=%s len=%d dstMAC=%s srcMAC=%s", n.TAP.Name(), nn,
			net.HardwareAddr(payload[0:6]).String(), net.HardwareAddr(payload[6:12]).String())
	}
	return nn, nil
}

// tapWriteUrgent injects a frame into the TAP device on the priority path.
// Used by diagnostics (TAP-probe echo reply) so a probe reply is not delayed
// behind a busy normal forwarding queue. It enqueues onto urgentWriteCh; the
// frame is drained by tapWriteUrgentLoop which owns the actual TAP.Write.
func (n *Node) tapWriteUrgent(payload []byte) {
	// Defense in depth: this injects a frame into the local TAP device. If the
	// node has no TAP device (TAP init failed, or a node type that runs without
	// one), n.TAP is nil and the select's default branch would dereference a nil
	// interface and panic — which, inside a libp2p stream handler, resets the
	// stream with "Application error 0x0". A probe (or any future caller) must
	// never crash the handler on a TAP-less peer, so no-op safely instead.
	if n.TAP == nil {
		return
	}
	// The urgent writer runs asynchronously, so never allow a caller-owned
	// receive buffer to be reused before the device consumes it.
	frame := append([]byte(nil), payload...)
	select {
	case n.urgentWriteCh <- frame:
	default:
		// Queue full: use the same serialized boundary rather than bypassing it.
		if _, err := n.tapWrite(frame); err != nil {
			log.Debug("urgent TAP write failed: %v", err)
		}
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
			if _, err := n.tapWrite(payload); err != nil {
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

	if hasRoute && !route.IsDirect && route.NextHop != "" && route.NextHop != exitPID && route.NextHop != n.Host.ID() && !n.isBootstrapPeer(route.NextHop) {

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
	if n.isPeerReady(p) || n.obfCipherForPeer(p) != nil || n.isDirectlyConnected(p) {
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
			// A blacklisted boot can never host a relay uplink; never egress
			// through it (fall through to false so the caller drops / retries).
			return n.hasBootRelayUplink(hop) && !n.isBootRelayBlacklisted(hop)
		}
		if n.isPeerReady(hop) || n.obfCipherForPeer(hop) != nil || n.isDirectlyConnected(hop) {
			// An overlay-relay hop (a regular peer forwarding the frame
			// hop-by-hop) reaches the target directly, so hop readiness or direct
			// connection is the correct signal.
			return true
		}
	}
	return false
}

// maybeDeliverProbeReply captures inbound ICMP echo-reply frames that belong to
// a running TAP-probe and hands them to the waiting prober. It is called from the
// overlay RECEIVE path (see node_streams.go, just before a peer frame is written
// into our TAP) — NOT from the TAP read loop — because a TUN/TAP device does not
// re-deliver a frame written to it back to its own read side: the echo reply that
// left the peer's real TAP, crossed the overlay, and is about to be injected into
// OUR real TAP must be captured on the receive path to make ProbeTapForward a
// genuine both-directions TAP-path test.
//
// Only a structural check is done here (ICMP echo reply + our probe identifier +
// dst IP == our TAP IP). The specific peer (src MAC/IP) is validated later by
// waitProbeReply, so this cheap pre-filter can serve any peer being probed and
// never blocks the receive loop. Returns true if the frame was a probe reply
// (captured); the capture is non-blocking so a full buffer simply drops the frame
// and the prober can retry.
func (n *Node) maybeDeliverProbeReply(payload []byte) bool {
	if atomic.LoadInt32(&n.probeActive) == 0 {
		return false
	}
	// Minimum: Ethernet(14) + IPv4(20) + ICMP(8) = 42; the ICMP identifier we
	// need to match lives inside the ICMP header.
	if len(payload) < 42 {
		log.Debug("probe-reply skip: frame too short (%d bytes)", len(payload))
		return false
	}
	if binary.BigEndian.Uint16(payload[12:14]) != 0x0800 {
		log.Debug("probe-reply skip: not IPv4 (ethertype=0x%x)", binary.BigEndian.Uint16(payload[12:14]))
		return false // not IPv4
	}
	ihl := int(payload[14]&0x0f) * 4
	if ihl < 20 || len(payload) < 14+ihl+8 {
		log.Debug("probe-reply skip: bad IHL=%d or frame too short (len=%d)", payload[14]&0x0f, len(payload))
		return false
	}
	if payload[14+9] != 1 { // protocol ICMP
		log.Debug("probe-reply skip: not ICMP (proto=%d)", payload[14+9])
		return false
	}
	icmpStart := 14 + ihl
	if payload[icmpStart] != 0 { // ICMP type 0 = echo reply
		log.Debug("probe-reply skip: not echo reply (type=%d)", payload[icmpStart])
		return false
	}
	if binary.BigEndian.Uint16(payload[icmpStart+4:icmpStart+6]) != tapProbeICMPIdentify {
		log.Debug("probe-reply skip: ICMP id mismatch (got 0x%x, want 0x%x) — likely a normal ping, not our probe",
			binary.BigEndian.Uint16(payload[icmpStart+4:icmpStart+6]), tapProbeICMPIdentify)
		return false
	}
	dstIP := net.IP(payload[14+16 : 14+20]).To4()
	if n.localV4IP == nil || !dstIP.Equal(n.localV4IP) {
		log.Debug("probe-reply skip: dstIP mismatch (got=%v want=%v) — frame not addressed to our TAP",
			dstIP, n.localV4IP)
		return false
	}
	// Genuine probe echo reply inbound on the real TAP path: hand a copy to the
	// waiting prober without blocking the receive loop.
	buf := make([]byte, len(payload))
	copy(buf, payload)
	select {
	case n.probeReplyCh <- buf:
	default:
	}
	return true
}

// It runs ARP/NDP proxy, WebUI intercept, and dispatch to peers.
// Returns false if the read loop should terminate (unrecoverable error).
func (n *Node) processTapFrame(payload, outBuf []byte) bool {
	readN := len(payload)
	if log.IsDebug() && readN >= ethernetHeaderLen {
		// This deliberately precedes ARP/NDP proxy early-returns so debug mode
		// confirms a frame was read even when it never reaches generic forwarding.
		log.Debug("TAP ingress: len=%d %s", readN, describeEthernetFrame(payload))
	}

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
		if log.IsDebug() {
			log.Debug("TAP ARP request: senderIP=%s senderMAC=%s targetIP=%s", senderIP, senderMAC, targetIP)
		}

		isDAD := senderIP == nil || senderIP.IsUnspecified() || (n.localV4IP != nil && senderIP.Equal(n.localV4IP))
		res := n.resolveProxyMAC(targetIP, n.lookupPeerMACByIPv4, n.lookupPeerMACByAdvertisedSubnet,
			func(ip net.IP) bool {
				if isDAD && n.localV4IP != nil && ip.Equal(n.localV4IP) {
					return false
				}
				return tap.ShouldRespondToARP(ip, n.localV4IP, n.virtualWebUIV4IP, n.localV4Net)
			})
		if res.via != proxyViaNone {
			reply := tap.BuildARPReplyFrame(res.mac, senderMAC, targetIP, senderIP)
			if _, err := n.tapWrite(reply); err != nil {
				log.Debug("ARP proxy reply for %s write failed: %v", targetIP, err)
			} else if log.IsDebug() {
				log.Debug("TAP ARP proxy reply: targetIP=%s via=%s resolvedMAC=%s", targetIP, res.via, res.mac)
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
		senderMAC := net.HardwareAddr(payload[6:12])
		if log.IsDebug() {
			log.Debug("TAP NDP solicitation: senderIP=%s senderMAC=%s targetIP=%s", senderIPv6, senderMAC, targetIPv6)
		}

		isV6DAD := senderIPv6 == nil || senderIPv6.IsUnspecified() || (n.localV6IP != nil && senderIPv6.Equal(n.localV6IP))
		res := n.resolveProxyMAC(targetIPv6, n.lookupPeerMACByIPv6, n.lookupPeerMACByAdvertisedSubnet,
			func(ip net.IP) bool {
				if isV6DAD && n.localV6IP != nil && ip.Equal(n.localV6IP) {
					return false
				}
				return ip.Equal(n.localV6IP) ||
					(n.virtualWebUIV6IP != nil && ip.Equal(n.virtualWebUIV6IP))
			})
		if res.via != proxyViaNone {
			naFrame := tap.BuildIPv6NeighborAdvertisementFrameWithMAC(res.mac, senderMAC, targetIPv6, senderIPv6)
			if len(naFrame) > 0 {
				if _, err := n.tapWrite(naFrame); err != nil {
					log.Debug("NDP NA reply (%v) for %s write failed: %v", res.via, targetIPv6, err)
				} else if log.IsDebug() {
					log.Debug("TAP NDP proxy reply: targetIP=%s via=%s resolvedMAC=%s", targetIPv6, res.via, res.mac)
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

	if n.Interceptor != nil && n.Interceptor.MatchAndHandle(payload, tapInjectionWriter{node: n}) {
		return true
	}

	if n.isLocalWebUIVirtualPacket(payload) {
		var srcIPStr string
		if len(payload) >= 30 && binary.BigEndian.Uint16(payload[12:14]) == 0x0800 {
			srcIPStr = net.IP(payload[26:30]).String()
		}
		log.Debug("TAPFWD DROP: frame involves local WebUI virtual IP/MAC, dropped from overlay dispatch (srcIP=%s)", srcIPStr)
		return true
	}

	dstMAC, srcMAC, okExtract := vswitch.ExtractEthernetMACs(payload)
	if !okExtract {
		log.Debug("TAP frame MAC extraction failed (len=%d) from %s", readN, n.TAP.Name())
		return true
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
		if log.IsDebug() {
			log.Debug("TAPFWD resolve: MACTable MISS dstMAC=%s srcMAC=%s", dstMAC.String(), srcMAC.String())
		}
		// Fallback: when the MAC table has no entry for dstMAC (e.g. the peer
		// hasn't sent a frame yet, so we never learned its MAC), resolve the
		// destination IP directly from the frame (direct TAP IP, advertised LAN subnet,
		// or runtime IPTracker) and look up the owning mesh peer.
		if dstIP := extractFrameDstIP(payload); dstIP != nil {
			pid, mac := n.resolvePeerIDByIP(dstIP)
			if len(mac) == 0 {
				if log.IsDebug() {
					log.Debug("TAPFWD resolve: dstIP=%s resolvePeerIDByIP => pid=(empty) mac=(none) [NOT found]", dstIP.String())
				}
			} else {
				if log.IsDebug() {
					log.Debug("TAPFWD resolve: dstIP=%s resolvePeerIDByIP => pid=%s mac=%s [found]", dstIP.String(), pid.String(), mac.String())
				}
			}
			if pid != "" && pid != n.Host.ID() {
				targetPeer = pid
				found = true
				// Self-learn the peer's tapMAC so that subsequent frames
				// addressed to this MAC hit the direct path via MACTable.Lookup
				// instead of re-resolving through the IP fallback (which can
				// route via relay/boot and cause one-direction stutter).
				if len(mac) == 6 {
					n.MACTable.Learn(mac, pid)
					// If the incoming L3 frame was synthesized with a broadcast MAC (e.g. Wintun initial ping),
					// or carries a synthetic/differing unicast dstMAC from local OS ARP cache,
					// learn the incoming dstMAC as well so subsequent frames hit MACTable directly,
					// and rewrite payload dstMAC to the target peer's genuine unicast MAC so Linux/Windows kernel
					// accepts and responds to unicast ICMP/TCP/UDP.
					if len(payload) >= 6 && !bytes.Equal(payload[0:6], mac) {
						if !isBroadcastOrMulticastMAC(dstMAC) {
							n.MACTable.Learn(dstMAC, pid)
						}
						copy(payload[0:6], mac)
						dstMAC = mac
					}
				}
			}
		} else {
			log.Debug("TAPFWD resolve: dstIP extraction failed (ethertype=%04x len=%d)", binary.BigEndian.Uint16(payload[12:14]), len(payload))
		}
	} else {
		if log.IsDebug() {
			log.Debug("TAPFWD resolve: MACTable HIT dstMAC=%s => targetPeer=%s", dstMAC.String(), targetPeer.String())
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
			hop := n.relayHopForTarget(targetPeer)
			bootUplink := hop != "" && n.isBootstrapPeer(hop) && n.hasBootRelayUplink(hop)
			if log.IsDebug() {
				log.Debug("TAPFWD DROP: canEgressToPeer=false for targetPeer=%s (isPeerReady=%v cipherPresent=%v relayHop=%s bootUplink=%v)",
					targetPeer.String(),
					n.isPeerReady(targetPeer),
					n.obfCipherForPeer(targetPeer) != nil,
					hop.String(),
					bootUplink)
			}
			n.triggerOnDemandConnect(targetPeer)
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
		n.Collector.RecordTxSeq(n.peerIDString(targetPeer), seqID)
		if n.Collector != nil {
			n.Collector.CaptureFrameWithPeers(observer.DirTx, payload, "self", n.peerIDString(targetPeer))
		}
		if log.IsDebug() {
			log.Debug("Tx Pack: seq=%d origLen=%d packedLen=%d mode=%s dst=%s", seqID, readN, totalLen, n.Packer.Mode, targetPeer.String())
		}

		if hasRoute && !route.IsDirect && route.NextHop != "" && route.NextHop != targetPeer && route.NextHop != n.Host.ID() && !n.isBootstrapPeer(route.NextHop) {
			if log.IsDebug() {
				log.Debug("Tx overlay relay: seq=%d len=%d dst=%s via nextHop=%s (totalRTT=%dms vs directRTT=%dms)",

					seqID, readN, targetPeer.String(), route.NextHop.String(), route.TotalRTTMs, route.DirectRTTMs)
			}
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
				log.Warn("Tx overlay relay: pack envelope for %s failed: %v; dispatching plaintext packed fallback", targetPeer.String(), rerr)
				n.dispatchNonblocking(dispatchTask{
					kind:    0,
					target:  targetPeer,
					dstMAC:  dstMAC,
					data:    fallbackCopy,
					origLen: readN,
				})
			} else if sealed, serr := n.sealRelayEnvelopeForHop(route.NextHop, relayBuf); serr != nil {
				log.Warn("Tx overlay relay: hop seal via %s failed: %v; dispatching plaintext packed fallback", route.NextHop.String(), serr)
				n.dispatchNonblocking(dispatchTask{
					kind:    0,
					target:  targetPeer,
					dstMAC:  dstMAC,
					data:    fallbackCopy,
					origLen: readN,
				})
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
		return true
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
		log.Debug("TAPFWD: dstMAC=%s resolved to SELF (targetPeer==local); checking exit-node redirect (exitNodeActive=%v)", dstMAC.String(), n.isExitNodeActive())
		if n.isExitNodeActive() {
			exitPeerID := n.Gateway.ActiveExitPeerID()
			exitPID := n.Gateway.ActiveExitPeerPID()
			if exitPeerID != "" && exitPeerID != n.Host.ID().String() {
				seqID := n.Packer.NextSeqID(n.txEpochForPeer(exitPID))
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
				log.Debug("Tx Pack exit-transit (local-MAC redirect): seq=%d origLen=%d packedLen=%d exitPeer=%s", seqID, readN, totalLen, exitPeerID)
				n.dispatchExitTransitFrame(exitPID, exitPeerID, packedCopy, payload, readN, "local-MAC redirect")
				return true
			}
		}
		// Genuinely local frame — nothing to forward.
		log.Debug("TAPFWD DROP: genuinely-local frame dstMAC=%s (exitNodeActive=%v, exitPeerID=%s) — nothing to forward",
			dstMAC.String(), n.isExitNodeActive(), n.Gateway.ActiveExitPeerID())
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
					seqID := n.Packer.NextSeqID(n.txEpochForPeer(exitPID))
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

		// If the frame has a UNICAST destination MAC (not broadcast/multicast), but its
		// destination IP is an external WAN address (outside mesh subnet & advertised subnets)
		// and no Exit Node is active:
		// Do NOT flood it to mesh peers. Flooding unroutable external packets wastes bandwidth
		// and leaks destination metadata across the mesh.
		if !isBroadcastOrMulticastMAC(dstMAC) {
			dstIP := extractFrameDstIP(payload)
			if dstIP != nil {
				isMeshTarget := false
				if dstIP.To4() != nil {
					if n.localV4Net != nil && n.localV4Net.Contains(dstIP) {
						isMeshTarget = true
					}
				} else {
					if (n.localV6Net != nil && n.localV6Net.Contains(dstIP)) || dstIP.IsLinkLocalUnicast() {
						isMeshTarget = true
					}
				}
				if !isMeshTarget {
					log.Debug("TAPFWD DROP: unroutable external unicast frame dstIP=%s dstMAC=%s without active exit node, suppressed from mesh flood",
						dstIP.String(), dstMAC.String())
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
