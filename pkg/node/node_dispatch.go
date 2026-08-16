package node

import (
	"fmt"
	"net"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/routing"
)

// dispatchWorkerCount is the size of the bounded dispatch worker pool that drains
// the normal egress queue. It is package-level so dispatchNonblocking can report
// the real worker count in its backpressure warnings (instead of a hard-coded 4).
const dispatchWorkerCount = 16

// dispatchDropWarnThreshold throttles backpressure warnings: we only log once the
// drop counter crosses this many NEW drops since the last report, so a flooded
// link does not spam the log. A nonzero count is the operator-visible signal that
// the egress queue is saturated and ping/Iperf frames are being silently dropped.
const dispatchDropWarnThreshold = 10

func (n *Node) dispatchNonblocking(task dispatchTask) {
	// Urgent frames skip the normal backlog and go straight to the priority
	// SEND queue (symmetric to the receive-side urgentWriteCh). This puts
	// time-critical real TAP frames at the front of the send path instead of
	// waiting behind ordinary TAP egress.
	if task.urgent {
		n.dispatchUrgent(task)
		return
	}
	select {
	case n.dispatchCh <- task:
		// delivered immediately
	default:
		// Channel full — try with a short timeout to avoid dropping under brief bursts
		timer := time.NewTimer(5 * time.Millisecond)
		defer timer.Stop()
		select {
		case n.dispatchCh <- task:
			// delivered after brief wait
		case <-timer.C:
			// The task is dropped: return a pooled payload buffer now so it
			// does not leak. Caller-owned buffers (owned=false) are plain heap
			// allocations and need no action.
			if task.owned {
				releaseFrameBuf(task.data)
			}
			dropped := atomic.AddUint64(&n.dispatchDropCount, 1)
			// Throttled warning: report only when enough NEW drops have
			// accumulated, and include the live queue fill ratio so an operator
			// can tell whether the egress path is genuinely saturated (a cause
			// of intermittent "ping stutter" under load).
			if dropped == 1 || dropped%dispatchDropWarnThreshold == 0 {
				fill := 0
				if cap(n.dispatchCh) > 0 {
					fill = (len(n.dispatchCh) * 100) / cap(n.dispatchCh)
				}
				log.Warn("Dispatch channel full after 5ms: dropped %d frames total (P2P send backpressure, %d active workers, queue %d%% full)",
					dropped, dispatchWorkerCount, fill)
			}
		}
	}
}

// dispatchWorker consumes tasks from the bounded dispatch channel and sends
// them to the appropriate P2P stream.  A fixed pool of these replaces the
// previous unbounded go-func-per-frame pattern that caused 75% ICMP loss
// under load.
// batchTasksKey groups dispatch tasks by (kind, target) for batched transmission.
type batchTasksKey struct {
	kind   uint8
	target peer.ID // empty for broadcast
}

// startDispatchWorker launches one dispatch worker and registers its WaitGroup
// credit up-front, in the calling (supervisor) goroutine. Centralising the
// wg.Add here guarantees two invariants:
//   - The replacement credit is always added by a goroutine that is itself still
//     counted in the WaitGroup, so wg.Wait() can never observe a transient zero
//     across a panic-respawn boundary (the dying worker's deferred wg.Done() runs
//     only AFTER the replacement's wg.Add, so the count is preserved).
//   - wg.Wait() is only ever called after ctx is cancelled, and dispatchWorker
//     only respawns while ctx.Err() == nil, so the respawn's wg.Add can never
//     race with wg.Wait() (the Add-after-zero rule).
func (n *Node) startDispatchWorker(id int) {
	n.wg.Add(1)
	go n.dispatchWorker(id)
}

func (n *Node) dispatchWorker(id int) {
	defer n.wg.Done()
	// A panic here (e.g. a malformed frame slipping past parsing) would kill the
	// whole daemon and permanently remove a worker from the pool. Recover,
	// log, and respawn so the pool does not silently shrink on each panic.
	defer func() {
		if r := recover(); r != nil {
			log.Error("dispatch worker %d panicked: %v\n%s", id, r, debug.Stack())
			// Respawn only while we are still supposed to run. The WaitGroup
			// accounting for the replacement is handled by startDispatchWorker
			// (see its doc comment for why this can never race w/ the shutdown
			// wg.Wait()).
			if n.ctx.Err() == nil {
				n.startDispatchWorker(id)
			}
		}
	}()
	for {
		select {
		case <-n.ctx.Done():
			return
		case task := <-n.dispatchCh:
			// Batch drain: collect up to 32 pending tasks grouped by target.
			batches := make(map[batchTasksKey][]dispatchTask)
			batches[batchTasksKey{kind: task.kind, target: task.target}] = []dispatchTask{task}

		drainLoop:
			for i := 0; i < 31; i++ {
				select {
				case t := <-n.dispatchCh:
					key := batchTasksKey{kind: t.kind, target: t.target}
					batches[key] = append(batches[key], t)
				default:
					break drainLoop
				}
			}

			for key, tasks := range batches {
				switch key.kind {
				case 0: // unicast — async to avoid blocking worker on slow stream writes
					batch := make([][]byte, 0, len(tasks))
					origLens := make([]int, 0, len(tasks))
					for _, t := range tasks {
						batch = append(batch, t.data)
						origLens = append(origLens, t.origLen)
					}
					target := key.target
					dstMAC := tasks[0].dstMAC
					if len(batch) == 1 {
						data := batch[0]
						origLen := origLens[0]
						owned := tasks[0].owned
						go func() {
							defer func() {
								if owned {
									releaseFrameBuf(data)
								}
							}()
							if err := n.Dispatcher.SendToPeer(n.ctx, target, data); err != nil {
								log.Debug("Tx unicast send error to peer %s: %v", target.String(), err)
								n.handleUnicastFailure(target, dstMAC, err)
							} else {
								n.Collector.RecordSent(origLen)
							}
						}()
					} else {
						go func() {
							defer func() {
								for i, t := range tasks {
									if t.owned {
										releaseFrameBuf(batch[i])
									}
								}
							}()
							if err := n.Dispatcher.SendBatchToPeer(n.ctx, target, batch); err != nil {
								log.Debug("Tx batched unicast send error to peer %s (n=%d): %v",
									target.String(), len(batch), err)
								n.handleUnicastFailure(target, dstMAC, err)
							} else {
								for _, ol := range origLens {
									n.Collector.RecordSent(ol)
								}
							}
						}()
					}
				case 1: // broadcast — async to avoid blocking worker on wg.Wait()
					// Broadcast fans out one L2 frame to N peers; count TX once per task.
					if len(tasks) == 1 {
						data := tasks[0].data
						origLen := tasks[0].origLen
						owned := tasks[0].owned
						go func() {
							defer func() {
								if owned {
									releaseFrameBuf(data)
								}
							}()
							n.Dispatcher.BroadcastToAllPeers(n.ctx, data)
							n.Collector.RecordSent(origLen)
						}()
					} else {
						batch := make([][]byte, 0, len(tasks))
						origLens := make([]int, 0, len(tasks))
						for _, t := range tasks {
							batch = append(batch, t.data)
							origLens = append(origLens, t.origLen)
						}
						go func() {
							defer func() {
								for i, t := range tasks {
									if t.owned {
										releaseFrameBuf(batch[i])
									}
								}
							}()
							n.Dispatcher.BroadcastBatchToAllPeers(n.ctx, batch)
							for _, ol := range origLens {
								n.Collector.RecordSent(ol)
							}
						}()
					}
				case 2: // relay — persistent pool per relayHop (eliminates per-frame stream open)
					for _, t := range tasks {
						t := t
						n.relayPool.Submit(t.relayHop, t.relayData,
							// onSent: track stats at origin
							func() { n.Collector.RecordSent(t.origLen) },
							// onFail: fallback to direct unicast
							func() {
								if derr := n.Dispatcher.SendToPeer(n.ctx, t.target, t.data); derr == nil {
									n.Collector.RecordSent(t.origLen)
								}
							},
						)
					}
				}
			}
		}
	}
}

// DispatchUrgentFrame sends a real Ethernet frame to a specific peer on the
// PRIORITY SEND path (front of the send queue), symmetric to the receive-side
// tapWriteUrgent.  Used by diagnostics (e.g. the TAP probe) that must not be
// starved behind a backlog of ordinary TAP egress frames.  Returns false if
// the urgent queue is full and the frame fell back to the normal queue.
func (n *Node) DispatchUrgentFrame(peerID peer.ID, frame []byte, dstMAC net.HardwareAddr, origLen int) bool {
	task := dispatchTask{
		kind:    0,
		target:  peerID,
		dstMAC:  dstMAC,
		data:    frame,
		origLen: origLen,
		urgent:  true,
	}
	select {
	case n.urgentDispatchCh <- task:
		return true
	default:
		// Urgent queue full — fall back to normal queue so the frame is still sent.
		// Clear the urgent flag first: leaving it set sends the task back through
		// dispatchUrgent, which bounces it here again (unbounded recursion → fatal
		// stack overflow). See dispatchUrgent for the full rationale.
		task.urgent = false
		n.dispatchNonblocking(task)
		return false
	}
}

// dispatchUrgent enqueues a time-critical send task onto the priority queue.
// It is the SEND-side counterpart to tapWriteUrgent: frames queued here are
// drained ahead of the normal dispatchCh so they reach the overlay before any
// backlog of ordinary TAP egress frames.  Non-blocking; if the urgent queue is
// full the frame falls back to the normal dispatch path.
func (n *Node) dispatchUrgent(task dispatchTask) {
	select {
	case n.urgentDispatchCh <- task:
		// delivered to priority queue
	default:
		// Urgent queue full — fall back to normal queue (still sent, just not ahead).
		//
		// CRITICAL: the urgent flag MUST be cleared before demoting. dispatchNonblocking
		// routes every task with urgent==true straight back into dispatchUrgent, so
		// keeping the flag set makes the two functions call each other without bound
		// the moment urgentDispatchCh is full. A Go stack overflow is a FATAL,
		// unrecoverable runtime error (no deferred recover can catch it), so that
		// recursion killed the entire daemon under urgent-queue pressure — the TAP
		// data path died instantly and no ping could get through afterwards.
		// task is a by-value parameter, so clearing the flag is local to this demote.
		task.urgent = false
		n.dispatchNonblocking(task)
	}
}

// urgentDispatchLoop drains the priority SEND queue and transmits each task
// immediately (no batching delay), giving urgent real-TAP frames first access
// to the overlay.  This is symmetric to the receive-side urgentWriteLoop.
func (n *Node) urgentDispatchLoop() {
	defer n.wg.Done()
	for {
		select {
		case <-n.ctx.Done():
			return
		case task := <-n.urgentDispatchCh:
			n.sendDispatchTask(task)
		}
	}
}

// sendDispatchTask transmits a single dispatch task immediately on its own
// goroutine.  Shared by the urgent dispatch loop (priority path) and could be
// reused by the batched dispatch worker.  Mirrors the per-kind branches in
// dispatchWorker but without batching overhead.
func (n *Node) sendDispatchTask(task dispatchTask) {
	switch task.kind {
	case 0: // unicast
		target := task.target
		dstMAC := task.dstMAC
		data := task.data
		origLen := task.origLen
		owned := task.owned
		go func() {
			// Pooled payloads (owned==true, from acquireFrameBuf) MUST be returned
			// once the send completes, exactly as dispatchWorker does. Without this
			// the priority path permanently drained the frame pool, so every urgent
			// frame forced a fresh allocation and the GC churned under load.
			defer func() {
				if owned {
					releaseFrameBuf(data)
				}
			}()
			if err := n.Dispatcher.SendToPeer(n.ctx, target, data); err != nil {
				log.Debug("Tx urgent unicast send error to peer %s: %v", target.String(), err)
				n.handleUnicastFailure(target, dstMAC, err)
			} else {
				n.Collector.RecordSent(origLen)
			}
		}()
	case 1: // broadcast
		data := task.data
		origLen := task.origLen
		owned := task.owned
		go func() {
			defer func() {
				if owned {
					releaseFrameBuf(data)
				}
			}()
			n.Dispatcher.BroadcastToAllPeers(n.ctx, data)
			n.Collector.RecordSent(origLen)
		}()
	case 2: // relay
		n.relayPool.Submit(task.relayHop, task.relayData,
			func() { n.Collector.RecordSent(task.origLen) },
			func() {
				if derr := n.Dispatcher.SendToPeer(n.ctx, task.target, task.data); derr == nil {
					n.Collector.RecordSent(task.origLen)
				}
			},
		)
	}
}

func (n *Node) macCleanLoop() {
	defer n.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.MACTable.CleanStale(300 * time.Second)
			n.Router.CleanStaleNodes(60 * time.Second)
			n.invalidateRouteCache()
			n.updateWebCollectorState()
		}
	}
}

// getCachedRoutes returns the current routing table, reusing a cached copy
// when available (<2s stale).  This avoids redundant per-frame Dijkstra
// computations in tapReadLoop when topology changes are infrequent.
func (n *Node) getCachedRoutes() map[peer.ID]routing.RouteInfo {
	n.cachedRoutesMu.RLock()
	if time.Since(n.cachedRoutesAt) < 2*time.Second && n.cachedRoutes != nil {
		defer n.cachedRoutesMu.RUnlock()
		return n.cachedRoutes
	}
	n.cachedRoutesMu.RUnlock()

	n.cachedRoutesMu.Lock()
	defer n.cachedRoutesMu.Unlock()
	// Double-check: another goroutine may have populated the cache between the RUnlock and Lock.
	if time.Since(n.cachedRoutesAt) < 2*time.Second && n.cachedRoutes != nil {
		return n.cachedRoutes
	}
	n.cachedRoutes = n.Router.ComputeRoutes()
	n.cachedRoutesAt = time.Now()
	return n.cachedRoutes
}

// invalidateRouteCache forces the next getCachedRoutes call to recompute.
// Called periodically from macCleanLoop to pick up topology changes.
func (n *Node) invalidateRouteCache() {
	n.cachedRoutesMu.Lock()
	n.cachedRoutesAt = time.Time{}
	n.cachedRoutesMu.Unlock()
}

// relayHopForTarget resolves the overlay-relay next hop for a peer that has no
// direct transport connection (a "circuit-only" peer). Circuit-relay peers are
// reached through the same PackRelayFrame overlay wrapper used for normal relay
// routing, so we need the relay hop's peer ID to (a) seal the outer envelope
// hop-by-hop and (b) open the OverlayRelayProtocolID stream via relayPool.
//
// Resolution order:
//  1. Route table NextHop (the natural overlay-relay hop).
//  2. A currently-connected bootstrap/circuit-relay node.
//
// CRITICAL: a candidate hop is only usable if it actually speaks the
// application-level OverlayRelayProtocolID. A pure Circuit Relay v2 node
// (the common bootstrap deployment) transits /p2p-circuit at the libp2p layer
// but never registers /p2ptap/relay/1.0.0. Returning such a peer made
// relayPool.ensureStream spin forever on "protocols not supported", the write
// queue filled to relayPoolMaxQueue, and every frame was silently dropped —
// which is exactly how the TAP data path died while plain echo still worked.
// We therefore probe protocol support and skip hops that cannot serve us, so
// the caller transparently falls back to the libp2p /p2p-circuit stream path.
//
// Returns "" when no usable relay hop exists (caller should fall back to the
// direct/circuit stream path).
// isDirectlyConnected reports whether targetPeer is connected to us at the
// libp2p transport layer (a direct connection, not via circuit relay). Used as
// a fast, transport-level guard so the dispatch layer never wraps a directly
// reachable peer in an overlay-relay envelope just because the application
// peerMap has not been populated yet (SeqSync handshake window).
func (n *Node) isDirectlyConnected(targetPeer peer.ID) bool {
	if n.Host == nil {
		return false
	}
	if targetPeer == n.Host.ID() {
		return false // never "connected" to self
	}
	return n.Host.Network().Connectedness(targetPeer) == network.Connected
}

// sealRelayEnvelopeForHop wraps an overlay-relay envelope in a p2ptap obfuscate
// frame and seals that frame with the cipher negotiated for the IMMEDIATE relay
// hop. It is the single source of truth for building hop-by-hop relay traffic,
// shared by the TAP egress path and the dispatcher's relay fallback so the two
// can never drift apart again.
//
// WHY THE Pack STEP IS MANDATORY: an envelope produced by routing.PackRelayFrame
// has its OWN wire layout —
//
//	[ver:0x02][ttl:1][dstLen:2][dstPeerID:dstLen][srcLen:2][srcPeerID:srcLen][payload]
//
// — and is NOT an obfuscate frame. EncryptPayloadRegion nevertheless parses its
// input AS one: it reads the payload length from frame[11:13], which for a relay
// envelope lands inside the base58 destination PeerID string (e.g. 'o','W' =>
// 0x6F57 = 28503). The declared length therefore always exceeded the real frame
// and the seal failed with ErrFrameCorrupted for EVERY relayed frame. Both former
// call sites ignored that error, so the envelope went out in PLAINTEXT; the
// receiving hop then tried to AEAD-open it, failed the identical structural
// check, classified the frame as undecryptable ciphertext and DROPPED it — while
// also tripping maybeResyncOnDecryptFail into a pointless rekey storm that
// destabilised the healthy direct links as collateral damage. Net effect: the
// overlay relay path silently blackholed 100% of traffic, which is exactly how a
// peer becomes unpingable the moment its direct stream stalls.
//
// Wrapping the envelope in a real obfuscate frame makes the seal structurally
// valid AND matches what handleRelayStream already expects (it Unpacks the
// received frame before parsing the relay header).
func (n *Node) sealRelayEnvelopeForHop(hop peer.ID, envelope []byte) ([]byte, error) {
	if n.Packer == nil {
		return nil, fmt.Errorf("seal relay envelope for hop %s: packer not initialised", hop.String())
	}
	seqID := n.Packer.NextSeqID(n.txEpochForPeer(hop))
	// Same headroom idiom as fragmentFrame: obfuscate header plus the largest
	// padding any Mode can add stays well inside 4096 bytes.
	outBuf := make([]byte, len(envelope)+obfuscate.HeaderLen+4096)
	totalLen, err := n.Packer.Pack(seqID, envelope, outBuf)
	if err != nil {
		return nil, fmt.Errorf("pack relay envelope for hop %s: %w", hop.String(), err)
	}
	packed := outBuf[:totalLen]

	cipher := n.obfCipherForPeer(hop)
	if cipher == nil {
		// No cipher negotiated for this hop yet (encryption disabled, or the
		// SeqSync handshake is still in flight). The envelope travels as a
		// plaintext obfuscate frame, which the hop accepts because
		// decryptPeerFrame deliberately skips decryption for a nil cipher.
		return packed, nil
	}
	sealed, err := n.sealPeerFrame(hop, cipher, packed)
	if err != nil {
		// Unlike before, this is now a hard error: sending the envelope
		// unencrypted would guarantee a drop at the hop and leak the relay
		// header, so the caller must handle the failure instead.
		return nil, fmt.Errorf("seal relay envelope for hop %s: %w", hop.String(), err)
	}
	return sealed, nil
}

func (n *Node) relayHopForTarget(targetPeer peer.ID) peer.ID {
	// A directly-connected target is routed directly; never return it (or self)
	// as a relay hop, which would wrap its own frames in a relay envelope.
	if n.isDirectlyConnected(targetPeer) {
		return ""
	}
	if routes := n.getCachedRoutes(); len(routes) > 0 {
		// A directly-connected target must NOT be relayed (self-as-hopper would
		// wrap its own frames in a relay envelope and drop the payload). Skip
		// any route whose NextHop is the target itself.
		if r, ok := routes[targetPeer]; ok && r.NextHop != "" &&
			r.NextHop != targetPeer && r.NextHop != n.Host.ID() &&
			n.supportsOverlayRelay(r.NextHop) {
			return r.NextHop
		}
	}
	// Fallback when the route table has no entry for the target yet (LSA not
	// propagated, or the per-tick route cache was invalidated mid-convergence):
	// pick any connected peer that supports overlay relay as the hop. Prefer
	// bootstrap peers (stable relay servers), but do NOT require one — this is
	// what lets a node configured with ONLY StaticPeers (no BootstrapPeers at
	// all) still relay through a directly-connected static peer to reach a
	// relay-only peer. Without it, such a node has no hop and every relayed
	// control stream / data frame to a relay-only peer is abandoned.
	//
	// NOTE: the old code rejected every candidate via isDirectlyConnected(pID),
	// which is ALWAYS true for peers returned by Network().Conns() (those are
	// open libp2p connections by definition) — making this whole branch dead
	// code. Fixed by only excluding the target and self.
	var fallback peer.ID
	for _, c := range n.Host.Network().Conns() {
		pID := c.RemotePeer()
		if pID == targetPeer || pID == n.Host.ID() {
			continue
		}
		if n.Host.Network().Connectedness(pID) != network.Connected ||
			!n.supportsOverlayRelay(pID) {
			continue
		}
		if n.isBootstrapPeer(pID) {
			// Boot relays are Circuit-Relay v2 servers; their reachability to a
			// target is NOT reflected in the LSA graph (boot doesn't speak LSA),
			// so GetEdge cannot be used for them. A connected boot is always a
			// viable circuit-relay hop — take it immediately.
			return pID
		}
		// Non-boot peers must actually know the target in their link-state
		// neighbourhood, otherwise forwarding into them is forwarding into the
		// void. GetEdge(graph[hop][target]) is the precise "can this hop reach
		// the target?" signal, and it is what stops a totally-unknown peer
		// (e.g. the "bogus" regression case) from becoming egressable just
		// because some random connected peer exists.
		if _, ok := n.Router.GetEdge(pID, targetPeer); !ok {
			continue
		}
		if fallback == "" {
			fallback = pID // remember first non-boot candidate as last resort
		}
	}
	// No overlay-relay hop found above. If the target is reachable ONLY through a
	// boot that is a relay-over-backbone bridge (a custom boot, NOT a Circuit-
	// Relay v2 node), return that boot as the hop. The caller then routes the
	// frame through the boot-relay uplink (see sendToPeerViaBootRelay /
	// openBootRelayControlStream). This is what lets two NAT'd peers in the same
	// PSK network — connected to the same (or a federated) boot but with no
	// direct path and no overlay-relay peer between them — exchange data and
	// complete their SeqSync handshake. Reachability is purely a function of the
	// persistent boot-relay uplink being alive (hasBootRelayUplink).
	//
	// A standard Circuit-Relay v2 boot never satisfies hasBootRelayUplink (we
	// only open /p2ptap/boot-relay/1.0.0 uplinks to custom boots that handle it),
	// so it is skipped here and the classic circuit path (openStreamViaRelay)
	// remains the fallback for those deployments.
	if !n.isDirectlyConnected(targetPeer) {
		for _, c := range n.Host.Network().Conns() {
			pID := c.RemotePeer()
			if pID == targetPeer || pID == n.Host.ID() {
				continue
			}
			if !n.isBootstrapPeer(pID) || !n.hasBootRelayUplink(pID) {
				continue
			}
			return pID
		}
	}
	return fallback
}

// supportsOverlayRelay reports whether the peer advertises the application-level
// overlay relay protocol in the peerstore.
//
// Semantics of the peerstore lookup:
//   - non-empty result  -> confirmed support, hop is usable.
//   - empty result      -> confirmed NOT supported, hop must be skipped.
//   - lookup error      -> identify has not completed yet; we optimistically
//     allow the hop rather than permanently blackholing a peer whose protocol
//     set is merely unknown at this instant. The relay pool's own reconnect
//     backoff bounds the cost of a wrong guess, and the next call will have the
//     real answer.
//
// The negative result is cached by the peerstore itself, so this stays cheap
// enough for the per-frame dispatch path.
func (n *Node) supportsOverlayRelay(p peer.ID) bool {
	if n.Host == nil {
		return false
	}
	supported, err := n.Host.Peerstore().SupportsProtocols(p, OverlayRelayProtocolID)
	if err != nil {
		return true // unknown yet — let the relay pool try, it backs off on failure
	}
	return len(supported) > 0
}
