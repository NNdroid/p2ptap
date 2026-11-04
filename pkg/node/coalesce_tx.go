package node

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/obfuscate"
	"p2ptap/pkg/routing"
)

// txCoalesceEntry is one destination's pending coalescing buffer: raw Ethernet
// sub-frames (owned pooled buffers) accumulated toward a single logical frame.
type txCoalesceEntry struct {
	subFrames  [][]byte
	totalBytes int
	dstMAC     net.HardwareAddr // representative destination MAC (last appended)
	firstAt    time.Time
}

// txCoalescer merges short unicast TAP frames destined to the same peer into one
// obfuscate frame so the padding rule has nothing to pad (the accumulated
// payload reaches the band target naturally), and only pads when the buffer is
// genuinely short and the flush timer expires. Knobs come from the rule's
// "coalesce" directive (see pkg/obfuscate/padding_rule.go).
//
// Flush triggers, checked on append:
//   - accumulated bytes reach the current band's target_min (flush unpadded),
//   - max_frames or max_bytes reached,
//   - the flusher goroutine observes the entry older than max_delay_ms (pad to
//     the band target if still short).
//
// The buffer is keyed by targetPeer and drained in FIFO order; a batch is one
// logical frame (one SeqID), so the receiver sees it after one dedup pass.
type txCoalescer struct {
	n   *Node
	mu  sync.Mutex
	buf map[peer.ID]*txCoalesceEntry
	// wake nudges the flusher goroutine to recompute its sleep deadline. The
	// only transition that needs it is the first frame buffered while the map
	// was empty: without it, an idle flusher sleeping on a long timer would
	// hold that frame past its max_delay. Buffered(1) + non-blocking send, so a
	// burst of appends costs one coalesced wakeup.
	wake chan struct{}
}

func newTxCoalescer(n *Node) *txCoalescer {
	return &txCoalescer{n: n, buf: make(map[peer.ID]*txCoalesceEntry), wake: make(chan struct{}, 1)}
}

// maybeBuffer attempts to buffer a unicast TAP frame for coalescing. It returns
// true when the frame was consumed (buffered, or flushed immediately because the
// buffer already reached the band target / caps); false when the frame must go
// out through the normal path (coalescing disabled, or exit-node transit).
func (c *txCoalescer) maybeBuffer(targetPeer peer.ID, dstMAC net.HardwareAddr, payload []byte) bool {
	rule, enabled := c.n.Packer.PaddingSnapshot()
	if rule == nil || !enabled || !rule.Coalesce.On {
		return false
	}
	// Exit-node egress is the most latency-sensitive traffic the node forwards;
	// never hold it in the coalescing buffer.
	if exitPID := c.n.Gateway.ActiveExitPeerPID(); exitPID != "" && exitPID == targetPeer {
		return false
	}

	sub := acquireFrameBuf(len(payload))
	copy(sub, payload)

	now := time.Now()
	c.mu.Lock()
	wasEmpty := len(c.buf) == 0
	entry := c.buf[targetPeer]
	if entry == nil {
		entry = &txCoalesceEntry{}
		c.buf[targetPeer] = entry
	}
	entry.subFrames = append(entry.subFrames, sub)
	entry.totalBytes += len(payload)
	entry.dstMAC = append(entry.dstMAC[:0], dstMAC...)
	if entry.firstAt.IsZero() {
		entry.firstAt = now
	}
	// Flush when the buffer reaches the current band's target (no padding) or
	// the hard caps; otherwise hold for the flusher timer.
	needFlush := len(entry.subFrames) >= rule.Coalesce.MaxFrames ||
		entry.totalBytes >= rule.Coalesce.MaxBytes ||
		entry.totalBytes >= rule.FlushThreshold(entry.totalBytes)
	c.mu.Unlock()

	if needFlush {
		c.flush(targetPeer)
	} else if wasEmpty {
		// The map went empty -> non-empty: any pending flusher sleep predates
		// this entry and may be longer than its max_delay. Wake the flusher so
		// it recomputes against the new earliest deadline.
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
	return true
}

// flush builds and dispatches the pending logical frame for one peer. The entry
// is removed under the lock, then the (potentially blocking) pack + dispatch
// runs outside it so overlayRoute / dispatchNonblocking never hold the buffer
// mutex.
func (c *txCoalescer) flush(targetPeer peer.ID) {
	c.mu.Lock()
	entry := c.buf[targetPeer]
	if entry == nil {
		c.mu.Unlock()
		return
	}
	delete(c.buf, targetPeer)
	subFrames := entry.subFrames
	dstMAC := entry.dstMAC
	c.mu.Unlock()

	// A single sub-frame goes out plain (no batch envelope). Several are wrapped
	// in the batch payload, built directly into the Pack output's payload region
	// (fragmentFrame pattern) so Pack's payload copy is a no-op — one allocation
	// and one copy saved per batch. Pack decides padding: the rule pads the
	// BATCH payload only when it is still below the band target (i.e. genuinely
	// insufficient data on a timer flush).
	if len(subFrames) == 1 {
		c.flushPayload(targetPeer, dstMAC, subFrames[0])
		releaseCoalesceSubFrames(subFrames)
		return
	}

	batchSize := obfuscate.BatchPayloadSize(subFrames)
	maxPacked := c.n.Packer.MaxPackedLen(batchSize)
	packedCopy := acquireFrameBuf(maxPacked)
	payload := obfuscate.BuildBatchPayloadInto(packedCopy[obfuscate.HeaderLen:], subFrames)
	if payload == nil {
		// Defensive: BuildBatchPayloadInto returns nil when the sub-frame count
		// cannot fit the 16-bit batch header (unreachable via config — MaxFrames
		// is capped at 64 — but a mis-sized caller must not drop frames). Deliver
		// each sub-frame individually instead.
		releaseFrameBuf(packedCopy)
		for _, sf := range subFrames {
			c.flushPayload(targetPeer, dstMAC, sf)
		}
		releaseCoalesceSubFrames(subFrames)
		return
	}

	// Rebuild the route so dispatch uses current link state.
	route, hasRoute := c.n.overlayRoute(targetPeer, routing.MaxRelayTTL, "")
	targetPeerStr := c.n.peerIDString(targetPeer)
	seqID := c.n.nextTxSeqID(targetPeer)
	totalLen, perr := c.n.Packer.Pack(seqID, payload, packedCopy)
	if perr != nil {
		releaseFrameBuf(packedCopy)
		releaseCoalesceSubFrames(subFrames)
		return
	}
	packedCopy = packedCopy[:totalLen]

	c.n.dispatchUnicastPacked(targetPeer, targetPeerStr, dstMAC, route, hasRoute, seqID, packedCopy, payload, len(payload))
	releaseCoalesceSubFrames(subFrames)
}

// flushPayload packs and dispatches one coalesced logical frame (a single
// sub-frame). Each call gets its own SeqID, so a fallback that splits an
// unrepresentable batch delivers each sub-frame independently.
func (c *txCoalescer) flushPayload(targetPeer peer.ID, dstMAC net.HardwareAddr, payload []byte) {
	payloadLen := len(payload)

	// Rebuild the route so dispatch uses current link state.
	route, hasRoute := c.n.overlayRoute(targetPeer, routing.MaxRelayTTL, "")
	targetPeerStr := c.n.peerIDString(targetPeer)
	seqID := c.n.nextTxSeqID(targetPeer)

	packedCopy := acquireFrameBuf(c.n.Packer.MaxPackedLen(payloadLen))
	totalLen, perr := c.n.Packer.Pack(seqID, payload, packedCopy)
	if perr != nil {
		releaseFrameBuf(packedCopy)
		return
	}
	packedCopy = packedCopy[:totalLen]

	c.n.dispatchUnicastPacked(targetPeer, targetPeerStr, dstMAC, route, hasRoute, seqID, packedCopy, payload, payloadLen)
}

// releaseCoalesceSubFrames returns the pooled sub-frame buffers. The batch
// envelope (if any) is a fresh allocation and is left to the GC; a single
// sub-frame IS the payload and is released here after Pack copied it out.
func releaseCoalesceSubFrames(subFrames [][]byte) {
	for _, sf := range subFrames {
		releaseFrameBuf(sf)
	}
}

// run is the flusher goroutine. It is fully event-driven: it sleeps until the
// earliest buffered entry's max_delay deadline (recomputed after every wake and
// every new-entry wake signal) and flushes everything on shutdown. The previous
// 1 ms ticker woke 1000 times per second around the clock for a flush that in
// practice happens at most once per max_delay per peer — constant scheduler and
// battery cost on the OpenWrt / laptop targets for zero latency benefit.
//
// Wake sources:
//   - the recomputed deadline of the earliest buffered entry (timer),
//   - maybeBuffer's wake signal when the map transitions empty -> non-empty,
//   - context cancellation (drains everything and exits).
func (c *txCoalescer) run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		rule, enabled := c.n.Packer.PaddingSnapshot()
		if rule == nil || !enabled || !rule.Coalesce.On {
			// Coalescing is off (or the packer is unconfigured): drain whatever
			// is buffered and sleep until woken. A hot reload back to coalescing
			// produces a first buffered frame, and the empty -> non-empty wake
			// signal covers exactly that transition.
			c.flushAll()
		} else {
			now := time.Now()
			c.mu.Lock()
			delay, ok := c.earliestDelayLocked(now, time.Duration(rule.Coalesce.MaxDelayMs)*time.Millisecond)
			c.mu.Unlock()
			if ok {
				// Cap the sleep at the current rule delay so a hot reload to a
				// shorter max_delay takes effect within one period instead of
				// waiting out a sleep scheduled under the old rule.
				if d := time.Duration(rule.Coalesce.MaxDelayMs) * time.Millisecond; delay > d {
					delay = d
				}
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(delay)
			}
			// No buffered entries: leave the timer idle and sleep on wake/ctx.
			// A later append sends the wake signal.
		}

		select {
		case <-ctx.Done():
			c.flushAll()
			return
		case <-timer.C:
			c.flushExpired()
		case <-c.wake:
			// Recompute the deadline on the next loop iteration.
		}
	}
}

// earliestDelayLocked returns the time remaining until the oldest buffered
// entry's max_delay deadline. ok is false when the buffer is empty. Caller
// holds mu.
func (c *txCoalescer) earliestDelayLocked(now time.Time, maxDelay time.Duration) (time.Duration, bool) {
	if len(c.buf) == 0 {
		return 0, false
	}
	earliest := now.Add(maxDelay)
	for _, e := range c.buf {
		if d := e.firstAt.Add(maxDelay); d.Before(earliest) {
			earliest = d
		}
	}
	if d := earliest.Sub(now); d > 0 {
		return d, true
	}
	// Already expired: flush immediately on the next timer tick.
	return 0, true
}

// flushExpired flushes every entry older than the rule's max_delay_ms. When
// coalescing was disabled by a hot reload, it drains the whole buffer.
func (c *txCoalescer) flushExpired() {
	rule, enabled := c.n.Packer.PaddingSnapshot()
	if rule == nil || !enabled || !rule.Coalesce.On {
		c.flushAll()
		return
	}
	delay := time.Duration(rule.Coalesce.MaxDelayMs) * time.Millisecond
	now := time.Now()
	c.mu.Lock()
	peers := make([]peer.ID, 0)
	for p, e := range c.buf {
		if now.Sub(e.firstAt) >= delay {
			peers = append(peers, p)
		}
	}
	c.mu.Unlock()
	for _, p := range peers {
		c.flush(p)
	}
}

// flushAll drains every pending entry (config change / shutdown).
func (c *txCoalescer) flushAll() {
	c.mu.Lock()
	peers := make([]peer.ID, 0, len(c.buf))
	for p := range c.buf {
		peers = append(peers, p)
	}
	c.mu.Unlock()
	for _, p := range peers {
		c.flush(p)
	}
}
