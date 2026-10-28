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
}

func newTxCoalescer(n *Node) *txCoalescer {
	return &txCoalescer{n: n, buf: make(map[peer.ID]*txCoalesceEntry)}
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

	// One sub-frame goes out plain (no batch envelope); several are wrapped in
	// the batch payload. Pack decides padding: the rule pads the BATCH payload
	// only when it is still below the band target (i.e. genuinely insufficient
	// data on a timer flush).
	var payload []byte
	if len(subFrames) == 1 {
		payload = subFrames[0]
	} else {
		payload = obfuscate.BuildBatchPayload(subFrames)
	}
	payloadLen := len(payload)

	// Rebuild the route so dispatch uses current link state.
	route, hasRoute := c.n.overlayRoute(targetPeer, routing.MaxRelayTTL, "")
	targetPeerStr := c.n.peerIDString(targetPeer)
	seqID := c.n.Packer.NextSeqID(c.n.txEpochForPeer(targetPeer))

	packedCopy := acquireFrameBuf(c.n.Packer.MaxPackedLen(payloadLen))
	totalLen, perr := c.n.Packer.Pack(seqID, payload, packedCopy)
	if perr != nil {
		releaseFrameBuf(packedCopy)
		releaseCoalesceSubFrames(subFrames)
		return
	}
	packedCopy = packedCopy[:totalLen]

	c.n.dispatchUnicastPacked(targetPeer, targetPeerStr, dstMAC, route, hasRoute, seqID, packedCopy, payload, payloadLen)
	releaseCoalesceSubFrames(subFrames)
}

// releaseCoalesceSubFrames returns the pooled sub-frame buffers. The batch
// envelope (if any) is a fresh allocation and is left to the GC; a single
// sub-frame IS the payload and is released here after Pack copied it out.
func releaseCoalesceSubFrames(subFrames [][]byte) {
	for _, sf := range subFrames {
		releaseFrameBuf(sf)
	}
}

// run is the flusher goroutine: every millisecond it flushes entries older than
// the rule's max_delay_ms (padding them to the band target when still short),
// and drains everything on shutdown.
func (c *txCoalescer) run(ctx context.Context) {
	t := time.NewTicker(time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.flushAll()
			return
		case <-t.C:
			c.flushExpired()
		}
	}
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
