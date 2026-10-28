package node

import (
	"sort"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/obfuscate"
)

// rxReorderEntry is a TAP write job buffered out of counter order.
type rxReorderEntry struct {
	job tapWriteJob // owns a pooled frame buffer until delivered
	at  time.Time
}

// rxReorderQueue is a per-peer bounded reorder buffer for the "multipath"
// strategy.
//
// Multipath distributes logical frames across several paths to a peer. Every
// frame carries a counter from the SAME process-wide sequence space (see
// obfuscate.BumpCounter), so although frames complete out of order across
// paths, their counters still define one global order per peer. This queue
// holds the out-of-order tail and releases it to the TAP write path in counter
// order, so the TUN device never sees a reordered Ethernet stream — the inner
// TCP/IP stack would otherwise trigger spurious fast-retransmits and undo the
// throughput multipath is meant to add.
//
// It only reorders; there is no retransmission, so a frame lost on one path
// leaves a hole at the head. The hole is force-released after releaseDelay (or
// when the window fills) to bound the added head-of-line latency: the buffered
// tail is flushed in counter order with the hole treated as lost.
//
// Ownership: the queue accepts an already-pooled tapWriteJob and releases its
// buffer exactly once — either by delivering it to enqueueTapWritePrepared
// (which passes it to the channel / synchronous writer) or by a drop path.
type rxReorderQueue struct {
	mu   sync.Mutex
	node *Node

	epoch       uint64
	next        uint64 // next expected counter
	window      map[uint64]rxReorderEntry
	maxWindow   int
	releaseDelay time.Duration
}

func newRxReorderQueue(n *Node, maxWindow int, releaseDelay time.Duration) *rxReorderQueue {
	if maxWindow < 2 {
		maxWindow = 2
	}
	if releaseDelay <= 0 {
		releaseDelay = 200 * time.Millisecond
	}
	return &rxReorderQueue{
		node:         n,
		window:       make(map[uint64]rxReorderEntry, 64),
		maxWindow:    maxWindow,
		releaseDelay: releaseDelay,
	}
}

// push handles one frame already accepted through the dedup layer. seqID is the
// logical frame's structured SeqID (counter + per-peer epoch). It validates and
// pools the payload itself, so the caller may return immediately after push.
// pathKey attributes this frame to a path for per-path receive telemetry; it is
// carried on the buffered job and honored when the frame is eventually written
// to TAP. Returns true when the frame was delivered synchronously (in order) or
// validated away; false when it was buffered for later in-order delivery.
func (q *rxReorderQueue) push(seqID uint64, payload []byte, recordGateway bool, relaySrc peer.ID, pathKey string) bool {
	epoch := obfuscate.ConnEpochFromSeq(seqID)
	counter := obfuscate.CounterFromSeq(seqID)

	job, err := q.node.prepareTapWriteJob(payload, recordGateway, relaySrc, pathKey)
	if err != nil {
		// Runt / oversized / no device: validated away, nothing to reorder.
		return true
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	// A new connection epoch marks a fresh session: the peer's counter space
	// restarts (possibly backward), so any buffered tail belongs to the previous
	// session and must be flushed before re-anchoring on this frame.
	if q.epoch != 0 && q.epoch != epoch {
		q.releaseAllLocked()
		q.epoch = epoch
		q.next = counter + 1
		q.node.enqueueTapWritePrepared(job)
		return true
	}
	if q.epoch == 0 {
		// First frame ever seen for this peer: anchor and deliver. next advances
		// past the delivered counter so the following frame arrives in order.
		q.epoch = epoch
		q.next = counter + 1
		q.node.enqueueTapWritePrepared(job)
		return true
	}

	if counter == q.next {
		q.node.enqueueTapWritePrepared(job)
		q.next++
		q.flushLocked()
		return true
	}

	if counter > q.next {
		if counter-q.next >= uint64(q.maxWindow) {
			// Too far ahead to hold: the intervening frames are gone (lost or the
			// sender fast-forwarded). Flush the stale tail and re-anchor here.
			q.releaseAllLocked()
			q.next = counter + 1
			q.node.enqueueTapWritePrepared(job)
			return true
		}
		q.window[counter] = rxReorderEntry{job: job, at: time.Now()}
		q.maybeForceReleaseLocked(time.Now())
		return false
	}

	// counter < q.next: the counter space already advanced past it (fast-forward
	// or window reset). The frame is too late to deliver in order — drop it and
	// return its buffer, matching the dedup far-behind semantics.
	releaseFrameBuf(job.data)
	return true
}

// flushLocked delivers every contiguous buffered frame starting at next. Caller
// holds mu.
func (q *rxReorderQueue) flushLocked() {
	for {
		e, ok := q.window[q.next]
		if !ok {
			return
		}
		q.node.enqueueTapWritePrepared(e.job)
		delete(q.window, q.next)
		q.next++
	}
}

// releaseAllLocked delivers every buffered frame in counter order, treating any
// holes as lost. Caller holds mu and re-anchors q.next afterwards.
func (q *rxReorderQueue) releaseAllLocked() {
	if len(q.window) == 0 {
		return
	}
	keys := make([]uint64, 0, len(q.window))
	for c := range q.window {
		keys = append(keys, c)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, c := range keys {
		q.node.enqueueTapWritePrepared(q.window[c].job)
	}
	q.window = make(map[uint64]rxReorderEntry, 64)
}

// maybeForceReleaseLocked flushes the buffered tail once the head hole has
// waited longer than releaseDelay or the window is full, bounding head-of-line
// latency. Caller holds mu.
func (q *rxReorderQueue) maybeForceReleaseLocked(now time.Time) {
	if len(q.window) == 0 {
		return
	}
	var oldestAt time.Time
	first := true
	maxC := uint64(0)
	for c, e := range q.window {
		if c > maxC {
			maxC = c
		}
		if first || e.at.Before(oldestAt) {
			oldestAt = e.at
			first = false
		}
	}
	if now.Sub(oldestAt) > q.releaseDelay || len(q.window) >= q.maxWindow {
		q.releaseAllLocked()
		q.next = maxC + 1
	}
}

// reorderTapWrite is the receive-side entry to the TAP write path. Under the
// "multipath" strategy it routes the frame through the per-peer reorder buffer
// so the TUN device sees an in-order Ethernet stream; otherwise it is a
// zero-overhead passthrough to enqueueTapWrite. seqID is the logical frame's
// structured SeqID (post-reassembly), already accepted by the dedup layer.
// pathKey attributes the frame to a path for per-path receive telemetry
// ("" for direct frames, "relay://<hop>" for relayed frames).
func (n *Node) reorderTapWrite(remotePeer peer.ID, seqID uint64, payload []byte, recordGateway bool, relaySrc peer.ID, pathKey string) {
	if !n.rxReorderEnabled.Load() {
		_ = n.enqueueTapWrite(payload, recordGateway, relaySrc)
		return
	}
	n.rxReorderFor(remotePeer).push(seqID, payload, recordGateway, relaySrc, pathKey)
}

// rxReorderFor returns the reorder queue for a peer, creating it on first use.
func (n *Node) rxReorderFor(p peer.ID) *rxReorderQueue {
	if v, ok := n.rxReorder.Load(p); ok {
		return v.(*rxReorderQueue)
	}
	q := newRxReorderQueue(n, n.rxReorderWindow, n.rxReorderDelay)
	v, _ := n.rxReorder.LoadOrStore(p, q)
	return v.(*rxReorderQueue)
}
