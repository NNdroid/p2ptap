package node

import (
	"sort"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/obfuscate"
)

// rxReorderEntry is one or more TAP write jobs buffered out of counter order.
// A coalesced batch is a single logical frame (one counter) made of several
// sub-frames, so all of them are held and released together.
type rxReorderEntry struct {
	jobs []tapWriteJob // owns pooled frame buffers until delivered
	at   time.Time
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
// Ownership: the queue accepts already-pooled tapWriteJobs and releases each
// buffer exactly once — either by delivering it to enqueueTapWritePrepared
// (which passes it to the channel / synchronous writer) or by a drop path.
type rxReorderQueue struct {
	mu   sync.Mutex
	node *Node

	epoch        uint64
	next         uint64 // next expected counter
	window       map[uint64]rxReorderEntry
	maxWindow    int
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

// push handles one logical frame (one seqID) already accepted through the dedup
// layer. jobs are the frame's TAP write jobs: one for a plain frame, several
// for a coalesced batch whose sub-frames share this seqID. All jobs are
// delivered together and in order. The caller hands over ownership of every
// job's pooled buffer. Returns true when the frame was delivered synchronously
// (in order) or validated away; false when it was buffered for later in-order
// delivery.
func (q *rxReorderQueue) push(seqID uint64, jobs []tapWriteJob) bool {
	if len(jobs) == 0 {
		return true
	}
	epoch := obfuscate.ConnEpochFromSeq(seqID)
	counter := obfuscate.CounterFromSeq(seqID)

	q.mu.Lock()
	defer q.mu.Unlock()

	// A new connection epoch marks a fresh session: the peer's counter space
	// restarts (possibly backward), so any buffered tail belongs to the previous
	// session and must be flushed before re-anchoring on this frame.
	if q.epoch != 0 && q.epoch != epoch {
		q.releaseAllLocked()
		q.epoch = epoch
		q.next = counter + 1
		q.enqueueAllLocked(jobs)
		return true
	}
	if q.epoch == 0 {
		// First frame ever seen for this peer: anchor and deliver. next advances
		// past the delivered counter so the following frame arrives in order.
		q.epoch = epoch
		q.next = counter + 1
		q.enqueueAllLocked(jobs)
		return true
	}

	if counter == q.next {
		q.enqueueAllLocked(jobs)
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
			q.enqueueAllLocked(jobs)
			return true
		}
		q.window[counter] = rxReorderEntry{jobs: jobs, at: time.Now()}
		q.maybeForceReleaseLocked(time.Now())
		return false
	}

	// counter < q.next: the counter space already advanced past it (fast-forward
	// or window reset). The frame is too late to deliver in order — drop it and
	// return its buffers, matching the dedup far-behind semantics.
	q.releaseJobsLocked(jobs)
	return true
}

// enqueueAllLocked hands every job of one logical frame to the TAP writer in
// order. Caller holds mu.
func (q *rxReorderQueue) enqueueAllLocked(jobs []tapWriteJob) {
	for i := range jobs {
		q.node.enqueueTapWritePrepared(jobs[i])
	}
}

// releaseJobsLocked returns every job's pooled buffer without writing it.
// Caller holds mu.
func (q *rxReorderQueue) releaseJobsLocked(jobs []tapWriteJob) {
	for i := range jobs {
		releaseFrameBuf(jobs[i].data)
	}
}

// flushLocked delivers every contiguous buffered frame starting at next. Caller
// holds mu.
func (q *rxReorderQueue) flushLocked() {
	for {
		e, ok := q.window[q.next]
		if !ok {
			return
		}
		q.enqueueAllLocked(e.jobs)
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
		q.enqueueAllLocked(q.window[c].jobs)
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

// reorderTapWrite is the receive-side entry to the TAP write path for a single
// logical frame. Under the "multipath" strategy it routes the frame through the
// per-peer reorder buffer so the TUN device sees an in-order Ethernet stream;
// otherwise it is a zero-overhead passthrough to enqueueTapWrite. seqID is the
// logical frame's structured SeqID (post-reassembly), already accepted by the
// dedup layer. pathKey attributes the frame to a path for per-path receive
// telemetry ("" for direct frames, "relay://<hop>" for relayed frames).
func (n *Node) reorderTapWrite(remotePeer peer.ID, seqID uint64, payload []byte, recordGateway bool, relaySrc peer.ID, pathKey string) {
	if !n.rxReorderEnabled.Load() {
		_ = n.enqueueTapWrite(payload, recordGateway, relaySrc)
		return
	}
	job, err := n.prepareTapWriteJob(payload, recordGateway, relaySrc, pathKey)
	if err != nil {
		return
	}
	n.rxReorderFor(remotePeer).push(seqID, []tapWriteJob{job})
}

// reorderTapWriteBatch is the receive-side entry for a coalesced batch: every
// sub-frame shares the batch's single seqID, so all jobs are pushed to the
// reorder buffer as ONE logical frame (or, with reorder disabled, enqueued in
// order). Jobs are already prepared (owned pooled buffers) by the caller.
func (n *Node) reorderTapWriteBatch(remotePeer peer.ID, seqID uint64, jobs []tapWriteJob) {
	if len(jobs) == 0 {
		return
	}
	if !n.rxReorderEnabled.Load() {
		for i := range jobs {
			n.enqueueTapWritePrepared(jobs[i])
		}
		return
	}
	n.rxReorderFor(remotePeer).push(seqID, jobs)
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
