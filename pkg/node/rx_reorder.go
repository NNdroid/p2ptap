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
// frame carries a counter from that peer's OWN outbound sequence (see
// tx_seq.go), so although frames complete out of order across paths, their
// counters still define one strict order per peer. This queue holds the
// out-of-order tail and releases it to the TAP write path in counter order, so
// the TUN device never sees a reordered Ethernet stream — the inner TCP/IP stack
// would otherwise trigger spurious fast-retransmits and undo the throughput
// multipath is meant to add.
//
// It only reorders; there is no retransmission, so a frame lost on one path
// leaves a hole at the head. A hole must never stall the stream indefinitely:
//
//   - A per-queue TIMER force-releases the hole after the effective delay, so a
//     lost frame costs bounded head-of-line latency even when traffic stops
//     right after it (the old code only checked for expiry on the next push,
//     which left the tail buffered forever).
//   - The effective delay adapts to the hole-fill latency actually observed on
//     this peer. A single-path peer sees almost no reordering, so it runs at the
//     floor and can force-release almost immediately; a peer whose paths differ
//     by tens of milliseconds gets a correspondingly wider window. It is always
//     clamped to the configured maximum.
//
// Ownership: the queue accepts already-pooled tapWriteJobs and releases each
// buffer exactly once — either by delivering it to enqueueTapWritePrepared
// (which passes it to the channel / synchronous writer) or by a drop path.
type rxReorderQueue struct {
	mu   sync.Mutex
	node *Node

	epoch     uint64
	next      uint64 // next expected counter
	window    map[uint64]rxReorderEntry
	maxWindow int
	// maxReleaseDelay is the configured upper bound on head-of-line delay.
	maxReleaseDelay time.Duration
	// holeWait is the EWMA of how long a buffered frame actually waited before
	// the hole ahead of it was filled. It drives the adaptive release delay.
	holeWait time.Duration
	// maxCounter tracks the largest counter currently buffered so a window-full
	// release can re-anchor in O(1) instead of scanning the map.
	maxCounter uint64
	// timer is the pending head-of-line release. Non-nil exactly while the
	// window is non-empty and a release is scheduled.
	timer *time.Timer
	// stopped is set when the peer goes away; a late timer callback must not
	// resurrect the queue.
	stopped bool
}

// rxReorderMinReleaseDelay is the floor for the adaptive head-of-line delay. It
// is a few times a LAN RTT: below this, ordinary socket scheduling noise would
// make the queue give up on frames that were merely a millisecond late.
const rxReorderMinReleaseDelay = 25 * time.Millisecond

func newRxReorderQueue(n *Node, maxWindow int, releaseDelay time.Duration) *rxReorderQueue {
	if maxWindow < 2 {
		maxWindow = 2
	}
	if releaseDelay <= 0 {
		releaseDelay = 200 * time.Millisecond
	}
	if releaseDelay < rxReorderMinReleaseDelay {
		releaseDelay = rxReorderMinReleaseDelay
	}
	return &rxReorderQueue{
		node:            n,
		window:          make(map[uint64]rxReorderEntry, 64),
		maxWindow:       maxWindow,
		maxReleaseDelay: releaseDelay,
		// Start conservative: with no observation yet the queue behaves exactly
		// like the old fixed delay, then narrows as real hole-fill latency is
		// measured. Starting at the floor instead would drop legitimate
		// cross-path reordering during the first seconds after a link comes up.
		holeWait: releaseDelay / 4,
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

	// The peer may have gone away between rxReorderFor and this lock. Retire the
	// frame instead of resurrecting a stopped queue.
	if q.stopped {
		q.releaseJobsLocked(jobs)
		return true
	}

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
		now := time.Now()
		q.window[counter] = rxReorderEntry{jobs: jobs, at: now}
		if counter > q.maxCounter {
			q.maxCounter = counter
		}
		// Window full: the oldest entries have waited long enough that holding
		// them further would cost more than the reorder is worth.
		if len(q.window) >= q.maxWindow {
			maxC := q.releaseAllLocked()
			q.next = maxC + 1
			return false
		}
		q.armLocked()
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

// flushLocked delivers every contiguous buffered frame starting at next. Caller
// holds mu.
func (q *rxReorderQueue) flushLocked() {
	now := time.Now()
	for {
		e, ok := q.window[q.next]
		if !ok {
			break
		}
		// This frame WAS held behind a hole: the wait it actually incurred is the
		// best available estimate of the reordering spread on this peer, so feed
		// it back into the adaptive release delay.
		q.noteHoleWaitLocked(now.Sub(e.at))
		q.enqueueAllLocked(e.jobs)
		delete(q.window, q.next)
		q.next++
	}
	if len(q.window) == 0 {
		q.maxCounter = 0
		q.disarmLocked()
	}
}

// releaseJobsLocked returns every job's pooled buffer without writing it.
// Caller holds mu.
func (q *rxReorderQueue) releaseJobsLocked(jobs []tapWriteJob) {
	for i := range jobs {
		releaseFrameBuf(jobs[i].data)
	}
}

// releaseAllLocked delivers every buffered frame in counter order, treating any
// holes as lost, and returns the largest counter that was buffered so the caller
// can re-anchor q.next. Caller holds mu.
func (q *rxReorderQueue) releaseAllLocked() (maxC uint64) {
	maxC = q.maxCounter
	if len(q.window) == 0 {
		q.maxCounter = 0
		q.disarmLocked()
		return 0
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
	q.maxCounter = 0
	q.disarmLocked()
	return maxC
}

// dropAllLocked returns every buffered frame's pooled buffer WITHOUT delivering
// it, and stops the timer. Used when the peer goes away: the frames can no
// longer be delivered, and their pooled buffers must still be returned.
// Caller holds mu.
func (q *rxReorderQueue) dropAllLocked() {
	for _, e := range q.window {
		q.releaseJobsLocked(e.jobs)
	}
	q.window = make(map[uint64]rxReorderEntry, 64)
	q.maxCounter = 0
	q.disarmLocked()
}

// noteHoleWaitLocked folds one observed hole-fill wait into the EWMA. Caller
// holds mu.
func (q *rxReorderQueue) noteHoleWaitLocked(wait time.Duration) {
	if wait < 0 {
		wait = 0
	}
	if wait > q.maxReleaseDelay {
		wait = q.maxReleaseDelay
	}
	q.holeWait = (3*q.holeWait + wait) / 4
}

// effectiveDelay is the adaptive head-of-line timeout: a few times the observed
// hole-fill latency, clamped to [rxReorderMinReleaseDelay, maxReleaseDelay].
// Caller holds mu.
func (q *rxReorderQueue) effectiveDelay() time.Duration {
	d := 4 * q.holeWait
	if d < rxReorderMinReleaseDelay {
		d = rxReorderMinReleaseDelay
	}
	if d > q.maxReleaseDelay {
		d = q.maxReleaseDelay
	}
	return d
}

// armLocked schedules the head-of-line release if the window is non-empty and no
// release is pending. Caller holds mu.
func (q *rxReorderQueue) armLocked() {
	if q.timer != nil || q.stopped || len(q.window) == 0 {
		return
	}
	q.timer = time.AfterFunc(q.effectiveDelay(), q.onReleaseTimer)
}

// disarmLocked cancels a pending release. Caller holds mu.
func (q *rxReorderQueue) disarmLocked() {
	if q.timer != nil {
		q.timer.Stop()
		q.timer = nil
	}
}

// onReleaseTimer is the head-of-line deadline. It is the only path that releases
// a hole when no further frame arrives — the previous implementation checked for
// expiry exclusively inside push, so the frames buffered behind a lost tail
// frame stayed in the window (and their pooled buffers unreleased) until the
// next frame happened to arrive.
func (q *rxReorderQueue) onReleaseTimer() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.timer = nil
	if q.stopped || len(q.window) == 0 {
		return
	}
	maxC := q.releaseAllLocked()
	q.next = maxC + 1
}

// stop retires the queue when its peer departs: the pending timer is cancelled
// and every buffered frame's pooled buffer is returned instead of being held
// until the process exits.
func (q *rxReorderQueue) stop() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.stopped = true
	q.dropAllLocked()
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
	window, delay := n.reorderSettings()
	q := newRxReorderQueue(n, window, delay)
	v, _ := n.rxReorder.LoadOrStore(p, q)
	return v.(*rxReorderQueue)
}
