package node

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// Per-stream asynchronous writers for the "multipath" strategy.
//
// Under multipath a peer has several direct streams and the DWRR scheduler
// hands frames to all of them. Before this writer existed every write ran
// under the peer's global writeMu, so ONE slow path blocked every other
// path's frame for up to its whole write deadline — a single measured-slow
// link made the peer's throughput saw-tooth even though the fast paths sat
// idle. That stall is now confined to the slow path's own queue: the submitter
// picks a path under writeMu, hands the batch to that path's writer, RELEASES
// writeMu and only then waits for the result. Every other path keeps draining
// concurrently, and the receiver's reorder buffer absorbs the cross-path
// interleaving that this concurrency produces (multipath is the only strategy
// that runs with a reorder buffer armed).
//
// Lock ordering: senders take writeMu and drop it before waiting; writer
// goroutines never take writeMu. Both take qualityMu briefly to touch
// writeQuality, and qualityMu holders never acquire writeMu, so the two lock
// orders cannot form a cycle.

const (
	// mpWriterQueueDepth bounds how many wire batches one path's writer may
	// buffer. Full means the path is a whole window behind live traffic —
	// genuinely congested. The submitter treats it as a soft failure and the
	// existing failover + per-path breaker machinery reacts, exactly as for a
	// failed write.
	mpWriterQueueDepth = 64
)

var (
	errWriterQueueFull = errors.New("multipath writer queue full")
	errWriterStopped   = errors.New("multipath writer stopped")
)

// mpWriteTask is one wire batch handed to a path's writer goroutine.
//
// Fragment buffer ownership stays with the SENDER, exactly as in the
// synchronous path: the writer never releases t.frags — the submitter's
// existing error handling does, and every submitter blocks on its result
// until ownership is settled.
type mpWriteTask struct {
	frags  [][]byte
	stat   tapPayloadStat
	node   *Node
	target peer.ID

	// result is buffered(1): the submitter always waits for exactly one
	// result, so the writer never blocks on delivering one.
	result chan mpWriteResult
}

type mpWriteResult struct {
	err       error
	wireBytes int
}

// streamWriter serializes writes to ONE stream on its own goroutine.
type streamWriter struct {
	q    chan mpWriteTask
	stop chan struct{}
	once sync.Once
}

func (w *streamWriter) close() {
	w.once.Do(func() { close(w.stop) })
}

// writerFor returns the async writer for s, spawning its goroutine on first
// use. Caller holds ps.writeMu; the map is writeMu-protected.
func (ps *PeerStreams) writerFor(s network.Stream) *streamWriter {
	if ps.mpWriters == nil {
		ps.mpWriters = make(map[network.Stream]*streamWriter, 4)
	}
	w := ps.mpWriters[s]
	if w == nil {
		w = &streamWriter{
			q:    make(chan mpWriteTask, mpWriterQueueDepth),
			stop: make(chan struct{}),
		}
		ps.mpWriters[s] = w
		go ps.runMpWriter(s, w)
	}
	return w
}

// submitMpWriteLocked hands one wire batch to s's writer without blocking on
// queue capacity. Caller holds ps.writeMu. On success it returns a wait func
// that delivers the write result; the caller MUST drop writeMu before calling
// it and re-acquire afterwards.
func (ps *PeerStreams) submitMpWriteLocked(s network.Stream, node *Node, target peer.ID, frags [][]byte, stat tapPayloadStat) (func() mpWriteResult, error) {
	w := ps.writerFor(s)
	t := mpWriteTask{
		frags:  frags,
		stat:   stat,
		node:   node,
		target: target,
		result: make(chan mpWriteResult, 1),
	}
	select {
	case w.q <- t:
		return func() mpWriteResult { return <-t.result }, nil
	default:
		return nil, errWriterQueueFull
	}
}

// runMpWriter is the writer loop for one stream. It owns the stream's write
// deadline bookkeeping privately (no shared map): only this goroutine writes
// to the stream, so per-stream deadline state needs no lock at all.
func (ps *PeerStreams) runMpWriter(s network.Stream, w *streamWriter) {
	var nextRenew time.Time
	// pathKey is cached per stream (this goroutine is the stream's only writer,
	// and the stream never changes here): rendering the multiaddr for every
	// batch is a heap alloc + base58 formatting on the packet path.
	var pathKey string
	for {
		select {
		case t := <-w.q:
			start := time.Now()
			wireBytes := 0
			for _, frag := range t.frags {
				wireBytes += len(frag) + 4
			}
			if !start.Before(nextRenew) {
				window := ps.writeDeadlineFor(s, wireBytes, start)
				if err := s.SetWriteDeadline(start.Add(window)); err != nil {
					t.result <- mpWriteResult{err: fmt.Errorf("set write deadline: %w", err)}
					continue
				}
				// Renew at the halfway point so a shrinking window takes
				// effect on the next write instead of one full window later.
				nextRenew = start.Add(window / 2)
			}
			err := writeFrames(s, t.frags)
			if err == nil {
				completed := time.Now()
				ps.recordStreamWrite(s, wireBytes, completed.Sub(start), completed)
				if t.node != nil && s.Conn() != nil {
					if pathKey == "" {
						pathKey = s.Conn().RemoteMultiaddr().String()
					}
					t.node.recordPeerTxBytesOnPath(t.target, pathKey, t.stat.bytes, t.stat.frames)
				}
			}
			t.result <- mpWriteResult{err: err, wireBytes: wireBytes}
		case <-w.stop:
			// Fail every still-queued task. Ownership of each task's buffers
			// stays with its sender, who is blocked on the result channel.
			for {
				select {
				case t := <-w.q:
					t.result <- mpWriteResult{err: errWriterStopped}
				default:
					return
				}
			}
		}
	}
}

// stopMpWriterLocked stops and forgets the writer for a retired stream.
// Caller holds ps.writeMu. Queued tasks are failed by the writer goroutine.
func (ps *PeerStreams) stopMpWriterLocked(s network.Stream) {
	if w := ps.mpWriters[s]; w != nil {
		w.close()
		delete(ps.mpWriters, s)
	}
}
