package node

import (
	"context"
	"errors"
	"sync"
	"time"

	"p2ptap/pkg/logger"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

var errStreamNotReady = errors.New("relay stream not ready")

var relayLog = logger.New("RelayPool")

// relayPoolMaxQueue is the per-relay-hop write buffer depth.
// When full, Submit returns false and the caller should fall back.
const relayPoolMaxQueue = 128

// relayPoolReconnectBackoff is the base interval between reconnect attempts.
const relayPoolReconnectBackoff = 200 * time.Millisecond

// relayJob represents a single frame to be written on a relay stream.
type relayJob struct {
	data   []byte // relay-wrapped payload
	onFail func() // called when this frame permanently fails to deliver
	onSent func() // called when this frame is successfully written (nil for forwarding)
}

// relayConn maintains a persistent OverlayRelayProtocolID stream to one relay peer.
type relayConn struct {
	peer   peer.ID
	host   host.Host
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	stream  network.Stream
	writeCh chan relayJob
}

// relayStreamPool manages persistent relay streams per relay hop.
// One background write goroutine per active relay peer.
type relayStreamPool struct {
	mu    sync.Mutex
	conns map[peer.ID]*relayConn
	host  host.Host
	ctx   context.Context
}

func newRelayStreamPool(ctx context.Context, h host.Host) *relayStreamPool {
	return &relayStreamPool{
		conns: make(map[peer.ID]*relayConn),
		host:  h,
		ctx:   ctx,
	}
}

// Submit queues a relay frame for delivery via the persistent relay stream to hop.
// onSent is called when the frame is successfully written (may be nil for
// relay forwarding where the origin already counted the send).
// onFail is called exactly once if this frame cannot be delivered after reconnect
// attempts (or if the queue is full).
// Returns false if the internal queue is full, meaning onFail has already been called.
func (p *relayStreamPool) Submit(hop peer.ID, data []byte, onSent, onFail func()) bool {
	rc := p.getOrCreate(hop)
	if rc == nil {
		onFail()
		return false
	}

	job := relayJob{
		data:   data,
		onSent: onSent,
		onFail: onFail,
	}

	select {
	case rc.writeCh <- job:
		return true
		default:
			relayLog.Warn("Relay pool write queue full for %s, dropping frame", hop.String())
			onFail()
			return false
	}
}

// getOrCreate returns or lazily creates a relayConn for the given hop.
func (p *relayStreamPool) getOrCreate(hop peer.ID) *relayConn {
	p.mu.Lock()
	rc, ok := p.conns[hop]
	if !ok {
		rc = p.startRelayConn(hop)
		p.conns[hop] = rc
	}
	p.mu.Unlock()
	return rc
}

// startRelayConn initializes a relayConn and launches its background write loop.
func (p *relayStreamPool) startRelayConn(hop peer.ID) *relayConn {
	ctx, cancel := context.WithCancel(p.ctx)
	rc := &relayConn{
		peer:    hop,
		host:    p.host,
		ctx:     ctx,
		cancel:  cancel,
		writeCh: make(chan relayJob, relayPoolMaxQueue),
	}
	rc.wg.Add(1)
	go rc.writeLoop()
	return rc
}

// shutdown stops all relay connections. Must be called before the host closes.
func (p *relayStreamPool) shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for hop, rc := range p.conns {
		rc.cancel()
		rc.wg.Wait()
		rc.closeStream()
		delete(p.conns, hop)
	}
}

// closeStream closes the current stream (if any) under the lock.
func (rc *relayConn) closeStream() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.stream != nil {
		rc.stream.Close()
		rc.stream = nil
	}
}

// writeLoop is the single goroutine that maintains a persistent relay stream.
// It opens the stream, pumps frames from writeCh, and reconnects on failure.
func (rc *relayConn) writeLoop() {
	defer rc.wg.Done()
	defer rc.closeStream()

	backoff := relayPoolReconnectBackoff

	for {
		// Ensure we have a stream open.
		if !rc.ensureStream(&backoff) {
			// Context cancelled, drain remaining jobs.
			rc.drainAll()
			return
		}

		// Pump frames.
		if !rc.pumpFrames(&backoff) {
			// PumpFrames returns false on shutdown.
			return
		}
		// Stream broke; backoff will grow, reconnect loop continues.
	}
}

// ensureStream opens (or reopens) the relay stream with exponential-ish backoff.
// Returns false only when the context is cancelled.
func (rc *relayConn) ensureStream(backoff *time.Duration) bool {
	for {
		select {
		case <-rc.ctx.Done():
			return false
		default:
		}

		s, err := rc.host.NewStream(rc.ctx, rc.peer, OverlayRelayProtocolID)
		if err == nil {
			rc.mu.Lock()
			rc.stream = s
			rc.mu.Unlock()
			*backoff = relayPoolReconnectBackoff // reset backoff on success
			relayLog.Debug("Relay pool stream established to %s", rc.peer.String())
			return true
		}

		// Reconnect backoff.
		relayLog.Debug("Relay pool stream open to %s failed (backoff=%dms): %v",
			rc.peer.String(), backoff.Milliseconds(), err)
		timer := time.NewTimer(*backoff)
		select {
		case <-rc.ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
		*backoff *= 2
		if *backoff > 5*time.Second {
			*backoff = 5 * time.Second
		}
	}
}

// pumpFrames reads from writeCh and writes to the current stream.
// Returns false on context cancellation, true on stream error (reconnect needed).
func (rc *relayConn) pumpFrames(backoff *time.Duration) bool {
	for {
		select {
		case <-rc.ctx.Done():
			return false
		case job, ok := <-rc.writeCh:
			if !ok {
				return false
			}

			if err := rc.writeFrame(job); err != nil {
				// Stream write failed — mark failed, retry after reconnect.
				rc.mu.Lock()
				if rc.stream != nil {
					rc.stream.Close()
					rc.stream = nil
				}
				rc.mu.Unlock()

				// Reconnect.
				if !rc.ensureStream(backoff) {
					job.onFail()
					continue
				}

				// Retry once after reconnect.
				if err := rc.writeFrame(job); err != nil {
					rc.mu.Lock()
					if rc.stream != nil {
						rc.stream.Close()
						rc.stream = nil
					}
					rc.mu.Unlock()
					job.onFail()
				}
			}
		}
	}
}

// writeFrame writes a single relay job to the current stream.
func (rc *relayConn) writeFrame(job relayJob) error {
	rc.mu.Lock()
	s := rc.stream
	rc.mu.Unlock()

	if s == nil {
		return errStreamNotReady
	}

	_ = s.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err := WriteFrame(s, job.data); err != nil {
		return err
	}
	if job.onSent != nil {
		job.onSent()
	}
	return nil
}

// drainAll drains all pending jobs from the writeCh during shutdown, calling onFail for each.
func (rc *relayConn) drainAll() {
	for {
		select {
		case job := <-rc.writeCh:
			job.onFail()
		default:
			return
		}
	}
}
