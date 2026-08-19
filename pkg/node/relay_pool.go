package node

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
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

// relayPoolUnsupportedRetry is the (long) re-probe interval used once a hop has
// been proven not to speak OverlayRelayProtocolID. It keeps recovery possible
// without spamming stream negotiations at the reconnect-backoff rate.
const relayPoolUnsupportedRetry = 60 * time.Second

// relayPoolDropWarnInterval throttles the "write queue full, dropping frame"
// WARN. A stalled hop otherwise emits hundreds of identical lines per second,
// burying real signal; we log at most one per interval per hop.
const relayPoolDropWarnInterval = 5 * time.Second

// relayPoolHealthyRxWindow is how recently we must have RECEIVED a frame back
// from a relay hop to treat a successful local write as proof the hop is alive.
// A local write only deposits the frame in the send buffer; in the
// "peer accepts the stream but never reads" failure class the write still
// succeeds while the hop is black-holed, so without this independent return-path
// signal the failure streak would be cleared on every buffered write and the
// circuit-breaker would never trip.
const relayPoolHealthyRxWindow = 10 * time.Second

// overlayRelayBlacklistTTL / overlayRelayBlacklistMaxFailures mirror the
// boot-relay equivalents but for overlay-relay HOPS (mesh peers used as relay
// next-hops). A shorter TTL lets a transiently-stalled mesh hop be retried
// sooner, since mesh relay membership is more dynamic than boot server
// membership. When the relay pool's write loop fails to open or keep a hop's
// relay stream alive for overlayRelayBlacklistMaxFailures consecutive attempts,
// the hop is circuit-broken (blacklisted) so relayHopForTarget stops selecting
// it and frames fall through to a different hop instead of being blackholed.
const overlayRelayBlacklistTTL = 2 * time.Minute
const overlayRelayBlacklistMaxFailures = 5

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

	// unsupported latches true once the hop is proven to not speak
	// OverlayRelayProtocolID, making Submit reject immediately instead of
	// queueing frames that can never be delivered.
	unsupported atomic.Bool

	// node is the owning Node, used to circuit-break (blacklist) the hop when
	// its relay stream is found to be persistently un-openable or stalled.
	node *Node

	// unhealthy is invoked when the hop's relay stream fails to open / keep
	// alive for overlayRelayBlacklistMaxFailures consecutive attempts, so the
	// Node blacklists it and relayHopForTarget picks a different hop. Set by the
	// pool at creation.
	unhealthy func()

	// failCount counts consecutive stream-open / write failures in the single
	// writeLoop goroutine; reaching overlayRelayBlacklistMaxFailures trips
	// unhealthy. Reset to 0 on any successful open/write.
	failCount int

	// lastDropWarn throttles the "queue full, dropping frame" WARN to at most
	// one per relayPoolDropWarnInterval per hop (atomic unix-nano timestamp).
	lastDropWarn int64
}

// isProtocolUnsupported reports whether err is libp2p's permanent
// "protocols not supported" multistream negotiation failure. Matched on the
// message because the concrete error type is a generic instantiation that
// varies across libp2p versions.
func isProtocolUnsupported(err error) bool {
	return err != nil && containsSub(err.Error(), "protocols not supported")
}

// relayStreamPool manages persistent relay streams per relay hop.
// One background write goroutine per active relay peer.
type relayStreamPool struct {
	mu    sync.Mutex
	conns map[peer.ID]*relayConn
	host  host.Host
	ctx   context.Context
	node  *Node // back-reference for overlay-relay-hop circuit breaking
}

func newRelayStreamPool(ctx context.Context, h host.Host, n *Node) *relayStreamPool {
	return &relayStreamPool{
		conns: make(map[peer.ID]*relayConn),
		host:  h,
		ctx:   ctx,
		node:  n,
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

	// Hop already proven to lack OverlayRelayProtocolID — reject without
	// queueing so the caller can immediately use the circuit fallback.
	if rc.unsupported.Load() {
		onFail()
		return false
	}

	// Hop circuit-broken by the overlay-relay health monitor (its relay stream
	// could not be opened / kept stalling). Fast-fail so the caller falls back
	// to a different path instead of piling frames onto a dead queue that would
	// otherwise pin full and drop every frame routed through this hop.
	if p.node != nil && p.node.isOverlayRelayBlacklisted(hop) {
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
		// Queue full: drop the frame (onFail already called) but throttle the
		// WARN — a stalled hop otherwise floods hundreds of identical lines per
		// second and buries the real signal. One WARN per interval per hop.
		rc.throttledDropWarn(hop)
		onFail()
		return false
	}
}

// throttledDropWarn emits the "queue full, dropping frame" WARN at most once per
// relayPoolDropWarnInterval for this hop, using an atomic timestamp so no mutex
// is needed on the hot Submit path.
func (rc *relayConn) throttledDropWarn(hop peer.ID) {
	now := time.Now().UnixNano()
	prev := atomic.LoadInt64(&rc.lastDropWarn)
	if now-prev > int64(relayPoolDropWarnInterval) &&
		atomic.CompareAndSwapInt64(&rc.lastDropWarn, prev, now) {
		relayLog.Warn("Relay pool write queue full for %s, dropping frame", hop.String())
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
		node:    p.node,
	}
	rc.unhealthy = func() {
		if rc.node != nil {
			rc.node.blacklistOverlayRelay(hop)
		}
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

		// Circuit-broken by the overlay-relay health monitor (relay stream could
		// not be opened / kept alive). Throttle reconnect attempts to one per TTL
		// instead of hammering NewStream; the blacklist auto-expires and we retry.
		if rc.node != nil && rc.node.isOverlayRelayBlacklisted(rc.peer) {
			rc.drainAll() // hop is circuit-broken: drop queued frames now so they
			              // fail fast instead of rotting for the whole TTL and being
			              // retried on every (doomed) reconnect attempt.
			select {
			case <-rc.ctx.Done():
				return false
			case <-time.After(overlayRelayBlacklistTTL):
			}
			continue
		}

		s, err := rc.host.NewStream(rc.ctx, rc.peer, OverlayRelayProtocolID)
		if err == nil {
			rc.mu.Lock()
			rc.stream = s
			rc.mu.Unlock()
			*backoff = relayPoolReconnectBackoff // reset backoff on success
			rc.unsupported.Store(false)
			// NOTE: do NOT reset failCount here. A *successful open* only means
			// the stream handshake completed — it says nothing about whether
			// frames can actually be written. In the "peer accepts the stream
			// but never reads" failure mode (the 12D3KooWM9cR... class), NewStream
			// keeps succeeding while every write times out; resetting failCount
			// here would pin the streak at 0 forever and the circuit-breaker
			// would never trip, leaving the hop black-holed and flooding the
			// "write queue full" WARN. failCount is cleared only on a *successful
			// write* (see pumpFrames), the only event proving the hop delivers.
			relayLog.Debug("Relay pool stream established to %s", rc.peer.String())
			return true
		}

		// A "protocols not supported" error is PERMANENT for this peer: it is a
		// pure Circuit Relay v2 node that transits /p2p-circuit but never
		// registers our application-level relay protocol. Retrying it forever
		// only burns the write queue until frames get dropped. Mark the hop so
		// Submit fails fast and the caller falls back to the circuit path.
		// Latch the hop as unsupported so Submit fast-fails, release everything
		// already queued (those frames can never be delivered here), then park
		// on a long retry interval. We deliberately do NOT kill the goroutine:
		// identify may still be in flight, or the peer may be upgraded later,
		// and the periodic re-probe lets the hop recover automatically.
		wait := *backoff
		if isProtocolUnsupported(err) {
			if !rc.unsupported.Swap(true) {
				relayLog.Warn("Relay hop %s does not support %s (circuit-relay-only node); "+
					"falling back to direct/circuit path", rc.peer.String(), OverlayRelayProtocolID)
			}
			rc.drainAll()
			wait = relayPoolUnsupportedRetry
		} else {
			rc.failCount++
			if rc.failCount >= overlayRelayBlacklistMaxFailures && rc.unhealthy != nil {
				// Hop's relay stream could not be opened after repeated attempts
				// — circuit-break it so relayHopForTarget routes around it.
				rc.unhealthy()
			}
			relayLog.Debug("Relay pool stream open to %s failed (backoff=%dms, fails=%d): %v",
				rc.peer.String(), backoff.Milliseconds(), rc.failCount, err)
		}

		timer := time.NewTimer(wait)
		if rc.unsupported.Load() {
			// Parked: keep failing jobs that raced past the latch instead of
			// letting them rot in the queue for the whole re-probe interval.
			if !rc.waitUnsupported(timer) {
				return false
			}
		} else {
			select {
			case <-rc.ctx.Done():
				timer.Stop()
				return false
			case <-timer.C:
			}
		}

		if !rc.unsupported.Load() {
			*backoff *= 2
			if *backoff > 5*time.Second {
				*backoff = 5 * time.Second
			}
		}
	}
}

// waitUnsupported blocks until the re-probe timer fires, immediately failing any
// job that was queued in the window between the last Submit check and the
// unsupported latch. Returns false when the context is cancelled.
func (rc *relayConn) waitUnsupported(timer *time.Timer) bool {
	for {
		select {
		case <-rc.ctx.Done():
			timer.Stop()
			return false
		case job := <-rc.writeCh:
			job.onFail()
		case <-timer.C:
			return true
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
				rc.bumpFailure()
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
					rc.bumpFailure()
					rc.mu.Lock()
					if rc.stream != nil {
						rc.stream.Close()
						rc.stream = nil
					}
					rc.mu.Unlock()
					job.onFail()
				}
		} else {
			// A successful local write only proves the frame entered the send
			// buffer, NOT that the hop consumed it — in the "peer accepts the
			// stream but never reads" class writes keep succeeding into a full
			// flow-control window then stall, so clearing the streak here would
			// let the circuit-breaker never trip. Only clear when we have
			// independent return-path proof: we recently received a frame back
			// FROM this hop.
			if rc.node != nil && rc.node.peerRxWithin(rc.peer, relayPoolHealthyRxWindow) {
				rc.failCount = 0
			}
		}
		}
	}
}

// bumpFailure records one consecutive relay-stream failure and trips the hop's
// circuit-breaker once the streak reaches overlayRelayBlacklistMaxFailures. The
// streak is reset to 0 on any successful open/write, so only a PERSISTENTLY dead
// hop is blacklisted — a single transient stall never is.
func (rc *relayConn) bumpFailure() {
	rc.failCount++
	if rc.failCount >= overlayRelayBlacklistMaxFailures && rc.unhealthy != nil {
		rc.unhealthy()
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
