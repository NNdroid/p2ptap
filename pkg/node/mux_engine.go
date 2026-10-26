package node

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	mux "p2ptap/pkg/mux"
)

// muxEngine is the unified multiplexer for the control channel. It replaces
// the three separate lsaStreamPool instances (lsaPool, metaPool, echoPool)
// with a single engine that multiplexes all control protocols onto one stream
// per peer. Fire-and-forget protocols (LSA, TapProbeAck) use Send; request/
// response protocols (Meta, Echo, SeqSync) use SendRecv.
type muxEngine struct {
	node *Node

	mu       sync.Mutex
	streams  map[peer.ID]network.Stream
	writeMu  map[peer.ID]*sync.Mutex

	sessionsMu sync.Mutex
	sessions   map[uint32]*muxSession

	nextReqID atomic.Uint32
}

func newMuxEngine(n *Node) *muxEngine {
	return &muxEngine{
		node:     n,
		streams:  make(map[peer.ID]network.Stream),
		writeMu:  make(map[peer.ID]*sync.Mutex),
		sessions: make(map[uint32]*muxSession),
	}
}

func (e *muxEngine) peerMuLocked(target peer.ID) *sync.Mutex {
	m, ok := e.writeMu[target]
	if !ok {
		m = &sync.Mutex{}
		e.writeMu[target] = m
	}
	return m
}

func (e *muxEngine) getOrOpenLocked(ctx context.Context, target peer.ID) network.Stream {
	e.mu.Lock()
	s, ok := e.streams[target]
	e.mu.Unlock()
	if ok {
		return s
	}

	s, err := e.node.openControlStream(ctx, target, mux.ControlProtocolID)
	if err != nil {
		log.Debug("mux stream open to %s failed: %v", target.ShortString(), err)
		return nil
	}

	e.mu.Lock()
	e.streams[target] = s
	e.mu.Unlock()

	go e.handleStream(s, target)
	return s
}

// handleControlStream is the stream handler for /p2ptap/ctrl/1.0.0.
// It reads mux frames and dispatches them to protocol handlers.
func (e *muxEngine) handleControlStream(s network.Stream) {
	from := s.Conn().RemotePeer()
	e.handleStream(s, from)
}

// handleStream reads mux frames from an accepted mux stream and dispatches
// them to protocol handlers.
func (e *muxEngine) handleStream(s network.Stream, from peer.ID) {
	defer s.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Error("mux handleStream panic (from %s): %v", from.ShortString(), r)
		}
		e.mu.Lock()
		if cur := e.streams[from]; cur == s {
			delete(e.streams, from)
		}
		e.mu.Unlock()
	}()
	// Reset on node shutdown, matching handleDataStream. The control channel is
	// idle between events by design (LSA/Meta updates arrive on their own
	// cadence, with no heartbeat), so no read deadline is set here — one would
	// tear down healthy idle streams. Without the ctx.Done reset, however, a
	// stream whose peer vanished silently pinned this goroutine and its 1 MiB
	// read buffer until the node's own shutdown tore the host down.
	if n := e.node; n.ctx != nil {
		streamDone := make(chan struct{})
		defer close(streamDone)
		go func() {
			select {
			case <-n.ctx.Done():
				_ = s.Reset()
			case <-streamDone:
			}
		}()
	}
	// maxFrameLen rather than a tighter bound: an LSA snapshot carries up to
	// maxLSANeighbors neighbours per origin, so the control channel is the only
	// mux channel whose frames can approach the full frame budget.
	buf := make([]byte, maxFrameLen+mux.HeaderLen)

	for {
		tag, dir, reqID, payload, err := mux.ReadFrame(s, buf)
		if err != nil {
			return
		}

		switch dir {
		case mux.DirRequest, mux.DirBroadcast:
			sess := &muxSession{
				tag:     tag,
				reqID:   reqID,
				stream:  s,
				request: append([]byte(nil), payload...),
				respCh:  make(chan []byte, 1),
			}
			if dir == mux.DirRequest {
				e.sessionsMu.Lock()
				e.sessions[reqID] = sess
				e.sessionsMu.Unlock()
			}
			e.dispatch(from, tag, sess)

		case mux.DirResponse:
			e.sessionsMu.Lock()
			sess := e.sessions[reqID]
			delete(e.sessions, reqID)
			e.sessionsMu.Unlock()
			if sess != nil {
				select {
				case sess.respCh <- append([]byte(nil), payload...):
				default:
				}
			}
		}
	}
}

// dispatch calls the protocol handler for a mux tag. Each handler runs in
// its own goroutine with a recover() guard so a panic in one handler does
// not kill the process.
func (e *muxEngine) dispatch(from peer.ID, tag uint8, sess *muxSession) {
	ms := &muxStream{sess: sess}
	wrapped := &logicalPeerStream{Stream: ms, logical: from}

	dispatchHandler := func(h func(network.Stream)) {
		defer func() {
			if r := recover(); r != nil {
				log.Error("mux dispatch panic (tag=%d, from=%s): %v", tag, from.ShortString(), r)
			}
		}()
		h(wrapped)
	}

	switch tag {
	case mux.TagSeqSync:
		go dispatchHandler(e.node.handleSeqSync)
	case mux.TagLSA:
		go dispatchHandler(e.node.handleLSAStream)
	case mux.TagMeta:
		go dispatchHandler(e.node.handleMetaStream)
	case mux.TagEcho:
		go dispatchHandler(e.node.handleEcho)
	case mux.TagTapProbeAck:
		go dispatchHandler(e.node.handleTapProbeAck)
	case mux.TagRelayCtrl:
		go dispatchHandler(e.node.handleRelayCtrl)
	default:
		log.Warn("mux: no handler for tag %d (from %s)", tag, from.ShortString())
	}
}

// Send sends a fire-and-forget mux frame (no response expected).
func (e *muxEngine) Send(target peer.ID, tag uint8, payload []byte) bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	m := e.peerMuLocked(target)
	e.mu.Unlock()

	m.Lock()
	defer m.Unlock()

	ctx, cancel := context.WithTimeout(e.node.ctx, 15*time.Second)
	defer cancel()
	s := e.getOrOpenLocked(ctx, target)
	if s == nil {
		return false
	}
	if _, err := mux.WriteFrame(s, tag, mux.DirBroadcast, 0, payload); err != nil {
		e.closeLocked(target)
		s = e.openLocked(target)
		if s == nil {
			return false
		}
		if _, err := mux.WriteFrame(s, tag, mux.DirBroadcast, 0, payload); err != nil {
			e.closeLocked(target)
			return false
		}
	}
	return true
}

// SendRecv sends a request mux frame and waits for a matching response.
func (e *muxEngine) SendRecv(target peer.ID, tag uint8, payload []byte, timeout time.Duration) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("mux engine is nil")
	}
	e.mu.Lock()
	m := e.peerMuLocked(target)
	e.mu.Unlock()

	m.Lock()
	defer m.Unlock()

	ctx, cancel := context.WithTimeout(e.node.ctx, timeout)
	defer cancel()
	s := e.getOrOpenLocked(ctx, target)
	if s == nil {
		return nil, fmt.Errorf("mux: cannot open stream to %s", target.ShortString())
	}

	reqID := e.nextReqID.Add(1)
	sess := &muxSession{
		tag:      tag,
		reqID:    reqID,
		stream:   s,
		respCh:   make(chan []byte, 1),
		deadline: time.Now().Add(timeout),
	}
	e.sessionsMu.Lock()
	e.sessions[reqID] = sess
	e.sessionsMu.Unlock()

	defer func() {
		e.sessionsMu.Lock()
		delete(e.sessions, reqID)
		e.sessionsMu.Unlock()
	}()

	if _, err := mux.WriteFrame(s, tag, mux.DirRequest, reqID, payload); err != nil {
		return nil, err
	}

	select {
	case resp := <-sess.respCh:
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(timeout):
		return nil, fmt.Errorf("mux: request timeout (tag=%d, target=%s)", tag, target.ShortString())
	}
}

func (e *muxEngine) openLocked(target peer.ID) network.Stream {
	ctx, cancel := context.WithTimeout(e.node.ctx, 15*time.Second)
	defer cancel()
	s, err := e.node.openControlStream(ctx, target, mux.ControlProtocolID)
	if err != nil {
		return nil
	}
	e.mu.Lock()
	e.streams[target] = s
	e.mu.Unlock()
	return s
}

func (e *muxEngine) closeLocked(target peer.ID) {
	e.mu.Lock()
	s, ok := e.streams[target]
	if ok {
		delete(e.streams, target)
	}
	e.mu.Unlock()
	if ok {
		s.Close()
	}
}

func (e *muxEngine) Invalidate(target peer.ID) {
	if e == nil {
		return
	}
	e.mu.Lock()
	m, ok := e.writeMu[target]
	e.mu.Unlock()
	if !ok {
		return
	}
	if !tryLockTimeout(m, peerInvalidateWaitTimeout) {
		e.closeLocked(target)
		return
	}
	defer m.Unlock()
	e.closeLocked(target)
}

func (e *muxEngine) DropConnStreams(target peer.ID, deadConn network.Conn) bool {
	if e == nil || deadConn == nil {
		return false
	}
	e.mu.Lock()
	m, ok := e.writeMu[target]
	s := e.streams[target]
	e.mu.Unlock()
	if s == nil {
		return false
	}
	if sc := s.Conn(); sc == nil || sc.RemotePeer() != target ||
		sc.RemoteMultiaddr().String() != deadConn.RemoteMultiaddr().String() {
		return false
	}
	if !ok || !tryLockTimeout(m, peerInvalidateWaitTimeout) {
		e.closeLocked(target)
		return true
	}
	defer m.Unlock()
	e.closeLocked(target)
	return true
}

// handleDataStream is the stream handler for /p2ptap/data/1.0.0.
// It reads data mux frames and dispatches them by kind.
func (e *muxEngine) handleDataStream(s network.Stream) {
	defer s.Close()
	from := s.Conn().RemotePeer()
	defer func() {
		if r := recover(); r != nil {
			log.Error("mux handleDataStream panic (from %s): %v", from.ShortString(), r)
		}
	}()
	// Reset on node shutdown, matching handleStream/handleRelayStream. An idle
	// data channel (peer connected but sending nothing) would otherwise pin this
	// goroutine and its 65 KiB read buffer for the node's entire lifetime.
	if n := e.node; n.ctx != nil {
		streamDone := make(chan struct{})
		defer close(streamDone)
		go func() {
			select {
			case <-n.ctx.Done():
				_ = s.Reset()
			case <-streamDone:
			}
		}()
	}
	// Sized to maxBootRelayEnvelope, NOT maxFrameLen: every data-channel kind
	// carries an obfuscate frame (VTP), a relay envelope (Relay) or a boot-relay
	// envelope (BootRelay), all of which are capped at ~65670 bytes by the
	// obfuscate frame limit. The control channel keeps maxFrameLen because LSA
	// snapshots carry up to maxLSANeighbors neighbours per origin and genuinely
	// approach the full budget — the data channel never does. This was 1 MiB,
	// 16x the largest frame it can ever see.
	buf := make([]byte, maxBootRelayEnvelope+mux.DataHeaderLen)

	for {
		kind, payload, err := mux.ReadDataFrame(s, buf)
		if err != nil {
			return
		}

		switch kind {
		case mux.KindVTP:
			p := append([]byte(nil), payload...)
			go e.node.handleDataMuxVTP(s, from, p)
		case mux.KindRelay:
			p := append([]byte(nil), payload...)
			go e.node.handleDataMuxRelay(s, from, p)
		case mux.KindBootRelay:
			p := append([]byte(nil), payload...)
			go e.node.handleDataMuxBootRelay(s, from, p)
		default:
			log.Warn("mux data: unknown kind %d from %s", kind, from.ShortString())
		}
	}
}

func (e *muxEngine) InvalidateAll() {
	if e == nil {
		return
	}
	e.mu.Lock()
	targets := make([]peer.ID, 0, len(e.streams))
	for id := range e.streams {
		targets = append(targets, id)
	}
	e.mu.Unlock()
	for _, id := range targets {
		e.Invalidate(id)
	}
}
