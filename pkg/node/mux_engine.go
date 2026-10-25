package node

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

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
				case sess.respCh <- payload:
				default:
				}
			}
		}
	}
}

// dispatch calls the protocol handler for a mux tag.
func (e *muxEngine) dispatch(from peer.ID, tag uint8, sess *muxSession) {
	ms := &muxStream{sess: sess}
	wrapped := &logicalPeerStream{Stream: ms, logical: from}

	switch tag {
	case mux.TagSeqSync:
		go e.node.handleSeqSync(wrapped)
	case mux.TagLSA:
		go e.node.handleLSAStream(wrapped)
	case mux.TagMeta:
		go e.node.handleMetaStream(wrapped)
	case mux.TagEcho:
		go e.node.handleEcho(wrapped)
	case mux.TagTapProbeAck:
		go e.node.handleTapProbeAck(wrapped)
	case mux.TagRelayCtrl:
		go e.node.handleRelayCtrl(wrapped)
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

	s := e.getOrOpenLocked(e.node.ctx, target)
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
	buf := make([]byte, maxFrameLen+mux.DataHeaderLen)
	from := s.Conn().RemotePeer()

	for {
		kind, payload, err := mux.ReadDataFrame(s, buf)
		if err != nil {
			return
		}

		switch kind {
		case mux.KindVTP:
			go e.node.handleDataMuxVTP(s, from, payload)
		case mux.KindRelay:
			go e.node.handleDataMuxRelay(s, from, payload)
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

// WrapStream wraps a raw mux stream into a muxInitStream for a specific
// protocol tag. The caller gets a network.Stream that transparently
// multiplexes over the underlying mux stream. Used by openControlStream
// when the mux protocol is available.
func (e *muxEngine) WrapStream(s network.Stream, proto protocol.ID) (network.Stream, bool) {
	tag, ok := muxTagForProto(proto)
	if !ok {
		return nil, false
	}
	reqID := e.nextReqID.Add(1)
	sess := &muxSession{
		tag:    tag,
		reqID:  reqID,
		stream: s,
		respCh: make(chan []byte, 1),
	}
	e.sessionsMu.Lock()
	e.sessions[reqID] = sess
	e.sessionsMu.Unlock()
	return &muxInitStream{stream: s, tag: tag, reqID: reqID, sess: sess, engine: e}, true
}
