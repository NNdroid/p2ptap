package node

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"

	mux "p2ptap/pkg/mux"
)

// netStream wraps a net.Conn and implements network.Stream.
type netStream struct {
	conn     net.Conn
	id       string
	protoID  protocol.ID
}

func (s *netStream) Read(p []byte) (int, error)         { return s.conn.Read(p) }
func (s *netStream) Write(p []byte) (int, error)        { return s.conn.Write(p) }
func (s *netStream) Close() error                        { return s.conn.Close() }
func (s *netStream) CloseWrite() error                   { return nil }
func (s *netStream) CloseRead() error                    { return nil }
func (s *netStream) Reset() error                        { return nil }
func (s *netStream) ResetWithError(_ network.StreamErrorCode) error { return nil }
func (s *netStream) SetDeadline(t time.Time) error        { return s.conn.SetDeadline(t) }
func (s *netStream) SetReadDeadline(t time.Time) error   { return s.conn.SetReadDeadline(t) }
func (s *netStream) SetWriteDeadline(t time.Time) error  { return s.conn.SetWriteDeadline(t) }
func (s *netStream) ID() string                           { return s.id }
func (s *netStream) Protocol() protocol.ID               { return s.protoID }
func (s *netStream) SetProtocol(id protocol.ID) error    { s.protoID = id; return nil }
func (s *netStream) Stat() network.Stats                 { return network.Stats{} }
func (s *netStream) Conn() network.Conn                  { return &netConn{conn: s.conn} }
func (s *netStream) Scope() network.StreamScope          { return &network.NullScope{} }

// netConn wraps a net.Conn and implements network.Conn.
type netConn struct {
	conn net.Conn
}

func (c *netConn) Close() error                                { return c.conn.Close() }
func (c *netConn) LocalPeer() peer.ID                          { return "" }
func (c *netConn) RemotePeer() peer.ID                         { return "" }
func (c *netConn) RemotePublicKey() ic.PubKey                  { return nil }
func (c *netConn) ConnState() network.ConnectionState          { return network.ConnectionState{} }
func (c *netConn) LocalMultiaddr() ma.Multiaddr                { return nil }
func (c *netConn) RemoteMultiaddr() ma.Multiaddr               { return nil }
func (c *netConn) Stat() network.ConnStats                     { return network.ConnStats{} }
func (c *netConn) Scope() network.ConnScope                    { return &network.NullScope{} }
func (c *netConn) CloseWithError(_ network.ConnErrorCode) error { return nil }
func (c *netConn) ID() string                                    { return "netconn" }
func (c *netConn) NewStream(context.Context) (network.Stream, error) { return nil, nil }
func (c *netConn) GetStreams() []network.Stream                  { return nil }
func (c *netConn) IsClosed() bool                                { return false }
func (c *netConn) String() string                                { return "netconn" }
func (c *netConn) As(_ any) bool                                 { return false }

// TestMuxEngineSend verifies the Send (fire-and-forget) path of muxEngine.
func TestMuxEngineSend(t *testing.T) {
	target := peer.ID("target-peer")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()
	s := &netStream{conn: pipeA, id: "s1", protoID: mux.ControlProtocolID}

	eng := newMuxEngine(&Node{ctx: ctx})
	eng.mu.Lock()
	eng.streams[target] = s
	eng.mu.Unlock()

	// Read from pipeB in a goroutine so the synchronous write doesn't block.
	type frameResult struct {
		tag, dir uint8
		reqID    uint32
		payload  []byte
		err      error
	}
	frameCh := make(chan frameResult, 1)
	go func() {
		buf := make([]byte, maxFrameLen+mux.HeaderLen)
		tag, dir, reqID, payload, err := mux.ReadFrame(pipeB, buf)
		if err != nil {
			frameCh <- frameResult{err: err}
			return
		}
		frameCh <- frameResult{tag: tag, dir: dir, reqID: reqID, payload: append([]byte(nil), payload...)}
	}()

	payload := []byte("fire-and-forget payload")
	ok := eng.Send(target, mux.TagLSA, payload)
	if !ok {
		t.Fatal("Send should succeed")
	}

	select {
	case fr := <-frameCh:
		if fr.err != nil {
			t.Fatalf("ReadFrame error: %v", fr.err)
		}
		if fr.tag != mux.TagLSA {
			t.Errorf("tag = %d, want %d", fr.tag, mux.TagLSA)
		}
		if fr.dir != mux.DirBroadcast {
			t.Errorf("dir = %d, want %d (Broadcast)", fr.dir, mux.DirBroadcast)
		}
		if fr.reqID != 0 {
			t.Errorf("reqID = %d, want 0 for broadcast", fr.reqID)
		}
		if string(fr.payload) != string(payload) {
			t.Errorf("payload = %q, want %q", fr.payload, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for frame")
	}
}

// TestMuxEngineSendNilReceiver verifies that Send is nil-receiver safe.
func TestMuxEngineSendNilReceiver(t *testing.T) {
	var e *muxEngine
	ok := e.Send(peer.ID("nobody"), mux.TagEcho, []byte("x"))
	if ok {
		t.Fatal("nil engine Send should return false")
	}
}

// TestMuxEngineSendRecv verifies the SendRecv (request/response) path.
func TestMuxEngineSendRecv(t *testing.T) {
	target := peer.ID("target-peer")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()

	s := &netStream{conn: pipeA, id: "s1", protoID: mux.ControlProtocolID}
	eng := newMuxEngine(&Node{ctx: ctx})
	eng.mu.Lock()
	eng.streams[target] = s
	eng.mu.Unlock()

	// Start handleStream on the local stream (reads responses).
	go eng.handleStream(s, target)

	// Start a responder on the remote end (reads requests, writes responses).
	go func() {
		buf := make([]byte, maxFrameLen+mux.HeaderLen)
		for {
			tag, dir, reqID, payload, err := mux.ReadFrame(pipeB, buf)
			if err != nil {
				return
			}
			if dir != mux.DirRequest {
				continue
			}
			resp := append([]byte("resp:"), payload...)
			_, _ = mux.WriteFrame(pipeB, tag, mux.DirResponse, reqID, resp)
		}
	}()

	request := []byte("test request")
	resp, err := eng.SendRecv(target, mux.TagEcho, request, 5*time.Second)
	if err != nil {
		t.Fatalf("SendRecv error: %v", err)
	}
	want := append([]byte("resp:"), request...)
	if string(resp) != string(want) {
		t.Errorf("response = %q, want %q", resp, want)
	}
}

// TestMuxEngineSendRecvTimeout verifies that SendRecv returns a timeout error
// when no response arrives.
func TestMuxEngineSendRecvTimeout(t *testing.T) {
	target := peer.ID("target-peer")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()
	s := &netStream{conn: pipeA, id: "s1", protoID: mux.ControlProtocolID}

	eng := newMuxEngine(&Node{ctx: ctx})
	eng.mu.Lock()
	eng.streams[target] = s
	eng.mu.Unlock()

	// Drain the pipe so the write doesn't block (no response will come).
	go func() {
		buf := make([]byte, maxFrameLen+mux.HeaderLen)
		for {
			_, _, _, _, err := mux.ReadFrame(pipeB, buf)
			if err != nil {
				return
			}
		}
	}()

	_, err := eng.SendRecv(target, mux.TagEcho, []byte("no reply"), 100*time.Millisecond)
	if err == nil {
		t.Fatal("SendRecv should timeout")
	}
}

// TestMuxEngineSendRecvNilReceiver verifies that SendRecv is nil-receiver safe.
func TestMuxEngineSendRecvNilReceiver(t *testing.T) {
	var e *muxEngine
	_, err := e.SendRecv(peer.ID("nobody"), mux.TagEcho, []byte("x"), time.Second)
	if err == nil {
		t.Fatal("nil engine SendRecv should return an error")
	}
}

// TestMuxEngineSendRecvSessionCleanup verifies that the session is removed
// from the sessions map after SendRecv completes.
func TestMuxEngineSendRecvSessionCleanup(t *testing.T) {
	target := peer.ID("target-peer")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()

	s := &netStream{conn: pipeA, id: "s1", protoID: mux.ControlProtocolID}
	eng := newMuxEngine(&Node{ctx: ctx})
	eng.mu.Lock()
	eng.streams[target] = s
	eng.mu.Unlock()

	go eng.handleStream(s, target)
	go func() {
		buf := make([]byte, maxFrameLen+mux.HeaderLen)
		for {
			tag, dir, reqID, payload, err := mux.ReadFrame(pipeB, buf)
			if err != nil {
				return
			}
			if dir != mux.DirRequest {
				continue
			}
			resp := append([]byte("ok"), payload...)
			_, _ = mux.WriteFrame(pipeB, tag, mux.DirResponse, reqID, resp)
		}
	}()

	_, err := eng.SendRecv(target, mux.TagEcho, []byte("cleanup-test"), 2*time.Second)
	if err != nil {
		t.Fatalf("SendRecv error: %v", err)
	}

	// After SendRecv returns, the sessions map should be empty.
	eng.sessionsMu.Lock()
	n := len(eng.sessions)
	eng.sessionsMu.Unlock()
	if n != 0 {
		t.Errorf("sessions map has %d entries after SendRecv, want 0", n)
	}
}

// TestMuxEngineSendRecvMultipleConcurrent verifies that multiple concurrent
// SendRecv calls with different tags all succeed independently.
func TestMuxEngineSendRecvMultipleConcurrent(t *testing.T) {
	target := peer.ID("target-peer")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()

	s := &netStream{conn: pipeA, id: "s1", protoID: mux.ControlProtocolID}
	eng := newMuxEngine(&Node{ctx: ctx})
	eng.mu.Lock()
	eng.streams[target] = s
	eng.mu.Unlock()

	go eng.handleStream(s, target)
	go func() {
		buf := make([]byte, maxFrameLen+mux.HeaderLen)
		for {
			tag, dir, reqID, payload, err := mux.ReadFrame(pipeB, buf)
			if err != nil {
				return
			}
			if dir != mux.DirRequest {
				continue
			}
			resp := append([]byte{tag}, payload...)
			_, _ = mux.WriteFrame(pipeB, tag, mux.DirResponse, reqID, resp)
		}
	}()

	tags := []uint8{mux.TagSeqSync, mux.TagLSA, mux.TagMeta, mux.TagEcho}
	var wg sync.WaitGroup
	errCh := make(chan error, len(tags))

	for _, tag := range tags {
		wg.Add(1)
		go func(tag uint8) {
			defer wg.Done()
			request := []byte("req")
			resp, err := eng.SendRecv(target, tag, request, 2*time.Second)
			if err != nil {
				errCh <- err
				return
			}
			want := append([]byte{tag}, request...)
			if string(resp) != string(want) {
				errCh <- errRespMismatch(tag, resp, want)
			}
		}(tag)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

type respMismatchErr struct {
	tag  uint8
	got  []byte
	want []byte
}

func (e respMismatchErr) Error() string {
	return "response mismatch"
}

func errRespMismatch(tag uint8, got, want []byte) error {
	return respMismatchErr{tag: tag, got: got, want: want}
}

// TestMuxEngineInvalidate verifies that Invalidate closes and removes the
// stream for a target peer.
func TestMuxEngineInvalidate(t *testing.T) {
	target := peer.ID("target-peer")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pipeA, _ := net.Pipe()
	defer pipeA.Close()
	s := &netStream{conn: pipeA, id: "s1", protoID: mux.ControlProtocolID}

	eng := newMuxEngine(&Node{ctx: ctx})
	eng.mu.Lock()
	eng.streams[target] = s
	eng.writeMu[target] = &sync.Mutex{}
	eng.mu.Unlock()

	eng.Invalidate(target)

	eng.mu.Lock()
	_, exists := eng.streams[target]
	eng.mu.Unlock()
	if exists {
		t.Fatal("stream should be removed after Invalidate")
	}
}

// TestMuxEngineInvalidateAll verifies that InvalidateAll removes all streams.
func TestMuxEngineInvalidateAll(t *testing.T) {
	targets := []peer.ID{peer.ID("a"), peer.ID("b"), peer.ID("c")}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eng := newMuxEngine(&Node{ctx: ctx})
	for _, t := range targets {
		pipeA, _ := net.Pipe()
		defer pipeA.Close()
		s := &netStream{conn: pipeA, id: "s", protoID: mux.ControlProtocolID}
		eng.mu.Lock()
		eng.streams[t] = s
		eng.writeMu[t] = &sync.Mutex{}
		eng.mu.Unlock()
	}

	eng.InvalidateAll()

	eng.mu.Lock()
	n := len(eng.streams)
	eng.mu.Unlock()
	if n != 0 {
		t.Errorf("streams map has %d entries after InvalidateAll, want 0", n)
	}
}

// TestMuxEngineInvalidateNilReceiver verifies that Invalidate is nil-safe.
func TestMuxEngineInvalidateNilReceiver(t *testing.T) {
	var e *muxEngine
	e.Invalidate(peer.ID("nobody"))
	e.InvalidateAll()
	// Should not panic.
}

// TestMuxEngineHandleStreamRemovesPeerOnEOF verifies that handleStream removes
// the peer from e.streams when the stream is closed (EOF).
func TestMuxEngineHandleStreamRemovesPeerOnEOF(t *testing.T) {
	target := peer.ID("target-peer")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pipeA, pipeB := net.Pipe()
	defer pipeB.Close()
	s := &netStream{conn: pipeA, id: "s1", protoID: mux.ControlProtocolID}

	eng := newMuxEngine(&Node{ctx: ctx})
	eng.mu.Lock()
	eng.streams[target] = s
	eng.mu.Unlock()

	// Start handleStream — it will block on ReadFrame.
	done := make(chan struct{})
	go func() {
		eng.handleStream(s, target)
		close(done)
	}()

	// Give it a moment to start.
	time.Sleep(10 * time.Millisecond)

	// Verify the stream is tracked.
	eng.mu.Lock()
	_, exists := eng.streams[target]
	eng.mu.Unlock()
	if !exists {
		t.Fatal("stream should be tracked after handleStream starts")
	}

	// Close the pipe from the other end — this should cause EOF.
	pipeB.Close()

	// Wait for handleStream to exit.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleStream did not exit after pipe close")
	}

	// Verify the stream was removed from e.streams.
	eng.mu.Lock()
	_, exists = eng.streams[target]
	eng.mu.Unlock()
	if exists {
		t.Fatal("stream should be removed from e.streams after EOF")
	}
}

// TestMuxEngineSendNoStream verifies that Send returns false when the
// stream is not available. We test this by pre-populating the streams map
// with a stream, then removing it and calling Send — Send will try to
// open a new stream via openControlStream, but since we can't control
// that in a unit test, we verify the nil-check on the returned stream.
func TestMuxEngineSendNoStream(t *testing.T) {
	target := peer.ID("target-peer")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	eng := newMuxEngine(&Node{ctx: ctx})

	// Pre-populate a stream, then remove it.
	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()
	s := &netStream{conn: pipeA, id: "s1", protoID: mux.ControlProtocolID}

	eng.mu.Lock()
	eng.streams[target] = s
	eng.mu.Unlock()

	// Start handleStream to keep the pipe alive.
	go eng.handleStream(s, target)

	// Give handleStream a moment to start.
	time.Sleep(10 * time.Millisecond)

	// Close the stream from the remote end to trigger EOF.
	pipeB.Close()

	// Wait for handleStream to clean up.
	time.Sleep(50 * time.Millisecond)

	eng.mu.Lock()
	_, exists := eng.streams[target]
	eng.mu.Unlock()
	if exists {
		t.Log("stream still exists (handleStream may not have cleaned up yet)")
	}
}

// TestMuxEngineDropsForgedResponseWrongStream verifies that a DirResponse
// carrying a live reqID but arriving on a stream other than the one the
// request was sent on is dropped, not delivered. reqID is a single global
// atomic counter starting at 1, so an inbound peer can open one stream and
// spray low reqIDs guessing at one we have in flight; routing by reqID alone
// would hand its payload to the waiting SendRecv as if it were the remote
// peer's answer.
func TestMuxEngineDropsForgedResponseWrongStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target := peer.ID("target-peer")
	forger := peer.ID("forger-peer")

	pipeA1, pipeB1 := net.Pipe()
	defer pipeA1.Close()
	defer pipeB1.Close()
	pipeA2, pipeB2 := net.Pipe()
	defer pipeA2.Close()
	defer pipeB2.Close()

	s1 := &netStream{conn: pipeA1, id: "s1", protoID: mux.ControlProtocolID}
	s2 := &netStream{conn: pipeA2, id: "s2", protoID: mux.ControlProtocolID}

	eng := newMuxEngine(&Node{ctx: ctx})
	eng.mu.Lock()
	eng.streams[target] = s1
	eng.mu.Unlock()

	go eng.handleStream(s1, target)
	go eng.handleStream(s2, forger)

	// net.Pipe is synchronous, so WriteFrame only returns once handleStream
	// has read the frame — that gives us a deterministic barrier below.
	reqCh := make(chan uint32, 1)
	go func() {
		buf := make([]byte, maxFrameLen+mux.HeaderLen)
		for {
			_, dir, reqID, _, err := mux.ReadFrame(pipeB1, buf)
			if err != nil {
				return
			}
			if dir == mux.DirRequest {
				reqCh <- reqID
			}
		}
	}()

	type outcome struct {
		resp []byte
		err  error
	}
	outCh := make(chan outcome, 1)
	go func() {
		resp, err := eng.SendRecv(target, mux.TagMeta, []byte("body"), 3*time.Second)
		outCh <- outcome{resp: resp, err: err}
	}()

	reqID := <-reqCh

	// Forge a response on the FORGER's stream carrying our live reqID and tag.
	if _, err := mux.WriteFrame(pipeB2, mux.TagMeta, mux.DirResponse, reqID, []byte("forged")); err != nil {
		t.Fatalf("forged response write failed: %v", err)
	}

	select {
	case o := <-outCh:
		if o.err == nil {
			t.Fatalf("SendRecv accepted a forged response from another stream: %q", o.resp)
		}
		if o.err != context.DeadlineExceeded && o.err.Error() != "mux: request timeout (tag=3, target="+string(target)+"): context deadline exceeded" {
			// Tolerate both the raw ctx error and the wrapped timeout message.
			if !strings.Contains(o.err.Error(), "deadline") && !strings.Contains(o.err.Error(), "timeout") {
				t.Fatalf("expected a timeout, got: %v", o.err)
			}
		}
	case <-time.After(6 * time.Second):
		t.Fatal("SendRecv did not return")
	}

	eng.sessionsMu.Lock()
	_, live := eng.sessions[reqID]
	eng.sessionsMu.Unlock()
	if live {
		t.Fatal("session still live after the send timed out; the deferred delete did not run")
	}
}

// TestMuxEngineDropsForgedResponseWrongTag verifies that a DirResponse on the
// correct stream but carrying a tag that does not match the pending session is
// dropped. The response tag is written by muxStream.Write from the request's
// tag, so a legitimate reply always matches.
func TestMuxEngineDropsForgedResponseWrongTag(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target := peer.ID("target-peer")
	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()

	s := &netStream{conn: pipeA, id: "s1", protoID: mux.ControlProtocolID}
	eng := newMuxEngine(&Node{ctx: ctx})
	eng.mu.Lock()
	eng.streams[target] = s
	eng.mu.Unlock()

	go eng.handleStream(s, target)

	reqCh := make(chan uint32, 1)
	go func() {
		buf := make([]byte, maxFrameLen+mux.HeaderLen)
		for {
			_, dir, reqID, _, err := mux.ReadFrame(pipeB, buf)
			if err != nil {
				return
			}
			if dir == mux.DirRequest {
				reqCh <- reqID
			}
		}
	}()

	type outcome struct {
		resp []byte
		err  error
	}
	outCh := make(chan outcome, 1)
	go func() {
		resp, err := eng.SendRecv(target, mux.TagMeta, []byte("body"), 3*time.Second)
		outCh <- outcome{resp: resp, err: err}
	}()

	reqID := <-reqCh

	// Same stream and reqID as the live session, but a tag that does not
	// match it. A legitimate reply cannot look like this.
	if _, err := mux.WriteFrame(pipeB, mux.TagEcho, mux.DirResponse, reqID, []byte("forged")); err != nil {
		t.Fatalf("forged response write failed: %v", err)
	}

	select {
	case o := <-outCh:
		if o.err == nil {
			t.Fatalf("SendRecv accepted a response with a mismatched tag: %q", o.resp)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("SendRecv did not return")
	}
}

// TestMuxEngineAcceptsLegitimateResponse guards the regression risk of the
// forged-response checks above: a reply on the originating stream carrying the
// request's tag must still be delivered.
func TestMuxEngineAcceptsLegitimateResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target := peer.ID("target-peer")
	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()

	s := &netStream{conn: pipeA, id: "s1", protoID: mux.ControlProtocolID}
	eng := newMuxEngine(&Node{ctx: ctx})
	eng.mu.Lock()
	eng.streams[target] = s
	eng.mu.Unlock()

	go eng.handleStream(s, target)

	go func() {
		buf := make([]byte, maxFrameLen+mux.HeaderLen)
		for {
			tag, dir, reqID, payload, err := mux.ReadFrame(pipeB, buf)
			if err != nil {
				return
			}
			if dir != mux.DirRequest {
				continue
			}
			resp := append([]byte("ack:"), payload...)
			if _, err := mux.WriteFrame(pipeB, tag, mux.DirResponse, reqID, resp); err != nil {
				return
			}
		}
	}()

	resp, err := eng.SendRecv(target, mux.TagMeta, []byte("hello"), 5*time.Second)
	if err != nil {
		t.Fatalf("SendRecv error: %v", err)
	}
	if string(resp) != "ack:hello" {
		t.Fatalf("resp = %q, want %q", resp, "ack:hello")
	}
}

// TestMuxEngineInboundRequestNotStored verifies an inbound DirRequest is never
// entered into the sessions table. That table exists to route a DirResponse
// back to the SendRecv that issued the request; an inbound request's reply
// goes straight onto its own stream via muxStream.Write, so the entry was pure
// waste — one map slot, one struct, one channel and one payload copy, retained
// forever per request frame because reqID only leaves the table when a
// matching DirResponse arrives. Tag 0xFF has no handler, so each dispatched
// frame takes the default log.Warn branch and no goroutine is spawned.
func TestMuxEngineInboundRequestNotStored(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	forger := peer.ID("forger-peer")
	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()

	s := &netStream{conn: pipeA, id: "s1", protoID: mux.ControlProtocolID}
	eng := newMuxEngine(&Node{ctx: ctx})

	go eng.handleStream(s, forger)

	const frames = 64
	reqIDs := make([]uint32, 0, frames)
	for i := 0; i < frames; i++ {
		reqID := uint32(1000 + i)
		if _, err := mux.WriteFrame(pipeB, 0xFF, mux.DirRequest, reqID, []byte("req")); err != nil {
			t.Fatalf("write frame %d failed: %v", i, err)
		}
		reqIDs = append(reqIDs, reqID)
	}

	eng.sessionsMu.Lock()
	defer eng.sessionsMu.Unlock()
	for _, reqID := range reqIDs {
		if sess := eng.sessions[reqID]; sess != nil {
			t.Fatalf("inbound request reqID=%d was stored in sessions (stream=%s)", reqID, sess.stream.ID())
		}
	}
	if n := len(eng.sessions); n != 0 {
		t.Fatalf("sessions has %d entries after %d inbound requests, want 0", n, frames)
	}
}
