package node

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"

	mux "p2ptap/pkg/mux"
	"p2ptap/pkg/meta"
)

// mockStream is a minimal network.Stream backed by in-memory buffers.
type mockStream struct {
	conn     *mockConn
	id       string
	protocol protocol.ID
	writeBuf bytes.Buffer
	readBuf  bytes.Buffer
}

func newMockStream(c *mockConn) *mockStream {
	return &mockStream{
		conn:     c,
		id:       "stream-" + c.remote.String(),
		protocol: mux.ControlProtocolID,
	}
}

func (m *mockStream) Read(p []byte) (int, error)  { return m.readBuf.Read(p) }
func (m *mockStream) Write(p []byte) (int, error) { return m.writeBuf.Write(p) }

func (m *mockStream) Close() error                 { return nil }
func (m *mockStream) CloseWrite() error             { return nil }
func (m *mockStream) CloseRead() error              { return nil }
func (m *mockStream) Reset() error                  { return nil }
func (m *mockStream) ResetWithError(_ network.StreamErrorCode) error { return nil }
func (m *mockStream) SetDeadline(_ time.Time) error      { return nil }
func (m *mockStream) SetReadDeadline(_ time.Time) error  { return nil }
func (m *mockStream) SetWriteDeadline(_ time.Time) error { return nil }
func (m *mockStream) ID() string                     { return m.id }
func (m *mockStream) Protocol() protocol.ID          { return m.protocol }
func (m *mockStream) SetProtocol(id protocol.ID) error { m.protocol = id; return nil }
func (m *mockStream) Stat() network.Stats            { return network.Stats{} }
func (m *mockStream) Conn() network.Conn             { return m.conn }
func (m *mockStream) Scope() network.StreamScope     { return &network.NullScope{} }

// mockConn is a minimal network.Conn for testing.
type mockConn struct {
	remote peer.ID
}

func (c *mockConn) Close() error                          { return nil }
func (c *mockConn) LocalPeer() peer.ID                    { return "" }
func (c *mockConn) RemotePeer() peer.ID                   { return c.remote }
func (c *mockConn) RemotePublicKey() ic.PubKey            { return nil }
func (c *mockConn) ConnState() network.ConnectionState    { return network.ConnectionState{} }
func (c *mockConn) LocalMultiaddr() ma.Multiaddr          { return nil }
func (c *mockConn) RemoteMultiaddr() ma.Multiaddr         { return nil }
func (c *mockConn) Stat() network.ConnStats               { return network.ConnStats{} }
func (c *mockConn) Scope() network.ConnScope              { return &network.NullScope{} }
func (c *mockConn) CloseWithError(_ network.ConnErrorCode) error { return nil }
func (c *mockConn) ID() string                             { return "mockconn" }
func (c *mockConn) NewStream(context.Context) (network.Stream, error) { return nil, nil }
func (c *mockConn) GetStreams() []network.Stream           { return nil }
func (c *mockConn) IsClosed() bool                         { return false }
func (c *mockConn) String() string                         { return "mockconn-" + c.remote.String() }
func (c *mockConn) As(_ any) bool                          { return false }

// TestMuxTagForProto verifies the protocol.ID → mux tag mapping.
func TestMuxTagForProto(t *testing.T) {
	tests := []struct {
		proto protocol.ID
		tag   uint8
		found bool
	}{
		{SeqSyncProtocolID, mux.TagSeqSync, true},
		{LSAProtocolID, mux.TagLSA, true},
		{meta.MetaProtocolID, mux.TagMeta, true},
		{EchoProtocolID, mux.TagEcho, true},
		{TapProbeAckProtocolID, mux.TagTapProbeAck, true},
		{RelayCtrlProtocolID, mux.TagRelayCtrl, true},
		{"/unknown/protocol", 0, false},
		{protocol.ID(""), 0, false},
	}
	for _, tt := range tests {
		tag, found := muxTagForProto(tt.proto)
		if tag != tt.tag || found != tt.found {
			t.Errorf("muxTagForProto(%q) = (%d, %v), want (%d, %v)",
				tt.proto, tag, found, tt.tag, tt.found)
		}
	}
}

// TestMuxStreamReadWrite verifies that muxStream.Read returns the request
// payload and muxStream.Write wraps data in a Response frame.
func TestMuxStreamReadWrite(t *testing.T) {
	conn := &mockConn{remote: peer.ID("test-peer")}
	s := newMockStream(conn)

	sess := &muxSession{
		tag:     mux.TagEcho,
		reqID:   42,
		stream:  s,
		request: []byte("ping"),
		respCh:  make(chan []byte, 1),
	}
	ms := &muxStream{sess: sess}

	// Read the request payload.
	buf := make([]byte, 64)
	n, err := ms.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if n != 4 || string(buf[:n]) != "ping" {
		t.Fatalf("Read got %d bytes %q, want 4 bytes \"ping\"", n, buf[:n])
	}

	// Second Read should return EOF (request already consumed).
	_, err = ms.Read(buf)
	if err != io.EOF {
		t.Fatalf("second Read: expected io.EOF, got %v", err)
	}

	// Write wraps in a Response frame.
	_, err = ms.Write([]byte("pong"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}

	// Verify the frame is a valid Response.
	s.readBuf.Reset()
	s.readBuf.Write(s.writeBuf.Bytes())
	tag, dir, reqID, payload, err := mux.ReadFrame(&s.readBuf, make([]byte, 256))
	if err != nil {
		t.Fatalf("ReadFrame error: %v", err)
	}
	if tag != mux.TagEcho {
		t.Errorf("tag = %d, want %d", tag, mux.TagEcho)
	}
	if dir != mux.DirResponse {
		t.Errorf("dir = %d, want %d", dir, mux.DirResponse)
	}
	if reqID != 42 {
		t.Errorf("reqID = %d, want 42", reqID)
	}
	if string(payload) != "pong" {
		t.Errorf("payload = %q, want \"pong\"", payload)
	}
}

// TestMuxInitStreamWrite verifies that muxInitStream.Write wraps data in a
// Request frame.
func TestMuxInitStreamWrite(t *testing.T) {
	conn := &mockConn{remote: peer.ID("test-peer")}
	s := newMockStream(conn)

	sess := &muxSession{
		tag:    mux.TagMeta,
		reqID:  100,
		stream: s,
		respCh: make(chan []byte, 1),
	}
	mis := &muxInitStream{
		stream: s,
		tag:    mux.TagMeta,
		reqID:  100,
		sess:   sess,
	}

	_, err := mis.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}

	// Verify the frame is a valid Request.
	s.readBuf.Reset()
	s.readBuf.Write(s.writeBuf.Bytes())
	tag, dir, reqID, payload, err := mux.ReadFrame(&s.readBuf, make([]byte, 256))
	if err != nil {
		t.Fatalf("ReadFrame error: %v", err)
	}
	if tag != mux.TagMeta {
		t.Errorf("tag = %d, want %d", tag, mux.TagMeta)
	}
	if dir != mux.DirRequest {
		t.Errorf("dir = %d, want %d", dir, mux.DirRequest)
	}
	if reqID != 100 {
		t.Errorf("reqID = %d, want 100", reqID)
	}
	if string(payload) != "hello" {
		t.Errorf("payload = %q, want \"hello\"", payload)
	}
}

// TestMuxInitStreamReadWithResponse verifies that muxInitStream.Read
// blocks until a response arrives on sess.respCh.
func TestMuxInitStreamReadWithResponse(t *testing.T) {
	conn := &mockConn{remote: peer.ID("test-peer")}
	s := newMockStream(conn)

	respCh := make(chan []byte, 1)
	sess := &muxSession{
		tag:    mux.TagEcho,
		reqID:  1,
		stream: s,
		respCh: respCh,
	}
	mis := &muxInitStream{
		stream: s,
		tag:    mux.TagEcho,
		reqID:  1,
		sess:   sess,
	}

	// Simulate a response arriving in a goroutine.
	go func() {
		time.Sleep(10 * time.Millisecond)
		respCh <- []byte("response-data")
	}()

	buf := make([]byte, 128)
	n, err := mis.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if string(buf[:n]) != "response-data" {
		t.Errorf("Read got %q, want \"response-data\"", buf[:n])
	}
}

// TestMuxInitStreamReadClosedSession returns EOF when the session is nil.
func TestMuxInitStreamReadClosedSession(t *testing.T) {
	conn := &mockConn{remote: peer.ID("test-peer")}
	s := newMockStream(conn)

	mis := &muxInitStream{
		stream: s,
		tag:    mux.TagEcho,
		reqID:  1,
		sess:   nil, // session cleared
	}

	_, err := mis.Read(make([]byte, 128))
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

// TestMuxInitStreamReadClosedChannel returns EOF when respCh is closed.
func TestMuxInitStreamReadClosedChannel(t *testing.T) {
	conn := &mockConn{remote: peer.ID("test-peer")}
	s := newMockStream(conn)

	respCh := make(chan []byte, 1)
	close(respCh)

	sess := &muxSession{
		tag:    mux.TagEcho,
		reqID:  1,
		stream: s,
		respCh: respCh,
	}
	mis := &muxInitStream{
		stream: s,
		tag:    mux.TagEcho,
		reqID:  1,
		sess:   sess,
	}

	_, err := mis.Read(make([]byte, 128))
	if err != io.EOF {
		t.Fatalf("expected io.EOF from closed channel, got %v", err)
	}
}

// TestMuxInitStreamPartialRead verifies that a response larger than the
// read buffer is served across multiple Read calls.
func TestMuxInitStreamPartialRead(t *testing.T) {
	conn := &mockConn{remote: peer.ID("test-peer")}
	s := newMockStream(conn)

	respCh := make(chan []byte, 1)
	respCh <- []byte("abcdefghij") // 10 bytes

	sess := &muxSession{
		tag:    mux.TagEcho,
		reqID:  1,
		stream: s,
		respCh: respCh,
	}
	mis := &muxInitStream{
		stream: s,
		tag:    mux.TagEcho,
		reqID:  1,
		sess:   sess,
	}

	// First read: 3 bytes.
	buf := make([]byte, 3)
	n, err := mis.Read(buf)
	if err != nil {
		t.Fatalf("first Read error: %v", err)
	}
	if n != 3 || string(buf) != "abc" {
		t.Fatalf("first Read got %d bytes %q, want 3 bytes \"abc\"", n, buf)
	}

	// Second read: remaining 7 bytes.
	buf = make([]byte, 8)
	n, err = mis.Read(buf)
	if err != nil {
		t.Fatalf("second Read error: %v", err)
	}
	if n != 7 || string(buf[:n]) != "defghij" {
		t.Fatalf("second Read got %d bytes %q, want 7 bytes \"defghij\"", n, buf[:n])
	}

	// Third Read would block waiting for another response on respCh.
	// Set sess to nil to simulate stream completion.
	mis.sess = nil
	_, err = mis.Read(buf)
	if err != io.EOF {
		t.Fatalf("third Read after nil session: expected io.EOF, got %v", err)
	}
}

// TestMuxStreamWriteMultipleFrames verifies that multiple Write calls each
// produce a valid Response frame.
func TestMuxStreamWriteMultipleFrames(t *testing.T) {
	conn := &mockConn{remote: peer.ID("test-peer")}
	s := newMockStream(conn)

	sess := &muxSession{
		tag:     mux.TagLSA,
		reqID:   7,
		stream:  s,
		request: []byte("payload"),
		respCh:  make(chan []byte, 1),
	}
	ms := &muxStream{sess: sess}

	// Write multiple frames.
	frames := []string{"frame1", "frame2", "frame3"}
	for _, f := range frames {
		if _, err := ms.Write([]byte(f)); err != nil {
			t.Fatalf("Write error for %q: %v", f, err)
		}
	}

	// Read back and verify each frame.
	s.readBuf.Reset()
	s.readBuf.Write(s.writeBuf.Bytes())

	for _, expected := range frames {
		tag, dir, reqID, payload, err := mux.ReadFrame(&s.readBuf, make([]byte, 256))
		if err != nil {
			t.Fatalf("ReadFrame error: %v", err)
		}
		if tag != mux.TagLSA {
			t.Errorf("tag = %d, want %d", tag, mux.TagLSA)
		}
		if dir != mux.DirResponse {
			t.Errorf("dir = %d, want %d", dir, mux.DirResponse)
		}
		if reqID != 7 {
			t.Errorf("reqID = %d, want 7", reqID)
		}
		if string(payload) != expected {
			t.Errorf("payload = %q, want %q", payload, expected)
		}
	}
}

// TestMuxStreamDelegatedMethods verifies that muxStream delegates protocol,
// stat, conn, and scope to the underlying stream.
func TestMuxStreamDelegatedMethods(t *testing.T) {
	conn := &mockConn{remote: peer.ID("test-peer")}
	s := newMockStream(conn)

	sess := &muxSession{
		tag:     mux.TagEcho,
		reqID:   1,
		stream:  s,
		request: []byte("data"),
		respCh:  make(chan []byte, 1),
	}
	ms := &muxStream{sess: sess}

	if ms.ID() != s.ID() {
		t.Error("ID() should delegate to underlying stream")
	}
	if ms.Protocol() != mux.ControlProtocolID {
		t.Error("Protocol() should delegate to underlying stream")
	}
	if ms.Conn() != s.Conn() {
		t.Error("Conn() should delegate to underlying stream")
	}
	scope := ms.Scope()
	if scope == nil {
		t.Error("Scope() should return a non-nil scope")
	}

	// SetDeadline should store the deadline on the session.
	d := time.Now().Add(5 * time.Second)
	if err := ms.SetDeadline(d); err != nil {
		t.Errorf("SetDeadline error: %v", err)
	}
	if !ms.sess.deadline.Equal(d) {
		t.Errorf("deadline not stored on session")
	}
}

// TestMuxInitStreamDelegatedMethods verifies that muxInitStream delegates
// protocol, stat, conn, and scope to the underlying stream.
func TestMuxInitStreamDelegatedMethods(t *testing.T) {
	conn := &mockConn{remote: peer.ID("test-peer")}
	s := newMockStream(conn)

	sess := &muxSession{
		tag:    mux.TagMeta,
		reqID:  1,
		stream: s,
		respCh: make(chan []byte, 1),
	}
	mis := &muxInitStream{
		stream: s,
		tag:    mux.TagMeta,
		reqID:  1,
		sess:   sess,
	}

	if mis.ID() != s.ID() {
		t.Error("ID() should delegate to underlying stream")
	}
	if mis.Protocol() != mux.ControlProtocolID {
		t.Error("Protocol() should delegate to underlying stream")
	}
	if mis.Conn() != s.Conn() {
		t.Error("Conn() should delegate to underlying stream")
	}
	scope := mis.Scope()
	if scope == nil {
		t.Error("Scope() should return a non-nil scope")
	}
}

// TestMuxStreamEmptyRequestNoPanic verifies that reading from a muxStream
// with an empty request returns EOF immediately.
func TestMuxStreamEmptyRequestNoPanic(t *testing.T) {
	sess := &muxSession{
		tag:    mux.TagEcho,
		reqID:  1,
		// stream and respCh are not needed for the empty request test
		respCh: make(chan []byte, 1),
	}
	ms := &muxStream{sess: sess}

	_, err := ms.Read(make([]byte, 64))
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

// TestMuxStreamWriteEmptyPayload verifies that writing an empty payload
// produces a valid empty Response frame.
func TestMuxStreamWriteEmptyPayload(t *testing.T) {
	conn := &mockConn{remote: peer.ID("test-peer")}
	s := newMockStream(conn)

	sess := &muxSession{
		tag:     mux.TagEcho,
		reqID:   1,
		stream:  s,
		request: []byte("req"),
		respCh:  make(chan []byte, 1),
	}
	ms := &muxStream{sess: sess}

	_, err := ms.Write([]byte{})
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}

	// Verify the frame.
	s.readBuf.Reset()
	s.readBuf.Write(s.writeBuf.Bytes())
	tag, dir, reqID, payload, err := mux.ReadFrame(&s.readBuf, make([]byte, 256))
	if err != nil {
		t.Fatalf("ReadFrame error: %v", err)
	}
	if tag != mux.TagEcho || dir != mux.DirResponse || reqID != 1 {
		t.Errorf("got tag=%d dir=%d reqID=%d, want tag=%d dir=%d reqID=%d",
			tag, dir, reqID, mux.TagEcho, mux.DirResponse, 1)
	}
	if len(payload) != 0 {
		t.Errorf("payload length = %d, want 0", len(payload))
	}
}
