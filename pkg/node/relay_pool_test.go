package node

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"
)

// ---------------------------------------------------------------------------
// mock for network.Stream — only Write and SetWriteDeadline are exercised
// ---------------------------------------------------------------------------

type mockWriteStream struct {
	buf      bytes.Buffer
	writeErr error
	deadline time.Time
}

func (s *mockWriteStream) Read([]byte) (int, error)       { return 0, io.EOF }
func (s *mockWriteStream) Write(p []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return s.buf.Write(p)
}
func (s *mockWriteStream) Close() error                       { return nil }
func (s *mockWriteStream) Reset() error                       { return nil }
func (s *mockWriteStream) ResetWithError(errCode network.StreamErrorCode) error { return nil }
func (s *mockWriteStream) CloseRead() error                   { return nil }
func (s *mockWriteStream) CloseWrite() error                  { return nil }
func (s *mockWriteStream) SetDeadline(t time.Time) error      { s.deadline = t; return nil }
func (s *mockWriteStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *mockWriteStream) SetWriteDeadline(t time.Time) error { s.deadline = t; return nil }
func (s *mockWriteStream) Conn() network.Conn                 { return &mockNetConn{} }
func (s *mockWriteStream) ID() string                         { return "mock:1" }
func (s *mockWriteStream) Protocol() protocol.ID              { return "" }
func (s *mockWriteStream) SetProtocol(id protocol.ID) error   { return nil }
func (s *mockWriteStream) Stat() network.Stats                { return network.Stats{Direction: network.DirOutbound} }
func (s *mockWriteStream) Scope() network.StreamScope         { return nil }
func (s *mockWriteStream) writtenBytes() []byte               { return s.buf.Bytes() }

// mockNetConn is a minimal network.Conn implementation returned by mockWriteStream.Conn().
type mockNetConn struct{}

func (c *mockNetConn) Close() error                            { return nil }
func (c *mockNetConn) LocalPeer() peer.ID                      { return "" }
func (c *mockNetConn) RemotePeer() peer.ID                     { return "" }
func (c *mockNetConn) RemotePublicKey() libp2pcrypto.PubKey    { return nil }
func (c *mockNetConn) LocalMultiaddr() ma.Multiaddr            { return nil }
func (c *mockNetConn) RemoteMultiaddr() ma.Multiaddr           { return nil }
func (c *mockNetConn) Stat() network.ConnStats                 { return network.ConnStats{} }
func (c *mockNetConn) ID() string                              { return "mock-conn" }
func (c *mockNetConn) NewStream(context.Context) (network.Stream, error) { return nil, nil }
func (c *mockNetConn) GetStreams() []network.Stream            { return nil }
func (c *mockNetConn) IsClosed() bool                          { return false }
func (c *mockNetConn) Scope() network.ConnScope                { return nil }
func (c *mockNetConn) CloseWithError(network.ConnErrorCode) error { return nil }
func (c *mockNetConn) TransportStat() interface{}               { return nil }
func (c *mockNetConn) As(target interface{}) bool               { return false }
func (c *mockNetConn) ConnState() network.ConnectionState       { return network.ConnectionState{} }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestRelayPoolWriteFrame_Success(t *testing.T) {
	rc := &relayConn{}
	stream := &mockWriteStream{}
	rc.stream = stream

	data := []byte("hello relay world")
	var sentCalled bool
	job := relayJob{
		data:   data,
		onSent: func() { sentCalled = true },
		onFail: func() { t.Error("onFail called unexpectedly") },
	}

	err := rc.writeFrame(job)
	if err != nil {
		t.Fatalf("writeFrame failed: %v", err)
	}
	if !sentCalled {
		t.Error("onSent was not called after successful write")
	}
	if stream.buf.Len() == 0 {
		t.Error("no bytes written to stream")
	}
}

func TestRelayPoolWriteFrame_NoStream(t *testing.T) {
	rc := &relayConn{} // stream = nil
	var failCalled bool
	job := relayJob{
		data:   []byte("should fail"),
		onFail: func() { failCalled = true },
	}

	err := rc.writeFrame(job)
	if err == nil {
		t.Error("expected error when stream is nil")
	}
	if err != errStreamNotReady {
		t.Errorf("expected errStreamNotReady, got: %v", err)
	}
	// onFail is NOT called by writeFrame — it only logs; caller handles fallback.
	if failCalled {
		t.Error("writeFrame should not call onFail; it returns the error")
	}
}

func TestRelayPoolWriteFrame_WriteError(t *testing.T) {
	rc := &relayConn{}
	stream := &mockWriteStream{writeErr: io.ErrShortWrite}
	rc.stream = stream

	job := relayJob{data: []byte("data")}

	err := rc.writeFrame(job)
	if err == nil {
		t.Error("expected error from writeFrame when stream write fails")
	}
}

func TestRelayPoolDrainAll(t *testing.T) {
	rc := &relayConn{
		writeCh: make(chan relayJob, 8),
	}

	var mu sync.Mutex
	var failCount int

	// Push 5 jobs
	for i := 0; i < 5; i++ {
		i := i
		rc.writeCh <- relayJob{
			data: []byte{byte(i)},
			onFail: func() {
				mu.Lock()
				failCount++
				mu.Unlock()
			},
		}
	}

	rc.drainAll()

	if failCount != 5 {
		t.Errorf("drainAll should call onFail for all 5 jobs, got %d", failCount)
	}

	// Channel should be empty
	select {
	case <-rc.writeCh:
		t.Error("writeCh should be empty after drainAll")
	default:
	}
}

func TestRelayPoolDrainAll_Empty(t *testing.T) {
	rc := &relayConn{
		writeCh: make(chan relayJob, 8),
	}
	// Should not block or panic
	rc.drainAll()
}

func TestRelayPoolShutdown(t *testing.T) {
	pool := newRelayStreamPool(nil, nil) // nil host/ctx for unit test
	if pool == nil {
		t.Fatal("newRelayStreamPool returned nil")
	}

	// shutdown on empty pool should not panic
	pool.shutdown()
}

func TestRelayPoolCloseStream(t *testing.T) {
	rc := &relayConn{}
	stream := &mockWriteStream{}
	rc.stream = stream
	rc.closeStream()
	if rc.stream != nil {
		t.Error("stream should be nil after closeStream")
	}
}

func TestRelayPoolCloseStream_Nil(t *testing.T) {
	rc := &relayConn{} // stream = nil
	// Should not panic
	rc.closeStream()
}

// TestRelayPoolWriteFrame_Deadline tests that writeFrame sets the deadline.
func TestRelayPoolWriteFrame_Deadline(t *testing.T) {
	rc := &relayConn{}
	stream := &mockWriteStream{}
	rc.stream = stream

	job := relayJob{
		data:   []byte("deadline check"),
		onSent: func() {},
		onFail: func() {},
	}

	if err := rc.writeFrame(job); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	if stream.deadline.IsZero() {
		t.Error("writeFrame did not set write deadline")
	}
}

// TestRelayPoolWriteFrame_NoDoubleOnSent tests that onSent is called exactly
// once per successful write.
func TestRelayPoolWriteFrame_NoDoubleOnSent(t *testing.T) {
	rc := &relayConn{}
	stream := &mockWriteStream{}
	rc.stream = stream

	count := 0
	for i := 0; i < 3; i++ {
		job := relayJob{
			data:   []byte{byte(i)},
			onSent: func() { count++ },
		}
		if err := rc.writeFrame(job); err != nil {
			t.Fatalf("writeFrame %d: %v", i, err)
		}
	}

	if count != 3 {
		t.Errorf("expected onSent called 3 times, got %d", count)
	}
}
