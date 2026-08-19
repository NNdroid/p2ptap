package node

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"p2ptap/pkg/config"
	"p2ptap/pkg/tap"
)

// actualMACTestTAP supplies the Linux-style verified MAC capability while
// reusing the in-memory TAP for the rest of TAPDevice.
type actualMACTestTAP struct {
	*tap.MemTAP
	actual string
	err    error
}

func (t *actualMACTestTAP) ActualMAC() (string, error) { return t.actual, t.err }

func TestVerifyTAPMACRejectsKernelMismatch(t *testing.T) {
	a, b := tap.NewMemTAPPair("verify-a", "verify-b")
	defer a.Close()
	defer b.Close()

	cfg := config.DefaultConfig()
	cfg.TapMAC = "02:00:00:00:00:01"
	dev := &actualMACTestTAP{MemTAP: a, actual: "02:00:00:00:00:02"}

	err := verifyTAPMAC(cfg, dev)
	if err == nil {
		t.Fatal("verifyTAPMAC accepted a MAC different from the kernel-reported value")
	}
	if !strings.Contains(err.Error(), "TAP MAC mismatch") {
		t.Fatalf("unexpected mismatch error: %v", err)
	}
}

func TestVerifyTAPMACCanonicalizesVerifiedMAC(t *testing.T) {
	a, b := tap.NewMemTAPPair("verify-a", "verify-b")
	defer a.Close()
	defer b.Close()

	cfg := config.DefaultConfig()
	cfg.TapMAC = "02:00:00:00:00:01"
	dev := &actualMACTestTAP{MemTAP: a, actual: "02:00:00:00:00:01"}

	if err := verifyTAPMAC(cfg, dev); err != nil {
		t.Fatalf("verify matching TAP MAC: %v", err)
	}
	if cfg.TapMAC != "02:00:00:00:00:01" {
		t.Fatalf("verified TAP MAC = %q, want canonical configured value", cfg.TapMAC)
	}
}

func TestTapWriteEnforcesConfiguredMTU(t *testing.T) {
	a, b := tap.NewMemTAPPair("mtu-a", "mtu-b")
	defer a.Close()
	defer b.Close()

	cfg := config.DefaultConfig()
	cfg.MTU = 100
	n := &Node{TAP: a, Config: cfg}
	n.configPtr.Store(cfg)

	valid := make([]byte, 100+ethernetHeaderLen)
	if wrote, err := n.tapWrite(valid); err != nil || wrote != len(valid) {
		t.Fatalf("tapWrite valid MTU frame = (%d, %v), want (%d, nil)", wrote, err, len(valid))
	}
	received := make([]byte, len(valid))
	if read, err := b.Read(received); err != nil || read != len(valid) {
		t.Fatalf("peer TAP read = (%d, %v), want (%d, nil)", read, err, len(valid))
	}

	if _, err := n.tapWrite(make([]byte, len(valid)+1)); err == nil {
		t.Fatal("tapWrite accepted a frame larger than configured MTU plus Ethernet header")
	}
}

type concurrentWriteTestTAP struct {
	*tap.MemTAP
	active  atomic.Int32
	overlap atomic.Bool
}

func (t *concurrentWriteTestTAP) Write(payload []byte) (int, error) {
	if t.active.Add(1) != 1 {
		t.overlap.Store(true)
	}
	// Keep the write boundary occupied long enough for competing goroutines to
	// overlap deterministically if Node.tapWrite stops serializing it.
	time.Sleep(200 * time.Microsecond)
	n, err := t.MemTAP.Write(payload)
	t.active.Add(-1)
	return n, err
}

func TestTapWriteSerializesNativeDeviceWrites(t *testing.T) {
	a, b := tap.NewMemTAPPair("serial-a", "serial-b")
	defer a.Close()
	defer b.Close()
	dev := &concurrentWriteTestTAP{MemTAP: a}
	cfg := config.DefaultConfig()
	n := &Node{TAP: dev, Config: cfg}

	const writers = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	var failures atomic.Int32
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := n.tapWrite(make([]byte, 64)); err != nil {
				failures.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if failures.Load() != 0 {
		t.Fatalf("tapWrite failures = %d, want 0", failures.Load())
	}
	if dev.overlap.Load() {
		t.Fatal("native TAP Write calls overlapped")
	}
}

func TestSendBatchFallbackUnlocksPeerWriteMutex(t *testing.T) {
	target := peer.ID("batch-fallback-peer")
	stream := &mockWriteStream{failWrites: 1}
	ps := NewPeerStreams(target)
	ps.AddStream("mock", stream)

	sd := NewStrategyDispatcher(nil, "fallback")
	sd.peerMap[target] = ps

	done := make(chan error, 1)
	go func() {
		done <- sd.SendBatchToPeer(context.Background(), target, [][]byte{[]byte("frame")})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("batch fallback returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("batch fallback blocked while re-acquiring PeerStreams.writeMu")
	}
	if stream.buf.Len() == 0 {
		t.Fatal("fallback path did not write the frame after the initial failure")
	}
}

type timeoutReadError struct{}

func (timeoutReadError) Error() string   { return "injected read timeout" }
func (timeoutReadError) Timeout() bool   { return true }
func (timeoutReadError) Temporary() bool { return true }

type timeoutReadConn struct{ mockNetConn }

func (c *timeoutReadConn) RemotePeer() peer.ID { return peer.ID("timeout-peer") }
func (c *timeoutReadConn) RemoteMultiaddr() ma.Multiaddr {
	addr, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/4001")
	return addr
}

// partialTimeoutStream consumes half of a frame-length prefix and then times
// out. Reusing it would make the next ReadFrame start at an unknown byte.
type partialTimeoutStream struct {
	*mockWriteStream
	reads  atomic.Int32
	resets atomic.Int32
	reset  atomic.Bool
}

func (s *partialTimeoutStream) Read(p []byte) (int, error) {
	if s.reset.Load() {
		return 0, io.EOF
	}
	if s.reads.Add(1) == 1 {
		copy(p, []byte{0, 0})
		return 2, nil
	}
	return 0, timeoutReadError{}
}

func (s *partialTimeoutStream) Reset() error {
	s.resets.Add(1)
	s.reset.Store(true)
	return nil
}

func (s *partialTimeoutStream) Conn() network.Conn { return &timeoutReadConn{} }

func TestHandleStreamResetsAfterPartialFrameTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := &Node{
		ctx:        ctx,
		Dispatcher: NewStrategyDispatcher(nil, "best_path"),
	}
	stream := &partialTimeoutStream{mockWriteStream: &mockWriteStream{}}
	done := make(chan struct{})
	go func() {
		n.handleStream(stream)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("handleStream reused a framing stream after a partial-read timeout")
	}
	if got := stream.resets.Load(); got != 1 {
		t.Fatalf("stream reset count = %d, want 1 after partial-frame timeout", got)
	}
	if got := stream.reads.Load(); got != 2 {
		t.Fatalf("stream read calls = %d, want exactly 2 with no retry", got)
	}
}

func TestActualMACTestTAPCanSurfaceReadbackFailure(t *testing.T) {
	a, b := tap.NewMemTAPPair("verify-a", "verify-b")
	defer a.Close()
	defer b.Close()

	cfg := config.DefaultConfig()
	dev := &actualMACTestTAP{MemTAP: a, err: errors.New("netlink unavailable")}
	if err := verifyTAPMAC(cfg, dev); err == nil {
		t.Fatal("verifyTAPMAC accepted an unavailable kernel MAC readback")
	}
}
