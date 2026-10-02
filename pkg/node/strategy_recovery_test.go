package node

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"p2ptap/pkg/config"
)

type strategyDeadlineStream struct {
	mockWriteStream
	deadlineCalls int
	deadlineErr   error
	resets        int
}

func (s *strategyDeadlineStream) SetWriteDeadline(d time.Time) error {
	s.deadlineCalls++
	if s.deadlineErr != nil {
		return s.deadlineErr
	}
	return s.mockWriteStream.SetWriteDeadline(d)
}

func (s *strategyDeadlineStream) Reset() error { s.resets++; return nil }

type strategyPipeStream struct {
	network.Stream
	conn net.Conn
}

func (s *strategyPipeStream) Conn() network.Conn                 { return nil }
func (s *strategyPipeStream) Write(b []byte) (int, error)        { return s.conn.Write(b) }
func (s *strategyPipeStream) SetWriteDeadline(d time.Time) error { return s.conn.SetWriteDeadline(d) }
func (s *strategyPipeStream) Reset() error                       { return s.conn.Close() }

func TestStrategyBlockedReplacementHasDeadlineAndReleasesWriter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pid := peer.ID("deadline-peer")
		sd := NewStrategyDispatcher(nil, "redundant")
		ps := sd.GetOrCreatePeerStreams(pid)
		healthy := &strategyDeadlineStream{}
		ps.AddStream("healthy", healthy)
		if err := sd.SendToPeer(context.Background(), pid, []byte("prime deadline cache")); err != nil {
			t.Fatal(err)
		}
		writer, reader := net.Pipe()
		defer reader.Close()
		defer writer.Close()
		blocked := &strategyPipeStream{conn: writer}
		ps.AddStream("replacement", blocked)
		start := time.Now()
		if err := sd.SendToPeer(context.Background(), pid, []byte("survives a blocked path")); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed != 2500*time.Millisecond {
			t.Fatalf("blocked write elapsed %v, want its 2.5s deadline", elapsed)
		}
		if streams := ps.GetAllStreams(); len(streams) != 1 || streams[0] != healthy {
			t.Fatal("timed out stream was not retired")
		}
		start = time.Now()
		if err := sd.SendToPeer(context.Background(), pid, []byte("writer is released")); err != nil {
			t.Fatal(err)
		}
		if time.Since(start) != 0 {
			t.Fatal("healthy sender still blocked after the timeout")
		}
	})
}

func TestStrategyDeadlineCacheTracksStreamIdentity(t *testing.T) {
	pid := peer.ID("replace-peer")
	sd := NewStrategyDispatcher(nil, "redundant")
	ps := sd.GetOrCreatePeerStreams(pid)
	a, b := &strategyDeadlineStream{}, &strategyDeadlineStream{}
	ps.AddStream("a", a)
	ps.AddStream("b", b)
	for i := 0; i < 2; i++ {
		if err := sd.SendToPeer(context.Background(), pid, []byte("payload")); err != nil {
			t.Fatal(err)
		}
	}
	if a.deadlineCalls != 1 || b.deadlineCalls != 1 {
		t.Fatalf("deadline renewal was not per stream and throttled: a=%d b=%d", a.deadlineCalls, b.deadlineCalls)
	}
	replacement := &strategyDeadlineStream{}
	ps.AddStream("a", replacement)
	if err := sd.SendToPeer(context.Background(), pid, []byte("replacement")); err != nil {
		t.Fatal(err)
	}
	if replacement.deadlineCalls != 1 || b.deadlineCalls != 1 {
		t.Fatal("new stream inherited a deadline or unchanged stream lost its cache")
	}
	if _, stale := ps.writeDeadlineRenew[a]; stale || len(ps.writeDeadlineRenew) != 2 {
		t.Fatal("retired stream retained by deadline cache")
	}
}

func TestStrategyDeadlineFailureNeverWrites(t *testing.T) {
	pid := peer.ID("deadline-error-peer")
	sd := NewStrategyDispatcher(nil, "best_path")
	stream := &strategyDeadlineStream{deadlineErr: errors.New("deadline unsupported")}
	sd.RegisterStream(pid, "broken", stream)
	if err := sd.SendToPeer(context.Background(), pid, []byte("must not write")); err == nil {
		t.Fatal("deadline error hidden")
	}
	if stream.buf.Len() != 0 || stream.resets == 0 {
		t.Fatal("unsafe stream was written or not reset")
	}
}

func TestStrategyEmptyFallbackReturnsFailureWithoutHost(t *testing.T) {
	sd := NewStrategyDispatcher(nil, "fallback")
	pid := peer.ID("empty-peer")
	sd.GetOrCreatePeerStreams(pid)
	if err := sd.SendToPeer(context.Background(), pid, []byte("payload")); err == nil {
		t.Fatal("empty stream set reported delivery")
	}
}

func TestStrategyBatchPreservesRedundantCopies(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(fmt.Sprintf("batch=%v", batch), func(t *testing.T) {
			pid := peer.ID("redundant-peer")
			sd := NewStrategyDispatcher(nil, "redundant")
			streams := []*strategyDeadlineStream{{}, {}}
			for i, s := range streams {
				sd.RegisterStream(pid, fmt.Sprint(i), s)
			}
			frames := [][]byte{[]byte("first"), []byte("second")}
			if batch {
				if err := sd.SendBatchToPeer(context.Background(), pid, frames); err != nil {
					t.Fatal(err)
				}
			} else {
				for _, f := range frames {
					if err := sd.SendToPeer(context.Background(), pid, f); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, s := range streams {
				for _, want := range frames {
					buf := make([]byte, 64)
					n, err := ReadFrame(&s.buf, buf)
					if err != nil || !bytes.Equal(buf[:n], want) {
						t.Fatalf("missing physical copy %q: %v", want, err)
					}
				}
				if s.buf.Len() != 0 {
					t.Fatal("extra physical copies")
				}
			}
		})
	}
}

func TestStrategyRedundancyCountsLogicalPayloadOnce(t *testing.T) {
	pid := peer.ID("accounting-peer")
	n := &Node{protoTracker: NewProtocolTrafficTracker()}
	sd := NewStrategyDispatcher(nil, "redundant")
	sd.SetNode(n)
	ps := sd.GetOrCreatePeerStreams(pid)
	ps.AddStream("one", &strategyDeadlineStream{})
	ps.AddStream("two", &strategyDeadlineStream{})
	ps.writeMu.Lock()
	err := sd.writeFragsToStreams(ps, pid, ps.GetAllStreams(), 42, [][]byte{[]byte("frag-1"), []byte("frag-2")}, true)
	ps.writeMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	v, ok := n.peerTxBytes.Load(pid)
	if !ok || v.(*atomic.Uint64).Load() != 42 {
		t.Fatal("logical payload counted once per physical copy")
	}
	frames, _, wireBytes, _, _, _, _ := n.protoTracker.Data.Snapshot()
	if frames != 4 || wireBytes != 24 {
		t.Fatalf("wire telemetry lost copies: frames=%d bytes=%d", frames, wireBytes)
	}
}

func TestStrategyReopensApplicationStreamOnLiveConnection(t *testing.T) {
	for _, mode := range []string{"best_path", "fallback", "redundant"} {
		t.Run(mode, func(t *testing.T) {
			a, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			received := make(chan string, 4)
			b.SetStreamHandler(ProtocolID, func(s network.Stream) {
				defer s.Close()
				buf := make([]byte, 128)
				for {
					n, err := ReadFrame(s, buf)
					if err != nil {
						return
					}
					received <- string(buf[:n])
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := a.Connect(ctx, peer.AddrInfo{ID: b.ID(), Addrs: b.Addrs()}); err != nil {
				t.Fatal(err)
			}
			sd := NewStrategyDispatcher(a, mode)
			if err := sd.SendToPeer(ctx, b.ID(), []byte("initial")); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-received:
				if got != "initial" {
					t.Fatal(got)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			old := sd.GetPeerStreams(b.ID()).GetAllStreams()[0]
			sd.UnregisterStream(b.ID(), old.Conn().RemoteMultiaddr().String(), old)
			_ = old.Reset()
			if a.Network().Connectedness(b.ID()) != network.Connected {
				t.Fatal("test lost the underlying connection")
			}
			if err := sd.SendToPeer(ctx, b.ID(), []byte("reopened")); err != nil {
				t.Fatal(err)
			}
			if err := sd.SendBatchToPeer(ctx, b.ID(), [][]byte{[]byte("batch-1"), []byte("batch-2")}); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"reopened", "batch-1", "batch-2"} {
				select {
				case got := <-received:
					if got != want {
						t.Fatalf("got %q want %q", got, want)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
		})
	}
}

type strategyReplacementHost struct {
	host.Host
	stream network.Stream
	err    error
}

func (h *strategyReplacementHost) NewStream(context.Context, peer.ID, ...protocol.ID) (network.Stream, error) {
	return h.stream, h.err
}

type strategyReplacementStream struct{ mockWriteStream }

func (s *strategyReplacementStream) Conn() network.Conn { return &timeoutReadConn{} }

func TestStrategyWrappedTimeoutArmsBreakerAfterReopenFailure(t *testing.T) {
	pid := peer.ID("timeout-peer")
	sd := NewStrategyDispatcher(&strategyReplacementHost{err: errors.New("reopen failed")}, "fallback")
	sd.RegisterStream(pid, "old", &mockWriteStream{writeErr: timeoutReadError{}})
	err := sd.SendBatchToPeer(context.Background(), pid, [][]byte{[]byte("one"), []byte("two")})
	n := &Node{}
	n.notePeerSendError(pid, err)
	if !n.peerStalled(pid) {
		t.Fatalf("wrapped timeout did not arm breaker: %v", err)
	}
	other := peer.ID("healthy-peer")
	n.notePeerSendError(other, errors.New("ordinary reset"))
	if n.peerStalled(other) {
		t.Fatal("non-timeout armed breaker")
	}
}

type strategySignalStream struct {
	mockWriteStream
	written chan []byte
}

func (s *strategySignalStream) Write(b []byte) (int, error) {
	s.written <- bytes.Clone(b)
	return len(b), nil
}

func TestDispatchWorkerWrappedTimeoutKeepsHealthyPeerMoving(t *testing.T) {
	for _, count := range []int{1, 2} {
		t.Run(fmt.Sprintf("batch=%d", count), func(t *testing.T) {
			h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			ctx, cancel := context.WithCancel(context.Background())
			sd := NewStrategyDispatcher(&strategyReplacementHost{err: errors.New("reopen failed")}, "best_path")
			bad, good := peer.ID("stalled-peer"), peer.ID("healthy-peer")
			sd.RegisterStream(bad, "old", &mockWriteStream{writeErr: timeoutReadError{}})
			healthy := &strategySignalStream{written: make(chan []byte, 1)}
			sd.RegisterStream(good, "healthy", healthy)
			cfg := config.DefaultConfig()
			cfg.BootstrapPeers = nil
			n := &Node{ctx: ctx, Host: h, Config: cfg, Dispatcher: sd, Collector: noopCollector{}, dispatchCh: make(chan dispatchTask, 4)}
			for i := 0; i < count; i++ {
				n.dispatchCh <- dispatchTask{target: bad, data: []byte("timeout"), origLen: 7}
			}
			n.startDispatchWorker(0)
			defer func() { cancel(); n.wg.Wait() }()
			deadline := time.NewTimer(time.Second)
			defer deadline.Stop()
			for !n.peerStalled(bad) {
				select {
				case <-deadline.C:
					t.Fatal("worker failed to arm the stall breaker")
				case <-time.After(time.Millisecond):
				}
			}
			n.dispatchCh <- dispatchTask{target: good, data: []byte("healthy"), origLen: 7}
			select {
			case framed := <-healthy.written:
				buf := make([]byte, 32)
				size, err := ReadFrame(bytes.NewReader(framed), buf)
				if err != nil || string(buf[:size]) != "healthy" {
					t.Fatalf("healthy peer did not receive its frame: %v", err)
				}
			case <-deadline.C:
				t.Fatal("stalled peer blocked healthy peer")
			}
		})
	}
}
