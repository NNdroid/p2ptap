package node

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/logger"
)

type deadlineBenchmarkStream struct{ network.Stream }

func (*deadlineBenchmarkStream) Conn() network.Conn               { return nil }
func (*deadlineBenchmarkStream) Write(b []byte) (int, error)      { return len(b), nil }
func (*deadlineBenchmarkStream) SetWriteDeadline(time.Time) error { return nil }

// Isolate the deadline cache from transport, encryption and delivery work.
// The workload is identical for every revision: one stream, two framed writes.
func BenchmarkStreamDeadlineWrite(b *testing.B) {
	logger.SetGlobalLevel(logger.LevelInfo)
	defer logger.SetGlobalLevel(logger.LevelDebug)
	pid := peer.ID("deadline-benchmark")
	sd := NewStrategyDispatcher(nil, "best_path")
	ps := sd.GetOrCreatePeerStreams(pid)
	ps.AddStream("stream", &deadlineBenchmarkStream{})
	streams := ps.GetAllStreams()
	frags := [][]byte{make([]byte, 1200), make([]byte, 1200)}
	b.ReportAllocs()
	ps.writeMu.Lock()
	defer ps.writeMu.Unlock()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := sd.writeFragsToStreams(ps, pid, streams, 2400, frags, true); err != nil {
			b.Fatal(err)
		}
	}
}
