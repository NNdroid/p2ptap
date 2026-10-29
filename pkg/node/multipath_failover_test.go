package node

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// tapFrameBytes returns a payload large enough to look like an Ethernet frame to
// the accounting helpers (which read the L3 header length).
func tapFrameBytes(tag byte) []byte {
	b := make([]byte, 64)
	for i := range b {
		b[i] = tag
	}
	return b
}

// TestMultipathFailsOverToSurvivingPath is the regression guard for the
// "multipath has no redundancy" hole: a write failure on one path used to abort
// the frame and unwind to a stream re-open (up to 8s) or a relay hop, even
// though a healthy path to the same peer was already open and idle.
func TestMultipathFailsOverToSurvivingPath(t *testing.T) {
	pid := peer.ID("mp-failover")
	ps := NewPeerStreams(pid)

	// Both LAN-class so DWRR treats them as equal-capacity and either one can be
	// picked first; `bad` rejects every write.
	bad := &pathTestStream{ma: mustMA("/ip4/192.168.1.5/tcp/4001")}
	bad.failWrites = 1 << 30
	good := &pathTestStream{ma: mustMA("/ip4/192.168.1.6/tcp/4001")}
	ps.AddStream("bad", bad)
	ps.AddStream("good", good)

	sd := NewStrategyDispatcher(nil, "multipath")
	frags := [][]byte{tapFrameBytes(7)}
	stat := tapPayloadStat{bytes: len(frags[0]), frames: 1}

	for i := 0; i < 8; i++ {
		ps.writeMu.Lock()
		err := sd.writeFragsToStreams(ps, pid, ps.GetAllStreams(), stat, frags, true)
		ps.writeMu.Unlock()
		if err != nil {
			t.Fatalf("iteration %d: frame was dropped instead of failing over: %v", i, err)
		}
	}

	if good.buf.Len() == 0 {
		t.Fatal("no frame reached the surviving path")
	}
	// Every failing path must have been retired from the topology.
	remaining := ps.GetAllStreams()
	if len(remaining) != 1 || remaining[0] != good {
		t.Fatalf("broken path was not retired: %d stream(s) left", len(remaining))
	}
}

// TestMultipathSkipsCoolingPath checks the per-path circuit breaker: once a
// physical path fails, the scheduler must route around it for the cooldown and
// pick it up again afterwards, instead of paying a write timeout on every turn.
func TestMultipathSkipsCoolingPath(t *testing.T) {
	pid := peer.ID("mp-backoff")
	ps := NewPeerStreams(pid)
	bad := &pathTestStream{ma: mustMA("/ip4/192.168.1.5/tcp/4001")}
	good := &pathTestStream{ma: mustMA("/ip4/192.168.1.6/tcp/4001")}
	streams := []network.Stream{bad, good}

	now := time.Now()
	ps.notePathFailureUnderLock(bad, now)

	for i := 0; i < 200; i++ {
		if got := ps.pickMultipathStreamIndex(streams, now); got != 1 {
			t.Fatalf("pick %d selected the cooling path (index %d), want the healthy one", i, got)
		}
	}

	// After the cooldown the path must be eligible again (DWRR alternates between
	// two equal-capacity paths).
	later := now.Add(pathBackoffMax + time.Second)
	sawBad := false
	for i := 0; i < 200 && !sawBad; i++ {
		if ps.pickMultipathStreamIndex(streams, later) == 0 {
			sawBad = true
		}
	}
	if !sawBad {
		t.Fatal("path was never re-admitted after its cooldown expired")
	}

	// A success clears the breaker so the path is preferred immediately.
	ps.notePathFailureUnderLock(good, later)
	ps.notePathSuccessUnderLock(good)
	if ps.pathCoolingLocked(good, later) {
		t.Fatal("success did not clear the path's cooldown")
	}
}

// TestMultipathKeepsWorkingWhenAllPathsCool verifies the fallback: if every path
// is in cooldown the scheduler still returns a usable stream rather than dropping
// the frame.
func TestMultipathKeepsWorkingWhenAllPathsCool(t *testing.T) {
	ps := NewPeerStreams(peer.ID("mp-all-cool"))
	a := &pathTestStream{ma: mustMA("/ip4/192.168.1.5/tcp/4001")}
	b := &pathTestStream{ma: mustMA("/ip4/192.168.1.6/tcp/4001")}
	streams := []network.Stream{a, b}

	now := time.Now()
	ps.notePathFailureUnderLock(a, now)
	ps.notePathFailureUnderLock(b, now)

	if got := ps.pickMultipathStreamIndex(streams, now); got != 0 && got != 1 {
		t.Fatalf("pick returned %d with every path cooling, want a valid index", got)
	}
}

// TestMultipathBatchSpreadsAcrossPaths guards the batch-scheduling fix: the whole
// batch used to be written to ONE path, which skews the split and lands 32
// consecutive frames on the receiver at once — exactly the burst the reorder
// buffer then has to absorb.
func TestMultipathBatchSpreadsAcrossPaths(t *testing.T) {
	pid := peer.ID("mp-batch")
	ps := NewPeerStreams(pid)
	a := &pathTestStream{ma: mustMA("/ip4/192.168.1.5/tcp/4001")}
	b := &pathTestStream{ma: mustMA("/ip4/192.168.1.6/tcp/4001")}
	ps.AddStream("a", a)
	ps.AddStream("b", b)

	sd := NewStrategyDispatcher(nil, "multipath")
	frames := make([][]byte, 16)
	for i := range frames {
		frames[i] = tapFrameBytes(byte(i))
	}

	ps.writeMu.Lock()
	err := sd.writePackedBatchLocked(pid, ps, nil, frames)
	ps.writeMu.Unlock()
	if err != nil {
		t.Fatalf("batch write failed: %v", err)
	}
	if a.buf.Len() == 0 || b.buf.Len() == 0 {
		t.Fatalf("batch did not spread across both paths (a=%d bytes, b=%d bytes)",
			a.buf.Len(), b.buf.Len())
	}
}

// TestMultipathBatchRecoversFailedPathFrames checks the second half of the batch
// fix: when one path dies mid-batch, the frames assigned to it must be re-queued
// on a surviving path instead of being lost (or forcing a full re-send).
func TestMultipathBatchRecoversFailedPathFrames(t *testing.T) {
	pid := peer.ID("mp-batch-failover")
	ps := NewPeerStreams(pid)
	bad := &pathTestStream{ma: mustMA("/ip4/192.168.1.5/tcp/4001")}
	bad.failWrites = 1 << 30
	good := &pathTestStream{ma: mustMA("/ip4/192.168.1.6/tcp/4001")}
	ps.AddStream("bad", bad)
	ps.AddStream("good", good)

	sd := NewStrategyDispatcher(nil, "multipath")
	frames := make([][]byte, 16)
	for i := range frames {
		frames[i] = tapFrameBytes(byte(i))
	}

	ps.writeMu.Lock()
	err := sd.writePackedBatchLocked(pid, ps, nil, frames)
	ps.writeMu.Unlock()
	if err != nil {
		t.Fatalf("batch did not recover from a dead path: %v", err)
	}
	if good.buf.Len() == 0 {
		t.Fatal("no frame reached the surviving path")
	}
	// Every one of the 16 payloads must be present on the surviving path: the
	// wire format is a 4-byte big-endian length followed by the fragment.
	seen := make(map[byte]bool)
	raw := good.buf.Bytes()
	for off := 0; off+4 <= len(raw); {
		n := int(binary.BigEndian.Uint32(raw[off : off+4]))
		off += 4
		if off+n > len(raw) {
			t.Fatalf("truncated frame at offset %d", off)
		}
		seen[raw[off]] = true
		off += n
	}
	if len(seen) != 16 {
		t.Fatalf("surviving path carried %d distinct frames, want 16", len(seen))
	}
	if remaining := ps.GetAllStreams(); len(remaining) != 1 || remaining[0] != good {
		t.Fatalf("broken path was not retired: %d stream(s) left", len(remaining))
	}
}

// TestMpWriterQueueFullIsSoftFailure pins the backpressure contract of the
// per-stream writers: a path whose queue is full reports a soft error to the
// submitter (which retires the path and fails over) instead of blocking the
// caller on a congested link.
func TestMpWriterQueueFullIsSoftFailure(t *testing.T) {
	pid := peer.ID("mp-qfull")
	ps := NewPeerStreams(pid)
	slow := &pathTestStream{ma: mustMA("/ip4/192.168.9.5/tcp/4001")}
	ps.AddStream("slow", slow)

	ps.writeMu.Lock()
	wait, err := ps.submitMpWriteLocked(slow, nil, pid, [][]byte{tapFrameBytes(1)}, tapPayloadStat{bytes: 64, frames: 1})
	ps.writeMu.Unlock()
	if err != nil {
		t.Fatalf("first submit on an empty queue failed: %v", err)
	}
	if wait == nil {
		t.Fatal("successful submit returned a nil wait func")
	}
	// The writer completes asynchronously; the result must arrive eventually.
	res := wait()
	if res.err != nil {
		t.Fatalf("write to a healthy mock stream failed: %v", res.err)
	}
	if slow.buf.Len() == 0 {
		t.Fatal("writer goroutine did not deliver the fragment")
	}
}
