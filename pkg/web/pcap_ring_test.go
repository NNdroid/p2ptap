package web

import (
	"encoding/binary"
	"testing"
)

// testPcapFrame returns a minimal frame long enough for parseFrame to walk the
// Ethernet header: a 14-byte L2 header (broadcast dst, locally administered src)
// plus an EtherType and a bit of payload.
func testPcapFrame(seq int) []byte {
	f := make([]byte, 40)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x63})
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	f[14] = byte(seq)
	f[15] = byte(seq >> 8)
	return f
}

// TestPcapRingWrapsWithoutMemmove verifies the fixed-capacity ring keeps
// exactly `cap` frames in Seq order after it has wrapped, evicting the oldest
// entry on every overwrite rather than compacting.
func TestPcapRingWrapsWithoutMemmove(t *testing.T) {
	p := NewPacketCapture(7, "")
	p.SetIdleSkip(false)
	p.Start()
	for i := 0; i < 20; i++ {
		p.AddWithPeers(DirTx, testPcapFrame(i), "", "")
	}

	st := p.State()
	if st.Count != 7 {
		t.Fatalf("count = %d, want 7 (the ring must hold exactly its capacity once full)", st.Count)
	}
	if st.Capacity != 7 {
		t.Fatalf("capacity = %d, want 7", st.Capacity)
	}
	if st.StartSeq != 13 || st.LastSeq != 19 {
		t.Fatalf("seq window = [%d,%d], want [13,19]", st.StartSeq, st.LastSeq)
	}

	got := p.Snapshot(0, 0)
	if len(got) != 7 {
		t.Fatalf("snapshot = %d frames, want 7", len(got))
	}
	for i, cf := range got {
		want := uint64(13 + i)
		if cf.Seq != want {
			t.Fatalf("snapshot[%d].Seq = %d, want %d", i, cf.Seq, want)
		}
	}
}

// TestPcapRingSinceShortCircuit exercises both sides of the caught-up fast
// path in Snapshot: a since at or above the newest Seq must return nothing
// without scanning, while a since inside the live window still returns the
// newer frames.
func TestPcapRingSinceShortCircuit(t *testing.T) {
	p := NewPacketCapture(5, "")
	p.SetIdleSkip(false)
	p.Start()
	for i := 0; i < 12; i++ {
		p.AddWithPeers(DirTx, testPcapFrame(i), "", "")
	}

	if got := p.Snapshot(11, 0); len(got) != 0 {
		t.Fatalf("snapshot since newest seq returned %d frames, want 0", len(got))
	}
	if got := p.Snapshot(12, 0); len(got) != 0 {
		t.Fatalf("snapshot(since=12) returned %d frames, want 0", len(got))
	}
	if got := p.Snapshot(10, 0); len(got) != 1 {
		t.Fatalf("snapshot(since=10) returned %d frames, want 1", len(got))
	}
	if got := p.Snapshot(9, 0); len(got) != 2 {
		t.Fatalf("snapshot(since=9) returned %d frames, want 2", len(got))
	}
	if got := p.Snapshot(8, 1); len(got) != 1 {
		t.Fatalf("snapshot(since=8,limit=1) returned %d frames, want 1", len(got))
	}
	if got := p.Snapshot(0, 2); len(got) != 2 {
		t.Fatalf("snapshot(since=0,limit=2) returned %d frames, want 2", len(got))
	}
}

// TestPcapRingClearReleasesSlots checks that Clear empties the ring without
// leaving a stale count behind, and that appending after a clear restarts
// the sequence window from the live start slot.
func TestPcapRingClearReleasesSlots(t *testing.T) {
	p := NewPacketCapture(3, "")
	p.SetIdleSkip(false)
	p.Start()
	for i := 0; i < 7; i++ {
		p.AddWithPeers(DirRx, testPcapFrame(i), "", "")
	}
	p.Clear()

	st := p.State()
	if st.Count != 0 || st.StartSeq != 0 || st.LastSeq != 0 {
		t.Fatalf("after clear: count=%d startSeq=%d lastSeq=%d, want all zero", st.Count, st.StartSeq, st.LastSeq)
	}
	if got := p.Snapshot(0, 0); len(got) != 0 {
		t.Fatalf("snapshot after clear = %d frames, want 0", len(got))
	}

	p.AddWithPeers(DirTx, testPcapFrame(99), "a", "b")
	st = p.State()
	if st.Count != 1 || st.StartSeq != 7 || st.LastSeq != 7 {
		t.Fatalf("after clear+add: count=%d window=[%d,%d], want 1 frame at seq 7", st.Count, st.StartSeq, st.LastSeq)
	}
	got := p.Snapshot(0, 0)
	if len(got) != 1 || got[0].FromPeer != "a" || got[0].ToPeer != "b" {
		t.Fatalf("unexpected snapshot after clear+add: %+v", got)
	}
}

// TestPcapRingSaveLoadRoundTrip verifies the JSON persistence path serialises
// the live window in oldest-first order across a ring wraparound, and that
// Load replays it at the front of the ring while resuming the sequence
// counter past the loaded tail.
func TestPcapRingSaveLoadRoundTrip(t *testing.T) {
	path := t.TempDir() + "/pcap.json"
	p := NewPacketCapture(5, path)
	p.SetIdleSkip(false)
	p.Start()
	for i := 0; i < 12; i++ {
		p.AddWithPeers(DirTx, testPcapFrame(i), "", "")
	}
	p.mu.Lock()
	p.saveLocked()
	p.mu.Unlock()

	q := NewPacketCapture(5, path)
	n, err := q.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n != 5 {
		t.Fatalf("loaded %d frames, want 5", n)
	}
	st := q.State()
	if st.StartSeq != 7 || st.LastSeq != 11 {
		t.Fatalf("loaded window = [%d,%d], want [7,11]", st.StartSeq, st.LastSeq)
	}
	got := q.Snapshot(0, 0)
	if len(got) != 5 {
		t.Fatalf("snapshot = %d frames, want 5", len(got))
	}
	for i, cf := range got {
		want := uint64(7 + i)
		if cf.Seq != want {
			t.Fatalf("snapshot[%d].Seq = %d, want %d", i, cf.Seq, want)
		}
	}
	if q.seq != 12 {
		t.Fatalf("seq resumed to %d, want 12", q.seq)
	}
}
