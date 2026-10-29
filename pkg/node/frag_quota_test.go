package node

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// buildFragEnvelope lays out a fragmentation envelope the way fragmentFrame does:
// magic(2) | origSeq(4) | fragIndex(2) | fragTotal(2) | chunkLen(2) | chunk.
func buildFragEnvelope(t *testing.T, origSeq uint32, index, total uint16, chunk []byte) []byte {
	t.Helper()
	if len(chunk) == 0 {
		t.Fatal("chunk must be non-empty")
	}
	if len(chunk) > 65535 {
		t.Fatal("chunk too large for the envelope")
	}
	var b []byte
	b = binary.BigEndian.AppendUint16(b, fragMagic)
	b = binary.BigEndian.AppendUint32(b, origSeq)
	b = binary.BigEndian.AppendUint16(b, index)
	b = binary.BigEndian.AppendUint16(b, total)
	b = binary.BigEndian.AppendUint16(b, uint16(len(chunk)))
	return append(b, chunk...)
}

// A write-deadline retry re-sends the identical fragment set under the same
// origSeq, and the send-side write deadline is DYNAMIC — 600 ms cold-start up
// to a 2500 ms window (writeDeadlineFor), so its upper bound outlives
// reasmTimeout (2 s). Reusing a key whose group has expired therefore happens
// in normal operation — and the stale group's quota slot has to be released
// before the replacement is counted.
//
// The old code overwrote f.bufs[key] and incremented perPeerGroups without
// ever decrementing, so one such reuse leaked a slot permanently. After 64
// leaks the per-peer quota guard tripped forever and every fragment from that
// peer was dropped until a restart.
func TestFragReassemblerExpiredReuseDoesNotLeakQuota(t *testing.T) {
	f := newFragReassembler()
	p := peer.ID("quota-peer")

	open := func(origSeq uint32) {
		f.reassemble(p, buildFragEnvelope(t, origSeq, 0, 2, []byte("aaaaaaaaaa")), 0, 1)
	}

	for i := 0; i < maxReasmGroupsPerPeer; i++ {
		open(uint32(i))
	}
	if got := f.perPeerGroups[p]; got != maxReasmGroupsPerPeer {
		t.Fatalf("groups = %d, want %d", got, maxReasmGroupsPerPeer)
	}

	// Expire one group, then retransmit its first fragment.
	var key reasmKey
	for k := range f.bufs {
		f.bufs[k].deadline = time.Now().Add(-time.Second)
		key = k
		break
	}
	f.reassemble(p, buildFragEnvelope(t, key.origSeq, 1, 2, []byte("bbbbbbbbbb")), 0, 1)

	if got := f.perPeerGroups[p]; got != maxReasmGroupsPerPeer {
		t.Fatalf("groups after an expired-reuse = %d, want %d — the stale slot leaked",
			got, maxReasmGroupsPerPeer)
	}
	if got := len(f.bufs); got != maxReasmGroupsPerPeer {
		t.Fatalf("groups stored after an expired-reuse = %d, want %d", got, maxReasmGroupsPerPeer)
	}

	// The peer must still be at its quota afterwards, and the guard must still
	// reject a new group — but it must NOT be permanently blocked: the bug
	// symptom was 64 leaks followed by every fragment from this peer being
	// dropped until restart.
	f.reassemble(p, buildFragEnvelope(t, 5000, 0, 2, []byte("cccccccccc")), 0, 1)
	if got := f.perPeerGroups[p]; got != maxReasmGroupsPerPeer {
		t.Fatalf("quota guard failed to reject an over-quota group: got %d", got)
	}
	if got := len(f.bufs); got != maxReasmGroupsPerPeer {
		t.Fatalf("a rejected group still consumed a slot: %d stored", got)
	}

	// Completing the retransmitted group frees exactly one slot…
	if _, complete := f.reassemble(p, buildFragEnvelope(t, key.origSeq, 0, 2, []byte("dddddddddd")), 0, 1); !complete {
		t.Fatal("the retransmitted group did not complete")
	}
	if got := f.perPeerGroups[p]; got != maxReasmGroupsPerPeer-1 {
		t.Fatalf("groups after completing = %d, want %d", got, maxReasmGroupsPerPeer-1)
	}
	// …and that slot is usable again, so the peer recovers.
	f.reassemble(p, buildFragEnvelope(t, 5000, 0, 2, []byte("cccccccccc")), 0, 1)
	if got := f.perPeerGroups[p]; got != maxReasmGroupsPerPeer {
		t.Fatalf("peer did not recover its quota: groups = %d, want %d", got, maxReasmGroupsPerPeer)
	}
	if got := len(f.bufs); got != maxReasmGroupsPerPeer {
		t.Fatalf("groups stored = %d, want %d", got, maxReasmGroupsPerPeer)
	}
}

// The map and the per-peer counter must never disagree. Every path that opens
// a group has a matching close path now, so drive all of them and check.
func TestFragReassemblerQuotaMatchesMap(t *testing.T) {
	f := newFragReassembler()
	a, b := peer.ID("peerA"), peer.ID("peerB")

	check := func(label string) {
		got := 0
		counts := map[peer.ID]int{}
		for k := range f.bufs {
			counts[k.peerID]++
			got++
		}
		for p, n := range counts {
			if f.perPeerGroups[p] != n {
				t.Errorf("%s: perPeerGroups[%s] = %d, map has %d", label, p.ShortString(), f.perPeerGroups[p], n)
			}
		}
		if len(f.perPeerGroups) != len(counts) {
			t.Errorf("%s: perPeerGroups has %d entries, map has %d peers", label, len(f.perPeerGroups), len(counts))
		}
		if len(f.bufs) != got {
			t.Errorf("%s: len(bufs) = %d, want %d", label, len(f.bufs), got)
		}
	}

	opened := 0
	for i := 0; i < 10; i++ {
		f.reassemble(a, buildFragEnvelope(t, uint32(i), 0, 2, []byte("peerA data")), 0, 1)
		opened++
	}
	f.reassemble(b, buildFragEnvelope(t, 0, 0, 2, []byte("peerB data")), 0, 1)
	opened++
	check("after opening")
	if f.perPeerGroups[a] != 10 || f.perPeerGroups[b] != 1 {
		t.Fatalf("counts = %d/%d, want 10/1", f.perPeerGroups[a], f.perPeerGroups[b])
	}

	// Complete every one of peer A's groups; each completion releases a slot.
	for i := 0; i < 10; i++ {
		if _, complete := f.reassemble(a, buildFragEnvelope(t, uint32(i), 1, 2, []byte("peerA tail")), 0, 1); !complete {
			t.Fatalf("group %d did not complete", i)
		}
	}
	opened -= 10
	check("after completing")
	if _, ok := f.perPeerGroups[a]; ok {
		t.Fatal("perPeerGroups still holds an entry for a peer with no open groups")
	}

	// Reap the rest.
	for k := range f.bufs {
		f.bufs[k].deadline = time.Now().Add(-time.Second)
	}
	f.reap()
	check("after reap")
	opened = 0

	// Evict under pressure.
	for i := 0; i < 5; i++ {
		f.reassemble(b, buildFragEnvelope(t, uint32(i), 0, 2, []byte("evict")), 0, 1)
	}
	check("after evict")
	_ = opened
}
