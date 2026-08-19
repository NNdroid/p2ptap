package node

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/obfuscate"
)

// splitIntoChunks splits b into n contiguous chunks for fragment testing. The
// reassembler does not care about chunk size (only fragTotal/indices matter), so
// an even-ish split is fine.
func splitIntoChunks(b []byte, n int) [][]byte {
	if n <= 0 {
		n = 1
	}
	chunks := make([][]byte, 0, n)
	size := (len(b) + n - 1) / n
	for i := 0; i < len(b); i += size {
		end := i + size
		if end > len(b) {
			end = len(b)
		}
		chunks = append(chunks, b[i:end])
	}
	return chunks
}

// TestFragReassemblePassthroughNonFragment proves the common small-packet path:
// a payload that does NOT begin with fragMagic must be reported complete with a
// nil "final" so the caller keeps the original frame untouched (zero overhead).
func TestFragReassemblePassthroughNonFragment(t *testing.T) {
	f := newFragReassembler()
	p := newTestPeerID(t)
	raw := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	out, complete := f.reassemble(p, raw)
	if !complete {
		t.Fatalf("non-fragment payload must be reported complete")
	}
	if out != nil {
		t.Fatalf("non-fragment payload must return nil final (caller keeps original), got %d bytes", len(out))
	}
}

// TestFragReassembleSingleFragment proves a one-part fragment envelope (fragTotal=1)
// is unpacked back to its chunk directly.
func TestFragReassembleSingleFragment(t *testing.T) {
	f := newFragReassembler()
	p := newTestPeerID(t)
	chunk := []byte("single-chunk-frame-payload")
	env := appendFragHeader(nil, 1, 0, 1, chunk)
	out, complete := f.reassemble(p, env)
	if !complete {
		t.Fatalf("single-fragment envelope must be complete")
	}
	if !bytes.Equal(out, chunk) {
		t.Fatalf("single-fragment reassemble: got %q want %q", out, chunk)
	}
}

// TestFragReassembleMultiInOrder proves an N-part group reassembles in order.
func TestFragReassembleMultiInOrder(t *testing.T) {
	f := newFragReassembler()
	p := newTestPeerID(t)
	orig := bytes.Repeat([]byte("ABCD"), 500) // 2000 bytes -> multi-fragment
	chunks := splitIntoChunks(orig, 4)
	total := uint16(len(chunks))
	var got []byte
	complete := false
	for i, c := range chunks {
		out, done := f.reassemble(p, appendFragHeader(nil, 7, uint16(i), total, c))
		if i < len(chunks)-1 {
			if done {
				t.Fatalf("fragment %d should NOT be complete yet", i)
			}
		} else {
			got, complete = out, done
		}
	}
	if !complete {
		t.Fatalf("final fragment must complete the group")
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("reassembled %d bytes, want %d", len(got), len(orig))
	}
}

// TestFragReassembleMultiOutOfOrder proves fragments arriving out of order still
// reassemble correctly (the receiver may receive fragments in any order).
func TestFragReassembleMultiOutOfOrder(t *testing.T) {
	f := newFragReassembler()
	p := newTestPeerID(t)
	orig := bytes.Repeat([]byte("Z"), 1500)
	chunks := splitIntoChunks(orig, 3)
	total := uint16(len(chunks))
	var got []byte
	complete := false
	// Feed in reverse order: 2, 1, 0.
	for k := len(chunks) - 1; k >= 0; k-- {
		out, done := f.reassemble(p, appendFragHeader(nil, 99, uint16(k), total, chunks[k]))
		if k == 0 {
			got, complete = out, done
		} else if done {
			t.Fatalf("fragment %d should not complete yet", k)
		}
	}
	if !complete {
		t.Fatalf("out-of-order group must complete")
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("out-of-order reassembly corrupted payload")
	}
}

// TestFragReassembleDuplicateFragmentIgnored proves a retransmitted/duplicated
// fragment index does not corrupt or double-count the group.
func TestFragReassembleDuplicateFragmentIgnored(t *testing.T) {
	f := newFragReassembler()
	p := newTestPeerID(t)
	orig := bytes.Repeat([]byte("Q"), 900)
	chunks := splitIntoChunks(orig, 3)
	total := uint16(len(chunks))
	// Feed index 0 twice, then 1, then 2.
	order := []int{0, 0, 1, 2}
	var got []byte
	complete := false
	for _, idx := range order {
		out, done := f.reassemble(p, appendFragHeader(nil, 5, uint16(idx), total, chunks[idx]))
		if idx == 2 {
			got, complete = out, done
		} else if done {
			t.Fatalf("fragment index %d should not complete yet", idx)
		}
	}
	if !complete {
		t.Fatalf("group must complete despite duplicate index 0")
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("duplicate fragment corrupted reassembly")
	}
}

// TestFragReassembleExcessiveFragTotalDropped proves an attacker-controlled
// fragTotal far above the cap is refused (no giant parts slice allocated).
func TestFragReassembleExcessiveFragTotalDropped(t *testing.T) {
	f := newFragReassembler()
	p := newTestPeerID(t)
	env := appendFragHeader(nil, 1, 0, 300, []byte("x")) // maxFragTotal = 256
	out, complete := f.reassemble(p, env)
	if complete || out != nil {
		t.Fatalf("excessive fragTotal must be dropped (complete=%v out=%v)", complete, out)
	}
}

// TestFragReassembleOversizedBytesAborted proves a multi-fragment group whose
// chunks exceed one obfuscated frame (maxReasmBytes = obfuscate.MaxFrameSize) is
// aborted so reassembly memory stays bounded.
func TestFragReassembleOversizedBytesAborted(t *testing.T) {
	f := newFragReassembler()
	p := newTestPeerID(t)
	big := make([]byte, obfuscate.MaxFrameSize+200)
	for i := range big {
		big[i] = byte(i)
	}
	// fragTotal=2, first chunk already exceeds the cap -> must abort on insert.
	env0 := appendFragHeader(nil, 1, 0, 2, big)
	out, complete := f.reassemble(p, env0)
	if complete || out != nil {
		t.Fatalf("oversized fragment group must abort (complete=%v out=%v)", complete, out)
	}
}

// TestFragReassemblePerPeerIsolation proves two peers using the SAME origSeq do
// not collide: each peer's group is keyed by (peerID, origSeq).
func TestFragReassemblePerPeerIsolation(t *testing.T) {
	f := newFragReassembler()
	pa := newTestPeerID(t)
	pb := newTestPeerID(t)
	origA := bytes.Repeat([]byte("A"), 600)
	origB := bytes.Repeat([]byte("B"), 600)
	ca := splitIntoChunks(origA, 2)
	cb := splitIntoChunks(origB, 2)
	// Interleave: A part0, B part0 (same origSeq=42, total=2), then A part1, B part1.
	f.reassemble(pa, appendFragHeader(nil, 42, 0, 2, ca[0]))
	f.reassemble(pb, appendFragHeader(nil, 42, 0, 2, cb[0]))
	outA, doneA := f.reassemble(pa, appendFragHeader(nil, 42, 1, 2, ca[1]))
	outB, doneB := f.reassemble(pb, appendFragHeader(nil, 42, 1, 2, cb[1]))
	if !doneA || !bytes.Equal(outA, origA) {
		t.Fatalf("peerA reassembly wrong (done=%v)", doneA)
	}
	if !doneB || !bytes.Equal(outB, origB) {
		t.Fatalf("peerB reassembly wrong (done=%v)", doneB)
	}
}

// TestFragReassemblerReapExpired proves the reaper drops expired groups and that
// a later group with the same origSeq opens fresh (not confused with the dead one).
func TestFragReassemblerReapExpired(t *testing.T) {
	f := newFragReassembler()
	p := newTestPeerID(t)
	// Open an incomplete group.
	f.reassemble(p, appendFragHeader(nil, 1, 0, 3, []byte("partial")))
	// Backdate its deadline and reap.
	for k := range f.bufs {
		f.bufs[k].deadline = time.Now().Add(-time.Hour)
	}
	f.reap()
	if len(f.bufs) != 0 {
		t.Fatalf("reap should remove expired groups, left %d", len(f.bufs))
	}
	// A fresh single-fragment group after reap must still work.
	env := appendFragHeader(nil, 1, 0, 1, []byte("fresh"))
	out, complete := f.reassemble(p, env)
	if !complete || !bytes.Equal(out, []byte("fresh")) {
		t.Fatalf("fresh group after reap failed (complete=%v)", complete)
	}
}

// TestFragReassembleConcurrentPeers proves the reassembler is safe for
// concurrent use: in production fragments from DIFFERENT peers arrive on
// different stream goroutines and all touch the shared f.bufs map, while a
// background reaper also mutates it. This test runs real parallel workers
// (distinct peers) plus a ticking reaper and asserts (a) no data race is
// reported by -race and (b) every peer's group reassembles correctly despite
// the contention. Without the sync.Mutex on fragReassembler this would either
// race (caught by -race) or corrupt groups (caught by the equality checks).
func TestFragReassembleConcurrentPeers(t *testing.T) {
	f := newFragReassembler()
	const nPeers = 16
	const nFrags = 3

	// Pre-generate distinct peer IDs on the test goroutine. newTestPeerID uses
	// t.Fatalf internally, which must not run inside a worker goroutine.
	peers := make([]peer.ID, nPeers)
	for i := range peers {
		peers[i] = newTestPeerID(t)
	}

	errCh := make(chan error, nPeers)
	var wg sync.WaitGroup

	// Background reaper contends on the same f.bufs map as the workers.
	stopReap := make(chan struct{})
	go func() {
		reapTick := time.NewTicker(5 * time.Millisecond)
		defer reapTick.Stop()
		for {
			select {
			case <-stopReap:
				return
			case <-reapTick.C:
				f.reap()
			}
		}
	}()

	for i := 0; i < nPeers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p := peers[id]
			orig := bytes.Repeat([]byte{byte(id)}, 900)
			chunks := splitIntoChunks(orig, nFrags)
			total := uint16(len(chunks))
			var got []byte
			complete := false
			// Feed the fragments with small jitter so goroutines interleave on
			// the shared map rather than serializing by construction.
			for idx := 0; idx < len(chunks); idx++ {
				out, done := f.reassemble(p, appendFragHeader(nil, uint32(id+1), uint16(idx), total, chunks[idx]))
				if idx == len(chunks)-1 {
					got, complete = out, done
				}
				time.Sleep(time.Duration(id) * 50 * time.Microsecond)
			}
			if !complete {
				errCh <- fmt.Errorf("peer %d: group did not complete", id)
				return
			}
			if !bytes.Equal(got, orig) {
				errCh <- fmt.Errorf("peer %d: reassembled %d bytes, want %d (concurrent corruption?)", id, len(got), len(orig))
				return
			}
		}(i)
	}

	wg.Wait()
	close(stopReap)
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}
