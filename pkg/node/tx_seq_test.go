package node

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"

	"p2ptap/pkg/obfuscate"
)

// newTxSeqTestNode returns a Node with just enough state for sequence
// allocation: a real packer plus the per-peer ledger table (zero value works).
func newTxSeqTestNode() *Node {
	fp := obfuscate.NewFramePackerFull(nil)
	fp.SetSourceIdentity("txseq-test")
	return &Node{Packer: fp}
}

// TestTxSeqPerPeerStaysDense is the regression guard for the multipath latency
// bug: the structured counter used to come from ONE process-wide sequence, so
// with several peers each peer observed a sparse subsequence. The receive-side
// reorder buffer cannot distinguish a gap from packet loss, so it delayed every
// frame by the full force-release timeout (200ms by default) — turning steady
// traffic into 200ms bursts.
//
// With a per-peer ledger, consecutive frames addressed to the SAME peer must
// carry consecutive counters no matter how the senders interleave.
func TestTxSeqPerPeerStaysDense(t *testing.T) {
	n := newTxSeqTestNode()
	peers := []peer.ID{"peer-a", "peer-b", "peer-c"}

	last := make(map[peer.ID]uint64)
	seen := make(map[peer.ID]int)

	for i := 0; i < 30; i++ {
		p := peers[i%len(peers)]
		c := obfuscate.CounterFromSeq(n.nextTxSeqID(p))
		if prev, ok := last[p]; ok {
			if c != prev+1 {
				t.Fatalf("peer %s: counter jumped %d -> %d (want consecutive): "+
					"the receive-side reorder buffer would treat this as a hole",
					p, prev, c)
			}
		}
		last[p] = c
		seen[p]++
	}

	for _, p := range peers {
		if seen[p] != 10 {
			t.Fatalf("peer %s allocated %d frames, want 10", p, seen[p])
		}
	}
}

// TestTxSeqAnchorReportsUsedCounter guards the SeqSync advertisement: MySeq
// carries the counter of the LAST frame already issued for the peer. The
// receiver's dedup SyncFrom marks exactly that counter as seen, so the value
// must describe what has been USED — advertising "the next one" would anchor
// the receiver on a counter the next data frame then reuses, and the frame
// would be dropped as a SameSeq duplicate (this actually broke ARP-then-ping).
func TestTxSeqAnchorReportsUsedCounter(t *testing.T) {
	n := newTxSeqTestNode()
	p := peer.ID("peer-peek")

	if got := obfuscate.CounterFromSeq(n.Packer.MakeSeqID(n.txFrameCounter(p), n.txEpochForPeer(p))); got != 0 {
		t.Fatalf("anchor before any send = %d, want 0", got)
	}
	first := obfuscate.CounterFromSeq(n.nextTxSeqID(p))
	// Reading the anchor repeatedly must not move the ledger.
	for i := 0; i < 5; i++ {
		if got := obfuscate.CounterFromSeq(n.Packer.MakeSeqID(n.txFrameCounter(p), n.txEpochForPeer(p))); got != first {
			t.Fatalf("anchor = %d, want %d (last used) — anchor moved the ledger", got, first)
		}
	}
	next := obfuscate.CounterFromSeq(n.nextTxSeqID(p))
	if next != first+1 {
		t.Fatalf("next = %d, want %d — anchor consumed a counter", next, first+1)
	}
}

// TestTxSeqFragmentsUseDisjointSpace guards the other half of the design:
// tunnel fragment envelopes are sealed independently and need their own nonce,
// so they are allocated above txFragSeqBase. They must never consume a value
// from the peer's logical-frame sequence, or a fragmented frame would look like
// a gap exactly the way the old global counter did.
func TestTxSeqFragmentsUseDisjointSpace(t *testing.T) {
	n := newTxSeqTestNode()
	p := peer.ID("peer-frag")

	frameBefore := obfuscate.CounterFromSeq(n.nextTxSeqID(p))
	frag1 := obfuscate.CounterFromSeq(n.nextTxFragSeqID(p))
	frag2 := obfuscate.CounterFromSeq(n.nextTxFragSeqID(p))
	frameAfter := obfuscate.CounterFromSeq(n.nextTxSeqID(p))

	if frameAfter != frameBefore+1 {
		t.Fatalf("logical frame counter jumped %d -> %d across fragment allocations",
			frameBefore, frameAfter)
	}
	if frag1 < txFragSeqBase || frag2 < txFragSeqBase {
		t.Fatalf("fragment counters %d,%d must live in the top half (>= %d)",
			frag1, frag2, txFragSeqBase)
	}
	if frag2 != frag1+1 {
		t.Fatalf("fragment counters %d -> %d must be consecutive", frag1, frag2)
	}
}

// TestTxSeqRekeyThresholdFitsBothHalves keeps the nonce budget honest: with the
// counter field split in two, the re-key threshold must stay below the size of
// one half or a key could protect more nonces than either half can express.
func TestTxSeqRekeyThresholdFitsBothHalves(t *testing.T) {
	if obfRekeyFrameThreshold >= txFragSeqBase {
		t.Fatalf("rekey threshold %d must be below the half-field size %d",
			obfRekeyFrameThreshold, txFragSeqBase)
	}
}
