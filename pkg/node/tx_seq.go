package node

import (
	"sync/atomic"

	"github.com/libp2p/go-libp2p/core/peer"
)

// Per-peer outbound sequence ledger.
//
// The structured SeqID carries a 32-bit counter field. Historically that
// counter was a single PROCESS-WIDE value: every unicast to any peer, every
// relay hop envelope, every control-plane SeqSync and every TAP probe consumed
// the same monotonic sequence. The AEAD nonce (derived from that counter) stayed
// unique, but each peer only OBSERVED a sparse subset of the sequence, because
// values in between were spent on frames addressed to other peers and on
// control traffic.
//
// The receive-side reorder buffer (rx_reorder.go) reconstructs TAP order from
// those counters, and in that buffer a sparse sequence is indistinguishable from
// packet loss: every frame looks like it arrived behind a hole, so it is held
// until the force-release timeout. Multipath therefore added a fixed
// ~200ms of latency and turned steady traffic into 200ms bursts as soon as a
// second peer existed in the mesh — which is precisely the "multipath feels
// slow and unstable" symptom.
//
// This ledger makes the counter PER-PEER, so each peer observes a strictly
// consecutive logical-frame sequence. Nonce safety is preserved and actually
// tightened: the counter is paired with that peer's own AEAD key and never
// resets while the process lives, so a (key, nonce) pair cannot repeat. The
// per-peer re-key budget (PeerObf.framesSinceRekey) still rotates the key long
// before this counter can wrap.
//
// Fragment envelopes need their own nonce per fragment, and those values must
// NOT interleave with the logical-frame sequence or they would re-introduce the
// gap. They are allocated from the top half of the 32-bit field
// (txFragSeqBase..2^32-1) while logical frames use the bottom half, so the two
// nonce spaces stay disjoint and the logical sequence stays dense.
const (
	// txFragSeqBase splits the 32-bit counter field: [1, txFragSeqBase) is the
	// per-peer logical-frame sequence, [txFragSeqBase, 2^32) is the per-peer
	// fragment-envelope sequence.
	txFragSeqBase = uint64(1) << 31
	// txSeqHalfMask masks a raw counter into one half of the field.
	txSeqHalfMask = txFragSeqBase - 1
)

// peerTxLedger is the per-peer pair of monotonic counters. Both are plain
// atomics: the TX hot path only ever performs one Add.
type peerTxLedger struct {
	// frame counts LOGICAL tunnel frames (one per Pack of a TAP frame,
	// coalesced batch, relay envelope or SeqSync probe) — NOT wire fragments.
	// This is the sequence the receive side reorders on.
	frame atomic.Uint64
	// frag counts tunnel FRAGMENT envelopes, which each need a distinct nonce.
	frag atomic.Uint64
}

// nextHalf returns the next value of a half-width counter. Zero is skipped: a
// structured SeqID carrying an all-zero counter would look to the receiver's
// dedup like "not yet anchored". The underlying atomic keeps growing; the mask
// only shapes the value placed on the wire, so the wrap never aliases an older
// in-flight value within a re-key generation.
func nextHalf(c *atomic.Uint64) uint64 {
	if v := c.Add(1) & txSeqHalfMask; v != 0 {
		return v
	}
	return c.Add(1) & txSeqHalfMask
}

func (l *peerTxLedger) nextFrame() uint64 { return nextHalf(&l.frame) }

func (l *peerTxLedger) nextFrag() uint64 { return nextHalf(&l.frag) }

// txLedgerFor returns the sequence ledger for peer p, creating it on first use.
// Entries are never removed: the counter must stay monotonic for the life of the
// process, because a peer may reconnect while retaining its negotiated AEAD key
// — restarting the counter under that same key would reuse nonces. The state is
// two machine words per identity, which is bounded by the number of VPN peers.
func (n *Node) txLedgerFor(p peer.ID) *peerTxLedger {
	if v, ok := n.peerTxSeq.Load(p); ok {
		return v.(*peerTxLedger)
	}
	l := new(peerTxLedger)
	v, _ := n.peerTxSeq.LoadOrStore(p, l)
	return v.(*peerTxLedger)
}

// nextTxSeqID returns the next structured SeqID for a LOGICAL frame addressed
// to peer p. Consecutive calls for the same peer yield consecutive counters,
// which is exactly what the receive-side reorder buffer needs to distinguish
// "still in flight on another path" from "lost".
func (n *Node) nextTxSeqID(p peer.ID) uint64 {
	return n.Packer.MakeSeqID(n.txLedgerFor(p).nextFrame(), n.txEpochForPeer(p))
}

// nextTxFragSeqID returns the next structured SeqID for a tunnel FRAGMENT
// envelope addressed to peer p. Fragment counters live in the top half of the
// field, so they never disturb the logical-frame sequence the reorder buffer
// depends on.
func (n *Node) nextTxFragSeqID(p peer.ID) uint64 {
	return n.Packer.MakeSeqID(txFragSeqBase|n.txLedgerFor(p).nextFrag(), n.txEpochForPeer(p))
}

// txFrameCounter reports the highest logical-frame counter already used for p
// (0 when nothing has been sent yet). It replaces the old process-wide
// FramePacker.CurrentCounter() as the re-key anchor AND as the SeqSync
// advertisement: the receive-side dedup anchors its window at the reported
// counter and marks it as already seen, which is only correct if the value
// describes what has been USED, not what comes next.
//
// The value is masked into the logical-frame half, matching what nextTxSeqID
// actually puts on the wire. The masked value is clamped away from 0 only when
// frames HAVE been sent: nextHalf skips the all-zero counter (so a fresh peer's
// 0 correctly means "nothing sent"), but the underlying atomic transiently holds
// a multiple of 2^31 for an instant during that skip, and a reader landing there
// would otherwise report 0 and make the receiver think the sender's counter
// restarted. A raw value of exactly 0 is the untouched ledger, so it stays 0.
func (n *Node) txFrameCounter(p peer.ID) uint64 {
	raw := n.txLedgerFor(p).frame.Load()
	if v := raw & txSeqHalfMask; v != 0 || raw == 0 {
		return v
	}
	return txSeqHalfMask
}
