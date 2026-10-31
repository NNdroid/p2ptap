package node

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/fec"
	"p2ptap/pkg/obfuscate"
)

// Tunnel-level fragmentation for TAP frames.
//
// Reliable libp2p streams perform their own transport segmentation, including
// QUIC, WebRTC and WebTransport. Application fragmentation is retained for
// explicitly configured limits and overlay paths without registered streams.
// Each fragment is independently obfuscated; the receiver reassembles the
// original sealed frame before decrypting and unpacking it.
//
// Layout of a fragment payload (carried inside the OUTER obfuscate.Pack):
//
//	plain: [FragMagic(2) | OrigSeq(4) | FragIndex(2) | FragTotal(2) | ChunkLen(2) | chunk...]
//	FEC:   [FecMagic(2)  | OrigSeq(4) | FragIndex(2) | FragTotal(2) | DataParts(2) |
//	        ChunkLen(2) | ChunkSize(2) | TailLen(2) | chunk...]
//
// A non-fragmented frame carries NO frag header and is passed through
// untouched (zero overhead on the common small-packet path).
//
// The FEC variant exists so one logical frame can be STRIPED across several
// paths without becoming unrecoverable when a path dies mid-frame: the data is
// cut into DataParts shards of ChunkSize bytes (the last one only TailLen) and
// FragTotal-DataParts Reed-Solomon parity shards are added, so any DataParts of
// the FragTotal shards rebuild the frame (see pkg/fec).
//
// ChunkSize and TailLen are on the wire rather than derived, because the shard
// size is a sender-side policy (multipathStripeChunk), not a function of the
// frame length — deriving it would silently disagree with the sender and make
// every shard fail its length check. Together they give the exact original
// length, so the zero padding the codec needs never reaches the wire or the
// inner AEAD open.
const (
	fragMagic     uint16 = 0xF5A1
	fragMagicFEC  uint16 = 0xF5A2
	fragHeaderLen        = 12 // 2+4+2+2+2
	// fragHeaderLenFEC adds DataParts(2), ChunkSize(2) and TailLen(2).
	fragHeaderLenFEC = 18

	// multipathStripeChunk is the per-shard payload cap used when a peer has
	// more than one usable path. A frame larger than this is split into equal
	// shards and striped across the paths, so a single jumbo/LSA/meta blob is no
	// longer pinned to one link while the others idle.
	//
	// Deliberately far above the Ethernet MTU: ordinary traffic is a single
	// shard and keeps the zero-overhead path (no frag header, no parity), so
	// only genuinely large frames pay the sharding and coding cost.
	multipathStripeChunk = 16 * 1024
	// fecParityPercent is the parity overhead for a striped group. 25% covers
	// one lost path out of up to four shard-carrying paths; it is a constant
	// rather than a knob because the shard count is itself bounded by
	// multipathStripeChunk and MaxSealedFrameSize (at most 4 data shards, so at
	// most 1 parity shard in practice).
	fecParityPercent = 25

	// reasmTimeout bounds how long a fragment group may wait for its remaining
	// parts before it is dropped. Fragments of one frame ride a single path
	// unless the group is striped (FEC variant), and even then the sender picks
	// all of its paths from the same peer set, so reassembly only has to cover
	// those paths' delivery latency. 5 s leaves headroom over a
	// satellite/high-latency RTT (a 2 s budget could expire on a >2 s RTT path
	// and force a retransmit that the path's own reliable transport would have
	// delivered); the real safety net against a genuinely lost fragment is the
	// inner TCP retransmit, so a longer timeout only delays that fallback in a
	// pathological case.
	reasmTimeout = 5 * time.Second

	// Reassembly hardening. The FragTotal, DataParts and OrigSeq fields travel
	// in cleartext frag headers, so a peer (or anyone who can inject a frame into
	// the overlay) controls them. Without caps, a single group can force a
	// 65535-slot parts slice and an unbounded number of concurrent groups can
	// be opened, exhausting memory before the reaper reclaims them.
	//
	// A full sealed frame split at the minimum configured 256-byte limit needs
	// 257 data parts, and a striped group adds parity on top of that, so the
	// part-count ceiling allows for both. Include the AEAD tag in the byte cap,
	// and allow that exact part count. At most maxReasmGroups groups may be in
	// flight at once.
	maxFragTotal   = (obfuscate.MaxSealedFrameSize+255)/256 + 128
	maxReasmGroups = 1024
	maxReasmBytes  = obfuscate.MaxSealedFrameSize

	// Per-peer reassembly quota. Without this, a single attacker peer can open
	// maxReasmGroups concurrent groups and starve all other peers (Round 9 MED).
	// 64 groups per peer is generous: a single frame at 256-byte fragments
	// needs 257 PARTS of ONE group (not 257 groups), and concurrent in-flight
	// frames are far fewer.
	maxReasmGroupsPerPeer = 64
)

type reasmKey struct {
	peerID  peer.ID
	origSeq uint32
	epoch   uint64 // a reconnect/restart may reuse origSeq while old parts remain
	// channel namespaces the two reassembly streams a single peer link can
	// interleave: DIRECT data frames (reasmChannelDirect) and RELAY envelope
	// frames (reasmChannelRelay). Both are fragmented with the SAME per-sender
	// origSeq counter, and a restart resets that counter — without the
	// namespace, a direct group could collide with (and corrupt) a relay
	// group of the same peer within the group-expiry window.
	channel uint8
}

const (
	reasmChannelDirect uint8 = 0
	reasmChannelRelay  uint8 = 1
)

// fragReassembler buffers incoming fragments and emits complete obfuscated
// frames once every fragment of a group has arrived.
type fragReassembler struct {
	mu   sync.Mutex
	bufs map[reasmKey]*reasmBuf

	// perPeerGroups tracks how many reassembly groups each peer has open.
	// Guarded by mu. Prevents a single peer from exhausting the global budget.
	perPeerGroups map[peer.ID]int

	// seqGen belongs exclusively to the TX fragmentation path. Keep it atomic
	// instead of protecting it with mu: mu serializes RX reassembly state, and
	// sharing that lock made every fragmented TX frame contend with every RX
	// fragment under bidirectional load. Atomic increment preserves the same
	// monotonically increasing uint32 sequence without coupling the two paths.
	seqGen atomic.Uint32
}

type reasmBuf struct {
	total    int
	parts    [][]byte
	got      int
	size     int // running total of stored chunk bytes (caps memory)
	deadline time.Time

	// FEC groups only: the data-shard count, the exact original frame length and
	// the derived shard size. Zero/false for plain groups.
	fec       bool
	dataParts int
	origLen   int
	chunkSize int
	tailLen   int
	// cap is the exact number of shard bytes this group may store: the data
	// shards add up to origLen, and each parity shard is chunkSize long. Derived
	// per group instead of using one global ceiling, because a two-shard group
	// carries proportionally far more parity than a four-shard one.
	cap int
}

func newFragReassembler() *fragReassembler {
	return &fragReassembler{
		bufs:          make(map[reasmKey]*reasmBuf),
		perPeerGroups: make(map[peer.ID]int),
	}
}

// nextOrigSeq allocates a monotonically increasing sequence for a new frame
// being fragmented on the TX side. It intentionally does not take the RX
// reassembly mutex: TX sequence allocation and RX fragment bookkeeping are
// independent and must not serialize each other under full-duplex traffic.
func (f *fragReassembler) nextOrigSeq() uint32 {
	return f.seqGen.Add(1)
}

// emitFragPart builds ONE obfuscated fragment envelope from hdr + chunk.
//
// The payload is assembled directly in the final Pack buffer: Pack writes only
// outBuf[:HeaderLen] before copying the payload into outBuf[HeaderLen:], so
// using that exact destination as the source turns the payload copy into a no-op
// and removes a per-fragment allocation on the fragmentation path.
//
// Returns (nil, false) after logging on a Pack failure. Callers must drop the
// whole group: emitting a bare (unobfuscated) envelope would leak the frag
// headers and TAP payload in cleartext, and the receiver's outer unpack rejects
// it as garbage, poisoning its decrypt-failure window and potentially triggering
// spurious key resyncs.
func (n *Node) emitFragPart(targetPeer peer.ID, hdr, chunk []byte) ([]byte, bool) {
	payloadLen := len(hdr) + len(chunk)
	outBuf := acquireFrameBuf(n.Packer.MaxPackedLen(payloadLen))
	fragPayload := outBuf[obfuscate.HeaderLen : obfuscate.HeaderLen+payloadLen]
	copy(fragPayload, hdr)
	copy(fragPayload[len(hdr):], chunk)

	n2, perr := n.Packer.Pack(n.nextTxFragSeqID(targetPeer), fragPayload, outBuf)
	if perr != nil {
		// Pack failure is effectively a can't-happen programming error
		// (MaxPackedLen under-sized), so surface it loudly.
		log.Error("Fragment Pack failed for a %d-byte part to peer %s: %v — dropping entire group",
			payloadLen, targetPeer, perr)
		releaseFrameBuf(outBuf)
		return nil, false
	}
	return outBuf[:n2], true
}

// putPlainFragHeader fills the fixed-size plain fragment header.
func putPlainFragHeader(dst []byte, origSeq uint32, fragIndex, fragTotal uint16, chunkLen int) {
	binary.BigEndian.PutUint16(dst[0:2], fragMagic)
	binary.BigEndian.PutUint32(dst[2:6], origSeq)
	binary.BigEndian.PutUint16(dst[6:8], fragIndex)
	binary.BigEndian.PutUint16(dst[8:10], fragTotal)
	binary.BigEndian.PutUint16(dst[10:12], uint16(chunkLen))
}

// putFECFragHeader fills the extended (parity-carrying) fragment header.
func putFECFragHeader(dst []byte, origSeq uint32, fragIndex, fragTotal, dataParts uint16, chunkLen, chunkSize, tailLen int) {
	binary.BigEndian.PutUint16(dst[0:2], fragMagicFEC)
	binary.BigEndian.PutUint32(dst[2:6], origSeq)
	binary.BigEndian.PutUint16(dst[6:8], fragIndex)
	binary.BigEndian.PutUint16(dst[8:10], fragTotal)
	binary.BigEndian.PutUint16(dst[10:12], dataParts)
	binary.BigEndian.PutUint16(dst[12:14], uint16(chunkLen))
	binary.BigEndian.PutUint16(dst[14:16], uint16(chunkSize))
	binary.BigEndian.PutUint16(dst[16:18], uint16(tailLen))
}

// fragmentFrame splits an already-obfuscated frame (the output of
// obfuscate.Pack) into N independently re-obfuscated WriteFrame payloads.
// Frames that already fit under maxPayload are returned untouched (true
// zero-overhead common path): the receiver detects the absence of a frag
// header and passes them through.
//
// Each fragment envelope carries its OWN SeqID because it is sealed
// independently and therefore needs a distinct AEAD nonce. Those numbers are
// allocated from the top half of the per-peer counter field
// (txFragSeqBase..2^32-1) so they never interleave with the peer's
// logical-frame sequence — otherwise every fragmented frame would look like a
// gap to the receive-side reorder buffer.
//
// When maxPayload > 0 it is used as the fragment size limit (allows callers
// to specify a larger limit for reliable streams). Otherwise the conservative
// node-default is used.
func (n *Node) fragmentFrame(packed []byte, frag *fragReassembler, targetPeer peer.ID, maxPayload int) ([][]byte, bool) {
	if maxPayload <= 0 {
		maxPayload = n.maxFragPayload()
	}
	if len(packed) <= maxPayload {
		return [][]byte{packed}, false
	}
	if frag == nil {
		log.Warn("Frame of %d bytes exceeds the %d-byte fragment payload but fragmentation is disabled; sending unfragmented",
			len(packed), maxPayload)
		return [][]byte{packed}, false
	}

	seq := frag.nextOrigSeq()
	total := (len(packed) + maxPayload - 1) / maxPayload
	out := make([][]byte, 0, total)
	var hdr [fragHeaderLen]byte
	for i := 0; i < total; i++ {
		start := i * maxPayload
		end := start + maxPayload
		if end > len(packed) {
			end = len(packed)
		}
		chunk := packed[start:end]
		putPlainFragHeader(hdr[:], seq, uint16(i), uint16(total), len(chunk))

		part, ok := n.emitFragPart(targetPeer, hdr[:], chunk)
		if !ok {
			releaseFragmentBuffers(out)
			return nil, false
		}
		out = append(out, part)
	}
	return out, true
}

// fragmentFrameForPaths chooses the fragmentation policy for a peer with
// pathCount usable paths.
//
// With a single path there is nothing to stripe and nothing to recover from, so
// the plain envelope is used and no parity is ever generated. With several
// paths a large frame is cut into equal shards plus Reed-Solomon parity
// (fragmentFrameStriped) so that it can be spread across paths AND survive one
// of them dying mid-frame.
func (n *Node) fragmentFrameForPaths(packed []byte, frag *fragReassembler, targetPeer peer.ID, maxPayload, pathCount int) ([][]byte, bool) {
	if pathCount < 2 || len(packed) <= multipathStripeChunk {
		// One path, or a frame small enough that plain fragmentation already
		// keeps it in a single fragment: nothing to stripe and nothing to
		// recover, so no parity is ever generated for ordinary traffic.
		return n.fragmentFrame(packed, frag, targetPeer, maxPayload)
	}
	chunkSize := maxPayload
	if chunkSize <= 0 || chunkSize > multipathStripeChunk {
		chunkSize = multipathStripeChunk
	}
	return n.fragmentFrameStriped(packed, frag, targetPeer, chunkSize)
}

// fragmentFrameStriped cuts packed into equal shards of at most chunkSize and
// appends Reed-Solomon parity shards, so the receiver can rebuild the frame from
// ANY dataParts of the FragTotal shards.
//
// Shards are equal-length on the wire except the last DATA shard, whose chunkLen
// is its real length; the codec works on a zero-padded copy, and OrigLen in the
// header tells the receiver exactly how much to keep, so padding never reaches
// the inner AEAD open.
func (n *Node) fragmentFrameStriped(packed []byte, frag *fragReassembler, targetPeer peer.ID, chunkSize int) ([][]byte, bool) {
	if chunkSize <= 0 || len(packed) <= chunkSize {
		return n.fragmentFrame(packed, frag, targetPeer, chunkSize)
	}
	if frag == nil {
		log.Warn("Frame of %d bytes exceeds the %d-byte stripe chunk but fragmentation is disabled; sending unfragmented",
			len(packed), chunkSize)
		return [][]byte{packed}, false
	}

	dataParts := (len(packed) + chunkSize - 1) / chunkSize
	parityParts := fecParityFor(dataParts)
	if dataParts < 2 || parityParts <= 0 {
		return n.fragmentFrame(packed, frag, targetPeer, chunkSize)
	}
	tailLen := len(packed) - (dataParts-1)*chunkSize

	// The codec needs equal-length shards: zero-pad the tail copy only.
	data := make([][]byte, dataParts)
	for i := 0; i < dataParts; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end <= len(packed) {
			data[i] = packed[start:end]
			continue
		}
		padded := make([]byte, chunkSize)
		copy(padded, packed[start:])
		data[i] = padded
	}
	parity, err := fec.Encode(data, parityParts)
	if err != nil {
		// Coding failure is a programming error (the shard count is bounded by
		// construction). Degrade to plain fragmentation: the frame still goes
		// out, it just loses cross-path recoverability.
		log.Error("FEC encode failed for a %d-byte frame in %d shards to peer %s: %v — falling back to plain fragmentation",
			len(packed), dataParts, targetPeer, err)
		return n.fragmentFrame(packed, frag, targetPeer, chunkSize)
	}

	total := dataParts + parityParts
	seq := frag.nextOrigSeq()
	out := make([][]byte, 0, total)
	var hdr [fragHeaderLenFEC]byte
	for i := 0; i < total; i++ {
		var chunk []byte
		if i < dataParts {
			start := i * chunkSize
			end := min(start+chunkSize, len(packed))
			chunk = packed[start:end]
		} else {
			chunk = parity[i-dataParts]
		}
		putFECFragHeader(hdr[:], seq, uint16(i), uint16(total), uint16(dataParts), len(chunk), chunkSize, tailLen)

		part, ok := n.emitFragPart(targetPeer, hdr[:], chunk)
		if !ok {
			releaseFragmentBuffers(out)
			return nil, false
		}
		out = append(out, part)
	}
	return out, true
}

// fecParityFor returns how many parity shards to add for dataParts data shards:
// ceil(fecParityPercent%) of them, at least one (a group with no parity could not
// recover anything) and at most the field's remaining capacity.
func fecParityFor(dataParts int) int {
	if dataParts < 2 {
		return 0
	}
	r := (dataParts*fecParityPercent + 99) / 100
	if r < 1 {
		r = 1
	}
	if dataParts+r > fec.MaxShards {
		r = fec.MaxShards - dataParts
	}
	return r
}

// releaseFragmentBuffers returns buffers owned by encryptAndFragment or the
// fragmented TX path. Callers must check the returned pooled-ownership flag.
func releaseFragmentBuffers(frags [][]byte) {
	for _, f := range frags {
		releaseFrameBuf(f)
	}
}

// appendFragHeader appends a fragmentation header (without the magic check on
// read) to dst and returns it.
func appendFragHeader(dst []byte, origSeq uint32, fragIndex, fragTotal uint16, chunk []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, fragMagic)
	dst = binary.BigEndian.AppendUint32(dst, origSeq)
	dst = binary.BigEndian.AppendUint16(dst, fragIndex)
	dst = binary.BigEndian.AppendUint16(dst, fragTotal)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(chunk)))
	dst = append(dst, chunk...)
	return dst
}

// isFragPayload reports whether an already-deobfuscated outer payload is a
// fragmentation envelope (plain or parity-carrying).
func isFragPayload(payload []byte) bool {
	if len(payload) < fragHeaderLen {
		return false
	}
	switch binary.BigEndian.Uint16(payload[0:2]) {
	case fragMagic:
		return true
	case fragMagicFEC:
		return len(payload) >= fragHeaderLenFEC
	}
	return false
}

// fragHeader is one parsed fragment envelope, covering both wire formats.
type fragHeader struct {
	fec       bool
	index     int
	total     int
	dataParts int // == total for plain groups
	chunkSize int // FEC only: shard length of every shard but the last data one
	tailLen   int // FEC only: real length of the LAST data shard
	origLen   int // FEC only, derived: (dataParts-1)*chunkSize + tailLen
	chunk     []byte
}

// parseFragHeader parses and validates a fragment envelope. Everything is
// checked BEFORE the caller allocates or opens a group, so a malformed or
// hostile header cannot claim memory or consume group slots.
func parseFragHeader(payload []byte) (fragHeader, bool) {
	var h fragHeader
	if len(payload) < fragHeaderLen {
		return h, false
	}
	h.total = int(binary.BigEndian.Uint16(payload[8:10]))
	h.index = int(binary.BigEndian.Uint16(payload[6:8]))
	if h.total == 0 || h.total > maxFragTotal || h.index >= h.total {
		return h, false
	}
	switch binary.BigEndian.Uint16(payload[0:2]) {
	case fragMagic:
		h.dataParts = h.total
		h.chunk = payload[fragHeaderLen:]
		chunkLen := int(binary.BigEndian.Uint16(payload[10:12]))
		if chunkLen != len(h.chunk) || len(h.chunk) == 0 || len(h.chunk) > maxReasmBytes {
			return h, false
		}
		return h, true
	case fragMagicFEC:
		if len(payload) < fragHeaderLenFEC {
			return h, false
		}
		h.fec = true
		h.dataParts = int(binary.BigEndian.Uint16(payload[10:12]))
		chunkLen := int(binary.BigEndian.Uint16(payload[12:14]))
		h.chunkSize = int(binary.BigEndian.Uint16(payload[14:16]))
		h.tailLen = int(binary.BigEndian.Uint16(payload[16:18]))
		h.chunk = payload[fragHeaderLenFEC:]
		if h.dataParts < 2 || h.dataParts >= h.total ||
			h.chunkSize <= 0 || h.chunkSize > maxReasmBytes ||
			h.tailLen <= 0 || h.tailLen > h.chunkSize ||
			chunkLen != len(h.chunk) || len(h.chunk) == 0 || len(h.chunk) > maxReasmBytes {
			return h, false
		}
		h.origLen = (h.dataParts-1)*h.chunkSize + h.tailLen
		if h.origLen > maxReasmBytes {
			return h, false
		}
		// Every shard is exactly chunkSize long except the LAST data shard,
		// which is tailLen. Enforcing the layout from the header keeps the
		// codec's equal-length contract without trusting the sender.
		want := h.chunkSize
		if h.index == h.dataParts-1 {
			want = h.tailLen
		}
		if chunkLen != want {
			return h, false
		}
		return h, true
	}
	return h, false
}

// reassemble processes one fragment (the deobfuscated outer payload).
// Keyed by peer, epoch and channel to isolate origSeq reuse across sessions.
//
//   - If the payload is NOT a fragment envelope: returns (nil, true) so the
//     caller treats payload as the finished TAP frame directly.
//   - If it IS a fragment envelope:
//   - if more fragments are pending -> returns (nil, false)
//   - if the group is now complete -> returns (reassembledPacked, true),
//     where reassembledPacked is the ORIGINAL obfuscated frame; the caller
//     deobfuscates it (a second Unpack) to obtain the TAP frame.
//
// For a parity-carrying (striped) group the frame is also emitted as soon as
// dataParts shards are present, reconstructing the missing ones instead of
// waiting for a path that is never going to deliver.
func (f *fragReassembler) reassemble(remotePeer peer.ID, payload []byte, channel uint8, epoch uint64) (finalPacked []byte, complete bool) {
	if !isFragPayload(payload) {
		// Not a fragment: the caller already has the finished TAP frame.
		return nil, true
	}
	h, ok := parseFragHeader(payload)
	if !ok {
		return nil, false
	}
	origSeq := binary.BigEndian.Uint32(payload[2:6])
	if h.total == 1 {
		// Copy chunk — it is a sub-slice of the caller's pooled payload buffer.
		// Returning the sub-slice directly lets the pooled buffer be recycled
		// while the caller still holds the reference, causing
		// "crypto/cipher: invalid buffer overlap" panics during AEAD open.
		return append([]byte(nil), h.chunk...), true
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	key := reasmKey{peerID: remotePeer, origSeq: origSeq, channel: channel, epoch: epoch}
	rb, ok := f.bufs[key]
	if ok && rb.deadline.Before(time.Now()) {
		// The group timed out but the sender retransmitted it under the same
		// origSeq: sendRedundant and retryWithFreshStream re-emit the identical
		// fragment set, and the send-side write deadline is DYNAMIC — 600 ms
		// cold-start up to a 2500 ms window (writeDeadlineFor), so its upper
		// bound outlives reasmTimeout. Release the stale group BEFORE
		// reusing the key — overwriting it without decrementing leaks one quota
		// slot per reuse, and once maxReasmGroupsPerPeer slots are leaked the
		// guard below trips for good, dropping every fragment from this peer
		// until a restart.
		f.dropGroupLocked(key)
		ok = false
	}
	if !ok {
		// Bound concurrent groups: evict the oldest group first so memory stays
		// capped even between reaper ticks, and so a peer that has filled its
		// quota can still make room by retiring its own expired group.
		if len(f.bufs) >= maxReasmGroups {
			f.evictOldestGroup()
		}
		// Per-peer quota: reject if this peer still has too many concurrent
		// groups. Checked after the evict so the cap is a real ceiling rather
		// than a spurious drop caused by the global limit.
		if f.perPeerGroups[remotePeer] >= maxReasmGroupsPerPeer {
			log.Debug("Rx: peer %s exceeded per-peer fragment group limit (%d); dropping",
				remotePeer.ShortString(), maxReasmGroupsPerPeer)
			return nil, false
		}
		// Exact ceiling for this group's stored shard bytes. Plain groups are
		// capped at one obfuscated TAP frame; a striped group additionally stores
		// its parity shards, so the cap is derived from its own layout instead of
		// a single global number.
		groupCap := maxReasmBytes
		if h.fec {
			groupCap = h.origLen + (h.total-h.dataParts)*h.chunkSize
		}
		rb = &reasmBuf{
			total:     h.total,
			parts:     make([][]byte, h.total),
			deadline:  time.Now().Add(reasmTimeout),
			fec:       h.fec,
			dataParts: h.dataParts,
			origLen:   h.origLen,
			chunkSize: h.chunkSize,
			tailLen:   h.tailLen,
			cap:       groupCap,
		}
		f.bufs[key] = rb
		f.perPeerGroups[remotePeer]++
	}
	// A retransmitted group must agree on its shape; a conflicting header means
	// a different frame reusing the same origSeq, so keep the existing group.
	if rb.total != h.total || rb.fec != h.fec || rb.dataParts != h.dataParts ||
		rb.origLen != h.origLen || rb.chunkSize != h.chunkSize || rb.tailLen != h.tailLen {
		return nil, false
	}
	if h.index < rb.total && rb.parts[h.index] == nil {
		// Cap the reassembled frame at one obfuscated TAP frame (plus the
		// parity overhead the FEC variant legitimately adds). A group that
		// would exceed this is corrupt or hostile; abort it rather than buffer
		// unbounded bytes.
		if rb.size+len(h.chunk) > rb.cap {
			log.Debug("Rx: fragment group from %s origSeq=%d exceeded max reassembly bytes; aborting", remotePeer.String(), origSeq)
			f.dropGroupLocked(key)
			return nil, false
		}
		chunkCopy := make([]byte, len(h.chunk))
		copy(chunkCopy, h.chunk)
		rb.size += len(chunkCopy)
		rb.parts[h.index] = chunkCopy
		rb.got++
	}
	if rb.got < rb.total {
		// A striped group is recoverable as soon as dataParts shards are here:
		// the missing ones are rebuilt instead of waiting for a path that died.
		if !rb.fec || rb.got < rb.dataParts {
			return nil, false
		}
	}
	out, ok := f.assembleLocked(rb)
	f.dropGroupLocked(key)
	if !ok {
		return nil, false
	}
	return out, true
}

// assembleLocked turns a complete (or FEC-recoverable) group into the original
// obfuscated frame. Caller MUST hold f.mu. Returns false when a striped group is
// irrecoverably damaged.
func (f *fragReassembler) assembleLocked(rb *reasmBuf) ([]byte, bool) {
	if rb.fec && rb.got < rb.total {
		shards := make([][]byte, rb.total)
		for i, p := range rb.parts {
			if p == nil {
				continue
			}
			if len(p) == rb.chunkSize {
				shards[i] = p
				continue
			}
			// The codec needs equal-length shards; only the last data shard can
			// arrive short (zero padding never travels on the wire).
			padded := make([]byte, rb.chunkSize)
			copy(padded, p)
			shards[i] = padded
		}
		if err := fec.Reconstruct(shards, rb.dataParts, rb.total-rb.dataParts); err != nil {
			log.Debug("Rx: FEC reconstruction failed (%v); dropping group", err)
			return nil, false
		}
		out := make([]byte, 0, rb.origLen)
		for i := 0; i < rb.dataParts; i++ {
			sh := shards[i]
			want := rb.chunkSize
			if i == rb.dataParts-1 {
				want = rb.tailLen
			}
			if len(sh) > want {
				sh = sh[:want]
			}
			out = append(out, sh...)
		}
		return out, true
	}

	// Every part arrived: concatenate the DATA shards in index order. For a
	// plain group dataParts == total, so parity can never leak into the frame.
	if rb.got < rb.total {
		return nil, false
	}
	size := 0
	for i := 0; i < rb.dataParts; i++ {
		size += len(rb.parts[i])
	}
	out := make([]byte, 0, size)
	for i := 0; i < rb.dataParts; i++ {
		out = append(out, rb.parts[i]...)
	}
	return out, true
}

// dropGroupLocked retires a group and releases its per-peer quota slot. Caller
// MUST hold f.mu. Missing keys are ignored.
func (f *fragReassembler) dropGroupLocked(key reasmKey) {
	if _, ok := f.bufs[key]; !ok {
		return
	}
	delete(f.bufs, key)
	f.perPeerGroups[key.peerID]--
	if f.perPeerGroups[key.peerID] <= 0 {
		delete(f.perPeerGroups, key.peerID)
	}
}

// evictOldestGroup drops the in-flight reassembly group with the earliest
// deadline. Called by reassemble when at the concurrent-group cap so memory
// stays bounded even between reaper ticks. Caller MUST hold f.mu.
func (f *fragReassembler) evictOldestGroup() {
	var oldestKey reasmKey
	var oldest time.Time
	first := true
	for k, rb := range f.bufs {
		if first || rb.deadline.Before(oldest) {
			oldest = rb.deadline
			oldestKey = k
			first = false
		}
	}
	if !first {
		delete(f.bufs, oldestKey)
		f.perPeerGroups[oldestKey.peerID]--
		if f.perPeerGroups[oldestKey.peerID] == 0 {
			delete(f.perPeerGroups, oldestKey.peerID)
		}
	}
}

// reap expires reassembly buffers to bound memory.
func (f *fragReassembler) reap() {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	for k, rb := range f.bufs {
		if rb.deadline.Before(now) {
			delete(f.bufs, k)
			f.perPeerGroups[k.peerID]--
			if f.perPeerGroups[k.peerID] == 0 {
				delete(f.perPeerGroups, k.peerID)
			}
		}
	}
}

// maxFragPayload returns the largest inner obfuscated-frame chunk size before
// fragmentation.  When Config.Obfuscation.MaxFragSize > 0 it is used directly
// (clamped to a sane range); otherwise it is derived from the tunnel MTU and
// obfuscation overhead so that each re-obfuscated fragment fits comfortably
// under the QUIC path MTU (~1250 bytes) without IP fragmentation.
func (n *Node) maxFragPayload() int {
	c := n.config()
	if c != nil && c.Obfuscation.MaxFragSize > 0 {
		v := c.Obfuscation.MaxFragSize
		if v < 256 {
			v = 256
		}
		if v > 1400 {
			v = 1400
		}
		// An explicit MaxFragSize above the datagram budget is an escape hatch:
		// it deliberately opts into transport fragmentation. Left untouched.
		return v
	}
	mtu := 1500
	if c != nil {
		mtu = c.MTU
	}
	if mtu <= 0 {
		mtu = 1500
	}
	// Each re-obfuscated fragment becomes one obfuscate frame: obfuscate header
	// + frag header + chunk, carried in a single transport datagram. The budget
	// below is the payload allowance, so it already accounts for the frame
	// header, the AEAD tag and the outer IP/UDP/QUIC headers.
	payload := obfuscate.MaxPayloadForPathMTU(mtu)
	if payload <= 0 {
		payload = 1500 - obfuscate.HeaderLen
	}
	p := payload - fragHeaderLen
	if p < 256 {
		p = 256
	}
	return p
}

// All registered libp2p data transports expose reliable byte streams. Their
// underlying datagram MTU does not constrain WriteFrame payloads.
const maxFragPayloadStream = 65400

// Explicit configuration applies to every transport. Without registered
// streams retain the conservative overlay fragment policy.
func (n *Node) maxFragPayloadForPS(ps *PeerStreams) int {
	if c := n.config(); c != nil && c.Obfuscation.MaxFragSize > 0 {
		return n.maxFragPayload()
	}
	if ps != nil && len(ps.GetAllStreams()) > 0 {
		return maxFragPayloadStream
	}
	return n.maxFragPayload()
}
