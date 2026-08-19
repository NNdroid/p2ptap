package node

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/obfuscate"
)

// Tunnel-level fragmentation for TAP frames.
//
// A single TAP Ethernet frame (up to ~1514 bytes) obfuscated via
// obfuscate.Pack can exceed the QUIC path MTU (~1250 bytes), forcing IP
// fragmentation / loss of the underlying UDP datagram and triggering TCP
// retransmits + congestion control on the carried L4 stream.  To avoid that,
// frames larger than MaxFragPayload are split into independent fragments,
// each fragment re-obfuscated and sent as its own WriteFrame.  The receiver
// reassembles fragments (keyed by the original frame's sequence) before
// deobfuscating the inner TAP frame.
//
// Layout of a fragment payload (carried inside the OUTER obfuscate.Pack):
//
//	[FragMagic(2) | OrigSeq(4) | FragIndex(2) | FragTotal(2) | ChunkLen(2) | chunk...]
//
// A non-fragmented frame carries NO frag header and is passed through
// untouched (zero overhead on the common small-packet path).

const (
	fragMagic     uint16 = 0xF5A1
	fragHeaderLen        = 12 // 2+4+2+2+2
	reasmTimeout         = 2 * time.Second

	// Reassembly hardening. The FragTotal and OrigSeq fields travel in
	// cleartext frag headers, so a peer (or anyone who can inject a frame into
	// the overlay) controls them. Without caps, a single group can force a
	// 65535-slot parts slice and an unbounded number of concurrent groups can
	// be opened, exhausting memory before the 2s reaper reclaims them.
	//
	// A real TAP frame (≤ obfuscate.MaxFrameSize) split into ≥512-byte chunks
	// yields at most ~128 parts, so 256 leaves generous margin. The per-group
	// reassembled size is itself capped at one obfuscated frame (MaxFrameSize),
	// and at most maxReasmGroups groups may be in flight at once.
	maxFragTotal   = 256
	maxReasmGroups = 1024
	maxReasmBytes  = obfuscate.MaxFrameSize
)

type reasmKey struct {
	peerID  peer.ID
	origSeq uint32
}

// fragReassembler buffers incoming fragments and emits complete obfuscated
// frames once every fragment of a group has arrived.
type fragReassembler struct {
	mu     sync.Mutex
	bufs   map[reasmKey]*reasmBuf
	seqGen uint32
}

type reasmBuf struct {
	total    int
	parts    [][]byte
	got      int
	size     int // running total of stored chunk bytes (caps memory)
	deadline time.Time
}

func newFragReassembler() *fragReassembler {
	return &fragReassembler{bufs: make(map[reasmKey]*reasmBuf)}
}

// nextOrigSeq allocates a monotonically increasing sequence for a new frame
// being fragmented on the TX side.
func (f *fragReassembler) nextOrigSeq() uint32 {
	f.mu.Lock()
	f.seqGen++
	seq := f.seqGen
	f.mu.Unlock()
	return seq
}

// fragmentFrame splits an already-obfuscated frame (the output of
// obfuscate.Pack) into N independently re-obfuscated WriteFrame payloads.
// Frames that already fit under maxPayload are returned untouched (true
// zero-overhead common path): the receiver detects the absence of a frag
// header and passes them through.
//
// When maxPayload > 0 it is used as the fragment size limit (allows callers
// to specify a larger limit for TCP/yamux streams). Otherwise the node-default
// (derived from Config.MTU / QUIC path-MTU) is used.
func (n *Node) fragmentFrame(packed []byte, frag *fragReassembler, txEpoch uint64, maxPayload int) [][]byte {
	if maxPayload <= 0 {
		maxPayload = n.maxFragPayload()
	}
	if len(packed) <= maxPayload {
		// Common case: no fragmentation needed. Send the frame as-is; the
		// receiver's tryReassemble sees no frag magic and passes it through.
		return [][]byte{packed}
	}
	if frag == nil {
		// Fragmentation state is required to allocate the original-frame sequence
		// that ties the fragments together. Without it we cannot fragment, so send
		// the frame whole rather than dereferencing a nil pointer and killing the
		// send goroutine.
		log.Warn("Frame of %d bytes exceeds the %d-byte fragment payload but fragmentation is disabled; sending unfragmented",
			len(packed), maxPayload)
		return [][]byte{packed}
	}

	seq := frag.nextOrigSeq()
	total := (len(packed) + maxPayload - 1) / maxPayload
	out := make([][]byte, 0, total)
	for i := 0; i < total; i++ {
		start := i * maxPayload
		end := start + maxPayload
		if end > len(packed) {
			end = len(packed)
		}
		chunk := packed[start:end]
		hdr := make([]byte, 0, len(chunk)+fragHeaderLen)
		hdr = appendFragHeader(hdr, seq, uint16(i), uint16(total), chunk)
		outBuf := make([]byte, n.Packer.MaxPackedLen(len(hdr)))
		// A FRESH seqID per fragment envelope. The AEAD nonce is derived from the
		// frame header (magic + seqID + obfType + paddingLen-high), so the previous
		// hard-coded 0 gave EVERY fragment envelope — across every message ever sent
		// to that peer — the SAME nonce under the SAME key. For ChaCha20-Poly1305 and
		// AES-GCM that is catastrophic nonce reuse: it leaks the XOR of the
		// plaintexts and enables authenticator forgery. Uniqueness is safe here
		// because the outer seqID is never used for dedup — the RX path dedups on
		// the reassembled INNER frame's seqID (see handleStream).
		n2, perr := n.Packer.Pack(n.Packer.NextSeqID(txEpoch), hdr, outBuf)
		if perr != nil {
			// Fallback: send the chunk without re-obfuscation wrapper so the
			// frame is not lost (it will simply not be obfuscated per-fragment).
			out = append(out, hdr)
			continue
		}
		out = append(out, outBuf[:n2])
	}
	return out
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
// fragmentation envelope (i.e. its first two bytes are fragMagic).
func isFragPayload(payload []byte) bool {
	return len(payload) >= fragHeaderLen && binary.BigEndian.Uint16(payload[0:2]) == fragMagic
}

// reassemble processes one fragment (the deobfuscated outer payload).
// Keyed per remotePeer to prevent cross-peer origSeq collision.
//
//   - If the payload is NOT a fragment envelope: returns (nil, true) so the
//     caller treats payload as the finished TAP frame directly.
//   - If it IS a fragment envelope:
//   - if more fragments are pending -> returns (nil, false)
//   - if the group is now complete -> returns (reassembledPacked, true),
//     where reassembledPacked is the ORIGINAL obfuscated frame; the caller
//     deobfuscates it (a second Unpack) to obtain the TAP frame.
func (f *fragReassembler) reassemble(remotePeer peer.ID, payload []byte) (finalPacked []byte, complete bool) {
	if !isFragPayload(payload) {
		// Not a fragment: the caller already has the finished TAP frame.
		return nil, true
	}

	origSeq := binary.BigEndian.Uint32(payload[2:6])
	fragIndex := binary.BigEndian.Uint16(payload[6:8])
	fragTotal := binary.BigEndian.Uint16(payload[8:10])
	chunk := payload[fragHeaderLen:]

	f.mu.Lock()
	defer f.mu.Unlock()

	if fragTotal <= 1 {
		// Single-fragment envelope: the chunk after the header IS the
		// original obfuscated frame.
		return chunk, true
	}
	if fragTotal > maxFragTotal {
		// Attacker-controlled part count; refuse to allocate a giant parts
		// slice. Legitimate frames never exceed maxFragTotal.
		log.Debug("Rx: dropping fragment group from %s origSeq=%d with excessive fragTotal=%d (>%d)",
			remotePeer.String(), origSeq, fragTotal, maxFragTotal)
		return nil, false
	}

	key := reasmKey{peerID: remotePeer, origSeq: origSeq}
	rb, ok := f.bufs[key]
	if !ok || rb.deadline.Before(time.Now()) {
		// Bound concurrent groups: if we are at capacity, evict the oldest
		// group before opening a new one so memory stays capped even between
		// reaper ticks.
		if !ok && len(f.bufs) >= maxReasmGroups {
			f.evictOldestGroup()
		}
		rb = &reasmBuf{
			total:    int(fragTotal),
			parts:    make([][]byte, fragTotal),
			got:      0,
			size:     0,
			deadline: time.Now().Add(reasmTimeout),
		}
		f.bufs[key] = rb
	}
	if int(fragIndex) < rb.total && rb.parts[fragIndex] == nil {
		chunkCopy := make([]byte, len(chunk))
		copy(chunkCopy, chunk)
		// Cap the reassembled frame at one obfuscated TAP frame. A group that
		// would exceed this is corrupt or hostile; abort it rather than buffer
		// unbounded bytes.
		if rb.size+len(chunkCopy) > maxReasmBytes {
			log.Debug("Rx: fragment group from %s origSeq=%d exceeded max reassembly bytes; aborting", remotePeer.String(), origSeq)
			delete(f.bufs, key)
			return nil, false
		}
		rb.size += len(chunkCopy)
		rb.parts[fragIndex] = chunkCopy
		rb.got++
	}
	if rb.got < rb.total {
		return nil, false
	}

	// Reassemble.
	var size int
	for _, p := range rb.parts {
		size += len(p)
	}
	reassembled := make([]byte, 0, size)
	for _, p := range rb.parts {
		reassembled = append(reassembled, p...)
	}
	delete(f.bufs, key)
	return reassembled, true
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
		return v
	}
	mtu := c.MTU
	if mtu <= 0 {
		mtu = 1500
	}
	pathMTU := 1200
	if mtu > pathMTU {
		mtu = pathMTU
	}
	// overhead: QUIC/IP/UDP headroom(~40) + obfuscate header(14) + AEAD(16)
	// + frag header(12)
	overhead := 40 + 14 + 16 + fragHeaderLen
	p := mtu - overhead
	if p < 512 {
		p = 512
	}
	return p
}

// maxFragPayloadTCP is the fragment-payload threshold used when the underlying
// transport is a reliable byte-stream (TCP + yamux). TCP has no datagram MTU
// constraint, so we use a large value to avoid pointless fragmentation and the
// associated double-AEAD overhead. Capped at 65400 bytes: well below the 1 MiB
// maxFrameLen limit but large enough that virtually no standard Ethernet frame
// (~1514 bytes) ever triggers fragmentation on a TCP link.
const maxFragPayloadTCP = 65400

// maxFragPayloadForPS returns the per-peer fragment-payload threshold appropriate
// for the active streams in ps. For purely TCP links the threshold is
// maxFragPayloadTCP (no UDP path-MTU constraint). For QUIC, WebRTC, or mixed
// transports the standard QUIC-safe limit is used. When ps is nil, falls back
// to the standard limit.
func (n *Node) maxFragPayloadForPS(ps *PeerStreams) int {
	if ps != nil && ps.prefersTCPFragPayload() {
		return maxFragPayloadTCP
	}
	return n.maxFragPayload()
}
