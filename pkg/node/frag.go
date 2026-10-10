package node

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
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
	// A full sealed frame split at the minimum configured 256-byte limit needs
	// 257 parts. Include the AEAD tag in the byte cap, and allow that exact
	// part count. At most maxReasmGroups groups may be in flight at once.
	maxFragTotal   = (obfuscate.MaxSealedFrameSize + 255) / 256
	maxReasmGroups = 1024
	maxReasmBytes  = obfuscate.MaxSealedFrameSize
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
}

func newFragReassembler() *fragReassembler {
	return &fragReassembler{bufs: make(map[reasmKey]*reasmBuf)}
}

// nextOrigSeq allocates a monotonically increasing sequence for a new frame
// being fragmented on the TX side. It intentionally does not take the RX
// reassembly mutex: TX sequence allocation and RX fragment bookkeeping are
// independent and must not serialize each other under full-duplex traffic.
func (f *fragReassembler) nextOrigSeq() uint32 {
	return f.seqGen.Add(1)
}

// fragmentFrame splits an already-obfuscated frame (the output of
// obfuscate.Pack) into N independently re-obfuscated WriteFrame payloads.
// Frames that already fit under maxPayload are returned untouched (true
// zero-overhead common path): the receiver detects the absence of a frag
// header and passes them through.
//
// When maxPayload > 0 it is used as the fragment size limit (allows callers
// to specify a larger limit for reliable streams). Otherwise the conservative
// node-default is used.
func (n *Node) fragmentFrame(packed []byte, frag *fragReassembler, txEpoch uint64, maxPayload int) ([][]byte, bool) {
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
	for i := 0; i < total; i++ {
		start := i * maxPayload
		end := start + maxPayload
		if end > len(packed) {
			end = len(packed)
		}
		chunk := packed[start:end]
		payloadLen := fragHeaderLen + len(chunk)

		// Build the fragmentation payload directly in the final Pack buffer.
		// Pack writes only outBuf[:HeaderLen] before copying payload into
		// outBuf[HeaderLen:], so using that exact destination as the source turns
		// the payload copy into a no-op and removes the old hdr allocation.
		outBuf := acquireFrameBuf(n.Packer.MaxPackedLen(payloadLen))
		fragPayload := outBuf[obfuscate.HeaderLen : obfuscate.HeaderLen+payloadLen]
		binary.BigEndian.PutUint16(fragPayload[0:2], fragMagic)
		binary.BigEndian.PutUint32(fragPayload[2:6], seq)
		binary.BigEndian.PutUint16(fragPayload[6:8], uint16(i))
		binary.BigEndian.PutUint16(fragPayload[8:10], uint16(total))
		binary.BigEndian.PutUint16(fragPayload[10:12], uint16(len(chunk)))
		copy(fragPayload[fragHeaderLen:], chunk)

		n2, perr := n.Packer.Pack(n.Packer.NextSeqID(txEpoch), fragPayload, outBuf)
		if perr != nil {
			// Pack failure means this fragment cannot be obfuscated. Emitting a
			// bare (unobfuscated) fragment envelope — the old "historical
			// fallback" — was a security bug: the fragment headers and TAP
			// payload travel in cleartext on the wire, and the receiver's
			// outer unpack rejects the bare envelope as garbage, polluting
			// its decrypt-failure window and potentially triggering spurious
			// key resyncs. Drop the whole group instead: silently losing a
			// frame is safer than leaking plaintext or poisoning rekey state.
			// Pack failure is effectively a can't-happen programming error
			// (MaxPackedLen under-sized), so surface it loudly.
			log.Error("Fragment Pack failed for part %d/%d of %d-byte frame from txEpoch=%d: %v — dropping entire group",
				i+1, total, len(packed), txEpoch, perr)
			releaseFrameBuf(outBuf)
			releaseFragmentBuffers(out)
			return nil, false
		}
		out = append(out, outBuf[:n2])
	}
	return out, true
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
// fragmentation envelope (i.e. its first two bytes are fragMagic).
func isFragPayload(payload []byte) bool {
	return len(payload) >= fragHeaderLen && binary.BigEndian.Uint16(payload[0:2]) == fragMagic
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
func (f *fragReassembler) reassemble(remotePeer peer.ID, payload []byte, channel uint8, epoch uint64) (finalPacked []byte, complete bool) {
	if !isFragPayload(payload) {
		// Not a fragment: the caller already has the finished TAP frame.
		return nil, true
	}

	origSeq := binary.BigEndian.Uint32(payload[2:6])
	fragIndex := binary.BigEndian.Uint16(payload[6:8])
	fragTotal := binary.BigEndian.Uint16(payload[8:10])
	chunk := payload[fragHeaderLen:]
	chunkLen := int(binary.BigEndian.Uint16(payload[10:12]))
	// Validate before allocating or looking up a group. Invalid envelopes must
	// not consume group slots or bypass bounds through the single-part path.
	if fragTotal == 0 || fragTotal > maxFragTotal || fragIndex >= fragTotal ||
		chunkLen != len(chunk) || len(chunk) == 0 || len(chunk) > maxReasmBytes {
		return nil, false
	}
	if fragTotal == 1 {
		return chunk, true
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	key := reasmKey{peerID: remotePeer, origSeq: origSeq, channel: channel, epoch: epoch}
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
	if rb.total != int(fragTotal) {
		return nil, false // preserve the existing valid group
	}
	if int(fragIndex) < rb.total && rb.parts[fragIndex] == nil {
		// Cap the reassembled frame at one obfuscated TAP frame. A group that
		// would exceed this is corrupt or hostile; abort it rather than buffer
		// unbounded bytes.
		if rb.size+len(chunk) > maxReasmBytes {
			log.Debug("Rx: fragment group from %s origSeq=%d exceeded max reassembly bytes; aborting", remotePeer.String(), origSeq)
			delete(f.bufs, key)
			return nil, false
		}
		chunkCopy := make([]byte, len(chunk))
		copy(chunkCopy, chunk)
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
	mtu := 1500
	if c != nil {
		mtu = c.MTU
	}
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
