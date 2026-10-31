package node

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/config"
	"p2ptap/pkg/obfuscate"
)

// unpackFragPayload strips the outer obfuscate frame so the reassembler sees the
// same payload it would receive off the wire.
func unpackFragPayload(t *testing.T, outer []byte) []byte {
	t.Helper()
	_, payload, err := obfuscate.Unpack(outer)
	if err != nil {
		t.Fatalf("Unpack fragment: %v", err)
	}
	return payload
}

// feedShards pushes the selected fragment envelopes into a fresh reassembler and
// reports whether the frame completed.
func feedShards(t *testing.T, rx *fragReassembler, remote peer.ID, frags [][]byte, skip map[int]bool) ([]byte, bool) {
	t.Helper()
	for i, outer := range frags {
		if skip[i] {
			continue
		}
		final, complete := rx.reassemble(remote, unpackFragPayload(t, outer), reasmChannelDirect, 0)
		if complete && final != nil {
			return final, true
		}
	}
	return nil, false
}

// TestFragStripeRebuildsFromAnyDataParts is the end-to-end guard for the
// multi-path FEC layer: a large frame is sharded with parity, and losing any ONE
// shard (the case where a whole path dies mid-frame) must still reconstruct it
// byte for byte, without waiting for a retransmit.
func TestFragStripeRebuildsFromAnyDataParts(t *testing.T) {
	packer := obfuscate.NewFramePackerFull(nil)
	n := &Node{Packer: packer}
	original := makePackedFragmentTestFrame(t, packer, 60000)

	tx := newFragReassembler()
	frags, pooled := n.fragmentFrameForPaths(original, tx, fragTestPeer, maxFragPayloadStream, 2)
	if !pooled {
		t.Fatal("striped frame did not report pooled ownership")
	}
	defer releaseFragmentBuffers(frags)

	// 60000 / 16384 -> 4 data shards + 1 parity shard.
	if len(frags) != 5 {
		t.Fatalf("shard count = %d, want 5 (4 data + 1 parity)", len(frags))
	}
	first := unpackFragPayload(t, frags[0])
	if binary.BigEndian.Uint16(first[0:2]) != fragMagicFEC {
		t.Fatalf("striped shard magic = %#x, want %#x", binary.BigEndian.Uint16(first[0:2]), fragMagicFEC)
	}
	if dp := binary.BigEndian.Uint16(first[10:12]); dp != 4 {
		t.Fatalf("dataParts = %d, want 4", dp)
	}
	if total := binary.BigEndian.Uint16(first[8:10]); total != 5 {
		t.Fatalf("fragTotal = %d, want 5", total)
	}

	remote := peer.ID("stripe-fec-peer")
	// Every single-shard loss is recoverable...
	for lost := 0; lost < len(frags); lost++ {
		rx := newFragReassembler()
		got, ok := feedShards(t, rx, remote, frags, map[int]bool{lost: true})
		if !ok {
			t.Fatalf("losing shard %d did not complete the frame", lost)
		}
		if !bytes.Equal(got, original) {
			t.Fatalf("losing shard %d: reconstructed frame mismatch (%d vs %d bytes)", lost, len(got), len(original))
		}
	}

	// ...and with only one parity shard, losing two is genuinely unrecoverable.
	rx := newFragReassembler()
	if _, ok := feedShards(t, rx, remote, frags, map[int]bool{0: true, 1: true}); ok {
		t.Fatal("two lost shards must not report completion with a single parity shard")
	}
}

// TestFragStripeWithoutLossIsByteExact covers the ordinary delivery: all shards
// arrive and the reassembled frame must be identical (no padding bytes leaking
// into the inner AEAD open).
func TestFragStripeWithoutLossIsByteExact(t *testing.T) {
	packer := obfuscate.NewFramePackerFull(nil)
	n := &Node{Packer: packer}
	// Not a multiple of the 16 KiB shard size, so the last data shard is short.
	original := makePackedFragmentTestFrame(t, packer, 40000)

	tx := newFragReassembler()
	frags, pooled := n.fragmentFrameForPaths(original, tx, fragTestPeer, maxFragPayloadStream, 2)
	if !pooled {
		t.Fatal("striped frame did not report pooled ownership")
	}
	defer releaseFragmentBuffers(frags)

	got, ok := feedShards(t, newFragReassembler(), peer.ID("stripe-exact"), frags, nil)
	if !ok {
		t.Fatal("complete shard set did not reassemble")
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("reassembled frame mismatch: got %d bytes, want %d", len(got), len(original))
	}
}

// TestFragStripeNeedsTwoPaths pins the policy: a peer with a single path never
// pays for sharding or parity, so ordinary single-link tunnels keep the exact
// wire format they had before.
func TestFragStripeNeedsTwoPaths(t *testing.T) {
	packer := obfuscate.NewFramePackerFull(nil)
	n := &Node{Packer: packer}
	original := makePackedFragmentTestFrame(t, packer, 40000)

	tx := newFragReassembler()
	frags, pooled := n.fragmentFrameForPaths(original, tx, fragTestPeer, maxFragPayloadStream, 1)
	if pooled {
		defer releaseFragmentBuffers(frags)
	}
	if len(frags) != 1 {
		t.Fatalf("single-path frame was split into %d parts, want 1", len(frags))
	}
	if !bytes.Equal(frags[0], original) {
		t.Fatal("single-path frame was rewritten instead of passed through")
	}
}

// TestFragStripeRejectsCorruptChunkLen proves the extended header is validated:
// a shard whose chunk length does not match the layout derived from origLen is
// dropped instead of being fed into the codec.
func TestFragStripeRejectsCorruptChunkLen(t *testing.T) {
	packer := obfuscate.NewFramePackerFull(nil)
	n := &Node{Packer: packer}
	original := makePackedFragmentTestFrame(t, packer, 60000)

	tx := newFragReassembler()
	frags, pooled := n.fragmentFrameForPaths(original, tx, fragTestPeer, maxFragPayloadStream, 2)
	if !pooled {
		t.Fatal("striped frame did not report pooled ownership")
	}
	defer releaseFragmentBuffers(frags)

	bad := append([]byte(nil), unpackFragPayload(t, frags[0])...)
	// Shard 0 must be exactly chunkSize long; claim one byte less.
	binary.BigEndian.PutUint16(bad[12:14], uint16(binary.BigEndian.Uint16(bad[12:14])-1))

	rx := newFragReassembler()
	if final, complete := rx.reassemble(peer.ID("stripe-corrupt"), bad, reasmChannelDirect, 0); complete || final != nil {
		t.Fatal("corrupt shard length was accepted")
	}
	if len(rx.bufs) != 0 {
		t.Fatalf("a rejected shard must not open a group (have %d)", len(rx.bufs))
	}
}

// TestMultipathBatchStripesLargeFrameAcrossPaths is the end-to-end guard for
// the striping fix: a single large frame used to be written entirely to ONE path
// while the others idled. It must now be sharded across the paths (with parity)
// and still reassemble to the exact original bytes at the receiver.
func TestMultipathBatchStripesLargeFrameAcrossPaths(t *testing.T) {
	cfg := config.DefaultConfig()
	packer := obfuscate.NewFramePackerFull(nil)
	pid := peer.ID("mp-stripe-batch")
	ps := NewPeerStreams(pid)
	a := &pathTestStream{ma: mustMA("/ip4/192.168.1.5/tcp/4001")}
	b := &pathTestStream{ma: mustMA("/ip4/192.168.1.6/tcp/4001")}
	ps.AddStream("a", a)
	ps.AddStream("b", b)

	n := &Node{Config: cfg, Packer: packer, fragRX: newFragReassembler()}
	n.SetConfig(cfg)
	sd := NewStrategyDispatcher(nil, "multipath")
	sd.SetNode(n)

	original := makePackedFragmentTestFrame(t, packer, 60000)
	ps.writeMu.Lock()
	err := sd.writePackedBatchLocked(pid, ps, nil, [][]byte{original})
	ps.writeMu.Unlock()
	if err != nil {
		t.Fatalf("striped batch write failed: %v", err)
	}
	if a.buf.Len() == 0 || b.buf.Len() == 0 {
		t.Fatalf("large frame was not striped across both paths (a=%d bytes, b=%d bytes)",
			a.buf.Len(), b.buf.Len())
	}

	// Collect every wire frame from both paths and reassemble.
	rx := newFragReassembler()
	remote := peer.ID("mp-stripe-rx")
	var got []byte
	var complete bool
	for _, st := range []*pathTestStream{a, b} {
		raw := st.buf.Bytes()
		for off := 0; off+4 <= len(raw); {
			l := int(binary.BigEndian.Uint32(raw[off : off+4]))
			off += 4
			if off+l > len(raw) {
				t.Fatalf("truncated wire frame at offset %d", off)
			}
			payload := unpackFragPayload(t, raw[off:off+l])
			off += l
			final, done := rx.reassemble(remote, payload, reasmChannelDirect, 0)
			if done && final != nil {
				got, complete = final, true
			}
		}
	}
	if !complete {
		t.Fatal("striped shards did not reassemble into a frame")
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("reassembled frame mismatch: got %d bytes, want %d", len(got), len(original))
	}
}

// TestPlanFragsOnPathsSpreadsShards verifies the transmit side of striping: a
// multi-shard frame is handed to more than one path, and no shard is lost or
// duplicated on the way.
func TestPlanFragsOnPathsSpreadsShards(t *testing.T) {
	ps := NewPeerStreams(peer.ID("stripe-plan"))
	a := &pathTestStream{ma: mustMA("/ip4/192.168.1.5/tcp/4001")}
	b := &pathTestStream{ma: mustMA("/ip4/192.168.1.6/tcp/4001")}
	streams := []network.Stream{a, b}

	frags := make([][]byte, 8)
	for i := range frags {
		frags[i] = tapFrameBytes(byte(i))
	}
	plans := ps.planFragsOnPaths(streams, frags)
	if len(plans) != 2 {
		t.Fatalf("plan count = %d, want 2 (both paths carry shards)", len(plans))
	}
	seen := 0
	for _, p := range plans {
		if len(p.frags) == 0 {
			t.Fatal("a plan with no shards was created")
		}
		seen += len(p.frags)
	}
	if seen != len(frags) {
		t.Fatalf("planned %d shards, want %d", seen, len(frags))
	}
}

// TestPlanFragsOnPathsSingleFragmentStaysOnOnePath pins the common case: an
// ordinary frame is still written to exactly ONE path (the scheduler's pick), so
// per-fragment scheduling does not turn every packet into a cross-path split.
func TestPlanFragsOnPathsSingleFragmentStaysOnOnePath(t *testing.T) {
	ps := NewPeerStreams(peer.ID("stripe-plan-one"))
	a := &pathTestStream{ma: mustMA("/ip4/192.168.1.5/tcp/4001")}
	b := &pathTestStream{ma: mustMA("/ip4/192.168.1.6/tcp/4001")}

	plans := ps.planFragsOnPaths([]network.Stream{a, b}, [][]byte{tapFrameBytes(1)})
	if len(plans) != 1 {
		t.Fatalf("plan count = %d, want 1", len(plans))
	}
	if len(plans[0].frags) != 1 {
		t.Fatalf("plan carries %d shards, want 1", len(plans[0].frags))
	}
}
