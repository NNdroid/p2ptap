package node

import (
	"bytes"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/obfuscate"
)

func makePackedFragmentTestFrame(t testing.TB, packer *obfuscate.FramePacker, payloadLen int) []byte {
	t.Helper()
	payload := bytes.Repeat([]byte{0x5a}, payloadLen)
	buf := make([]byte, packer.MaxPackedLen(len(payload)))
	n, err := packer.Pack(packer.NextSeqID(1), payload, buf)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return buf[:n]
}

func TestFragmentFramePooledRoundTrip(t *testing.T) {
	packer := obfuscate.NewFramePackerFull(nil)
	n := &Node{Packer: packer}
	tx := newFragReassembler()
	original := makePackedFragmentTestFrame(t, packer, 1500)

	frags, pooled := n.fragmentFrame(original, tx, 1, 512)
	if !pooled {
		t.Fatal("fragmented frame did not report pooled ownership")
	}
	defer releaseFragmentBuffers(frags)
	if len(frags) < 2 {
		t.Fatalf("fragment count = %d, want >= 2", len(frags))
	}

	rx := newFragReassembler()
	remote := peer.ID("fragment-pool-peer")
	var reassembled []byte
	for i, outer := range frags {
		_, fragPayload, err := obfuscate.Unpack(outer)
		if err != nil {
			t.Fatalf("Unpack fragment %d: %v", i, err)
		}
		final, complete := rx.reassemble(remote, fragPayload, reasmChannelDirect)
		if complete && final != nil {
			reassembled = final
		}
	}
	if !bytes.Equal(reassembled, original) {
		t.Fatalf("reassembled frame mismatch: got %d bytes, want %d", len(reassembled), len(original))
	}
}

func TestFragmentFrameNonFragmentedRemainsCallerOwned(t *testing.T) {
	packer := obfuscate.NewFramePackerFull(nil)
	n := &Node{Packer: packer}
	original := makePackedFragmentTestFrame(t, packer, 128)
	frags, pooled := n.fragmentFrame(original, newFragReassembler(), 1, 512)
	if pooled {
		t.Fatal("non-fragmented frame must remain caller-owned")
	}
	if len(frags) != 1 || !bytes.Equal(frags[0], original) {
		t.Fatal("non-fragmented frame was changed")
	}
}

func BenchmarkFragmentFramePooled(b *testing.B) {
	packer := obfuscate.NewFramePackerFull(nil)
	n := &Node{Packer: packer}
	tx := newFragReassembler()
	original := makePackedFragmentTestFrame(b, packer, 1500)

	// Warm the sync.Pool before measuring steady-state allocation pressure.
	if frags, pooled := n.fragmentFrame(original, tx, 1, 512); pooled {
		releaseFragmentBuffers(frags)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frags, pooled := n.fragmentFrame(original, tx, 1, 512)
		if pooled {
			releaseFragmentBuffers(frags)
		}
	}
}
