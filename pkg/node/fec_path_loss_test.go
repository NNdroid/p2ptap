package node

import (
	"bytes"
	"fmt"
	"testing"

	"p2ptap/pkg/fec"
)

// TestFECRecoversSinglePathLoss proves the multipath FEC stripe survives ANY ONE
// physical path silently losing its shards — the case the scheduler cannot see
// because the writes still succeed (a radio path dropping packets without a
// write error). A frame striped across `paths` paths is cut into data shards
// plus Reed-Solomon parity sized by fecParityFor so that a single dead path's
// shards are always within the recovery budget; feeding the surviving shards to
// the receiver reassembler must rebuild the original frame.
//
// The DWRR scheduler round-robins shard index over `paths` paths, so the shards
// of one dead path are exactly those with idx%paths==k. Every k is exercised so
// the test cannot accidentally pick a path whose shard set is recoverable by
// luck of layout.
func TestFECRecoversSinglePathLoss(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, 3000)
	const (
		chunkSize = 512
		paths     = 3
	)
	dataParts := (len(payload) + chunkSize - 1) / chunkSize
	parityParts := fecParityFor(dataParts, paths)
	if parityParts <= 0 || dataParts < 2 {
		t.Fatalf("stripe setup degenerate: dataParts=%d parityParts=%d", dataParts, parityParts)
	}

	// Equal-length zero-padded data shards for the codec (mirrors
	// fragmentFrameStriped, which zero-pads the tail copy before fec.Encode).
	data := make([][]byte, dataParts)
	for i := 0; i < dataParts; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		d := make([]byte, chunkSize)
		copy(d, payload[start:end])
		data[i] = d
	}
	parity, err := fec.Encode(data, parityParts)
	if err != nil {
		t.Fatalf("fec.Encode: %v", err)
	}

	total := dataParts + parityParts
	tailLen := len(payload) - (dataParts-1)*chunkSize
	const origSeq = 7

	// build wraps one shard in a FEC fragment envelope, the exact wire format
	// putFECFragHeader produces (parseFragHeader then validates it).
	build := func(idx int, chunk []byte) []byte {
		var hdr [fragHeaderLenFEC]byte
		putFECFragHeader(hdr[:], origSeq, uint16(idx), uint16(total), uint16(dataParts), len(chunk), chunkSize, tailLen)
		env := make([]byte, 0, fragHeaderLenFEC+len(chunk))
		env = append(env, hdr[:]...)
		return append(env, chunk...)
	}
	// wireChunk is the on-wire shard body: every data shard but the last carries
	// the full chunk, the last data shard carries exactly tailLen (the codec
	// works on a zero-padded copy, but the wire never carries the padding), and
	// parity shards carry the codec output.
	wireChunk := func(idx int) []byte {
		if idx < dataParts {
			if idx == dataParts-1 {
				return payload[idx*chunkSize:]
			}
			return data[idx]
		}
		return parity[idx-dataParts]
	}

	for k := 0; k < paths; k++ {
		k := k
		t.Run(fmt.Sprintf("lose_path_%d_of_%d", k, paths), func(t *testing.T) {
			f := newFragReassembler()
			pid := newTestPeerID(t)
			lost := 0
			var out []byte
			var complete bool
			for idx := 0; idx < total; idx++ {
				if idx%paths == k {
					// This path's shards never arrive (silent drop: the sender
					// sees a successful write, the receiver never gets them).
					lost++
					continue
				}
				out, complete = f.reassemble(pid, build(idx, wireChunk(idx)), reasmChannelDirect, 1)
			}
			if !complete {
				t.Fatalf("frame not reconstructed after losing %d/%d shards on one path", lost, total)
			}
			if !bytes.Equal(out, payload) {
				t.Fatalf("reconstructed frame corrupted (got %d bytes, want %d)", len(out), len(payload))
			}
		})
	}
}
