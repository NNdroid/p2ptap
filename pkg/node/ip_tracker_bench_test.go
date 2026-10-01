package node

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func makeIPTrackerIPv4Frame(src, dst uint32, flow byte) []byte {
	frame := make([]byte, 14+20+8+256)
	copy(frame[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x01, flow})
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x02, flow})
	frame[12], frame[13] = 0x08, 0x00
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(frame)-14))
	ip[8] = 64
	ip[9] = 17
	binary.BigEndian.PutUint32(ip[12:16], src)
	binary.BigEndian.PutUint32(ip[16:20], dst)
	return frame
}

func benchmarkIPTrackerFrames(b *testing.B, frames [][]byte) {
	tr := NewIPTrafficTracker()
	// Prime the table so the benchmark measures steady-state packet accounting,
	// not first-seen IP allocation.
	for _, frame := range frames {
		tr.ExtractAndRecord(frame, true)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			tr.ExtractAndRecord(frames[i%len(frames)], true)
			i++
		}
	})
}

func BenchmarkIPTrackerExtractAndRecordIPv4(b *testing.B) {
	b.Run("stable_pair", func(b *testing.B) {
		benchmarkIPTrackerFrames(b, [][]byte{
			makeIPTrackerIPv4Frame(0x0a000001, 0x0a000002, 1),
		})
	})
	for _, flows := range []int{16, 64} {
		flows := flows
		b.Run(fmt.Sprintf("flows_%d", flows), func(b *testing.B) {
			frames := make([][]byte, flows)
			for i := 0; i < flows; i++ {
				src := uint32(0x0a010000 + i + 1)
				dst := uint32(0x0a020000 + i + 1)
				frames[i] = makeIPTrackerIPv4Frame(src, dst, byte(i+1))
			}
			benchmarkIPTrackerFrames(b, frames)
		})
	}
}
