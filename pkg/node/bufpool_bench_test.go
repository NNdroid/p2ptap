package node

import (
	"fmt"
	"io"
	"testing"
)

// commonFrameSizes mirrors the payload sizes the TAP egress path actually
// copies: a typical 1500-byte Ethernet frame and a jumbo frame.
var benchFrameSizes = []struct {
	name string
	size int
}{
	{"eth1500", 1500},
	{"jumbo9000", 9000},
}

// BenchmarkFrameBufPool measures the allocation cost of the pooled copy path
// that replaced the old per-frame `make([]byte, totalLen)` in processTapFrame.
// After the pool warms up, Get returns a recycled buffer, so this should
// report ~0 allocs/op — the win that lowers both GC pressure and CPU.
func BenchmarkFrameBufPool(b *testing.B) {
	for _, fs := range benchFrameSizes {
		b.Run(fs.name, func(b *testing.B) {
			payload := make([]byte, fs.size)
			for i := range payload {
				payload[i] = byte(i)
			}
			b.ReportAllocs()
			for b.Loop() {
				buf := acquireFrameBuf(fs.size)
				copy(buf, payload)
				// simulate the per-peer Pack that consumes the copy
				sum := byte(0)
				for i := 0; i < len(buf); i++ {
					sum ^= buf[i]
				}
				releaseFrameBuf(buf)
				_ = sum
			}
		})
	}
}

// BenchmarkFrameBufMake is the pre-optimization baseline: every frame copy is
// a fresh heap allocation. This should report 1 alloc/op and a higher
// alloc_bytes/op than BenchmarkFrameBufPool, making the improvement visible in
// `go test -bench` output.
func BenchmarkFrameBufMake(b *testing.B) {
	for _, fs := range benchFrameSizes {
		b.Run(fs.name, func(b *testing.B) {
			payload := make([]byte, fs.size)
			for i := range payload {
				payload[i] = byte(i)
			}
			b.ReportAllocs()
			for b.Loop() {
				buf := make([]byte, fs.size)
				copy(buf, payload)
				sum := byte(0)
				for i := 0; i < len(buf); i++ {
					sum ^= buf[i]
				}
				_ = sum
			}
		})
	}
}

// BenchmarkWriteFrame exercises the length-prefixed framing on the egress path.
// WriteFrame writes its 4-byte header from a stack buffer and streams the
// payload in place, so it should report 0 allocs/op across all frame sizes —
// the framing layer adds no GC pressure on top of the pooled copy.
func BenchmarkWriteFrame(b *testing.B) {
	sizes := []int{64, 1500, 9000}
	for _, sz := range sizes {
		b.Run(fmt.Sprintf("size%d", sz), func(b *testing.B) {
			data := make([]byte, sz)
			b.ReportAllocs()
			for b.Loop() {
				if err := WriteFrame(io.Discard, data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
