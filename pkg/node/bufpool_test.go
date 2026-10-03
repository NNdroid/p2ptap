package node

import "testing"

func BenchmarkBufferPoolRoundTrip(b *testing.B) {
	for _, size := range []int{1500, 9000, 65552} {
		name := "frame"
		if size == 9000 {
			name = "jumbo"
		}
		if size == 65552 {
			name = "sealed"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if size == 65552 {
					buf := AcquireSealedBuf(size)
					ReleaseSealedBuf(buf)
				} else {
					buf := acquireFrameBuf(size)
					releaseFrameBuf(buf)
				}
			}
		})
	}
}

func TestBufferPoolBoundsAndOwnership(t *testing.T) {
	for _, pool := range []struct {
		name           string
		acquire        func(int) []byte
		release        func([]byte)
		size, capacity int
	}{
		{"frame", acquireFrameBuf, releaseFrameBuf, 1500, 2048},
		{"jumbo", acquireFrameBuf, releaseFrameBuf, 9000, 9216},
		{"cipher", AcquireCipherBuf, ReleaseCipherBuf, 1500, 2080},
		{"sealed", AcquireSealedBuf, ReleaseSealedBuf, 65551, 65552},
	} {
		t.Run(pool.name, func(t *testing.T) {
			// Oversized foreign slices must not cause retained pool capacity to grow.
			pool.release(make([]byte, 0, pool.capacity*2))
			first, second := pool.acquire(pool.size), pool.acquire(pool.size)
			if len(first) != pool.size || cap(first) != pool.capacity || cap(second) != pool.capacity {
				t.Fatalf("unexpected capacity: %d/%d", cap(first), cap(second))
			}
			first[0], second[0] = 1, 2
			if first[0] != 1 {
				t.Fatal("in-flight buffers alias")
			}
			pool.release(first[:0])
			pool.release(second)
			short := pool.acquire(1)
			pool.release(short[:0]) // len may be zero; full capacity remains available
		})
	}
}
