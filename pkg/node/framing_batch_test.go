package node

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
)

type countedFrameWriter struct {
	bytes.Buffer
	writes int
	limit  int
}

func (w *countedFrameWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.limit > 0 && len(p) > w.limit {
		p = p[:w.limit]
	}
	return w.Buffer.Write(p)
}

func TestWriteFramesPreservesWireAcrossBoundaries(t *testing.T) {
	for _, sizes := range [][]int{{}, {64}, {64, 0, 1500}, {32000, 32000, 2000}, {65536, 9000}, {maxFrameLen, 64}} {
		t.Run(fmt.Sprint(sizes), func(t *testing.T) {
			var expected bytes.Buffer
			frames := make([][]byte, len(sizes))
			for i, size := range sizes {
				frames[i] = bytes.Repeat([]byte{byte(i + 1)}, size)
				if err := WriteFrame(&expected, frames[i]); err != nil {
					t.Fatal(err)
				}
			}
			for _, limit := range []int{0, 257} {
				writer := &countedFrameWriter{limit: limit}
				if err := writeFrames(writer, frames); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(writer.Bytes(), expected.Bytes()) {
					t.Fatalf("wire differs with short-write limit %d", limit)
				}
			}
		})
	}
}

type noProgressFrameWriter struct{}

func (noProgressFrameWriter) Write([]byte) (int, error) { return 0, nil }

func TestWriteFramesReportsWriteFailure(t *testing.T) {
	if err := writeFrames(noProgressFrameWriter{}, [][]byte{[]byte("a"), []byte("b")}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("no-progress write returned %v", err)
	}
	if err := writeFrames(io.Discard, [][]byte{make([]byte, maxFrameLen+1)}); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func BenchmarkWriteFrameBatch(b *testing.B) {
	for _, count := range []int{1, 8, 32} {
		frames := make([][]byte, count)
		for i := range frames {
			frames[i] = make([]byte, 1500)
		}
		for _, batched := range []bool{false, true} {
			b.Run(fmt.Sprintf("frames_%d/coalesced_%v", count, batched), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if batched {
						if err := writeFrames(io.Discard, frames); err != nil {
							b.Fatal(err)
						}
					} else {
						for _, frame := range frames {
							if err := WriteFrame(io.Discard, frame); err != nil {
								b.Fatal(err)
							}
						}
					}
				}
			})
		}
	}
}
