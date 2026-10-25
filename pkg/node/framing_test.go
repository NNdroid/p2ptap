package node

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// overEagerWriter returns more bytes than it wrote, violating the io.Writer
// contract. The writeAll clamp (commit e0387a6) must not panic when this
// happens — it should treat n as len(data) and drain the slice.
type overEagerWriter struct {
	bytes.Buffer
	written int
}

func (w *overEagerWriter) Write(p []byte) (int, error) {
	w.Buffer.Write(p)
	w.written += len(p)
	return w.written, nil // return cumulative total, exceeding len(p)
}

func TestWriteAllNormal(t *testing.T) {
	for _, size := range []int{0, 1, 4, 16, 1024, 65536} {
		data := bytes.Repeat([]byte{0xAB}, size)
		var buf bytes.Buffer
		if err := writeAll(&buf, data); err != nil {
			t.Fatalf("size=%d: unexpected error: %v", size, err)
		}
		if !bytes.Equal(buf.Bytes(), data) {
			t.Fatalf("size=%d: output mismatch", size)
		}
	}
}

func TestWriteAllOverEagerWriterNoPanic(t *testing.T) {
	// This is the regression test for the Android crash:
	// panic: runtime error: slice bounds out of range [18:8]
	// at writeAll when a writer returns n > len(data).
	data := []byte("hello world, this is a test message")
	w := &overEagerWriter{}
	if err := writeAll(w, data); err != nil {
		t.Fatalf("writeAll with over-eager writer failed: %v", err)
	}
	if !bytes.Equal(w.Buffer.Bytes(), data) {
		t.Fatalf("output mismatch: got %q, want %q", w.Buffer.Bytes(), data)
	}
}

func TestWriteAllOverEagerWriterMultipleCalls(t *testing.T) {
	// Multiple sequential calls with an over-eager writer must all succeed.
	for i := 0; i < 10; i++ {
		data := bytes.Repeat([]byte{byte(i)}, 8)
		w := &overEagerWriter{}
		if err := writeAll(w, data); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if !bytes.Equal(w.Buffer.Bytes(), data) {
			t.Fatalf("call %d: output mismatch", i)
		}
	}
}

// noProgressWriter returns 0, nil — the write made no progress.
type noProgressWriter struct{}

func (noProgressWriter) Write([]byte) (int, error) { return 0, nil }

func TestWriteAllNoProgressReturnsErrShortWrite(t *testing.T) {
	if err := writeAll(noProgressWriter{}, []byte("data")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected ErrShortWrite, got %v", err)
	}
}

// failingWriter returns a persistent error on the first Write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("persistent failure") }

func TestWriteAllReturnsWriterError(t *testing.T) {
	err := writeAll(failingWriter{}, []byte("data"))
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

// shortWriter writes at most `limit` bytes per call, simulating a real
// socket that fills up in chunks.
type shortWriter struct {
	limit int
	bytes.Buffer
}

func (w *shortWriter) Write(p []byte) (int, error) {
	n := len(p)
	if w.limit > 0 && n > w.limit {
		n = w.limit
	}
	_, err := w.Buffer.Write(p[:n])
	return n, err
}

func TestWriteAllShortWrites(t *testing.T) {
	for _, limit := range []int{1, 3, 7, 100} {
		data := bytes.Repeat([]byte{0x42}, 1000)
		w := &shortWriter{limit: limit}
		if err := writeAll(w, data); err != nil {
			t.Fatalf("limit=%d: unexpected error: %v", limit, err)
		}
		if !bytes.Equal(w.Buffer.Bytes(), data) {
			t.Fatalf("limit=%d: output mismatch, got %d bytes", limit, len(w.Buffer.Bytes()))
		}
	}
}

func TestWriteFrameRoundTrip(t *testing.T) {
	// WriteFrame is a no-op for empty data, so size=0 has no wire bytes.
	for _, size := range []int{1, 4, 100, 4096, maxFrameLen} {
		data := bytes.Repeat([]byte{0xCC}, size)
		var buf bytes.Buffer
		if err := WriteFrame(&buf, data); err != nil {
			t.Fatalf("size=%d: WriteFrame error: %v", size, err)
		}
		out := make([]byte, maxFrameLen)
		n, err := ReadFrame(&buf, out)
		if err != nil {
			t.Fatalf("size=%d: ReadFrame error: %v", size, err)
		}
		if n != size {
			t.Fatalf("size=%d: read %d bytes, want %d", size, n, size)
		}
		if size > 0 && !bytes.Equal(out[:n], data) {
			t.Fatalf("size=%d: payload mismatch", size)
		}
	}
}

func TestWriteFrameRejectsOversized(t *testing.T) {
	data := make([]byte, maxFrameLen+1)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, data); err == nil {
		t.Fatal("WriteFrame should reject oversized data")
	}
}

func TestReadFrameRejectsTooSmallBuffer(t *testing.T) {
	// Write a frame with a 100-byte payload.
	payload := bytes.Repeat([]byte{0x55}, 100)
	var buf bytes.Buffer
	WriteFrame(&buf, payload)

	// Try to read with a buffer too small for the payload.
	small := make([]byte, 10)
	_, err := ReadFrame(&buf, small)
	if err == nil {
		t.Fatal("ReadFrame should reject too-small buffer")
	}
}

func TestReadFrameEmptyStream(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader(nil), make([]byte, 1024))
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}
