package node

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	frameLenSize = 4 // 4 bytes for uint32 length prefix
	// maxFrameLen is the maximum frame payload size. Raised to 1MiB to support
	// jumbo TAP frames (MTU up to ~9000) and large LSA/Meta blobs without the
	// old 64KiB ceiling forcing extra fragmentation on the data path. The 4-byte
	// length prefix is transmitted separately and is NOT counted here.
	maxFrameLen = 1024 * 1024 // 1MiB maximum payload
)

// WriteFrame writes a length-prefixed frame to the stream.
// Format: [4-byte big-endian length][payload]
//
// The 4-byte length prefix is written from a stack-allocated buffer (no heap
// allocation), followed by a single streaming write of the payload. Keeping the
// header off the heap matters on the hot path; the transport coalesces the two
// writes into as few segments as its own buffering permits.
func WriteFrame(w io.Writer, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if len(data) > maxFrameLen {
		return fmt.Errorf("frame too large: %d > %d", len(data), maxFrameLen)
	}

	total := frameLenSize + len(data)
	buf := acquireFrameBuf(total)
	binary.BigEndian.PutUint32(buf[0:frameLenSize], uint32(len(data)))
	copy(buf[frameLenSize:], data)

	err := writeAll(w, buf)
	releaseFrameBuf(buf)
	if err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// ReadFrame reads a length-prefixed frame from the stream.
// Returns the complete frame payload.
func ReadFrame(r io.Reader, buf []byte) (int, error) {
	// Read 4-byte length prefix
	var lenBuf [frameLenSize]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, err
	}

	frameLen := binary.BigEndian.Uint32(lenBuf[:])
	if frameLen == 0 {
		return 0, nil
	}
	if frameLen > uint32(len(buf)) {
		return 0, fmt.Errorf("frame too large: %d > %d", frameLen, len(buf))
	}

	// Read exact frame payload
	if _, err := io.ReadFull(r, buf[:frameLen]); err != nil {
		return 0, err
	}

	return int(frameLen), nil
}
