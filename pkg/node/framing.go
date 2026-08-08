package node

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	frameLenSize = 4         // 4 bytes for uint32 length prefix
	maxFrameLen  = 65535 + 4 // Maximum frame size including length prefix
)

// WriteFrame writes a length-prefixed frame to the stream.
// Format: [4-byte big-endian length][payload]
func WriteFrame(w io.Writer, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	// Write 4-byte length prefix
	var lenBuf [frameLenSize]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if err := writeAll(w, lenBuf[:]); err != nil {
		return fmt.Errorf("write frame length: %w", err)
	}

	// Write payload
	if err := writeAll(w, data); err != nil {
		return fmt.Errorf("write frame data: %w", err)
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
