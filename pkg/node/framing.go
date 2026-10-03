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
// Prefix and payload share a pooled buffer and a write so transports do not
// emit a separate record just for the four-byte prefix.
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

// writeFrames coalesces an already available burst of independently framed
// messages. Each length prefix and payload is unchanged; no receiver support
// or timer is needed. Bound the scratch buffer and each transport write, and
// fall back to WriteFrame for a single oversized message.
func writeFrames(w io.Writer, frames [][]byte) error {
	if len(frames) == 1 {
		return WriteFrame(w, frames[0])
	}
	const maxWriteBatch = 64 * 1024
	buf := AcquireSealedBuf(maxWriteBatch)
	defer ReleaseSealedBuf(buf)
	used := 0
	flush := func() error {
		if used == 0 {
			return nil
		}
		if err := writeAll(w, buf[:used]); err != nil {
			return fmt.Errorf("write frames: %w", err)
		}
		used = 0
		return nil
	}
	for _, data := range frames {
		if len(data) == 0 {
			continue
		}
		if len(data) > maxFrameLen {
			return fmt.Errorf("frame too large: %d > %d", len(data), maxFrameLen)
		}
		total := frameLenSize + len(data)
		if total > maxWriteBatch {
			if err := flush(); err != nil {
				return err
			}
			if err := WriteFrame(w, data); err != nil {
				return err
			}
			continue
		}
		if used+total > maxWriteBatch {
			if err := flush(); err != nil {
				return err
			}
		}
		binary.BigEndian.PutUint32(buf[used:used+frameLenSize], uint32(len(data)))
		copy(buf[used+frameLenSize:used+total], data)
		used += total
	}
	return flush()
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
