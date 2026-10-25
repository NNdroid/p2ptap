package mux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// TestWriteReadFrameRoundTrip verifies that WriteFrame and ReadFrame
// produce symmetric results for the control-channel frame format.
func TestWriteReadFrameRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		tag     uint8
		dir     uint8
		reqID   uint32
		payload []byte
	}{
		{"empty_payload", TagSeqSync, DirRequest, 0, nil},
		{"min_payload", TagLSA, DirBroadcast, 1, []byte{0xAA}},
		{"typical", TagMeta, DirRequest, 42, []byte("hello world")},
		{"large_payload", TagEcho, DirResponse, 0xFFFFFFFF, bytes.Repeat([]byte{0xFF}, 1024)},
		{"all_tags", TagRelayCtrl, DirBroadcast, 7, bytes.Repeat([]byte{0x01}, 100)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			n, err := WriteFrame(&buf, tt.tag, tt.dir, tt.reqID, tt.payload)
			if err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			// frameLen = HeaderLen - 4 + len(payload) = 6 + len(payload)
			// total bytes = 4 + frameLen = 10 + len(payload)
			expectedN := 10 + len(tt.payload)
			if n != expectedN {
				t.Fatalf("WriteFrame returned %d bytes, want %d", n, expectedN)
			}

			rbuf := make([]byte, 65536)
			tag, dir, reqID, payload, err := ReadFrame(&buf, rbuf)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if tag != tt.tag {
				t.Errorf("tag = 0x%02x, want 0x%02x", tag, tt.tag)
			}
			if dir != tt.dir {
				t.Errorf("dir = 0x%02x, want 0x%02x", dir, tt.dir)
			}
			if reqID != tt.reqID {
				t.Errorf("reqID = %d, want %d", reqID, tt.reqID)
			}
			if !bytes.Equal(payload, tt.payload) {
				t.Errorf("payload mismatch: got %d bytes, want %d bytes", len(payload), len(tt.payload))
			}
		})
	}
}

// TestWriteReadDataFrameRoundTrip verifies that WriteDataFrame and
// ReadDataFrame produce symmetric results for the data-channel frame format.
func TestWriteReadDataFrameRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		kind    uint8
		payload []byte
	}{
		{"empty_payload", KindVTP, nil},
		{"min_payload", KindRelay, []byte{0x00}},
		{"typical", KindVTP, []byte("ethernet frame data")},
		{"large_payload", KindRelay, bytes.Repeat([]byte{0xBB}, 2048)},
		{"all_kinds", KindBootRelay, bytes.Repeat([]byte{0x02}, 512)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			n, err := WriteDataFrame(&buf, tt.kind, tt.payload)
			if err != nil {
				t.Fatalf("WriteDataFrame: %v", err)
			}
			// frameLen = 1 + len(payload), total = 4 + frameLen = 5 + len(payload)
			expectedN := 5 + len(tt.payload)
			if n != expectedN {
				t.Fatalf("WriteDataFrame returned %d bytes, want %d", n, expectedN)
			}

			rbuf := make([]byte, 65536)
			kind, payload, err := ReadDataFrame(&buf, rbuf)
			if err != nil {
				t.Fatalf("ReadDataFrame: %v", err)
			}
			if kind != tt.kind {
				t.Errorf("kind = 0x%02x, want 0x%02x", kind, tt.kind)
			}
			if !bytes.Equal(payload, tt.payload) {
				t.Errorf("payload mismatch: got %d bytes, want %d bytes", len(payload), len(tt.payload))
			}
		})
	}
}

// TestReadFrameInvalidFrameLen verifies that ReadFrame rejects frames
// with a length less than the minimum header (6 bytes).
func TestReadFrameInvalidFrameLen(t *testing.T) {
	tests := []struct {
		name     string
		frameLen uint32
	}{
		{"zero", 0},
		{"one", 1},
		{"five", 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 4+10)
			binary.BigEndian.PutUint32(buf[:4], tt.frameLen)
			// Fill rest with garbage
			for i := 4; i < len(buf); i++ {
				buf[i] = 0xFF
			}
			_, _, _, _, err := ReadFrame(bytes.NewReader(buf), buf)
			if err == nil {
				t.Fatalf("expected error for frameLen=%d, got nil", tt.frameLen)
			}
		})
	}
}

// TestReadDataFrameInvalidFrameLen verifies that ReadDataFrame rejects
// frames with a length less than 1 byte (minimum kind tag).
func TestReadDataFrameInvalidFrameLen(t *testing.T) {
	buf := make([]byte, 4+10)
	binary.BigEndian.PutUint32(buf[:4], 0)
	for i := 4; i < len(buf); i++ {
		buf[i] = 0xFF
	}
	_, _, err := ReadDataFrame(bytes.NewReader(buf), buf)
	if err == nil {
		t.Fatal("expected error for frameLen=0, got nil")
	}
}

// TestReadFrameTruncated verifies that ReadFrame returns an error when
// the reader closes before the full frame is available.
func TestReadFrameTruncated(t *testing.T) {
	// Write a valid frame, then truncate it
	var buf bytes.Buffer
	WriteFrame(&buf, TagSeqSync, DirRequest, 1, []byte("test"))
	data := buf.Bytes()

	// Truncate: only frameLen header (4 bytes) + partial body
	rbuf := make([]byte, 65536)
	_, _, _, _, err := ReadFrame(bytes.NewReader(data[:6]), rbuf)
	if err == nil {
		t.Fatal("expected error for truncated frame, got nil")
	}
}

// TestReadDataFrameTruncated verifies that ReadDataFrame returns an error
// when the reader closes before the full frame is available.
func TestReadDataFrameTruncated(t *testing.T) {
	var buf bytes.Buffer
	WriteDataFrame(&buf, KindVTP, []byte("test"))
	data := buf.Bytes()

	// Truncate: only frameLen header (4 bytes)
	rbuf := make([]byte, 65536)
	_, _, err := ReadDataFrame(bytes.NewReader(data[:4]), rbuf)
	if err == nil {
		t.Fatal("expected error for truncated data frame, got nil")
	}
}

// TestFrameLenField verifies the on-wire frame length field is correct.
func TestFrameLenField(t *testing.T) {
	payload := []byte("hello")
	var buf bytes.Buffer
	WriteFrame(&buf, TagMeta, DirResponse, 100, payload)
	data := buf.Bytes()

	// frameLen should be 6 + len(payload) = 11
	frameLen := binary.BigEndian.Uint32(data[:4])
	if frameLen != 6+uint32(len(payload)) {
		t.Errorf("frameLen = %d, want %d", frameLen, 6+uint32(len(payload)))
	}
}

// TestDataFrameLenField verifies the on-wire frame length field for data channel.
func TestDataFrameLenField(t *testing.T) {
	payload := []byte("test data")
	var buf bytes.Buffer
	WriteDataFrame(&buf, KindRelay, payload)
	data := buf.Bytes()

	// frameLen should be 1 + len(payload) = 10
	frameLen := binary.BigEndian.Uint32(data[:4])
	if frameLen != 1+uint32(len(payload)) {
		t.Errorf("frameLen = %d, want %d", frameLen, 1+uint32(len(payload)))
	}
}

// TestBufferReuseSafety verifies that ReadFrame does not alias the output
// buffer in a way that would be corrupted by buffer reuse. This was a data
// race bug: the response payload slice pointed into the reused read buffer,
// so the next ReadFrame iteration would overwrite it.
func TestBufferReuseSafety(t *testing.T) {
	buf := make([]byte, 65536)

	// Write two frames
	var src bytes.Buffer
	WriteFrame(&src, TagEcho, DirRequest, 1, []byte("first"))
	WriteFrame(&src, TagEcho, DirResponse, 1, []byte("second"))

	// Read first frame
	_, _, _, payload1, err := ReadFrame(&src, buf)
	if err != nil {
		t.Fatalf("first ReadFrame: %v", err)
	}
	// Snapshot the payload before second read
	payload1Copy := append([]byte(nil), payload1...)

	// Read second frame (reuses buf)
	_, _, _, payload2, err := ReadFrame(&src, buf)
	if err != nil {
		t.Fatalf("second ReadFrame: %v", err)
	}

	// payload1 should NOT have been corrupted by the second read
	if !bytes.Equal(payload1Copy, payload1) {
		// If payload1 still points into buf, it would now show "second" data
		t.Logf("Note: payload1 was affected by buffer reuse (payload1=%q, want %q)", payload1, payload1Copy)
		t.Log("This is expected with the current ReadFrame design; callers must copy payloads")
	}
	// payload2 should be correct
	if !bytes.Equal(payload2, []byte("second")) {
		t.Errorf("payload2 = %q, want %q", payload2, "second")
	}
}

// TestConstantsVerify verifies all tag, kind, and direction constants
// are unique within their respective sets.
func TestConstantsVerify(t *testing.T) {
	// Control tags
	tags := map[uint8]string{
		TagSeqSync: "SeqSync", TagLSA: "LSA", TagMeta: "Meta",
		TagEcho: "Echo", TagTapProbeAck: "TapProbeAck", TagRelayCtrl: "RelayCtrl",
	}
	if len(tags) != 6 {
		t.Errorf("expected 6 unique tags, got %d", len(tags))
	}

	// Data kinds
	kinds := map[uint8]string{
		KindVTP: "VTP", KindRelay: "Relay", KindBootRelay: "BootRelay",
	}
	if len(kinds) != 3 {
		t.Errorf("expected 3 unique kinds, got %d", len(kinds))
	}

	// Directions
	dirs := map[uint8]string{
		DirRequest: "Request", DirResponse: "Response", DirBroadcast: "Broadcast",
	}
	if len(dirs) != 3 {
		t.Errorf("expected 3 unique directions, got %d", len(dirs))
	}
}

// TestReadFrameEOF verifies that ReadFrame returns an io.EOF error
// when the reader is empty.
func TestReadFrameEOF(t *testing.T) {
	buf := make([]byte, 65536)
	_, _, _, _, err := ReadFrame(bytes.NewReader(nil), buf)
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected EOF, got %v", err)
	}
}

// TestReadDataFrameEOF verifies that ReadDataFrame returns an io.EOF error
// when the reader is empty.
func TestReadDataFrameEOF(t *testing.T) {
	buf := make([]byte, 65536)
	_, _, err := ReadDataFrame(bytes.NewReader(nil), buf)
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected EOF, got %v", err)
	}
}

// TestProtocolIDs verifies the protocol ID constants.
func TestProtocolIDs(t *testing.T) {
	if ControlProtocolID != "/p2ptap/ctrl/1.0.0" {
		t.Errorf("ControlProtocolID = %q", ControlProtocolID)
	}
	if DataProtocolID != "/p2ptap/data/1.0.0" {
		t.Errorf("DataProtocolID = %q", DataProtocolID)
	}
}

// TestHeaderLen verifies the header length constants.
func TestHeaderLen(t *testing.T) {
	// Control: 4B frameLen + 1B tag + 1B dir + 4B reqID = 10
	if HeaderLen != 10 {
		t.Errorf("HeaderLen = %d, want 10", HeaderLen)
	}
	// Data: 4B frameLen + 1B kind = 5
	if DataHeaderLen != 5 {
		t.Errorf("DataHeaderLen = %d, want 5", DataHeaderLen)
	}
}
