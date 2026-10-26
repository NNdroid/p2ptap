// Package mux defines the multiplexed stream frame format shared between
// the node and the boot server. Two channels are defined:
//
//   - Control: /p2ptap/ctrl/1.0.0 — multiplexes SeqSync, LSA, Meta, Echo,
//     TapProbeAck, and RelayCtrl onto one stream per peer.
//     Frame: [4B BE frameLen][1B tag][1B dir][4B BE reqID][payload]
//
//   - Data: /p2ptap/data/1.0.0 — multiplexes VTP and Relay onto one
//     stream per peer.
//     Frame: [4B BE frameLen][1B kind][payload]
package mux

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/libp2p/go-libp2p/core/protocol"
)

// Control-channel protocol ID.
const ControlProtocolID protocol.ID = "/p2ptap/ctrl/1.0.0"

// Data-channel protocol ID.
const DataProtocolID protocol.ID = "/p2ptap/data/1.0.0"

// Control-channel proto tags (1 byte each).
const (
	TagSeqSync     uint8 = 0x01
	TagLSA         uint8 = 0x02
	TagMeta        uint8 = 0x03
	TagEcho        uint8 = 0x04
	TagTapProbeAck uint8 = 0x05
	TagRelayCtrl   uint8 = 0x06
)

// Data-channel kind tags (1 byte each).
const (
	KindVTP      uint8 = 0x00
	KindRelay    uint8 = 0x01
	KindBootRelay uint8 = 0x02
)

// Direction bytes for the control channel.
const (
	DirRequest  uint8 = 0x00
	DirResponse uint8 = 0x01
	DirBroadcast uint8 = 0x02
)

// HeaderLen is the control-channel frame header size (excluding payload).
const HeaderLen = 10 // 4B frameLen + 1B tag + 1B dir + 4B reqID

// DataHeaderLen is the data-channel frame header size (excluding payload).
const DataHeaderLen = 5 // 4B frameLen + 1B kind

// MaxPayloadLen bounds the payload of a single mux frame on either channel.
// It matches the node's per-frame limit (framing.maxFrameLen, 1 MiB): a peer
// sizes its read buffer to that value, so a larger payload would be rejected
// there as "invalid frame length" and tear down the stream. Failing here
// instead reports the error at the point it is actually actionable, rather
// than as a confusing peer-side stream reset one RTT later.
const MaxPayloadLen = 1 << 20

// WriteFrame writes a control-channel mux frame to w.
// Format: [4B BE frameLen][1B tag][1B dir][4B BE reqID][payload]
func WriteFrame(w io.Writer, tag uint8, dir uint8, reqID uint32, payload []byte) (int, error) {
	if len(payload) > MaxPayloadLen {
		return 0, fmt.Errorf("mux: payload too large: %d > %d", len(payload), MaxPayloadLen)
	}
	frameLen := HeaderLen - 4 + len(payload)
	buf := make([]byte, 4+frameLen)
	binary.BigEndian.PutUint32(buf[:4], uint32(frameLen))
	buf[4] = tag
	buf[5] = dir
	binary.BigEndian.PutUint32(buf[6:10], reqID)
	copy(buf[10:], payload)
	return w.Write(buf)
}

// ReadFrame reads a control-channel mux frame from r.
func ReadFrame(r io.Reader, buf []byte) (tag uint8, dir uint8, reqID uint32, payload []byte, err error) {
	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return 0, 0, 0, nil, err
	}
	frameLen := binary.BigEndian.Uint32(buf[:4])
	if frameLen < 6 || frameLen > uint32(len(buf)-4) {
		return 0, 0, 0, nil, fmt.Errorf("mux: invalid frame length %d", frameLen)
	}
	if _, err := io.ReadFull(r, buf[4:4+frameLen]); err != nil {
		return 0, 0, 0, nil, err
	}
	tag = buf[4]
	dir = buf[5]
	reqID = binary.BigEndian.Uint32(buf[6:10])
	payload = buf[10 : 4+frameLen]
	return
}

// WriteDataFrame writes a data-channel mux frame to w.
// Format: [4B BE frameLen][1B kind][payload]
func WriteDataFrame(w io.Writer, kind uint8, payload []byte) (int, error) {
	if len(payload) > MaxPayloadLen {
		return 0, fmt.Errorf("mux: data payload too large: %d > %d", len(payload), MaxPayloadLen)
	}
	frameLen := 1 + len(payload)
	buf := make([]byte, 4+frameLen)
	binary.BigEndian.PutUint32(buf[:4], uint32(frameLen))
	buf[4] = kind
	copy(buf[5:], payload)
	return w.Write(buf)
}

// ReadDataFrame reads a data-channel mux frame from r.
func ReadDataFrame(r io.Reader, buf []byte) (kind uint8, payload []byte, err error) {
	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return 0, nil, err
	}
	frameLen := binary.BigEndian.Uint32(buf[:4])
	if frameLen < 1 || frameLen > uint32(len(buf)-4) {
		return 0, nil, fmt.Errorf("mux: invalid data frame length %d", frameLen)
	}
	if _, err := io.ReadFull(r, buf[4:4+frameLen]); err != nil {
		return 0, nil, err
	}
	kind = buf[4]
	payload = buf[5 : 4+frameLen]
	return
}
