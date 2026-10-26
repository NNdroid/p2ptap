package node

import (
	"fmt"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"

	mux "p2ptap/pkg/mux"

	"p2ptap/pkg/meta"
)

// Re-export the mux protocol IDs for backward compatibility with existing
// code in pkg/node that references MuxControlProtocolID / MuxDataProtocolID.
const (
	MuxControlProtocolID = mux.ControlProtocolID
	MuxDataProtocolID    = mux.DataProtocolID
)

// Re-export tag constants.
const (
	MuxTagSeqSync     = mux.TagSeqSync
	MuxTagLSA         = mux.TagLSA
	MuxTagMeta        = mux.TagMeta
	MuxTagEcho        = mux.TagEcho
	MuxTagTapProbeAck = mux.TagTapProbeAck
	MuxTagRelayCtrl   = mux.TagRelayCtrl
)

// Re-export data kind constants.
const (
	MuxDataKindVTP       = mux.KindVTP
	MuxDataKindRelay     = mux.KindRelay
	MuxDataKindBootRelay = mux.KindBootRelay
)

// Re-export direction constants.
const (
	MuxDirRequest   = mux.DirRequest
	MuxDirResponse  = mux.DirResponse
	MuxDirBroadcast = mux.DirBroadcast
)

// muxHeaderLen and muxDataHeaderLen are aliases for the shared package.
const (
	muxHeaderLen     = mux.HeaderLen
	muxDataHeaderLen = mux.DataHeaderLen
)

// muxSession tracks a single request/response exchange on a mux stream.
type muxSession struct {
	tag     uint8
	reqID   uint32
	stream  network.Stream
	request []byte
	respCh  chan []byte
}

// muxStream implements network.Stream on top of a muxSession. Protocol
// handlers (handleLSAStream, handleMetaStream, etc.) receive a muxStream
// and use ReadFrame/WriteFrame/json as they normally would. The mux layer
// transparently adds the multiplexing header.
type muxStream struct {
	sess *muxSession
	rpos int
	data []byte
}

var _ network.Stream = (*muxStream)(nil)

func (m *muxStream) Read(p []byte) (int, error) {
	if m.rpos < len(m.data) {
		n := copy(p, m.data[m.rpos:])
		m.rpos += n
		return n, nil
	}
	if m.sess.request != nil {
		m.data = m.sess.request
		m.sess.request = nil
		m.rpos = 0
		n := copy(p, m.data)
		m.rpos = n
		if m.rpos >= len(m.data) {
			m.data = nil
			m.rpos = 0
		}
		return n, nil
	}
	return 0, io.EOF
}

func (m *muxStream) Write(p []byte) (int, error) {
	return mux.WriteFrame(m.sess.stream, m.sess.tag, MuxDirResponse, m.sess.reqID, p)
}

func (m *muxStream) Close() error      { return nil }
func (m *muxStream) CloseWrite() error { return nil }
func (m *muxStream) CloseRead() error  { return nil }
func (m *muxStream) Reset() error      { return nil }

// Set*Deadline are no-ops, and deliberately so: muxStream.Read returns either
// the already-delivered request bytes or io.EOF and can never block, so there
// is nothing for a deadline to bound. They are kept because protocol handlers
// (handleTapProbeAck, handleMetaStream, handleSeqSync) call them unconditionally
// on an opaque network.Stream. An earlier version stored the value in
// muxSession.deadline, which was written but never read — a caller could easily
// have believed the deadline was live.
func (m *muxStream) SetDeadline(time.Time) error      { return nil }
func (m *muxStream) SetReadDeadline(time.Time) error  { return nil }
func (m *muxStream) SetWriteDeadline(time.Time) error { return nil }

func (m *muxStream) ID() string                       { return m.sess.stream.ID() }
func (m *muxStream) Protocol() protocol.ID            { return m.sess.stream.Protocol() }
func (m *muxStream) SetProtocol(id protocol.ID) error { return m.sess.stream.SetProtocol(id) }
func (m *muxStream) Stat() network.Stats              { return m.sess.stream.Stat() }
func (m *muxStream) Conn() network.Conn               { return m.sess.stream.Conn() }
func (m *muxStream) Scope() network.StreamScope       { return &network.NullScope{} }
func (m *muxStream) ResetWithError(code network.StreamErrorCode) error {
	return m.sess.stream.ResetWithError(code)
}

// muxInitStream is the initiator-side wrapper for a mux stream. It presents
// a network.Stream interface to callers (lsaPool, metaPool, etc.) that use
// ReadFrame/WriteFrame. Write() wraps data in a mux frame with dir=Request;
// Read() waits for the matching response via the session's respCh. The
// muxEngine routes the response from the mux stream to this session.
type muxInitStream struct {
	stream network.Stream
	tag    uint8
	reqID  uint32
	sess   *muxSession
	engine *muxEngine
	data   []byte
	rpos   int
}

var _ network.Stream = (*muxInitStream)(nil)

func (m *muxInitStream) Write(p []byte) (int, error) {
	return mux.WriteFrame(m.stream, m.tag, MuxDirRequest, m.reqID, p)
}

func (m *muxInitStream) Read(p []byte) (int, error) {
	if m.rpos < len(m.data) {
		n := copy(p, m.data[m.rpos:])
		m.rpos += n
		return n, nil
	}
	if m.sess == nil {
		return 0, io.EOF
	}
	select {
	case resp, ok := <-m.sess.respCh:
		if !ok {
			return 0, io.EOF
		}
		m.data = resp
		m.rpos = 0
		n := copy(p, m.data)
		m.rpos = n
		if m.rpos >= len(m.data) {
			m.data = nil
			m.rpos = 0
		}
		return n, nil
	case <-time.After(15 * time.Second):
		return 0, fmt.Errorf("mux: read timeout")
	}
}

func (m *muxInitStream) Close() error                     { return m.stream.Close() }
func (m *muxInitStream) CloseWrite() error                { return nil }
func (m *muxInitStream) CloseRead() error                 { return nil }
func (m *muxInitStream) Reset() error                     { return nil }
func (m *muxInitStream) SetDeadline(time.Time) error      { return nil }
func (m *muxInitStream) SetReadDeadline(time.Time) error  { return nil }
func (m *muxInitStream) SetWriteDeadline(time.Time) error { return nil }

func (m *muxInitStream) ID() string                       { return m.stream.ID() }
func (m *muxInitStream) Protocol() protocol.ID            { return m.stream.Protocol() }
func (m *muxInitStream) SetProtocol(id protocol.ID) error { return m.stream.SetProtocol(id) }
func (m *muxInitStream) Stat() network.Stats              { return m.stream.Stat() }
func (m *muxInitStream) Conn() network.Conn               { return m.stream.Conn() }
func (m *muxInitStream) Scope() network.StreamScope       { return &network.NullScope{} }
func (m *muxInitStream) ResetWithError(code network.StreamErrorCode) error {
	return m.stream.ResetWithError(code)
}

// muxTagForProto maps a protocol.ID to its mux tag for the control channel.
func muxTagForProto(proto protocol.ID) (uint8, bool) {
	switch proto {
	case SeqSyncProtocolID:
		return mux.TagSeqSync, true
	case LSAProtocolID:
		return mux.TagLSA, true
	case meta.MetaProtocolID:
		return mux.TagMeta, true
	case EchoProtocolID:
		return mux.TagEcho, true
	case TapProbeAckProtocolID:
		return mux.TagTapProbeAck, true
	case RelayCtrlProtocolID:
		return mux.TagRelayCtrl, true
	default:
		return 0, false
	}
}
