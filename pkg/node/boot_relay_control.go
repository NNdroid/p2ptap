package node

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"

	"p2ptap/pkg/meta"
	"p2ptap/pkg/routing"
)

// errBootRelayCtrlDeadline is returned by Read/Write on a boot-relay control
// stream once its deadline has elapsed. It is treated by the control handlers
// (SeqSync/LSA/Meta/Echo) like any other stream read/write error — the caller
// retries the handshake, so a missed frame is self-healing.
var errBootRelayCtrlDeadline = errors.New("boot-relay control stream deadline exceeded")

// --- per-conversation stream identity --------------------------------------
//
// A boot-relay control "stream" is a logical byte pipe multiplexed onto the ONE
// shared boot-relay uplink. Unlike a real libp2p stream there is no per-stream
// identity on the wire — every frame is just (finalDst, srcPeer, proto,
// payload). The original design keyed the control-stream registry by
// (srcPeer, proto); that collapsed TWO simultaneous conversations with the same
// peer onto one byte pipe (e.g. a leader's SeqSync handshake AND a follower's
// rekeyReq nudge), so each side's inbound bytes were enqueued into the OTHER's
// in-flight stream and the JSON framing corrupted ("cannot unmarshal number").
//
// The fix mirrors libp2p: each logical conversation carries a unique convID
// INSIDE the payload (the boot forwards the payload opaquely, so the boot needs
// no change). The initiator mints convID, writes it on every frame it sends, and
// registers its stream under convID. The responder learns convID from the first
// inbound frame and registers its OWN stream under the SAME convID, so the
// initiator's reply (e.g. the SeqSync ack) routes back to the exact stream that
// sent the sync — exactly like a bidirectional libp2p tunnel. A fresh convID is
// minted for every openControlStream call (handshake vs rekeyReq vs meta vs
// echo), so concurrent conversations over the same (peer, proto) never
// interleave.
const bootRelayCtrlConvIDLen = 8

// encodeBootRelayCtrlFrame prepends a self-delimiting convID to the inner
// control-protocol payload. The boot carries the result as an opaque payload, so
// the convID survives the bridge untouched.
func encodeBootRelayCtrlFrame(convID, inner []byte) []byte {
	out := make([]byte, 2+len(convID)+len(inner))
	binary.BigEndian.PutUint16(out[:2], uint16(len(convID)))
	copy(out[2:], convID)
	copy(out[2+len(convID):], inner)
	return out
}

// decodeBootRelayCtrlFrame splits a control payload back into its convID and the
// inner control-protocol bytes.
func decodeBootRelayCtrlFrame(payload []byte) (convID, inner []byte, err error) {
	if len(payload) < 2 {
		return nil, nil, fmt.Errorf("boot-relay ctrl frame too short")
	}
	cl := int(binary.BigEndian.Uint16(payload[:2]))
	if 2+cl > len(payload) {
		return nil, nil, fmt.Errorf("boot-relay ctrl frame convID length overflow")
	}
	return payload[2 : 2+cl], payload[2+cl:], nil
}

// newBootRelayCtrlConvID mints a fresh random conversation ID.
func newBootRelayCtrlConvID() []byte {
	b := make([]byte, bootRelayCtrlConvIDLen)
	_, _ = rand.Read(b)
	return b
}

// bootRelayCtrlStream is a network.Stream simulator that multiplexes ONE control
// protocol conversation (SeqSync / LSA / Meta / Echo) over a persistent
// boot-relay uplink. The custom boot is a relay-over-backbone bridge, NOT a
// Circuit-Relay v2 node, so it has no relay-ctrl handler; instead we send
// kind=Control boot-relay frames carrying the inner protocol bytes, and the
// peer's downlink feeds the matching inbound stream's read buffer.
//
// It is a fully transparent byte pipe: every Write ships the raw bytes as one
// boot-relay frame, and the peer concatenates the frames' payloads in order into
// its Read buffer. This is deliberately framing-agnostic — Meta/LSA use
// length-prefixed ReadFrame/WriteFrame while SeqSync uses newline-delimited
// JSON; both reconstructed correctly because the byte order is preserved exactly.
//
// Because every control handler keys per-peer state on s.Conn().RemotePeer(),
// the stream reports the LOGICAL peer (the true origin), not the boot hop.
type bootRelayCtrlStream struct {
	n       *Node
	remote  peer.ID // true origin/target peer the protocol runs between
	bootHop peer.ID // which boot uplink carries this control stream
	proto   protocol.ID
	convID  []byte // unique per-conversation ID; matches the peer's reply routing

	mu            sync.Mutex
	readBuf       []byte
	readCh        chan []byte
	closeCh       chan struct{}
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time
}

// --- network.MuxedStream (io.Reader / io.Writer / io.Closer) ---

// Read returns buffered inbound control bytes, blocking (subject to the read
// deadline) until the peer's downlink enqueues a frame or the stream is closed.
func (s *bootRelayCtrlStream) Read(p []byte) (int, error) {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return 0, io.EOF
		}
		if len(s.readBuf) > 0 {
			n := copy(p, s.readBuf)
			s.readBuf = s.readBuf[n:]
			s.mu.Unlock()
			return n, nil
		}
		var timerCh <-chan time.Time
		if !s.readDeadline.IsZero() {
			d := time.Until(s.readDeadline)
			if d <= 0 {
				s.mu.Unlock()
				return 0, errBootRelayCtrlDeadline
			}
			t := time.NewTimer(d)
			defer t.Stop()
			timerCh = t.C
		}
		ch := s.readCh
		closeCh := s.closeCh
		s.mu.Unlock()
		select {
		case frame := <-ch:
			s.mu.Lock()
			s.readBuf = frame
			s.mu.Unlock()
			// loop to hand bytes to the caller
		case <-closeCh:
			// re-check closed/readBuf at loop top
		case <-timerCh:
			return 0, errBootRelayCtrlDeadline
		}
	}
}

// Write ships the raw bytes as a single kind=Control boot-relay frame on the
// persistent uplink to bootHop. It returns the byte count written (the whole
// payload is one frame) or an error if the uplink is unavailable.
func (s *bootRelayCtrlStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	if !s.writeDeadline.IsZero() && time.Now().After(s.writeDeadline) {
		s.mu.Unlock()
		return 0, errBootRelayCtrlDeadline
	}
	s.mu.Unlock()

	// Stamp every frame with this conversation's unique ID so the peer can route
	// its reply back to the exact stream that sent these bytes (libp2p tunnel
	// semantics). The boot forwards the wrapped payload opaquely.
	wrapped := encodeBootRelayCtrlFrame(s.convID, p)
	env, err := routing.PackBootRelayFrame(s.n.bootRelayNetID, routing.BootRelayKindControl, s.proto, s.remote, s.n.Host.ID(), routing.MaxRelayTTL, wrapped)
	if err != nil {
		return 0, fmt.Errorf("boot-relay control pack: %w", err)
	}
	if !s.n.bootRelaySubmit(s.bootHop, env, nil, nil) {
		return 0, fmt.Errorf("boot-relay control uplink to %s unavailable", s.bootHop.ShortString())
	}
	return len(p), nil
}

// Close tears the stream down, wakes any blocked reader, and unregisters it from
// the control-stream table so a later inbound frame for the same (remote, proto)
// pair opens a fresh stream (e.g. a re-handshake).
func (s *bootRelayCtrlStream) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.closeCh)
	s.mu.Unlock()
	s.n.bootRelayCtrlMu.Lock()
	delete(s.n.bootRelayCtrlStreams, string(s.convID))
	s.n.bootRelayCtrlMu.Unlock()
	return nil
}

func (s *bootRelayCtrlStream) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// CloseRead forces the read side closed so a blocked Read returns EOF.
func (s *bootRelayCtrlStream) CloseRead() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.closeCh)
	}
	s.mu.Unlock()
	return nil
}

// CloseWrite is a no-op: the boot-relay uplink is shared and must stay open for
// data traffic, so half-closing this logical control stream must not touch it.
func (s *bootRelayCtrlStream) CloseWrite() error { return nil }

// Reset aborts the stream.
func (s *bootRelayCtrlStream) Reset() error { return s.Close() }

// ResetWithError aborts the stream (the error code is best-effort only).
func (s *bootRelayCtrlStream) ResetWithError(network.StreamErrorCode) error { return s.Close() }

// --- deadlines ---

func (s *bootRelayCtrlStream) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	_ = s.SetWriteDeadline(t)
	return nil
}

func (s *bootRelayCtrlStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.mu.Unlock()
	return nil
}

func (s *bootRelayCtrlStream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeDeadline = t
	s.mu.Unlock()
	return nil
}

// --- network.Stream metadata ---

func (s *bootRelayCtrlStream) ID() string {
	return "bootrelay-ctrl-" + hex.EncodeToString(s.convID) + "-" + string(s.proto)
}

func (s *bootRelayCtrlStream) Protocol() protocol.ID { return s.proto }

func (s *bootRelayCtrlStream) SetProtocol(p protocol.ID) error {
	s.mu.Lock()
	s.proto = p
	s.mu.Unlock()
	return nil
}

func (s *bootRelayCtrlStream) Stat() network.Stats { return network.Stats{} }

func (s *bootRelayCtrlStream) Scope() network.StreamScope { return nil }

func (s *bootRelayCtrlStream) Conn() network.Conn {
	return &bootRelayCtrlConn{n: s.n, remote: s.remote}
}

// enqueue appends inbound control bytes to the read buffer. It prefers to signal
// a parked reader via readCh (so ordering across frames is preserved exactly),
// stashing directly in readBuf only when no reader is currently parked.
func (s *bootRelayCtrlStream) enqueue(data []byte) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if len(s.readBuf) == 0 {
		select {
		case s.readCh <- data:
			s.mu.Unlock()
			return
		default:
			s.readBuf = data
			s.mu.Unlock()
			return
		}
	}
	// A partial frame is still being consumed by the reader; queue this one.
	select {
	case s.readCh <- data:
	default:
		// Channel full: append to the in-flight buffer (byte order is what
		// matters, and the protocol re-synchronises on its own framing).
		s.readBuf = append(s.readBuf, data...)
	}
	s.mu.Unlock()
}

// bootRelayCtrlConn is the network.Conn view handed back by
// bootRelayCtrlStream.Conn(). It reports the LOGICAL remote peer so every
// control handler that keys state on s.Conn().RemotePeer() binds to the true
// origin rather than the boot hop. Only RemotePeer is meaningful; the rest are
// zero values that the control handlers tolerate (connPathLabel nil-checks the
// multiaddrs).
type bootRelayCtrlConn struct {
	n      *Node
	remote peer.ID
}

func (c *bootRelayCtrlConn) Close() error                               { return nil }
func (c *bootRelayCtrlConn) LocalPeer() peer.ID                         { return c.n.Host.ID() }
func (c *bootRelayCtrlConn) RemotePeer() peer.ID                        { return c.remote }
func (c *bootRelayCtrlConn) RemotePublicKey() ic.PubKey                 { return nil }
func (c *bootRelayCtrlConn) ConnState() network.ConnectionState         { return network.ConnectionState{} }
func (c *bootRelayCtrlConn) LocalMultiaddr() ma.Multiaddr               { return nil }
func (c *bootRelayCtrlConn) RemoteMultiaddr() ma.Multiaddr              { return nil }
func (c *bootRelayCtrlConn) Stat() network.ConnStats                    { return network.ConnStats{} }
func (c *bootRelayCtrlConn) Scope() network.ConnScope                   { return nil }
func (c *bootRelayCtrlConn) CloseWithError(network.ConnErrorCode) error { return nil }
func (c *bootRelayCtrlConn) ID() string                                 { return "bootrelay-ctrl-conn-" + c.remote.String() }
func (c *bootRelayCtrlConn) NewStream(context.Context) (network.Stream, error) {
	return nil, errors.New("boot-relay control conn: NewStream not supported")
}
func (c *bootRelayCtrlConn) GetStreams() []network.Stream { return nil }
func (c *bootRelayCtrlConn) IsClosed() bool               { return false }
func (c *bootRelayCtrlConn) As(target any) bool           { return false }

// openBootRelayControlStream opens (or reuses) the boot-relay control tunnel for
// target over proto. It is the boot-hop analogue of openRelayCtrlStream: rather
// than opening a real /p2ptap/relay-ctrl/1.0.0 stream to the boot (which a custom
// boot does not serve), it returns a bootRelayCtrlStream simulator that
// multiplexes the inner protocol onto the persistent boot-relay uplink. Returns
// an error (so the caller retries) if the uplink is not yet alive.
func (n *Node) openBootRelayControlStream(bootHop, target peer.ID, proto protocol.ID) (network.Stream, error) {
	if !n.hasBootRelayUplink(bootHop) {
		return nil, fmt.Errorf("boot-relay control: no uplink to boot %s", bootHop.ShortString())
	}
	// Mint a fresh conversation ID for this logical stream. Every call to
	// openControlStream is a distinct conversation (a new physical libp2p stream
	// in the overlay path), so it gets its own ID here too — this is what stops a
	// leader's handshake and a follower's rekeyReq nudge (both (target, SeqSync)
	// on the same uplink) from sharing one byte pipe and corrupting framing.
	convID := newBootRelayCtrlConvID()
	st := &bootRelayCtrlStream{
		n:       n,
		remote:  target,
		bootHop: bootHop,
		proto:   proto,
		convID:  append([]byte(nil), convID...),
		readCh:  make(chan []byte, 64),
		closeCh: make(chan struct{}),
	}
	n.bootRelayCtrlMu.Lock()
	n.bootRelayCtrlStreams[string(convID)] = st
	n.bootRelayCtrlMu.Unlock()
	return st, nil
}

// deliverBootRelayControl routes an inbound kind=Control frame from the boot
// downlink to the right control stream. The frame carries a per-conversation
// convID (stamped by the sender); we decode it and route by that ID so a leader's
// handshake reply and a follower's rekeyReq nudge (both from the same peer, same
// proto) never share a byte pipe. If a stream already exists for this convID —
// e.g. the initiator side awaiting the peer's reply — the bytes are appended to
// its read buffer. Otherwise the frame is the start of a fresh inbound
// conversation: a responder stream is created, keyed by convID, and the matching
// control handler is spawned with the logical peer set to srcPeer.
func (n *Node) deliverBootRelayControl(finalDst, srcPeer peer.ID, proto protocol.ID, viaBoot peer.ID, payload []byte) {
	if finalDst != n.Host.ID() {
		log.Debug("[boot-relay] control frame finalDst %s != self; dropping", finalDst.ShortString())
		return
	}
	n.notePeerRx(srcPeer)
	if viaBoot != "" && viaBoot != srcPeer {
		n.recordPeekMapOrigin(srcPeer, viaBoot, 1, false)
	}
	convID, inner, err := decodeBootRelayCtrlFrame(payload)
	if err != nil {
		log.Debug("[boot-relay] control frame decode error from %s: %v", srcPeer.ShortString(), err)
		return
	}
	// Copy BOTH fields out of the downlink's REUSED read buffer. The downlink
	// loop calls ReadFrame(s, buf) on the very next iteration, which overwrites
	// buf — and the convID/inner slices we just decoded alias that buffer. We
	// hand them to an ASYNC handler goroutine, so without copying the queued
	// control bytes would be silently clobbered (observed as "frame too large"
	// on a later Meta exchange whose length prefix got shredded mid-read).
	convID = append([]byte(nil), convID...)
	inner = append([]byte(nil), inner...)
	key := string(convID)
	n.bootRelayCtrlMu.Lock()
	st, ok := n.bootRelayCtrlStreams[key]
	if !ok {
		st = &bootRelayCtrlStream{
			n:       n,
			remote:  srcPeer,
			bootHop: viaBoot,
			proto:   proto,
			convID:  append([]byte(nil), convID...),
			readCh:  make(chan []byte, 64),
			closeCh: make(chan struct{}),
		}
		n.bootRelayCtrlStreams[key] = st
		n.bootRelayCtrlMu.Unlock()
		// Enqueue the very first frame so the spawned handler reads it, then run
		// the handler (which binds all per-peer state to srcPeer via Conn()).
		st.enqueue(inner)
		go n.dispatchBootRelayControlStream(st)
		return
	}
	n.bootRelayCtrlMu.Unlock()
	st.enqueue(inner)
}

// dispatchBootRelayControlStream runs the inner control protocol on the
// responder-side boot-relay control stream. It mirrors dispatchRelayCtrlInner:
// the stream's logical peer is already the true origin (set in
// deliverBootRelayControl), so the cipher / identity negotiated here is anchored
// on srcPeer, not the boot hop.
func (n *Node) dispatchBootRelayControlStream(st *bootRelayCtrlStream) {
	defer st.Close()
	switch st.proto {
	case SeqSyncProtocolID:
		n.handleSeqSync(st)
	case LSAProtocolID:
		n.handleLSAStream(st)
	case meta.MetaProtocolID:
		n.handleMetaStream(st)
	case EchoProtocolID:
		n.handleEcho(st)
	case TapProbeAckProtocolID:
		// Tunnelled peer-side TAP probe acks, mirroring dispatchRelayCtrlInner.
		// A relay-only peer's ack traverses the boot-relay control tunnel, so
		// without this case it would fall into default: and be closed before
		// reaching the prober, making ProbeTapForward falsely time out.
		n.handleTapProbeAck(st)
	default:
		log.Warn("[boot-relay] no control handler for proto %s (origin %s); closing", st.proto, st.remote.ShortString())
	}
}
