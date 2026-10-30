package node

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	tpt "github.com/libp2p/go-libp2p/core/transport"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	webrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	ma "github.com/multiformats/go-multiaddr"
)

// webrtcSignalTimeout bounds one SDP exchange phase (send or recv) and the whole
// signaled dial/accept. ICE gathering of a TURN relay can take seconds; the
// Noise handshake runs on top of SCTP. 30s mirrors the WebRTC Direct dial budget.
const webrtcSignalTimeout = 30 * time.Second

// webrtcSignalBackoff is how long a failed signaling attempt is parked before
// the relay-upgrade loop may try that peer again.
const webrtcSignalBackoff = 60 * time.Second

// webrtcSignalMsg is the JSON payload carried on a /p2ptap/webrtc-signal/1.0.0
// stream. A complete exchange is exactly one offer and one answer (non-trickle:
// each SDP already carries every gathered candidate).
type webrtcSignalMsg struct {
	Type string `json:"type"` // "offer" | "answer"
	SDP  string `json:"sdp"`
}

// nodeSignalTransport adapts a /p2ptap/webrtc-signal/1.0.0 stream to the
// transport.SignalTransport interface (JSON over WriteFrame/ReadFrame).
type nodeSignalTransport struct {
	s network.Stream
}

func (st *nodeSignalTransport) SendSDP(ctx context.Context, sdp string, isOffer bool) error {
	kind := "answer"
	if isOffer {
		kind = "offer"
	}
	payload, err := json.Marshal(webrtcSignalMsg{Type: kind, SDP: sdp})
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_ = st.s.SetWriteDeadline(time.Now().Add(webrtcSignalTimeout))
	return WriteFrame(st.s, payload)
}

func (st *nodeSignalTransport) RecvSDP(ctx context.Context) (string, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	_ = st.s.SetReadDeadline(time.Now().Add(webrtcSignalTimeout))
	buf := make([]byte, maxFrameLen)
	rn, err := ReadFrame(st.s, buf)
	if err != nil {
		return "", false, err
	}
	var msg webrtcSignalMsg
	if err := json.Unmarshal(buf[:rn], &msg); err != nil {
		return "", false, fmt.Errorf("bad webrtc signal message: %w", err)
	}
	if msg.Type != "offer" && msg.Type != "answer" {
		return "", false, fmt.Errorf("unknown webrtc signal type %q", msg.Type)
	}
	return msg.SDP, msg.Type == "offer", nil
}

func (st *nodeSignalTransport) close() { _ = st.s.Close() }

// webrtcTransportFor returns the node's WebRTC transport instance, or nil if
// the transport was not registered (config disabled it) or the host has none.
func (n *Node) webrtcTransportFor() *webrtc.WebRTCTransport {
	sw, ok := n.Host.Network().(*swarm.Swarm)
	if !ok {
		return nil
	}
	for _, tr := range sw.Transports() {
		if wt, ok := tr.(*webrtc.WebRTCTransport); ok {
			return wt
		}
	}
	return nil
}

// webrtcSignalEligible reports whether a WebRTC signaling upgrade may be
// attempted for pid: config enabled, not a bootstrap peer, no in-flight attempt
// already running, and outside the failure backoff window.
func (n *Node) webrtcSignalEligible(pid peer.ID) bool {
	if !n.config().Transports.EnableWebRTCSignaling {
		return false
	}
	if n.isBootstrapPeer(pid) {
		return false
	}
	if _, inflight := n.webRTCSignalInFlight.Load(pid); inflight {
		return false
	}
	if at, ok := n.webRTCSignalFailAt.Load(pid); ok {
		if t, ok := at.(time.Time); ok && time.Now().Before(t) {
			return false
		}
	}
	return true
}

// webrtcSignalOfferer reports whether myID is the SDP offerer for peerID. The
// HIGHER peer.ID offers and the lower answers, so two nodes racing the upgrade
// never both offer (no ICE glare). Deterministic and asymmetric.
func webrtcSignalOfferer(myID, peerID peer.ID) bool {
	return myID > peerID
}

// webrtcSignalUpgrade is the INITIATOR path: a relay-only peer whose direct
// QUIC/TCP dial failed. The higher peer.ID offers (deterministic role), the
// lower one accepts, so two nodes racing the upgrade never glare.
func (n *Node) webrtcSignalUpgrade(pid peer.ID) {
	if !n.webrtcSignalEligible(pid) {
		return
	}
	if !webrtcSignalOfferer(n.Host.ID(), pid) {
		// The peer is the offerer; wait for its offer on our handler.
		return
	}
	if _, loaded := n.webRTCSignalInFlight.LoadOrStore(pid, struct{}{}); loaded {
		return
	}
	defer n.webRTCSignalInFlight.Delete(pid)

	t := n.webrtcTransportFor()
	if t == nil {
		n.setWebRTCSignalStatus(pid, "failed")
		return
	}

	ctx, cancel := context.WithTimeout(n.ctx, webrtcSignalTimeout)
	defer cancel()

	sig, err := n.dialSignalTransport(ctx, pid)
	if err != nil {
		log.Debug("webrtc-signal: open signal stream to %s failed: %v", pid.ShortString(), err)
		n.noteWebRTCSignalFailure(pid)
		return
	}
	defer sig.close()

	conn, err := t.DialSignal(ctx, pid, sig)
	if err != nil {
		log.Debug("webrtc-signal: dial to %s failed: %v", pid.ShortString(), err)
		n.noteWebRTCSignalFailure(pid)
		return
	}
	n.registerWebRTCSignalConn(pid, conn)
}

// handleWebRTCSignal is the RESPONDER path: an inbound offer arrived on a
// /p2ptap/webrtc-signal/1.0.0 stream. We answer it and register the resulting
// data-channel stream.
func (n *Node) handleWebRTCSignal(s network.Stream) {
	defer s.Close()
	remote := s.Conn().RemotePeer()

	if !n.webrtcSignalEligible(remote) {
		log.Debug("webrtc-signal: ignoring offer from %s (ineligible)", remote.ShortString())
		return
	}
	// The offerer is the higher peer.ID. If we are also higher, we must be the
	// offerer, so an offer from a lower peer is a role violation — drop it.
	if webrtcSignalOfferer(n.Host.ID(), remote) {
		log.Debug("webrtc-signal: unexpected offer from %s (we are the offerer)", remote.ShortString())
		return
	}
	if _, loaded := n.webRTCSignalInFlight.LoadOrStore(remote, struct{}{}); loaded {
		return
	}
	defer n.webRTCSignalInFlight.Delete(remote)

	t := n.webrtcTransportFor()
	if t == nil {
		n.setWebRTCSignalStatus(remote, "failed")
		return
	}

	ctx, cancel := context.WithTimeout(n.ctx, webrtcSignalTimeout)
	defer cancel()

	conn, err := t.AcceptSignal(ctx, remote, &nodeSignalTransport{s: s})
	if err != nil {
		log.Debug("webrtc-signal: accept from %s failed: %v", remote.ShortString(), err)
		n.noteWebRTCSignalFailure(remote)
		return
	}
	n.registerWebRTCSignalConn(remote, conn)
}

// dialSignalTransport opens the signaling stream to target over whatever path
// is currently live (direct / overlay-relay / boot circuit).
func (n *Node) dialSignalTransport(ctx context.Context, target peer.ID) (*nodeSignalTransport, error) {
	s, err := n.openControlStream(ctx, target, WebRTCSignalProtocolID)
	if err != nil {
		return nil, err
	}
	return &nodeSignalTransport{s: s}, nil
}

// registerWebRTCSignalConn surfaces a negotiated WebRTC connection as a data
// path: open one application ProtocolID stream, register it with the strategy
// dispatcher (multipath / DWRR), and feed its reads into handleStream.
func (n *Node) registerWebRTCSignalConn(pid peer.ID, conn tpt.CapableConn) {
	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	defer cancel()
	muxed, err := conn.OpenStream(ctx)
	if err != nil {
		log.Warn("webrtc-signal: open data stream to %s failed: %v", pid.ShortString(), err)
		_ = conn.Close()
		n.noteWebRTCSignalFailure(pid)
		return
	}

	// RemoteMultiaddr is the selected ICE candidate pair's remote address; it
	// identifies the path in the per-path table and scores its priority.
	transportName := conn.RemoteMultiaddr().String()
	if transportName == "" {
		transportName = "/webrtc-signal/" + pid.String()
	}
	stream := n.wrapWebRTCStream(pid, conn, muxed)
	n.Dispatcher.RegisterStream(pid, streamRegistryKey(stream), stream)
	go n.handleStream(stream)

	n.setWebRTCSignalStatus(pid, "up")
	log.Info("WebRTC signaling link to %s established via %s", pid.ShortString(), transportName)
}

// wrapWebRTCStream adapts the bare muxed stream returned by a signaled WebRTC
// connection into the full network.Stream the dispatcher/handleStream consume.
// The webrtc connection never enters the swarm (so ConnectedF / connection
// tracking are untouched), and its stream type only implements MuxedStream, so
// we supply the Conn()/Stat()/etc. surface here.
func (n *Node) wrapWebRTCStream(pid peer.ID, conn tpt.CapableConn, muxed network.MuxedStream) network.Stream {
	localPubKey := n.Host.Peerstore().PubKey(n.Host.ID())
	return &webrtcSignalStream{
		MuxedStream: muxed,
		conn: &webrtcSignalConn{
			conn:        conn,
			localPubKey: localPubKey,
		},
	}
}

// noteWebRTCSignalFailure records a failed attempt and parks the peer in the
// backoff window.
func (n *Node) noteWebRTCSignalFailure(pid peer.ID) {
	n.webRTCSignalFailAt.Store(pid, time.Now().Add(webrtcSignalBackoff))
	n.setWebRTCSignalStatus(pid, "failed")
}

// setWebRTCSignalStatus updates the per-peer signaling outcome for telemetry.
func (n *Node) setWebRTCSignalStatus(pid peer.ID, status string) {
	n.webRTCSignalStatus.Store(pid, status)
}

// webRTCSignalStatusFor reads the per-peer signaling status for the WebUI.
func (n *Node) webRTCSignalStatusFor(pid peer.ID) string {
	if !n.config().Transports.EnableWebRTCSignaling {
		return "disabled"
	}
	if v, ok := n.webRTCSignalStatus.Load(pid); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// webrtcSignalConn adapts a signaled webrtc connection (tpt.CapableConn) to the
// network.Conn surface the data path reads (RemotePeer / RemoteMultiaddr).
// The full interface is satisfied with delegations and inert stubs; the fields
// the strategy layer never touches (Stat, ID, NewStream, GetStreams) are
// defaulted rather than plumbed, because this connection intentionally lives
// OUTSIDE the swarm's connection registry.
type webrtcSignalConn struct {
	conn        tpt.CapableConn
	localPubKey ic.PubKey
}

var _ network.Conn = (*webrtcSignalConn)(nil)

func (c *webrtcSignalConn) Close() error                          { return c.conn.Close() }
func (c *webrtcSignalConn) CloseWithError(code network.ConnErrorCode) error { return c.conn.CloseWithError(code) }
func (c *webrtcSignalConn) ID() string                            { return "webrtc-signal" }
func (c *webrtcSignalConn) IsClosed() bool                        { return c.conn.IsClosed() }
func (c *webrtcSignalConn) As(target any) bool                    { return c.conn.As(target) }
func (c *webrtcSignalConn) LocalPeer() peer.ID                    { return c.conn.LocalPeer() }
func (c *webrtcSignalConn) RemotePeer() peer.ID                   { return c.conn.RemotePeer() }
func (c *webrtcSignalConn) LocalMultiaddr() ma.Multiaddr          { return c.conn.LocalMultiaddr() }
func (c *webrtcSignalConn) RemoteMultiaddr() ma.Multiaddr         { return c.conn.RemoteMultiaddr() }
func (c *webrtcSignalConn) LocalPublicKey() ic.PubKey             { return c.localPubKey }
func (c *webrtcSignalConn) RemotePublicKey() ic.PubKey            { return c.conn.RemotePublicKey() }
func (c *webrtcSignalConn) ConnState() network.ConnectionState    { return c.conn.ConnState() }
func (c *webrtcSignalConn) Stat() network.ConnStats               { return network.ConnStats{} }
func (c *webrtcSignalConn) Scope() network.ConnScope              { return &network.NullScope{} }
func (c *webrtcSignalConn) NewStream(ctx context.Context) (network.Stream, error) {
	muxed, err := c.conn.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return &webrtcSignalStream{MuxedStream: muxed, conn: c}, nil
}
func (c *webrtcSignalConn) GetStreams() []network.Stream { return nil }

// webrtcSignalStream decorates the webrtc MuxedStream with the methods
// network.Stream requires (Conn / ID / Protocol / Stat / Scope / ResetWithError).
type webrtcSignalStream struct {
	network.MuxedStream
	conn *webrtcSignalConn
}

var _ network.Stream = (*webrtcSignalStream)(nil)

func (s *webrtcSignalStream) ID() string                    { return "webrtc-signal" }
func (s *webrtcSignalStream) Protocol() protocol.ID         { return "" }
func (s *webrtcSignalStream) SetProtocol(id protocol.ID) error { return nil }
func (s *webrtcSignalStream) Stat() network.Stats           { return network.Stats{} }
func (s *webrtcSignalStream) Conn() network.Conn            { return s.conn }
func (s *webrtcSignalStream) Scope() network.StreamScope    { return &network.NullScope{} }
func (s *webrtcSignalStream) ResetWithError(code network.StreamErrorCode) error {
	return s.MuxedStream.Reset()
}
