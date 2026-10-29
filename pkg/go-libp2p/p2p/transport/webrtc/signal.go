package libp2pwebrtc

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	tpt "github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/pion/webrtc/v4"
)

// SignalTransport carries the SDP offer/answer for a signaled WebRTC dial.
//
// The exchange is NON-trickle: the offer is sent exactly once after local ICE
// gathering completes (so it already contains every gathered host / srflx /
// TURN-relay candidate), and the answer is received exactly once. The remote
// SDP is what carries the remote's gathered candidates — this is the piece
// webrtc-direct cannot do, because it synthesizes the SDP from a multiaddr and
// therefore only ever knows a single host candidate.
//
// Implementations decide the transport (a direct stream, an overlay relay
// tunnel, a circuit-relay stream, ...) and own the timeout.
type SignalTransport interface {
	// SendSDP delivers one side's SDP (isOffer=true for the offerer).
	SendSDP(ctx context.Context, sdp string, isOffer bool) error
	// RecvSDP blocks until the peer's SDP arrives, or returns on ctx.
	RecvSDP(ctx context.Context) (sdp string, isOffer bool, err error)
}

// DialSignal establishes a full-ICE WebRTC connection to remote, exchanging
// SDP through sig instead of inferring it from a /webrtc-direct multiaddr.
//
// Unlike WebRTC Direct (no signaling), this peer connection is a FULL ICE agent
// (SetLite(false) — the default), so it gathers host, server-reflexive (STUN)
// and relay (TURN) candidates and the remote learns them from the SDP. That is
// what lets the connection survive when the remote listener sits behind NAT:
// the answer's srflx/relay candidates are reachable, whereas the single host
// candidate webrtc-direct would have used is not.
//
// The connection is fully authenticated (DTLS + Noise over the negotiated
// data channel 0) and returned as a CapableConn that is NOT registered with any
// swarm — the caller decides how to surface it (e.g. register its streams with
// a strategy dispatcher).
func (t *WebRTCTransport) DialSignal(ctx context.Context, remote peer.ID, sig SignalTransport) (tpt.CapableConn, error) {
	scope, err := t.rcmgr.OpenConnection(network.DirOutbound, false, nil)
	if err != nil {
		return nil, err
	}
	if err := scope.SetPeer(remote); err != nil {
		scope.Done()
		return nil, err
	}
	conn, err := t.dialSignal(ctx, scope, remote, sig)
	if err != nil {
		scope.Done()
		return nil, err
	}
	return conn, nil
}

func (t *WebRTCTransport) dialSignal(ctx context.Context, scope network.ConnManagementScope, remote peer.ID, sig SignalTransport) (tConn tpt.CapableConn, err error) {
	var w webRTCConnection
	defer func() {
		if err != nil {
			if w.PeerConnection != nil {
				_ = w.PeerConnection.Close()
			}
			if tConn != nil {
				_ = tConn.Close()
				tConn = nil
			}
		}
	}()

	settingEngine := webrtc.SettingEngine{LoggerFactory: pionLoggerFactory}
	if t.customNet != nil {
		settingEngine.SetNet(t.customNet)
	}
	// Full ICE agent (no SetLite): gather host + srflx + TURN relay candidates.
	// Both sides generate independent local credentials; the SDP carries them,
	// so no ufrag/pwd recovery-from-STUN trickery is needed (unlike webrtc-direct).
	settingEngine.SetICECredentials(randIceString(32), randIceString(32))
	settingEngine.DetachDataChannels()
	settingEngine.SetPrflxAcceptanceMinWait(0)
	settingEngine.SetICETimeouts(
		t.peerConnectionTimeouts.Disconnect,
		t.peerConnectionTimeouts.Failed,
		t.peerConnectionTimeouts.Keepalive,
	)
	settingEngine.SetIncludeLoopbackCandidate(true)
	settingEngine.SetSCTPMaxReceiveBufferSize(sctpReceiveBufferSize)
	if err := scope.ReserveMemory(sctpReceiveBufferSize, network.ReservationPriorityMedium); err != nil {
		return nil, err
	}

	w, err = newWebRTCConnection(settingEngine, t.configWithIceServers())
	if err != nil {
		return nil, fmt.Errorf("instantiating peer connection failed: %w", err)
	}
	errC := addOnConnectionStateChangeCallback(w.PeerConnection)
	gatherDone := waitForGatherComplete(w.PeerConnection)

	// Non-trickle offer: wait for gathering to finish so the SDP already carries
	// every candidate, then send it once.
	offer, err := w.PeerConnection.CreateOffer(nil)
	if err != nil {
		return nil, fmt.Errorf("create offer: %w", err)
	}
	if err := w.PeerConnection.SetLocalDescription(offer); err != nil {
		return nil, fmt.Errorf("set local description: %w", err)
	}
	select {
	case <-gatherDone:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	localDesc := w.PeerConnection.LocalDescription()
	if localDesc == nil {
		return nil, errors.New("local description nil after gathering")
	}
	if err := sig.SendSDP(ctx, localDesc.SDP, true); err != nil {
		return nil, fmt.Errorf("send offer: %w", err)
	}

	answerSDP, isOffer, err := sig.RecvSDP(ctx)
	if err != nil {
		return nil, fmt.Errorf("recv answer: %w", err)
	}
	if isOffer {
		return nil, errors.New("expected answer, got offer")
	}
	if err := w.PeerConnection.SetRemoteDescription(webrtc.SessionDescription{SDP: answerSDP, Type: webrtc.SDPTypeAnswer}); err != nil {
		return nil, fmt.Errorf("set remote description: %w", err)
	}

	// Await ICE + DTLS + SCTP connectivity.
	select {
	case err := <-errC:
		if err != nil {
			return nil, err
		}
	case <-ctx.Done():
		return nil, errors.New("peerconnection opening timed out")
	}

	// Run the Noise handshake over the negotiated data channel 0. We are the
	// DTLS server (we answer), matching webrtc-direct's dialer role, so the
	// inbound flag is false (SecureInbound).
	remoteHash, err := sdpFingerprintHash(answerSDP)
	if err != nil {
		return nil, fmt.Errorf("remote fingerprint: %w", err)
	}
	detached, err := detachHandshakeDataChannel(ctx, w.HandshakeDataChannel)
	if err != nil {
		return nil, err
	}
	channel := newStream(w.HandshakeDataChannel, detached, maxSendMessageSize, nil)
	remotePubKey, err := t.noiseHandshake(ctx, w.PeerConnection, channel, remote, remoteHash, false)
	if err != nil {
		return nil, err
	}

	// Derive local/remote multiaddrs from the selected candidate pair.
	cp, err := w.HandshakeDataChannel.Transport().Transport().ICETransport().GetSelectedCandidatePair()
	if err != nil {
		return nil, fmt.Errorf("ice selected candidate pair: %w", err)
	}
	if cp == nil {
		return nil, errors.New("ice connection did not have selected candidate pair: nil result")
	}
	localAddr, err := udpCandidateMultiaddr(cp.Local.Address, int(cp.Local.Port))
	if err != nil {
		return nil, err
	}
	remoteAddr, err := udpCandidateMultiaddr(cp.Remote.Address, int(cp.Remote.Port))
	if err != nil {
		return nil, err
	}

	conn, err := newConnection(network.DirOutbound, w.PeerConnection, t, scope,
		t.localPeerId, localAddr, remote, remotePubKey, remoteAddr,
		w.IncomingDataChannels, w.PeerConnectionClosedCh)
	if err != nil {
		return nil, err
	}
	if t.gater != nil && !t.gater.InterceptSecured(network.DirOutbound, remote, &connMultiaddrs{local: localAddr, remote: remoteAddr}) {
		_ = conn.Close()
		return nil, errors.New("gater rejected secured connection")
	}
	return conn, nil
}

// AcceptSignal accepts an inbound full-ICE WebRTC connection whose SDP offer
// arrives over sig. It answers with the local SDP (after gathering completes)
// and returns the authenticated connection. The caller must have already
// validated that remote is the peer it expects (the signal channel is trusted
// for peer identity; the Noise handshake enforces it cryptographically).
func (t *WebRTCTransport) AcceptSignal(ctx context.Context, remote peer.ID, sig SignalTransport) (tpt.CapableConn, error) {
	scope, err := t.rcmgr.OpenConnection(network.DirInbound, false, nil)
	if err != nil {
		return nil, err
	}
	if err := scope.SetPeer(remote); err != nil {
		scope.Done()
		return nil, err
	}
	conn, err := t.acceptSignal(ctx, scope, remote, sig)
	if err != nil {
		scope.Done()
		return nil, err
	}
	return conn, nil
}

func (t *WebRTCTransport) acceptSignal(ctx context.Context, scope network.ConnManagementScope, remote peer.ID, sig SignalTransport) (tConn tpt.CapableConn, err error) {
	var w webRTCConnection
	defer func() {
		if err != nil {
			if w.PeerConnection != nil {
				_ = w.PeerConnection.Close()
			}
			if tConn != nil {
				_ = tConn.Close()
				tConn = nil
			}
		}
	}()

	settingEngine := webrtc.SettingEngine{LoggerFactory: pionLoggerFactory}
	if t.customNet != nil {
		settingEngine.SetNet(t.customNet)
	}
	settingEngine.SetICECredentials(randIceString(32), randIceString(32))
	settingEngine.DetachDataChannels()
	settingEngine.SetPrflxAcceptanceMinWait(0)
	settingEngine.SetICETimeouts(
		t.peerConnectionTimeouts.Disconnect,
		t.peerConnectionTimeouts.Failed,
		t.peerConnectionTimeouts.Keepalive,
	)
	settingEngine.SetIncludeLoopbackCandidate(true)
	settingEngine.SetSCTPMaxReceiveBufferSize(sctpReceiveBufferSize)
	if err := scope.ReserveMemory(sctpReceiveBufferSize, network.ReservationPriorityMedium); err != nil {
		return nil, err
	}

	w, err = newWebRTCConnection(settingEngine, t.configWithIceServers())
	if err != nil {
		return nil, fmt.Errorf("instantiating peer connection failed: %w", err)
	}
	errC := addOnConnectionStateChangeCallback(w.PeerConnection)
	gatherDone := waitForGatherComplete(w.PeerConnection)

	offerSDP, isOffer, err := sig.RecvSDP(ctx)
	if err != nil {
		return nil, fmt.Errorf("recv offer: %w", err)
	}
	if !isOffer {
		return nil, errors.New("expected offer, got answer")
	}
	if err := w.PeerConnection.SetRemoteDescription(webrtc.SessionDescription{SDP: offerSDP, Type: webrtc.SDPTypeOffer}); err != nil {
		return nil, fmt.Errorf("set remote description: %w", err)
	}
	answer, err := w.PeerConnection.CreateAnswer(nil)
	if err != nil {
		return nil, fmt.Errorf("create answer: %w", err)
	}
	if err := w.PeerConnection.SetLocalDescription(answer); err != nil {
		return nil, fmt.Errorf("set local description: %w", err)
	}
	select {
	case <-gatherDone:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	localDesc := w.PeerConnection.LocalDescription()
	if localDesc == nil {
		return nil, errors.New("local description nil after gathering")
	}
	if err := sig.SendSDP(ctx, localDesc.SDP, false); err != nil {
		return nil, fmt.Errorf("send answer: %w", err)
	}

	select {
	case err := <-errC:
		if err != nil {
			return nil, err
		}
	case <-ctx.Done():
		return nil, errors.New("peerconnection opening timed out")
	}

	// We are the DTLS client (we offer), matching webrtc-direct's listener
	// role, so the inbound flag is true (SecureOutbound).
	remoteHash, err := sdpFingerprintHash(offerSDP)
	if err != nil {
		return nil, fmt.Errorf("remote fingerprint: %w", err)
	}
	detached, err := detachHandshakeDataChannel(ctx, w.HandshakeDataChannel)
	if err != nil {
		return nil, err
	}
	channel := newStream(w.HandshakeDataChannel, detached, maxSendMessageSize, nil)
	remotePubKey, err := t.noiseHandshake(ctx, w.PeerConnection, channel, remote, remoteHash, true)
	if err != nil {
		return nil, err
	}

	cp, err := w.HandshakeDataChannel.Transport().Transport().ICETransport().GetSelectedCandidatePair()
	if err != nil {
		return nil, fmt.Errorf("ice selected candidate pair: %w", err)
	}
	if cp == nil {
		return nil, errors.New("ice connection did not have selected candidate pair: nil result")
	}
	localAddr, err := udpCandidateMultiaddr(cp.Local.Address, int(cp.Local.Port))
	if err != nil {
		return nil, err
	}
	remoteAddr, err := udpCandidateMultiaddr(cp.Remote.Address, int(cp.Remote.Port))
	if err != nil {
		return nil, err
	}

	conn, err := newConnection(network.DirInbound, w.PeerConnection, t, scope,
		t.localPeerId, localAddr, remote, remotePubKey, remoteAddr,
		w.IncomingDataChannels, w.PeerConnectionClosedCh)
	if err != nil {
		return nil, err
	}
	if t.gater != nil && !t.gater.InterceptSecured(network.DirInbound, remote, &connMultiaddrs{local: localAddr, remote: remoteAddr}) {
		_ = conn.Close()
		return nil, errors.New("gater rejected secured connection")
	}
	return conn, nil
}

// udpCandidateMultiaddr builds a UDP multiaddr from a candidate address/port.
func udpCandidateMultiaddr(address string, port int) (ma.Multiaddr, error) {
	return manet.FromNetAddr(&net.UDPAddr{IP: net.ParseIP(address), Port: port})
}

// sdpFingerprintHash maps the a=fingerprint: line of an SDP to the crypto.Hash
// used to verify the remote DTLS certificate (and to seed the Noise prologue).
// webrtc-direct derives this from the /certhash multiaddr; signaled mode must
// read it out of the SDP, since there is no multiaddr.
func sdpFingerprintHash(sdp string) (crypto.Hash, error) {
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "a=fingerprint:") {
			continue
		}
		algo := strings.SplitN(strings.TrimPrefix(line, "a=fingerprint:"), " ", 2)[0]
		switch algo {
		case "md5":
			return crypto.MD5, nil
		case "sha-1":
			return crypto.SHA1, nil
		case "sha3-224":
			return crypto.SHA3_224, nil
		case "sha-256":
			return crypto.SHA256, nil
		case "sha3-384":
			return crypto.SHA3_384, nil
		case "sha-512":
			return crypto.SHA512, nil
		default:
			return 0, fmt.Errorf("unsupported fingerprint algorithm %q", algo)
		}
	}
	return 0, errors.New("no a=fingerprint line in SDP")
}

// signalDialTimeout is the default per-phase deadline a caller should apply to
// a signaled dial/accept (gathering + SDP exchange + ICE + Noise). The ICE
// gather of a TURN relay can take several seconds; the noise handshake runs on
// top of SCTP. This mirrors the WebRTC Direct dial time budget so a slow but
// reachable peer still succeeds.
const signalDialTimeout = 30 * time.Second

// waitForGatherComplete returns a channel closed when ICE gathering finishes.
// It must be called BEFORE CreateOffer/SetLocalDescription so the state-change
// handler is armed before gathering starts (pion fires the callback only on
// state transitions, not for an already-complete gatherer). Non-trickle mode
// waits for the full candidate set so the SDP we send already carries every
// host / srflx / TURN-relay candidate.
func waitForGatherComplete(pc *webrtc.PeerConnection) <-chan struct{} {
	done := make(chan struct{})
	var once sync.Once
	pc.OnICEGatheringStateChange(func(s webrtc.ICEGatheringState) {
		if s == webrtc.ICEGatheringStateComplete {
			once.Do(func() { close(done) })
		}
	})
	return done
}
