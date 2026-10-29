package libp2pwebrtc

import (
	"context"
	"testing"
	"time"

	tpt "github.com/libp2p/go-libp2p/core/transport"
	"github.com/stretchr/testify/require"
)

type signalMsg struct {
	sdp   string
	offer bool
}

// memSignal is an in-memory SignalTransport pair for tests (non-trickle: one
// message each way).
type memSignal struct {
	sendCh chan signalMsg
	recvCh chan signalMsg
}

func newMemSignalPair() (*memSignal, *memSignal) {
	a2b := make(chan signalMsg, 1)
	b2a := make(chan signalMsg, 1)
	return &memSignal{sendCh: a2b, recvCh: b2a}, &memSignal{sendCh: b2a, recvCh: a2b}
}

func (m *memSignal) SendSDP(ctx context.Context, sdp string, isOffer bool) error {
	select {
	case m.sendCh <- signalMsg{sdp: sdp, offer: isOffer}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *memSignal) RecvSDP(ctx context.Context) (string, bool, error) {
	select {
	case msg := <-m.recvCh:
		return msg.sdp, msg.offer, nil
	case <-ctx.Done():
		return "", false, ctx.Err()
	}
}

func TestTransportSignalDialAccept(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	dialer, dialerID := getTransport(t)
	responder, responderID := getTransport(t)

	dialerSig, responderSig := newMemSignalPair()

	var accepted tpt.CapableConn
	acceptErrCh := make(chan error, 1)
	go func() {
		conn, err := responder.AcceptSignal(ctx, dialerID, responderSig)
		if err != nil {
			acceptErrCh <- err
			return
		}
		accepted = conn
		acceptErrCh <- nil
	}()

	conn, err := dialer.DialSignal(ctx, responderID, dialerSig)
	require.NoError(t, err)
	require.NoError(t, <-acceptErrCh)
	require.NotNil(t, accepted)
	require.Equal(t, responderID, conn.RemotePeer())
	require.Equal(t, dialerID, accepted.RemotePeer())

	// Two-way stream over the negotiated connection.
	s1, err := conn.OpenStream(ctx)
	require.NoError(t, err)
	s2, err := accepted.AcceptStream()
	require.NoError(t, err)
	defer s1.Close()
	defer s2.Close()

	_, err = s1.Write([]byte("hello-from-dialer"))
	require.NoError(t, err)
	buf := make([]byte, 64)
	rn, err := s2.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello-from-dialer", string(buf[:rn]))

	_, err = s2.Write([]byte("hello-from-responder"))
	require.NoError(t, err)
	rn, err = s1.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello-from-responder", string(buf[:rn]))
}

func TestTransportSignalRecvAnswerExpected(t *testing.T) {
	// A dialer receiving an offer where it expected an answer must fail fast.
	dialer, responderID := getTransport(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The dialer receives an offer where it expected an answer (wrong role) —
	// it must fail fast instead of trying to SetRemoteDescription an offer.
	badSig := &memSignal{sendCh: make(chan signalMsg, 1), recvCh: make(chan signalMsg, 1)}
	badSig.recvCh <- signalMsg{sdp: "v=0\r\n", offer: true}
	_, err := dialer.DialSignal(ctx, responderID, badSig)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected answer")
}

func TestSDPFingerprintHash(t *testing.T) {
	h, err := sdpFingerprintHash("v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=fingerprint:sha-256 aa:bb\r\n")
	require.NoError(t, err)
	require.Equal(t, "SHA-256", h.String())

	_, err = sdpFingerprintHash("v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n")
	require.Error(t, err)
}
