package node

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// signalTestStream is a network.Stream whose reads come from a fixed byte slice
// and whose writes are captured into a buffer, so nodeSignalTransport can be
// exercised without a live libp2p connection.
type signalTestStream struct {
	mockWriteStream
	r *bytes.Reader
}

func (s *signalTestStream) Read(p []byte) (int, error) { return s.r.Read(p) }

func newSignalTestStream(wire []byte) *signalTestStream {
	return &signalTestStream{r: bytes.NewReader(wire)}
}

// framePayload produces the on-wire framing ReadFrame expects:
// [4-byte big-endian length][payload].
func framePayload(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out[:4], uint32(len(payload)))
	copy(out[4:], payload)
	return out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestWebRTCSignalMsgRoundTrip pins the JSON contract carried on a
// /p2ptap/webrtc-signal/1.0.0 stream: a "type" discriminator plus the raw SDP.
func TestWebRTCSignalMsgRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		msg webrtcSignalMsg
	}{
		{webrtcSignalMsg{Type: "offer", SDP: "v=0\r\na=offer\r\n"}},
		{webrtcSignalMsg{Type: "answer", SDP: "v=0\r\na=answer\r\n"}},
	} {
		wire, err := json.Marshal(tc.msg)
		if err != nil {
			t.Fatalf("marshal %+v: %v", tc.msg, err)
		}
		var got webrtcSignalMsg
		if err := json.Unmarshal(wire, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got != tc.msg {
			t.Errorf("round-trip = %+v, want %+v", got, tc.msg)
		}
	}
}

// TestWebRTCSignalRecvSDP validates the type discriminator and error paths of
// nodeSignalTransport.RecvSDP.
func TestWebRTCSignalRecvSDP(t *testing.T) {
	ctx := context.Background()

	t.Run("answer is not an offer", func(t *testing.T) {
		wire, _ := json.Marshal(webrtcSignalMsg{Type: "answer", SDP: "v=0"})
		st := &nodeSignalTransport{s: newSignalTestStream(framePayload(wire))}
		sdp, isOffer, err := st.RecvSDP(ctx)
		if err != nil {
			t.Fatalf("RecvSDP: %v", err)
		}
		if sdp != "v=0" || isOffer {
			t.Errorf("got sdp=%q isOffer=%v, want v=0 false", sdp, isOffer)
		}
	})

	t.Run("offer is an offer", func(t *testing.T) {
		wire, _ := json.Marshal(webrtcSignalMsg{Type: "offer", SDP: "v=0"})
		st := &nodeSignalTransport{s: newSignalTestStream(framePayload(wire))}
		sdp, isOffer, err := st.RecvSDP(ctx)
		if err != nil {
			t.Fatalf("RecvSDP: %v", err)
		}
		if !isOffer {
			t.Errorf("got isOffer=false, want true")
		}
		if sdp != "v=0" {
			t.Errorf("got sdp=%q, want v=0", sdp)
		}
	})

	t.Run("unknown type is rejected", func(t *testing.T) {
		wire, _ := json.Marshal(webrtcSignalMsg{Type: "pranswer", SDP: "v=0"})
		st := &nodeSignalTransport{s: newSignalTestStream(framePayload(wire))}
		if _, _, err := st.RecvSDP(ctx); err == nil {
			t.Fatal("RecvSDP accepted unknown type")
		}
	})

	t.Run("malformed JSON is rejected", func(t *testing.T) {
		st := &nodeSignalTransport{s: newSignalTestStream(framePayload([]byte("not-json")))}
		if _, _, err := st.RecvSDP(ctx); err == nil {
			t.Fatal("RecvSDP accepted malformed JSON")
		}
	})

	t.Run("truncated frame is an error", func(t *testing.T) {
		// Frame announces 100 bytes but only delivers 4.
		st := &nodeSignalTransport{s: newSignalTestStream([]byte{0, 0, 0, 100, 'x', 'y', 'z', 'w'})}
		if _, _, err := st.RecvSDP(ctx); err == nil {
			t.Fatal("RecvSDP accepted a truncated frame")
		}
	})

	t.Run("cancelled context short-circuits", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		st := &nodeSignalTransport{s: newSignalTestStream(nil)}
		if _, _, err := st.RecvSDP(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("RecvSDP err = %v, want context.Canceled", err)
		}
	})
}

// TestWebRTCSignalSendSDP verifies the offer/answer type written onto the wire
// and the framing itself.
func TestWebRTCSignalSendSDP(t *testing.T) {
	ctx := context.Background()

	t.Run("offer", func(t *testing.T) {
		stream := &signalTestStream{}
		st := &nodeSignalTransport{s: stream}
		if err := st.SendSDP(ctx, "v=0", true); err != nil {
			t.Fatalf("SendSDP: %v", err)
		}
		// The buffer holds the full framed record: [4-byte length][payload].
		wire := stream.buf.Bytes()
		if len(wire) < 4 {
			t.Fatalf("written %d bytes, want framed payload", len(wire))
		}
		var msg webrtcSignalMsg
		if err := json.Unmarshal(wire[4:], &msg); err != nil {
			t.Fatalf("unmarshal written payload: %v", err)
		}
		if msg.Type != "offer" || msg.SDP != "v=0" {
			t.Errorf("written = %+v, want offer/v=0", msg)
		}
	})

	t.Run("answer", func(t *testing.T) {
		stream := &signalTestStream{}
		st := &nodeSignalTransport{s: stream}
		if err := st.SendSDP(ctx, "v=0", false); err != nil {
			t.Fatalf("SendSDP: %v", err)
		}
		wire := stream.buf.Bytes()
		if len(wire) < 4 {
			t.Fatalf("written %d bytes, want framed payload", len(wire))
		}
		var msg webrtcSignalMsg
		if err := json.Unmarshal(wire[4:], &msg); err != nil {
			t.Fatalf("unmarshal written payload: %v", err)
		}
		if msg.Type != "answer" {
			t.Errorf("written type = %q, want answer", msg.Type)
		}
	})

	t.Run("cancelled context short-circuits", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		st := &nodeSignalTransport{s: &signalTestStream{}}
		if err := st.SendSDP(ctx, "v=0", true); !errors.Is(err, context.Canceled) {
			t.Fatalf("SendSDP err = %v, want context.Canceled", err)
		}
	})
}

// TestWebRTCSignalOfferer pins the glare-avoidance role rule: the HIGHER
// peer.ID offers, the lower answers. It must be deterministic and asymmetric
// (one side always offers, never both).
func TestWebRTCSignalOfferer(t *testing.T) {
	mkID := func(t *testing.T) peer.ID {
		t.Helper()
		sk, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		id, err := peer.IDFromPrivateKey(sk)
		if err != nil {
			t.Fatalf("id from key: %v", err)
		}
		return id
	}

	high := mkID(t)
	low := mkID(t)
	if high == low {
		t.Fatal("generated identical peer IDs")
	}
	// Order by actual byte comparison to keep the assertion independent of the
	// specific values generated.
	highIsGreater := high > low
	if highIsGreater {
		if !webrtcSignalOfferer(high, low) || webrtcSignalOfferer(low, high) {
			t.Errorf("offerer(high,low)=%v offerer(low,high)=%v, want true false", webrtcSignalOfferer(high, low), webrtcSignalOfferer(low, high))
		}
	} else {
		if !webrtcSignalOfferer(low, high) || webrtcSignalOfferer(high, low) {
			t.Errorf("offerer(low,high)=%v offerer(high,low)=%v, want true false", webrtcSignalOfferer(low, high), webrtcSignalOfferer(high, low))
		}
	}
	// Exactly one side offers — never a tie.
	if webrtcSignalOfferer(high, low) == webrtcSignalOfferer(low, high) {
		t.Errorf("both sides report the same role: high=%v low=%v", webrtcSignalOfferer(high, low), webrtcSignalOfferer(low, high))
	}
}

// TestWebRTCSignalRecvSDPEOF documents the idle-signal behavior: a peer that
// closes the stream without sending an SDP surfaces as an EOF, which the caller
// treats as a failed upgrade (not a hang).
func TestWebRTCSignalRecvSDPEOF(t *testing.T) {
	st := &nodeSignalTransport{s: newSignalTestStream(nil)}
	if _, _, err := st.RecvSDP(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("RecvSDP on empty stream err = %v, want io.EOF", err)
	}
}
