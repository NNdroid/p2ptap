package libp2pwebrtc

import (
	"bytes"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/pion/webrtc/v4"
)

func testKey(t *testing.T) crypto.PrivKey {
	t.Helper()
	k, _, err := crypto.GenerateEd25519Key(bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}
	return k
}

// TestWithTURNServersWithoutCredentialsDoesNotPoisonPeerConnections guards the
// option pair that TURN support depends on. pion's ICEServer.validate rejects a
// turn: URL with no Username or Credential, and PeerConnection.initConfiguration
// returns on the first invalid server — so a TURN list registered without
// credentials did not fall back to host/reflexive candidates, it made every
// WebRTC dial and answer fail. The transport therefore has to refuse to emit
// them.
func TestWithTURNServersWithoutCredentialsDoesNotPoisonPeerConnections(t *testing.T) {
	tpt, err := New(testKey(t), nil, nil, nil, nil, WithTURNServers([]string{"turn:turn.cloud-rtc.com:80"}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(tpt.webrtcConfig.ICEServers) != 0 {
		t.Fatalf("emitted %d ICE servers without credentials: %v", len(tpt.webrtcConfig.ICEServers), tpt.webrtcConfig.ICEServers)
	}

	// Sanity: had it emitted the entry, pion would have rejected it.
	_, err = webrtc.NewPeerConnection(webrtc.Configuration{ICEServers: []webrtc.ICEServer{
		{URLs: []string{"turn:turn.cloud-rtc.com:80"}},
	}})
	if err == nil {
		t.Fatal("pion accepted a credential-less TURN server; the guard is no longer needed")
	}
}

func TestWithTURNServersWithCredentialsEmitsThem(t *testing.T) {
	tpt, err := New(testKey(t), nil, nil, nil, nil,
		WithSTUNServers([]string{"/udp/stun.l.google.com/19302"}),
		WithTURNServers([]string{"turn:relay1.expressturn.com:3478"}),
		WithTURNCredentials("alice", "s3cr3t"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(tpt.webrtcConfig.ICEServers) != 2 {
		t.Fatalf("ICE servers = %v, want 2 entries", tpt.webrtcConfig.ICEServers)
	}

	turn := tpt.webrtcConfig.ICEServers[1]
	if len(turn.URLs) != 1 || turn.URLs[0] != "turn:relay1.expressturn.com:3478" {
		t.Fatalf("TURN entry = %v", turn)
	}
	if turn.Username != "alice" || turn.Credential != "s3cr3t" || turn.CredentialType != webrtc.ICECredentialTypePassword {
		t.Fatalf("TURN credentials = (user=%q cred=%q type=%v)", turn.Username, turn.Credential, turn.CredentialType)
	}

	// The config the transport actually produced must be accepted by pion.
	_, err = webrtc.NewPeerConnection(tpt.webrtcConfig)
	if err != nil {
		t.Fatalf("pion rejected the transport's own ICE config: %v", err)
	}
}

func TestWithTURNCredentialsAloneEmitsNoServers(t *testing.T) {
	tpt, err := New(testKey(t), nil, nil, nil, nil, WithTURNCredentials("alice", "s3cr3t"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(tpt.webrtcConfig.ICEServers) != 0 {
		t.Fatalf("ICE servers = %v, want none", tpt.webrtcConfig.ICEServers)
	}
}
