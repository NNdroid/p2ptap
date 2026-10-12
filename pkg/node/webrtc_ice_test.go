package node

import (
	"testing"

	"github.com/pion/webrtc/v4"
)

// TestIceTURNConfigStripsQueryProvesPionAcceptsTheResult locks down the whole
// chain behind the WebRTC TURN fix. pion rejects a credential-less TURN ICE
// server with ErrNoTurnCredentials, and PeerConnection.initConfiguration returns
// on the FIRST invalid server, so one anonymous entry in the ICE list disabled
// every WebRTC dial and answer — not just the TURN paths. IceTURNConfig must
// therefore hand back URLs that pion will actually accept.
func TestIceTURNConfigStripsQueryProvesPionAcceptsTheResult(t *testing.T) {
	_, user, cred, dropped := IceTURNConfig([]string{
		"turn:relay1.expressturn.com:3478?username=alice&credential=s3cr3t",
	})
	if user != "alice" || cred != "s3cr3t" {
		t.Fatalf("credentials = (%q,%q), want (alice,s3cr3t)", user, cred)
	}
	if dropped != 0 {
		t.Fatalf("dropped = %d, want 0", dropped)
	}

	// The URL handed to pion must carry no query: stun.ParseURI returns
	// "invalid query" for an unknown query string, so the original form fails
	// validation too.
	_, err := webrtc.NewPeerConnection(webrtc.Configuration{ICEServers: []webrtc.ICEServer{
		{URLs: []string{"turn:relay1.expressturn.com:3478?username=alice&credential=s3cr3t"}},
	}})
	if err == nil {
		t.Fatal("raw ?username= URL was accepted; stripping it would be unnecessary")
	}
	_, err = webrtc.NewPeerConnection(webrtc.Configuration{ICEServers: []webrtc.ICEServer{
		{URLs: []string{"turn:relay1.expressturn.com:3478"},
			Username: user, Credential: cred, CredentialType: webrtc.ICECredentialTypePassword},
	}})
	if err != nil {
		t.Fatalf("stripped URL with credentials rejected: %v", err)
	}
}

// TestIceTURNConfigDropsCredentialLessServers is the regression test for the
// "everything except QUIC barely connects" report. The default TurnServers list
// is entirely credential-less, and passing it straight to pion made every
// PeerConnection fail before ICE even started.
func TestIceTURNConfigDropsCredentialLessServers(t *testing.T) {
	defaults := []string{
		"turn:turn.cloud-rtc.com:80",
		"turn:w1.xirsys.com:3478",
		"turn:global.turn.twilio.com:3478",
	}
	urls, user, cred, dropped := IceTURNConfig(defaults)
	if len(urls) != 0 {
		t.Fatalf("urls = %v, want none", urls)
	}
	if user != "" || cred != "" {
		t.Fatalf("credentials = (%q,%q), want empty", user, cred)
	}
	if dropped != len(defaults) {
		t.Fatalf("dropped = %d, want %d", dropped, len(defaults))
	}

	// The shape p2ptap used to emit: STUN plus credential-less TURN. This is the
	// exact failure mode — the whole peer connection dies.
	_, err := webrtc.NewPeerConnection(webrtc.Configuration{ICEServers: []webrtc.ICEServer{
		{URLs: []string{"stun:stun.l.google.com:19302"}},
		{URLs: []string{"turn:turn.cloud-rtc.com:80"}},
	}})
	if err == nil {
		t.Fatal("credential-less TURN was accepted; the reported failure mode no longer reproduces")
	}

	// With the credential-less servers dropped, the same STUN server is fine —
	// which is the state IceTURNConfig now leaves WebRTC in.
	_, err = webrtc.NewPeerConnection(webrtc.Configuration{ICEServers: []webrtc.ICEServer{
		{URLs: []string{"stun:stun.l.google.com:19302"}},
	}})
	if err != nil {
		t.Fatalf("STUN-only ICE rejected: %v", err)
	}
}

// TestIceTURNConfigRejectsMixedCredentials makes sure a server whose pair
// differs from the first one is left out instead of poisoning the list, since
// pion applies one credential pair per ICEServer entry.
func TestIceTURNConfigRejectsMixedCredentials(t *testing.T) {
	urls, user, cred, dropped := IceTURNConfig([]string{
		"turn:a.example.com:3478?username=u1&credential=c1",
		"turn:b.example.com:3478?username=u2&credential=c2",
		"turn:c.example.com:3478?username=u1&credential=c1",
	})
	if len(urls) != 2 || urls[0] != "turn:a.example.com:3478" || urls[1] != "turn:c.example.com:3478" {
		t.Fatalf("urls = %v", urls)
	}
	if user != "u1" || cred != "c1" {
		t.Fatalf("credentials = (%q,%q), want (u1,c1)", user, cred)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
}

func TestIceTURNConfigEmpty(t *testing.T) {
	urls, user, cred, dropped := IceTURNConfig(nil)
	if len(urls) != 0 || user != "" || cred != "" || dropped != 0 {
		t.Fatalf("got urls=%v user=%q cred=%q dropped=%d", urls, user, cred, dropped)
	}
}
