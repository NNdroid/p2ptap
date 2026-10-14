package node

import (
	"errors"
	"strings"
	"testing"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	"github.com/pion/webrtc/v4"

	"p2ptap/pkg/config"
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
// "everything except QUIC barely connects" report. The pre-2026-10 default
// TurnServers list was entirely anonymous, and passing it straight to pion made
// every PeerConnection fail before ICE even started. The default is empty now,
// but a legacy config file (or a hand-edited one) can still carry such URLs, so
// the drop has to keep working.
func TestIceTURNConfigDropsCredentialLessServers(t *testing.T) {
	anonymous := []string{
		"turn:turn.cloud-rtc.com:80",
		"turn:w1.xirsys.com:3478",
		"turn:global.turn.twilio.com:3478",
	}
	urls, user, cred, dropped := IceTURNConfig(anonymous)
	if len(urls) != 0 {
		t.Fatalf("urls = %v, want none", urls)
	}
	if user != "" || cred != "" {
		t.Fatalf("credentials = (%q,%q), want empty", user, cred)
	}
	if dropped != len(anonymous) {
		t.Fatalf("dropped = %d, want %d", dropped, len(anonymous))
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

// TestLiteAgentRefusesICEServers is the regression guard for "WebRTC never
// connects". It pins the pion invariant the WebRTC Direct listener relies on:
//
// WebRTC Direct's listener is a LITE ICE agent (SettingEngine.SetLite(true)),
// so pion builds its agent with CandidateTypes = [host] only. pion's NewAgent
// then refuses to build an agent that was handed ICE server URLs it can never
// use:
//
//	if len(config.Urls) > 0 && !contains(srflx) && !contains(relay) {
//		return nil, ErrUselessUrlsProvided
//	}
//
// A lite agent has neither of those candidate types, so handing it ANY
// STUN/TURN server made every inbound WebRTC peer connection fail immediately
// with "agent does not need URL with selected candidate types". DefaultConfig
// ships eight UDP STUN servers, so WebRTC was completely dead out of the box
// and the failure was invisible in CI because the transport matrix treated it
// as an expected skip. The listener now strips the server list before handing
// the config to a lite agent; this test fails if either half of that breaks —
// pion starts accepting the combination (the strip becomes a silent no-op if
// the wrong thing is being guarded) or pion stops accepting a clean lite agent
// (the strip becomes too aggressive).
//
// NewAgent returns the error synchronously before any socket is opened, so the
// test is deterministic and needs no network.
func TestLiteAgentRefusesICEServers(t *testing.T) {
	srv, err := stun.ParseURI("stun:stun.l.google.com:19302")
	if err != nil {
		t.Fatalf("parse STUN URL: %v", err)
	}

	lite := func() *ice.AgentConfig {
		return &ice.AgentConfig{
			Lite:           true,
			CandidateTypes: []ice.CandidateType{ice.CandidateTypeHost},
		}
	}

	cfg := lite()
	cfg.Urls = []*stun.URI{srv}
	agent, err := ice.NewAgent(cfg)
	if !errors.Is(err, ice.ErrUselessUrlsProvided) {
		t.Fatalf("lite agent with an ICE server was accepted (err=%v agent=%v): the WebRTC "+
			"listener MUST strip ICEServers, otherwise every inbound WebRTC connection "+
			"is refused", err, agent != nil)
	}

	if _, err := ice.NewAgent(lite()); err != nil {
		t.Fatalf("lite agent with no ICE servers was rejected: %v", err)
	}

	// The same STUN server is fine for a FULL agent: the guard is specific to
	// lite, which is what makes stripping servers only on the listener side
	// correct. The dialer is a full agent and legitimately keeps STUN/TURN.
	full := lite()
	full.Lite = false
	full.CandidateTypes = []ice.CandidateType{
		ice.CandidateTypeHost,
		ice.CandidateTypeServerReflexive,
		ice.CandidateTypeRelay,
	}
	full.Urls = []*stun.URI{srv}
	if _, err := ice.NewAgent(full); err != nil {
		t.Fatalf("full agent with an ICE server was rejected: %v", err)
	}
}

// TestDefaultSTUNServersSurviveTheLiteAgent is a staleness guard for
// TestLiteAgentRefusesICEServers. The defect only bites when the default config
// actually ships STUN servers, so if someone empties StunServers this test must
// fail: the guard above would otherwise stop testing anything, and the next
// person to touch WebRTC would rediscover the bug from scratch.
//
// Only UDP STUN servers count — buildIceServers skips /tcp/ entries (WebRTC ICE
// speaks UDP only) — so the assertion mirrors what the transport actually sees.
func TestDefaultSTUNServersSurviveTheLiteAgent(t *testing.T) {
	udp := 0
	for _, srv := range config.DefaultConfig().StunServers {
		if !strings.HasPrefix(srv, "/tcp/") {
			udp++
		}
	}
	if udp == 0 {
		t.Fatal("DefaultConfig().StunServers carries no UDP STUN server: the WebRTC " +
			"lite-agent guard has nothing to protect against, so restore the list")
	}
}
