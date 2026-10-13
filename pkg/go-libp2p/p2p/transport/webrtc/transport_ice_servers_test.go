package libp2pwebrtc

import (
	"strings"
	"testing"

	"github.com/pion/webrtc/v4"
)

// TestBuildIceServers pins the p2ptap -> pion URL translation. Every form the
// config accepts must land as a server pion will actually accept, and nothing
// must be emitted that pion would reject (a single bad server aborts the whole
// peer connection, STUN-only ones included).
func TestBuildIceServers(t *testing.T) {
	stun := []string{
		"/udp/stun.l.google.com:19302",     // multiaddr form
		"stun:stun1.l.google.com:19302",    // already in pion form
		"stun2.l.google.com:19302",         // bare host:port
		"stun3.l.google.com",               // bare host, needs the default port
		"/tcp/relay1.expressturn.com:3478", // TCP: WebRTC ICE speaks UDP only
	}
	turn := []string{
		"turn:turn.cloud-rtc.com:80",
		"turn:relay1.expressturn.com:3478",
	}

	got := buildIceServers(stun, turn, "user", "cred")

	if len(got) != 6 {
		t.Fatalf("built %d ICE servers, want 6 (5 STUN minus 1 TCP, plus 2 TURN): %v", len(got), got)
	}

	var urls []string
	for _, s := range got {
		urls = append(urls, s.URLs...)
		if strings.HasPrefix(s.URLs[0], "turn:") {
			if s.Username != "user" || s.Credential != "cred" {
				t.Fatalf("TURN server %v missing credentials: user=%q cred=%q", s.URLs, s.Username, s.Credential)
			}
			if s.CredentialType != webrtc.ICECredentialTypePassword {
				t.Fatalf("TURN server %v credential type = %v, want Password", s.URLs, s.CredentialType)
			}
			continue
		}
		// The CredentialType zero value IS Password, so it cannot tell a STUN
		// entry from a TURN one; the credentials themselves can.
		if s.Username != "" || s.Credential != nil {
			t.Fatalf("STUN server %v must carry no credentials: %q / %v", s.URLs, s.Username, s.Credential)
		}
	}

	want := []string{
		"stun:stun.l.google.com:19302",
		"stun:stun1.l.google.com:19302",
		"stun:stun2.l.google.com:19302",
		"stun:stun3.l.google.com:19302",
		"turn:turn.cloud-rtc.com:80",
		"turn:relay1.expressturn.com:3478",
	}
	if len(urls) != len(want) {
		t.Fatalf("got %d URLs, want %d: %v", len(urls), len(want), urls)
	}
	for i := range want {
		if urls[i] != want[i] {
			t.Errorf("URL[%d] = %q, want %q", i, urls[i], want[i])
		}
	}

	// A credential-less TURN list must come back with only the STUN servers, so
	// the connection degrades instead of aborting.
	if got := buildIceServers(stun, turn, "", ""); len(got) != 4 {
		t.Fatalf("credential-less TURN list produced %d servers, want the 4 STUN ones: %v", len(got), got)
	}
}

// TestWithIceServersProviderResolvesPerConnection is the regression test for
// the STUN/TURN lists being frozen at transport construction: the provider must
// be consulted for every new peer connection, and it must not mutate the
// transport's base configuration.
func TestWithIceServersProviderResolvesPerConnection(t *testing.T) {
	var stun, turn []string
	tpt, err := New(testKey(t), nil, nil, nil, nil, WithIceServers(
		func() []string { return stun },
		func() []string { return turn },
		func() (username, credential string) { return "user", "cred" },
	))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	stun = []string{"stun:stun1.l.google.com:19302"}
	first := tpt.configWithIceServers()
	if len(first.ICEServers) != 1 {
		t.Fatalf("first resolution produced %d servers, want 1", len(first.ICEServers))
	}

	// Reload: the next connection must see the new list.
	stun = []string{"stun:stun2.l.google.com:19302"}
	turn = []string{"turn:turn.cloud-rtc.com:80"}
	second := tpt.configWithIceServers()
	if len(second.ICEServers) != 2 {
		t.Fatalf("after reload got %d servers, want 2: %v", len(second.ICEServers), second.ICEServers)
	}
	if got := second.ICEServers[0].URLs[0]; got != "stun:stun2.l.google.com:19302" {
		t.Fatalf("after reload URL = %q, want the reloaded server", got)
	}

	// The base configuration must be untouched, so code that still reads
	// webrtcConfig directly observes the construction-time view.
	if len(tpt.webrtcConfig.ICEServers) != 0 {
		t.Fatalf("base configuration was mutated by the provider: %v", tpt.webrtcConfig.ICEServers)
	}

	// Certificates from the base configuration must survive the override.
	if len(second.Certificates) != 1 {
		t.Fatalf("Certificates = %d, want the base certificate", len(second.Certificates))
	}
}

// TestWithIceServersNilProviders documents that nil arguments mean "no such
// servers" rather than a nil-function panic mid-handshake.
func TestWithIceServersNilProviders(t *testing.T) {
	tpt, err := New(testKey(t), nil, nil, nil, nil, WithIceServers(nil, nil, nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := tpt.configWithIceServers(); len(got.ICEServers) != 0 {
		t.Fatalf("nil providers produced %d ICE servers, want none", len(got.ICEServers))
	}
}

// TestWithIceServersOverridesStaticOptions confirms the provider subsumes the
// static pair instead of supplementing it, so a caller that sets both does not
// end up with a doubled list.
func TestWithIceServersOverridesStaticOptions(t *testing.T) {
	tpt, err := New(testKey(t), nil, nil, nil, nil,
		WithSTUNServers([]string{"stun:stun1.l.google.com:19302"}),
		WithIceServers(nil, nil, nil),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := tpt.configWithIceServers(); len(got.ICEServers) != 0 {
		t.Fatalf("static servers survived the provider override: %v", got.ICEServers)
	}
}
