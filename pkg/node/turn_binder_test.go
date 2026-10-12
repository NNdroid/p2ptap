package node

import (
	"testing"
)

// TestUsableTURNServersSplitsOnCredentials is the regression test for
// credential-less TURN defaults. The old TurnServers list was entirely
// anonymous, so the QUIC relay binder spent a full allocation cycle — a
// concurrency slot, a 30s timeout and a fresh UDP socket per server, every
// relay-upgrade interval — against servers that can never allocate.
func TestUsableTURNServersSplitsOnCredentials(t *testing.T) {
	servers := []string{
		"turn:public.example.com:3478",                        // anonymous: must be dropped
		"turn:ok1.example.com:3478?username=u1&credential=c1", // query form: kept
		"turn:u2:p2@ok2.example.com:3478",                     // userinfo form: kept
		"",                                                    // unparseable: dropped
		"turn:ok3.example.com:3478?username=u3&credential=c3", // kept
	}
	usable, dropped := usableTURNServers(servers)

	wantUsable := []string{
		"turn:ok1.example.com:3478?username=u1&credential=c1",
		"turn:u2:p2@ok2.example.com:3478",
		"turn:ok3.example.com:3478?username=u3&credential=c3",
	}
	if len(usable) != len(wantUsable) {
		t.Fatalf("usable = %v, want %v", usable, wantUsable)
	}
	for i, want := range wantUsable {
		if usable[i] != want {
			t.Fatalf("usable[%d] = %q, want %q (order must be preserved)", i, usable[i], want)
		}
	}
	if len(dropped) != 2 {
		t.Fatalf("dropped = %v, want the anonymous and the unparseable entry", dropped)
	}
}

// TestUsableTURNServersRejectsPartialCredentials makes sure a credential set
// that is only half present counts as missing. TURN authenticates with both,
// so one alone is as useless as neither and must not be sent to the wire.
func TestUsableTURNServersRejectsPartialCredentials(t *testing.T) {
	servers := []string{
		"turn:a.example.com:3478?username=u",
		"turn:b.example.com:3478?credential=c",
		"turn:u@example.com:3478",
	}
	usable, dropped := usableTURNServers(servers)
	if len(usable) != 0 {
		t.Fatalf("usable = %v, want none", usable)
	}
	if len(dropped) != len(servers) {
		t.Fatalf("dropped = %v, want every entry", dropped)
	}
}

// TestUsableTURNServersKeepsCleanLists confirms the filter is a no-op for a
// correctly configured list, so users with real credentials lose nothing.
func TestUsableTURNServersKeepsCleanLists(t *testing.T) {
	servers := []string{
		"turn://ok.example.com:3478?username=u&credential=c",
		"turn://ok2.example.com:3478?username=u&credential=c",
	}
	usable, dropped := usableTURNServers(servers)
	if len(usable) != len(servers) || len(dropped) != 0 {
		t.Fatalf("usable = %v, dropped = %v", usable, dropped)
	}
	for i := range servers {
		if usable[i] != servers[i] {
			t.Fatalf("usable[%d] = %q, want %q", i, usable[i], servers[i])
		}
	}
}

// TestHasTURNCredentials pins the accepted credential forms. Both this and
// IceTURNConfig decide through turnCredentialsUsable, so the QUIC relay binder
// and WebRTC ICE cannot disagree about which servers exist.
func TestHasTURNCredentials(t *testing.T) {
	for input, want := range map[string]bool{
		"":                                     false,
		"turn:public.example.com:3478":         false,
		"turn:a.example.com:3478?username=u":   false,
		"turn:b.example.com:3478?credential=c": false,
		"turn:u@example.com:3478":              false,
		"turn://ok.example.com:3478?username=u&credential=c": true,
		"turn://u:p@ok.example.com:3478":                     true,
		"turn:u:p@ok.example.com:3478":                       true,
		"stun:public.example.com:3478":                       false,
	} {
		if got := hasTURNCredentials(input); got != want {
			t.Errorf("hasTURNCredentials(%q) = %v, want %v", input, got, want)
		}
	}
}
