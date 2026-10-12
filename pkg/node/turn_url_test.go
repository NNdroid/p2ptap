package node

import (
	"testing"
)

// TestParseTurnURLCredentials covers every credential form a real user can put
// in config.json. If any of these reads Username/Credential as empty,
// IceTURNConfig drops the server and WebRTC runs with no relay at all — which
// is the failure mode the pion credential check is designed to prevent, so the
// parser must not manufacture it.
func TestParseTurnURLCredentials(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		server   string
		username string
		cred     string
		wantErr  bool
	}{
		// The form every default config entry uses: no credentials at all.
		{"colon no creds", "turn:relay1.expressturn.com:3478", "relay1.expressturn.com:3478", "", "", false},
		{"colon port 80", "turn:turn.cloud-rtc.com:80", "turn.cloud-rtc.com:80", "", "", false},

		// RFC 7861 userinfo, the canonical TURN credential form.
		{"userinfo colon", "turn:alice:s3cret@relay1.expressturn.com:3478",
			"relay1.expressturn.com:3478", "alice", "s3cret", false},

		// Query-string credentials on the colon form. net/url treats the colon
		// form as an opaque URL, so this used to be parsed as if there were no
		// credentials at all.
		{"query colon", "turn:relay1.expressturn.com:3478?username=alice&credential=s3cret",
			"relay1.expressturn.com:3478", "alice", "s3cret", false},

		// Both forms at once: the query wins.
		{"userinfo and query", "turn:alice:old@relay1.expressturn.com:3478?username=bob&credential=new",
			"relay1.expressturn.com:3478", "bob", "new", false},

		// The "://" forms pion also accepts.
		{"slash userinfo", "turn://alice:s3cret@relay1.expressturn.com:3478",
			"relay1.expressturn.com:3478", "alice", "s3cret", false},
		{"slash query", "turn://relay1.expressturn.com:3478?username=alice&credential=s3cret",
			"relay1.expressturn.com:3478", "alice", "s3cret", false},

		// Malformed inputs must fail loudly, not silently become anonymous.
		{"wrong scheme", "stun:relay1.expressturn.com:3478", "", "", "", true},
		{"missing host", "turn:?", "", "", "", true},
		{"empty", "", "", "", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTurnURL(tc.url)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseTurnURL(%q) = %+v, want error", tc.url, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTurnURL(%q) error: %v", tc.url, err)
			}
			if got.ServerAddr != tc.server {
				t.Errorf("ServerAddr = %q, want %q", got.ServerAddr, tc.server)
			}
			if got.Username != tc.username {
				t.Errorf("Username = %q, want %q", got.Username, tc.username)
			}
			if got.Credential != tc.cred {
				t.Errorf("Credential = %q, want %q", got.Credential, tc.cred)
			}
		})
	}
}

// TestIceTURNConfigAcceptsRealCredentialForms is the end-to-end check: servers
// configured with real credentials must survive IceTURNConfig intact and reach
// pion with a usable URL plus a credential pair.
func TestIceTURNConfigAcceptsRealCredentialForms(t *testing.T) {
	servers := []string{
		"turn:alice:s3cret@relay1.expressturn.com:3478",
		"turn:u1.xirsys.com:3478?username=alice&credential=s3cret",
		"turn:turn.cloud-rtc.com:80", // anonymous: must be dropped, not fatal
	}

	urls, user, cred, dropped := IceTURNConfig(servers)
	if user != "alice" || cred != "s3cret" {
		t.Fatalf("credentials = %q/%q, want alice/s3cret", user, cred)
	}
	if len(urls) != 2 {
		t.Fatalf("kept %d server(s) %v, want 2", len(urls), urls)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	// No query may leak through: pion's stun.ParseURI rejects unknown queries.
	for _, u := range urls {
		if len(u) > 5 && u[5] == '?' {
			t.Errorf("URL %q still carries a query string", u)
		}
	}
}
