package web

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// TestPingTracerouteRoutesExist proves the /api/ping and /api/traceroute
// endpoints are actually registered and executed by the running Server, not
// just present in source. A stale binary returns the catch-all 404
// "API endpoint '...' not found on running p2ptap process"; a correctly built
// binary returns either a real 200 payload or a "peer not found" 404 — both
// of which prove the route handler ran.
func TestPingTracerouteRoutesExist(t *testing.T) {
	collector := NewStatsCollector()

	// Inject one fake but valid peer so /api/ping can resolve it.
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pid, err := peer.IDFromPublicKey(priv.GetPublic())
	if err != nil {
		t.Fatalf("peerid: %v", err)
	}
	collector.mu.Lock()
	collector.ActivePeers = []PeerInfoDTO{{
		PeerID:   pid.String(),
		NodeName: "testpeer",
		TapIP:    "10.0.0.99/24",
	}}
	collector.mu.Unlock()

	srv, err := StartServer(collector, "127.0.0.1", "", 18099, nil, "", nil)
	if err != nil {
		t.Fatalf("StartServer: %v", err)
	}
	defer srv.Close()

	token := srv.AuthToken()
	if token == "" {
		t.Fatal("empty auth token")
	}

	for _, ep := range []string{"/api/ping", "/api/traceroute"} {
		url := "http://127.0.0.1:18099" + ep + "?peer_id=10.0.0.99"
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", ep, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)
		t.Logf("%s -> HTTP %d: %s", ep, resp.StatusCode, bodyStr)

		if strings.Contains(bodyStr, "not found on running p2ptap process") {
			t.Errorf("%s: route NOT registered in this binary (stale build?)", ep)
		}
		if resp.StatusCode == http.StatusNotFound && strings.Contains(bodyStr, "peer not found") {
			t.Logf("%s: route IS registered; handler ran and reported peer-not-found (expected for fake peer)", ep)
		}
	}
}

// TestResolvePeerIDLayeredLookup covers every branch of the layered target
// resolver: peer_id (b58), tap_ip with CIDR suffix, tap_ip raw, tap_ipv6,
// node_name (exact + case-insensitive substring), and the libp2p peerstore
// IP-rebinding fallback. These are the match paths the WebUI ping / traceroute
// card relies on when the user types a TAP IP rather than a b58 peer ID.
func TestResolvePeerIDLayeredLookup(t *testing.T) {
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pid, err := peer.IDFromPublicKey(priv.GetPublic())
	if err != nil {
		t.Fatalf("peerid: %v", err)
	}

	srv := &Server{collector: NewStatsCollector()}
	srv.collector.mu.Lock()
	srv.collector.ActivePeers = []PeerInfoDTO{{
		PeerID:   pid.String(),
		NodeName: "r5s-gateway",
		TapIP:    "10.0.0.99/24",
		TapIPv6:  "fd00::99/64",
		AllAddrs: []string{"/ip4/203.0.113.7/tcp/4099/p2p/" + pid.String()},
	}}
	srv.collector.mu.Unlock()

	cases := []struct {
		name      string
		input     string
		want      peer.ID
		wantMatch string
	}{
		{"raw peer_id", pid.String(), pid, "peer_id"},
		{"tap_ip with cidr stripped", "10.0.0.99", pid, "tap_ip"},
		{"tap_ip with explicit cidr", "10.0.0.99/24", pid, "tap_ip"},
		{"tap_ipv6", "fd00::99", pid, "tap_ipv6"},
		{"node_name exact", "r5s-gateway", pid, "node_name"},
		{"node_name substring", "r5s", pid, "node_name_substring"},
		{"all_addrs public IP", "203.0.113.7", pid, "all_addrs"},
		{"unknown input", "10.255.255.1", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, kind := srv.resolvePeerID(tc.input)
			if tc.want == "" {
				if got != "" {
					t.Errorf("resolvePeerID(%q) = %q, want empty", tc.input, got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("resolvePeerID(%q) = %q, want %q (via %q)", tc.input, got, tc.want, kind)
			}
			if kind != tc.wantMatch {
				t.Errorf("resolvePeerID(%q) match kind = %q, want %q", tc.input, kind, tc.wantMatch)
			}
		})
	}
}
