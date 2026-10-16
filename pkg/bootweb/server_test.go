package bootweb

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

type mockBootDataProvider struct {
	nodeName   string
	pskEnabled bool
	alerts     *AlertBuffer
}

func (m *mockBootDataProvider) GetHost() host.Host                 { return nil }
func (m *mockBootDataProvider) GetNodeName() string                { return m.nodeName }
func (m *mockBootDataProvider) GetStartTime() time.Time            { return time.Now().Add(-10 * time.Minute) }
func (m *mockBootDataProvider) IsPSKEnabled() bool                 { return m.pskEnabled }
func (m *mockBootDataProvider) GetPSKCount() int                   { return 2 }
func (m *mockBootDataProvider) IsPeerAuthenticated(p peer.ID) bool { return true }
func (m *mockBootDataProvider) GetPeerNetworkID(p peer.ID) string  { return "6b87ce74b335cc1a" }
func (m *mockBootDataProvider) HasPeekMapListener(p peer.ID) bool  { return true }
func (m *mockBootDataProvider) GetPeekMapListenerCount() int       { return 3 }
func (m *mockBootDataProvider) HasBootRelayClient(p peer.ID) bool  { return true }
func (m *mockBootDataProvider) GetPeerNodeInfo(p peer.ID) (string, string, string, string, string, string, string, []string, bool, string, string) {
	return "TestNode", "10.0.0.5", "", "aa:bb:cc:dd:ee:ff", "linux", "amd64", "v0.1.0", []string{"192.168.1.0/24"}, false, "aes-gcm", "fixed"
}
func (m *mockBootDataProvider) GetMeshPeers() []MeshPeerInfo { return nil }
func (m *mockBootDataProvider) GetRecentAlerts() []AlertEventDTO {
	if m.alerts != nil {
		return m.alerts.GetAll()
	}
	return nil
}
func (m *mockBootDataProvider) GetRelaySessions() []RelaySessionDTO { return nil }
func (m *mockBootDataProvider) GetRelayLimits() RelayStatsDTO {
	return RelayStatsDTO{Enabled: true, MaxCircuits: 1024, MaxReservations: 1024, MaxPerPeer: 1, MaxPerIP: 64, MaxPerASN: 256, DurationLimitSec: 300, DataLimitMB: 512}
}
func (m *mockBootDataProvider) GetGeoNodes() []GeoNodeDTO         { return nil }
func (m *mockBootDataProvider) GetGeoArcs() []GeoArcDTO           { return nil }
func (m *mockBootDataProvider) GetTrafficHistory() []TrafficPoint { return nil }
func (m *mockBootDataProvider) GetHealth(peers []PeerItemDTO) HealthCheckDTO {
	return HealthCheckDTO{Healthy: true}
}
func (m *mockBootDataProvider) GetConfigSummary() ConfigSummaryDTO {
	return ConfigSummaryDTO{NodeName: m.nodeName, PSKCount: 2}
}

func TestBootWebAuthAndStats(t *testing.T) {
	alerts := NewAlertBuffer(10)
	alerts.Add("warn", "auth_failed", "12D3KooWTest", "PSK mismatch")

	mockProvider := &mockBootDataProvider{
		nodeName:   "MockBoot",
		pskEnabled: true,
		alerts:     alerts,
	}

	server := NewServer(mockProvider, "127.0.0.1:0", "secret123")

	mux, err := server.buildMux()
	if err != nil {
		t.Fatalf("buildMux: %v", err)
	}

	// 1. Test Index HTML — unauthenticated by design, and never cached so a
	// token change is visible without a hard refresh.
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for index, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("expected text/html; charset=utf-8, got %q", w.Header().Get("Content-Type"))
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("expected Cache-Control no-store on the auth-prompt page, got %q", w.Header().Get("Cache-Control"))
	}

	// 1b. Static assets resolve through the file server with a real
	// Content-Type instead of a hand-set one. These are asserted exactly
	// because buildMux pins .js via mime.AddExtensionType — without the pin
	// the same asset answers "text/javascript; charset=utf-8" on Linux and
	// "application/javascript" on Windows, and the assertion would pass on
	// one runner and fail on the other.
	for path, wantType := range map[string]string{
		"/styles.css": "text/css; charset=utf-8",
		"/app.js":     "application/javascript",
		"/i18n.js":    "application/javascript",
	} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d", path, w.Code)
		}
		if got := w.Header().Get("Content-Type"); got != wantType {
			t.Errorf("%s: expected Content-Type %q, got %q", path, wantType, got)
		}
		if len(w.Body.Bytes()) == 0 {
			t.Errorf("%s: empty body", path)
		}
	}

	// 1c. A stale binary should answer unknown /api/* paths as JSON so the
	// dashboard can distinguish "endpoint missing" from "wrong address".
	req = httptest.NewRequest("GET", "/api/nope", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown api path, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected JSON 404 body, got Content-Type %q", ct)
	}

	// 1d. The favicon handler replaces the browser's /favicon.ico 404.
	req = httptest.NewRequest("GET", "/favicon.ico", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/svg+xml" {
		t.Errorf("favicon: expected 200 image/svg+xml, got %d %q", w.Code, w.Header().Get("Content-Type"))
	}

	// 1e. Security headers land on the unauthenticated shell too.
	req = httptest.NewRequest("GET", "/", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("expected X-Content-Type-Options nosniff, got %q", got)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("expected X-Frame-Options DENY, got %q", got)
	}

	// 2. Test Stats without Auth -> expect 401
	req = httptest.NewRequest("GET", "/api/stats", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", w.Code)
	}

	// 3. Test Verify Auth with wrong token
	verifyBody, _ := json.Marshal(map[string]string{"token": "wrong"})
	req = httptest.NewRequest("POST", "/api/auth/verify", bytes.NewReader(verifyBody))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var verifyResp authVerifyResp
	_ = json.NewDecoder(w.Body).Decode(&verifyResp)
	if verifyResp.OK {
		t.Fatalf("expected verify OK=false for wrong token")
	}

	// 4. Test Verify Auth with correct token
	verifyBody, _ = json.Marshal(map[string]string{"token": "secret123"})
	req = httptest.NewRequest("POST", "/api/auth/verify", bytes.NewReader(verifyBody))
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	_ = json.NewDecoder(w.Body).Decode(&verifyResp)
	if !verifyResp.OK {
		t.Fatalf("expected verify OK=true for correct token")
	}

	// 5. Test Stats with Bearer token
	req = httptest.NewRequest("GET", "/api/stats", nil)
	req.Header.Set("Authorization", "Bearer secret123")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for stats with token, got %d", w.Code)
	}

	var dash BootDashboardDTO
	if err := json.NewDecoder(w.Body).Decode(&dash); err != nil {
		t.Fatalf("failed to decode dashboard json: %v", err)
	}
	if dash.Server.NodeName != "MockBoot" {
		t.Errorf("expected NodeName MockBoot, got %s", dash.Server.NodeName)
	}
	if len(dash.Alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(dash.Alerts))
	}
}
