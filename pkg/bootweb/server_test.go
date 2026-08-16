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

func (m *mockBootDataProvider) GetHost() host.Host                                { return nil }
func (m *mockBootDataProvider) GetNodeName() string                               { return m.nodeName }
func (m *mockBootDataProvider) GetStartTime() time.Time                           { return time.Now().Add(-10 * time.Minute) }
func (m *mockBootDataProvider) IsPSKEnabled() bool                                { return m.pskEnabled }
func (m *mockBootDataProvider) GetPSKCount() int                                  { return 2 }
func (m *mockBootDataProvider) IsPeerAuthenticated(p peer.ID) bool                { return true }
func (m *mockBootDataProvider) GetPeerNetworkID(p peer.ID) string                 { return "6b87ce74b335cc1a" }
func (m *mockBootDataProvider) HasPeekMapListener(p peer.ID) bool                 { return true }
func (m *mockBootDataProvider) GetPeekMapListenerCount() int                      { return 3 }
func (m *mockBootDataProvider) HasBootRelayClient(p peer.ID) bool                 { return true }
func (m *mockBootDataProvider) GetPeerNodeInfo(p peer.ID) (string, string, string, string, string, string, string, []string, bool) {
	return "TestNode", "10.0.0.5", "", "aa:bb:cc:dd:ee:ff", "linux", "amd64", "v0.1.0", []string{"192.168.1.0/24"}, false
}
func (m *mockBootDataProvider) GetMeshPeers() []MeshPeerInfo { return nil }
func (m *mockBootDataProvider) GetRecentAlerts() []AlertEventDTO {
	if m.alerts != nil {
		return m.alerts.GetAll()
	}
	return nil
}
func (m *mockBootDataProvider) GetRelaySessions() []RelaySessionDTO   { return nil }
func (m *mockBootDataProvider) GetGeoNodes() []GeoNodeDTO             { return nil }
func (m *mockBootDataProvider) GetGeoArcs() []GeoArcDTO               { return nil }
func (m *mockBootDataProvider) GetTrafficHistory() []TrafficPoint     { return nil }
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

	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleIndex)
	mux.HandleFunc("/api/auth/verify", server.handleAuthVerify)
	mux.HandleFunc("/api/stats", server.requireAuth(server.handleStats))
	mux.HandleFunc("/api/logs", server.requireAuth(server.handleLogs))

	// 1. Test Index HTML
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for index, got %d", w.Code)
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
