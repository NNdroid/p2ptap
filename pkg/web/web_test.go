package web

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestWebServerEndpoints(t *testing.T) {
	collector := NewStatsCollector()
	collector.PeerID = "12D3KooWTestPeer"
	collector.TapIP = "127.0.0.1/24"
	collector.RecordSent(1024)
	collector.RecordRecv(2048)
	collector.RecordDedup()

	// Listen on 127.0.0.1 on a high port for testing
	srv, err := StartServer(collector, "127.0.0.1", "", 18080, nil, "")
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer srv.Close()

	// Test GET /
	resp, err := http.Get("http://127.0.0.1:18080/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 OK for GET /, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("GET / returned empty body")
	}

	// Test GET /api/stats
	respAPI, err := http.Get("http://127.0.0.1:18080/api/stats")
	if err != nil {
		t.Fatalf("GET /api/stats failed: %v", err)
	}
	defer respAPI.Body.Close()

	if respAPI.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for GET /api/stats, got %d", respAPI.StatusCode)
	}

	var statsResp StatsResponse
	if err := json.NewDecoder(respAPI.Body).Decode(&statsResp); err != nil {
		t.Fatalf("Failed to decode JSON response from /api/stats: %v", err)
	}

	if statsResp.PeerID != "12D3KooWTestPeer" {
		t.Errorf("Expected PeerID '12D3KooWTestPeer', got '%s'", statsResp.PeerID)
	}
	if statsResp.PacketStats.BytesSent != 1024 || statsResp.PacketStats.BytesRecv != 2048 {
		t.Errorf("PacketStats mismatch: %+v", statsResp.PacketStats)
	}
	if statsResp.PacketStats.DedupCount != 1 {
		t.Errorf("DedupCount expected 1, got %d", statsResp.PacketStats.DedupCount)
	}

	// Test GET /api/peer/echo
	collector.ProbePeerEcho = func(peerIDStr string) *PeerEchoResultDTO {
		return &PeerEchoResultDTO{
			PeerID:        peerIDStr,
			Success:       true,
			RTTMs:         15.5,
			BytesSent:     32,
			BytesRecv:     32,
			PayloadMatched: true,
		}
	}
	collector.ProbePeerEchoAddr = func(peerIDStr string, targetAddrStr string) *PeerEchoResultDTO {
		return &PeerEchoResultDTO{
			PeerID:        peerIDStr,
			Success:       true,
			RTTMs:         15.5,
			BytesSent:     32,
			BytesRecv:     32,
			PayloadMatched: true,
			TransportAddr: targetAddrStr,
		}
	}

	url1 := "http://127.0.0.1:18080/api/peer/echo?peer_id=12D3KooWTestPeer&multiaddr=%2Fip4%2F172.16.219.2%2Ftcp%2F4001"
	respEcho1, err := http.Get(url1)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url1, err)
	}
	defer respEcho1.Body.Close()
	if respEcho1.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for %s, got %d", url1, respEcho1.StatusCode)
	}
	var echoDto1 PeerEchoResultDTO
	if err := json.NewDecoder(respEcho1.Body).Decode(&echoDto1); err != nil {
		t.Fatalf("Failed to decode JSON from %s: %v", url1, err)
	}
	if !echoDto1.Success || echoDto1.TransportAddr != "/ip4/172.16.219.2/tcp/4001" {
		t.Errorf("Unexpected echo response: %+v", echoDto1)
	}

}
