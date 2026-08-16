package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"p2ptap/pkg/logger"

	"github.com/gorilla/websocket"
)

func TestWebServerEndpoints(t *testing.T) {
	t.Log("[web] starting test WebUI server on 127.0.0.1:18080")
	collector := NewStatsCollector()
	collector.PeerID = "12D3KooWTestPeer"
	collector.TapIP = "127.0.0.1/24"
	collector.RecordSent(1024)
	collector.RecordRecv(2048)
	collector.RecordDedup()

	// Listen on 127.0.0.1 on a high port for testing
	srv, err := StartServer(collector, "127.0.0.1", "", 18080, nil, "", nil)
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer srv.Close()
	t.Log("[web] ✓ server started")

	// Auth token is generated at startup; all /api/* requests must carry it.
	token := srv.AuthToken()
	if token == "" {
		t.Fatal("StartServer generated an empty auth token")
	}
	t.Logf("[web] ✓ auth token issued (len=%d)", len(token))
	apiURL := func(path string) string {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		return "http://127.0.0.1:18080" + path + sep + "token=" + token
	}

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
	} else {
		t.Logf("[web] ✓ GET / -> %d, body %d bytes", resp.StatusCode, len(body))
	}

	// Test GET /api/stats (must NOT require token)
	respAPI, err := http.Get(apiURL("/api/stats"))
	if err != nil {
		t.Fatalf("GET /api/stats failed: %v", err)
	}
	defer respAPI.Body.Close()

	if respAPI.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for GET /api/stats, got %d", respAPI.StatusCode)
	} else {
		t.Logf("[web] ✓ GET /api/stats -> %d", respAPI.StatusCode)
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
	t.Logf("[web] ✓ /api/stats PeerID=%s sent=%d recv=%d dedup=%d",
		statsResp.PeerID, statsResp.PacketStats.BytesSent, statsResp.PacketStats.BytesRecv, statsResp.PacketStats.DedupCount)

	// Test GET /api/peer/echo
	collector.ProbePeerEcho = func(peerIDStr string) *PeerEchoResultDTO {
		return &PeerEchoResultDTO{
			PeerID:         peerIDStr,
			Success:        true,
			RTTMs:          15.5,
			BytesSent:      32,
			BytesRecv:      32,
			PayloadMatched: true,
		}
	}
	collector.ProbePeerEchoAddr = func(peerIDStr string, targetAddrStr string) *PeerEchoResultDTO {
		return &PeerEchoResultDTO{
			PeerID:         peerIDStr,
			Success:        true,
			RTTMs:          15.5,
			BytesSent:      32,
			BytesRecv:      32,
			PayloadMatched: true,
			TransportAddr:  targetAddrStr,
		}
	}

	url1 := apiURL("/api/peer/echo?peer_id=12D3KooWTestPeer&multiaddr=%2Fip4%2F172.16.219.2%2Ftcp%2F4001")
	respEcho1, err := http.Get(url1)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url1, err)
	}
	defer respEcho1.Body.Close()
	if respEcho1.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for %s, got %d", url1, respEcho1.StatusCode)
	} else {
		t.Logf("[web] ✓ GET %s -> %d", url1, respEcho1.StatusCode)
	}
	var echoDto1 PeerEchoResultDTO
	if err := json.NewDecoder(respEcho1.Body).Decode(&echoDto1); err != nil {
		t.Fatalf("Failed to decode JSON from %s: %v", url1, err)
	}
	if !echoDto1.Success || echoDto1.TransportAddr != "/ip4/172.16.219.2/tcp/4001" {
		t.Errorf("Unexpected echo response: %+v", echoDto1)
	} else {
		t.Logf("[web] ✓ /api/peer/echo success=%v addr=%s", echoDto1.Success, echoDto1.TransportAddr)
	}

	// Test POST /api/tap/forward-test — end-to-end TAP data-path forwarding test.
	collector.ProbeTapForward = func(peerIDStr string) *TapProbeResultDTO {
		return &TapProbeResultDTO{
			PeerID:    peerIDStr,
			PeerName:  "test-peer",
			TapIP:     "10.0.0.2",
			Success:   true,
			RTTMills:  12,
			SentBytes: 50,
		}
	}
	fwdURL := apiURL("/api/tap/forward-test")
	fwdBody, _ := json.Marshal(map[string]string{"peer_id": "12D3KooWTestPeer"})
	fwdResp, err := http.Post(fwdURL, "application/json", bytes.NewReader(fwdBody))
	if err != nil {
		t.Fatalf("POST %s failed: %v", fwdURL, err)
	}
	defer fwdResp.Body.Close()
	if fwdResp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for %s, got %d", fwdURL, fwdResp.StatusCode)
	} else {
		t.Logf("[web] ✓ POST %s -> %d", fwdURL, fwdResp.StatusCode)
	}
	var fwdDto TapProbeResultDTO
	if err := json.NewDecoder(fwdResp.Body).Decode(&fwdDto); err != nil {
		t.Fatalf("Failed to decode JSON from %s: %v", fwdURL, err)
	}
	if !fwdDto.Success || fwdDto.SentBytes != 50 || fwdDto.TapIP != "10.0.0.2" {
		t.Errorf("Unexpected TAP forward-test response: %+v", fwdDto)
	} else {
		t.Logf("[web] ✓ /api/tap/forward-test success=%v sent=%d tapIP=%s", fwdDto.Success, fwdDto.SentBytes, fwdDto.TapIP)
	}

	// Negative check: missing peer_id must be rejected with 400.
	badBody, _ := json.Marshal(map[string]string{})
	badResp, err := http.Post(fwdURL, "application/json", bytes.NewReader(badBody))
	if err != nil {
		t.Fatalf("POST %s (bad) failed: %v", fwdURL, err)
	}
	defer badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing peer_id, got %d", badResp.StatusCode)
	} else {
		t.Logf("[web] ✓ missing peer_id rejected with %d", badResp.StatusCode)
	}

	// Positive check: a request WITHOUT the token must be rejected.
	noToken, err := http.Get("http://127.0.0.1:18080/api/stats")
	if err != nil {
		t.Fatalf("GET /api/stats without token failed: %v", err)
	}
	defer noToken.Body.Close()
	if noToken.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected 401 for /api/stats without token, got %d", noToken.StatusCode)
	} else {
		t.Logf("[web] ✓ request without token rejected with %d (auth enforced)", noToken.StatusCode)
	}
}

// TestPcapWebSocketStream verifies the live-stream WebSocket endpoint:
//  1. It upgrades successfully with a valid token.
//  2. The first message on the wire is a `state` envelope.
//  3. Frames added via PacketCapture.AddWithPeers are pushed live to the
//     subscriber (no polling).
//  4. Clear() propagates a `cleared` event.
//  5. The HTTP fallback /api/pcap/packets still returns the buffered frames
//     for legacy clients.
func TestPcapWebSocketStream(t *testing.T) {
	collector := NewStatsCollector()
	collector.Pcap = NewPacketCapture(64, "") // in-memory only

	srv, err := StartServer(collector, "127.0.0.1", "", 18081, nil, "", nil)
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer srv.Close()
	token := srv.AuthToken()

	wsURL := "ws://127.0.0.1:18081/api/pcap/stream?backlog=10&token=" + token
	header := http.Header{}
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("WebSocket dial failed: %v (status=%v)", err, resp)
	}
	defer conn.Close()

	// 1. First message should be the initial state.
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var env pcapWSMessage
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if env.Type != "state" || env.State == nil {
		t.Fatalf("expected state envelope, got %q", env.Type)
	}
	if env.State.Running {
		t.Errorf("expected running=false on a fresh capture")
	}
	t.Logf("[ws] ✓ initial state received: running=%v count=%d", env.State.Running, env.State.Count)

	// 2. Start capture and inject a synthetic frame. We send raw bytes that
	//    look like a minimal Ethernet/IPv4/UDP frame so parseFrame can
	//    extract a human-readable info string.
	collector.Pcap.Start()
	frame := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst MAC (broadcast)
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, // src MAC
		0x08, 0x00, // EtherType IPv4
		0x45, 0x00, 0x00, 0x1c, // ver/ihl, tos, total length 28
		0x00, 0x01, 0x00, 0x00, // id, flags/frag
		0x40, 0x11, 0x00, 0x00, // TTL=64, proto=UDP(17), checksum
		0x0a, 0x00, 0x00, 0x01, // src 10.0.0.1
		0x0a, 0x00, 0x00, 0x02, // dst 10.0.0.2
		0x00, 0x35, 0x00, 0x36, // src port 53, dst port 54
		0x00, 0x08, 0x00, 0x00, // UDP length 8, checksum
	}
	collector.Pcap.AddWithPeers(DirTx, frame, "self", "12D3KooWpeer")

	// 3. Wait for the live frame event. Frames may arrive as a single
	//    `frame` envelope or a batched `frames` envelope (the server coalesces
	//    bursts), so accept either.
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	gotLive := false
	for !gotLive {
		_, raw, err = conn.ReadMessage()
		if err != nil {
			t.Fatalf("read live: %v", err)
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("decode live: %v", err)
		}
		var f *CapturedFrame
		switch {
		case env.Type == "frame" && env.Frame != nil:
			f = env.Frame
		case env.Type == "frames" && len(env.Frames) > 0:
			f = &env.Frames[0]
		}
		if f != nil {
			gotLive = true
			if f.SrcIP != "10.0.0.1" || f.DstIP != "10.0.0.2" {
				t.Errorf("frame fields wrong: %+v", f)
			}
			if f.FromPeer != "self" || f.ToPeer != "12D3KooWpeer" {
				t.Errorf("peer labels wrong: from=%q to=%q", f.FromPeer, f.ToPeer)
			}
			env.Frame = f
		}
	}
	t.Logf("[ws] ✓ live frame received: seq=%d src=%s dst=%s", env.Frame.Seq, env.Frame.SrcIP, env.Frame.DstIP)

	// 4. Clear() must produce a `cleared` event.
	collector.Pcap.Clear()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	gotCleared := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !gotCleared {
		_, raw, err = conn.ReadMessage()
		if err != nil {
			t.Fatalf("read cleared: %v", err)
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("decode cleared: %v", err)
		}
		if env.Type == "cleared" {
			gotCleared = true
		}
	}
	if !gotCleared {
		t.Error("did not receive cleared event after Clear()")
	} else {
		t.Log("[ws] ✓ cleared event received")
	}

	// 5. The HTTP fallback /api/pcap/packets must still work for clients
	//    that haven't switched to the WebSocket yet.
	fbURL := "http://127.0.0.1:18081/api/pcap/packets?limit=10&token=" + token
	fbResp, err := http.Get(fbURL)
	if err != nil {
		t.Fatalf("fallback GET failed: %v", err)
	}
	defer fbResp.Body.Close()
	if fbResp.StatusCode != 200 {
		t.Fatalf("fallback status: %d", fbResp.StatusCode)
	}
	var out struct {
		Frames []CapturedFrame `json:"frames"`
		Count  int             `json:"count"`
	}
	if err := json.NewDecoder(fbResp.Body).Decode(&out); err != nil {
		t.Fatalf("decode fallback: %v", err)
	}
	if out.Count != 0 {
		t.Errorf("after Clear(), fallback should be empty, got count=%d", out.Count)
	} else {
		t.Log("[ws] ✓ legacy /api/pcap/packets still functional (0 frames after clear)")
	}
}

// TestPcapPubSubNoBlock ensures that slow subscribers do not block the
// datapath: a PcapSubscriber that never reads its channel must not stall
// subsequent AddWithPeers calls.
func TestPcapPubSubNoBlock(t *testing.T) {
	p := NewPacketCapture(8, "")
	p.Start()
	sub := p.Subscribe(1) // tiny buffer to force drops quickly
	defer p.Unsubscribe(sub)
	frame := make([]byte, 64) // minimum Ethernet length is 14; padded with zeros
	frame[12] = 0x08          // EtherType IPv4
	frame[13] = 0x00
	// Should not deadlock even with a stuck consumer.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			p.AddWithPeers(DirTx, frame, "", "")
		}
		close(done)
	}()
	select {
	case <-done:
		// good — we made it through 200 frames without blocking
	case <-time.After(2 * time.Second):
		t.Fatal("AddWithPeers blocked on a stuck subscriber")
	}
	if sub.Dropped.Load() == 0 {
		t.Errorf("expected dropped > 0 for an unread subscriber, got 0")
	} else {
		t.Logf("[ws] ✓ 200 frames added; subscriber dropped %d (non-blocking)", sub.Dropped.Load())
	}
}

// TestLogWebSocketStream verifies the live-log WebSocket endpoint:
//  1. It upgrades successfully with a valid token.
//  2. The first message on the wire is a `backlog` envelope (up to ?backlog=N
//     recent entries from the global ring buffer).
//  3. A log written via logger.New(...).Info(...) is pushed live as an `entry`
//     (no re-fetching the whole buffer).
//  4. ClearLogs() propagates a `cleared` event.
//  5. The HTTP fallback /api/logs still returns the recent ring buffer for
//     legacy clients.
func TestLogWebSocketStream(t *testing.T) {
	collector := NewStatsCollector()

	srv, err := StartServer(collector, "127.0.0.1", "", 18082, nil, "", nil)
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer srv.Close()
	token := srv.AuthToken()

	// Seed a few entries into the global logger ring before connecting so the
	// backlog has something to deliver.
	logger.ClearLogs()
	for i := 0; i < 3; i++ {
		logger.New("test").Info("seed-%d", i)
	}

	wsURL := "ws://127.0.0.1:18082/api/logs/stream?backlog=100&token=" + token
	header := http.Header{}
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("WebSocket dial failed: %v (status=%v)", err, resp)
	}
	defer conn.Close()

	// 1. First message should be the backlog envelope.
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read backlog: %v", err)
	}
	var env logWSMessage
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode backlog: %v", err)
	}
	if env.Type != "backlog" || len(env.Entries) == 0 {
		t.Fatalf("expected backlog envelope with entries, got type=%q len=%d", env.Type, len(env.Entries))
	}
	if len(env.Entries) < 3 {
		t.Errorf("expected at least 3 seeded entries in backlog, got %d", len(env.Entries))
	}
	t.Logf("[ws-log] ✓ backlog received: %d entries", len(env.Entries))

	// 2. Write a new log line; it must arrive live as a single `entry`.
	logger.New("test").Info("live-line")
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	gotEntry := false
	for !gotEntry {
		_, raw, err = conn.ReadMessage()
		if err != nil {
			t.Fatalf("read live entry: %v", err)
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("decode live entry: %v", err)
		}
		if env.Type == "entry" && env.Entry != nil {
			gotEntry = true
			if env.Entry.Message != "live-line" {
				t.Errorf("entry message wrong: %q", env.Entry.Message)
			}
			if env.Entry.Level != "INFO" {
				t.Errorf("entry level wrong: %q", env.Entry.Level)
			}
		}
	}
	t.Log("[ws-log] ✓ live entry received")

	// 3. ClearLogs() must produce a `cleared` event.
	logger.ClearLogs()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	gotCleared := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !gotCleared {
		_, raw, err = conn.ReadMessage()
		if err != nil {
			t.Fatalf("read cleared: %v", err)
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("decode cleared: %v", err)
		}
		if env.Type == "cleared" {
			gotCleared = true
		}
	}
	if !gotCleared {
		t.Error("did not receive cleared event after ClearLogs()")
	} else {
		t.Log("[ws-log] ✓ cleared event received")
	}

	// 4. HTTP fallback /api/logs still returns the recent ring (empty after clear).
	fbURL := "http://127.0.0.1:18082/api/logs?token=" + token
	fbResp, err := http.Get(fbURL)
	if err != nil {
		t.Fatalf("fallback GET failed: %v", err)
	}
	defer fbResp.Body.Close()
	if fbResp.StatusCode != 200 {
		t.Fatalf("fallback status: %d", fbResp.StatusCode)
	}
	var logs []logger.LogEntry
	if err := json.NewDecoder(fbResp.Body).Decode(&logs); err != nil {
		t.Fatalf("decode fallback: %v", err)
	}
	if len(logs) != 0 {
		t.Errorf("after ClearLogs(), fallback should be empty, got %d", len(logs))
	} else {
		t.Log("[ws-log] ✓ legacy /api/logs still functional (empty after clear)")
	}
}

// TestLogPubSubNoBlock ensures that a slow log subscriber does not block the
// logger's hot path: a LogSubscriber that never reads its channel must not
// stall subsequent log writes.
func TestLogPubSubNoBlock(t *testing.T) {
	sub := logger.Subscribe(1) // tiny buffer to force drops quickly
	defer logger.Unsubscribe(sub)
	l := logger.New("test")
	// Should not deadlock even with a stuck consumer.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			l.Info("log line %d", i)
		}
		close(done)
	}()
	select {
	case <-done:
		// good — we made it through 200 log lines without blocking
	case <-time.After(2 * time.Second):
		t.Fatal("log write blocked on a stuck subscriber")
	}
	if sub.Dropped.Load() == 0 {
		t.Errorf("expected dropped > 0 for an unread subscriber, got 0")
	} else {
		t.Logf("[ws-log] ✓ 200 log lines written; subscriber dropped %d (non-blocking)", sub.Dropped.Load())
	}
}
