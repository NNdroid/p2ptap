package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"p2ptap/pkg/config"
)

func TestConfigSavePersistsBeforePublishAndKeepsPendingRestart(t *testing.T) {
	baseline := config.DefaultConfig()
	baseline.WebUI.AuthToken = "test-config-token"
	collector := NewStatsCollector()
	collector.SetNodeInfo("test", "", baseline.TapIP, baseline.TapIPv6, baseline.TransportStrategy)
	var persisted *config.Config
	failSave := false
	collector.PersistConfig = func(cfg *config.Config) error {
		if failSave {
			return errors.New("storage failed")
		}
		copy := *cfg
		persisted = &copy
		return nil
	}
	applied := 0
	collector.OnConfigReload = func(cfg *config.Config) { applied++ }
	srv, host := startConfigTestServerOnFreePort(t, collector, baseline)
	defer srv.Close()
	post := func(cfg *config.Config, wantStatus int, restart bool) {
		t.Helper()
		body, _ := json.Marshal(cfg)
		resp, err := http.Post("http://"+host+"/api/config?token="+srv.AuthToken(), "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != wantStatus {
			t.Fatalf("status=%d, body=%s", resp.StatusCode, data)
		}
		if wantStatus == http.StatusOK {
			var result struct {
				Restart bool `json:"restart_required"`
			}
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			if result.Restart != restart {
				t.Fatalf("restart=%v, want %v: %s", result.Restart, restart, data)
			}
		}
	}
	next := *baseline
	next.TransportStrategy = "redundant"
	post(&next, http.StatusOK, true)
	if persisted == nil || persisted.TransportStrategy != "redundant" || applied != 1 {
		t.Fatal("save did not persist and publish")
	}
	if collector.GetResponse().TransportStrategy != "best_path" {
		t.Fatal("pending strategy reported as active")
	}
	next.LogLevel = "debug"
	post(&next, http.StatusOK, true)
	// The virtual-IP route must serve the same saved snapshot and keep the
	// restart flag, even though the previous save already requested redundant.
	it := &TAPInterceptor{collector: collector, configState: configStateFor(collector, baseline)}
	body, _ := json.Marshal(&next)
	req := append([]byte("POST /api/config HTTP/1.1\r\nAuthorization: Bearer test-config-token\r\n\r\n"), body...)
	response := it.processHTTP(req)
	if !bytes.Contains(response, []byte(`"restart_required":true`)) {
		t.Fatalf("interceptor lost pending restart: %s", response)
	}
	if it.loadCfg() != srv.loadCfg() {
		t.Fatal("HTTP routes diverged")
	}
	oldSnapshot, oldApplied := srv.loadCfg(), applied
	failSave = true
	next.TransportStrategy = "fallback"
	post(&next, http.StatusInternalServerError, false)
	if srv.loadCfg() != oldSnapshot || applied != oldApplied {
		t.Fatal("failed save changed runtime/saved state")
	}
	if resp := it.processHTTP(append([]byte("POST /api/config HTTP/1.1\r\nAuthorization: Bearer test-config-token\r\n\r\n"), []byte(`{"transport_strategy":"fallback"}`)...)); !bytes.Contains(resp, []byte("500")) {
		t.Fatalf("interceptor accepted failed storage: %s", resp)
	}
	failSave = false
	invalid := next
	invalid.StaticPeers = []string{"192.0.2.1"}
	post(&invalid, http.StatusBadRequest, false)
	if srv.loadCfg() != oldSnapshot || applied != oldApplied {
		t.Fatal("invalid candidate published")
	}
	// Restoring the actual startup strategy clears its pending flag.
	next.TransportStrategy = "best_path"
	post(&next, http.StatusOK, false)
	if persisted.TransportStrategy != "best_path" {
		t.Fatal("last saved candidate was lost")
	}
}

func TestConfigFilePersistenceFailureRejectsSave(t *testing.T) {
	cfg := config.DefaultConfig()
	if err := persistWebConfig(nil, t.TempDir()+"/missing/config.json", cfg); err == nil || !strings.Contains(err.Error(), "config.json") {
		t.Fatalf("file persistence failure was swallowed: %v", err)
	}
}

func TestAddStaticPeerPersistsAndRejectsInvalidOrFailedSaves(t *testing.T) {
	baseline := config.DefaultConfig()
	baseline.WebUI.AuthToken = "static-test-token"
	collector := NewStatsCollector()
	failSave := false
	var persisted *config.Config
	collector.PersistConfig = func(cfg *config.Config) error {
		if failSave {
			return errors.New("storage failed")
		}
		copy := *cfg
		persisted = &copy
		return nil
	}
	dials := 0
	collector.AddStaticPeer = func(address string) error { dials++; return nil }
	srv, host := startConfigTestServerOnFreePort(t, collector, baseline)
	defer srv.Close()
	post := func(address string, status int) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"multiaddr": address})
		resp, err := http.Post("http://"+host+"/api/peer/add_static?token="+srv.AuthToken(), "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != status {
			t.Fatalf("status=%d body=%s", resp.StatusCode, data)
		}
		if status == http.StatusOK && !bytes.Contains(data, []byte(`"restart_required":true`)) {
			t.Fatalf("lost reconnect policy restart flag: %s", data)
		}
	}
	address := "/ip4/192.0.2.1/tcp/4001/p2p/QmNnooDu7bfjPFoTmoXMY5PeBKyy1EicV2g7HQ1b18423b"
	post(address, http.StatusOK)
	post("  "+address+"  ", http.StatusOK)
	if persisted == nil || len(persisted.StaticPeers) != 1 || dials != 2 {
		t.Fatal("static peer was not saved/deduplicated/dialed")
	}
	old := srv.loadCfg()
	post("192.0.2.1", http.StatusBadRequest)
	failSave = true
	post(address, http.StatusInternalServerError)
	if srv.loadCfg() != old || dials != 2 {
		t.Fatal("invalid or failed save changed runtime")
	}
}

func TestPendingConfigKeepsActiveTokenUntilRestart(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WebUI.AuthToken = "active-test-token"
	collector := NewStatsCollector()
	collector.PersistConfig = func(cfg *config.Config) error { return nil }
	srv, host := startConfigTestServerOnFreePort(t, collector, cfg)
	defer srv.Close()
	next := *cfg
	next.WebUI.AuthToken = "pending-test-token"
	body, _ := json.Marshal(&next)
	resp, err := http.Post("http://"+host+"/api/config?token="+srv.AuthToken(), "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("save status=%d", resp.StatusCode)
	}
	it := &TAPInterceptor{collector: collector, configState: configStateFor(collector, cfg)}
	if it.effectiveToken() != "active-test-token" {
		t.Fatal("pending config changed active authentication")
	}
	// Config GET redacts the token; an unrelated save must retain the pending
	// token rather than clearing it or restoring the old active value.
	next.WebUI.AuthToken = ""
	body, _ = json.Marshal(&next)
	result := it.processHTTP(append([]byte("POST /api/config HTTP/1.1\r\nAuthorization: Bearer active-test-token\r\n\r\n"), body...))
	if !bytes.Contains(result, []byte(`"restart_required":true`)) || srv.loadCfg().WebUI.AuthToken != "pending-test-token" {
		t.Fatalf("redacted save lost pending token: %s", result)
	}
}
