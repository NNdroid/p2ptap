//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"p2ptap/pkg/config"
)


// --- Daemon /api/* DTOs (minimal shapes the tray client needs) ---

type peerInfoDTO struct {
	PeerID    string `json:"peer_id"`
	NodeName  string `json:"node_name"`
	TapIP     string `json:"tap_ip"`
	TapIPv6   string `json:"tap_ipv6"`
	IsExitNode bool `json:"is_exit_node"`
}

type exitNodeInfoDTO struct {
	ActiveExitPeerID string `json:"active_exit_peer_id"`
	ActiveExitTapIP  string `json:"active_exit_tap_ip"`
}

type speedStatsDTO struct {
	TxBytesPerSec uint64 `json:"tx_bytes_per_sec"`
	RxBytesPerSec uint64 `json:"rx_bytes_per_sec"`
}

type statsResponse struct {
	PeerID      string          `json:"peer_id"`
	TapIP       string          `json:"tap_ip"`
	TapIPv6     string          `json:"tap_ipv6"`
	ActivePeers []peerInfoDTO   `json:"active_peers"`
	ExitNode    exitNodeInfoDTO `json:"exit_node"`
	Speed       speedStatsDTO   `json:"speed"`
}

// DaemonClient is the thin control client the tray uses to talk to the p2ptap
// daemon (running as a Windows service or foreground process). The tray itself
// no longer hosts a node — it only queries status and issues control actions
// over the daemon's existing /api/* surface, which keeps "service + tray" from
// ever running two nodes that fight over the TAP adapter.
type DaemonClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func resolveDaemonBaseURL(cfg *config.Config, configPath string) string {
	fallbackPort := 5857
	if cfg != nil && cfg.WebUI.Port > 0 {
		fallbackPort = cfg.WebUI.Port
	}
	fallbackIP := "127.0.0.1"
	if cfg != nil && cfg.WebUI.ListenIP != "" && cfg.WebUI.ListenIP != "0.0.0.0" {
		fallbackIP = cfg.WebUI.ListenIP
	} else if cfg != nil && cfg.WebUI.ListenIPv6 != "" && cfg.WebUI.ListenIPv6 != "::" {
		fallbackIP = "[" + strings.Trim(cfg.WebUI.ListenIPv6, "[]") + "]"
	} else if cfg != nil && cfg.WebUI.ListenIPv6 == "::" && (cfg.WebUI.ListenIP == "" || cfg.WebUI.ListenIP == "0.0.0.0") {
		fallbackIP = "[::1]"
	}
	fallback := fmt.Sprintf("http://%s:%d", fallbackIP, fallbackPort)

	if configPath != "" {
		sidecarPath := filepath.Join(filepath.Dir(configPath), ".p2ptap_webui_url")
		if data, err := os.ReadFile(sidecarPath); err == nil {
			var configuredV4, configuredV6, loopbackV4, loopbackV6, first string
			cleanV6 := ""
			if cfg != nil && cfg.WebUI.ListenIPv6 != "" && cfg.WebUI.ListenIPv6 != "::" {
				cleanV6 = strings.Trim(cfg.WebUI.ListenIPv6, "[]")
			}
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				if cfg != nil && cfg.WebUI.ListenIP != "" && cfg.WebUI.ListenIP != "0.0.0.0" && strings.Contains(line, cfg.WebUI.ListenIP) {
					configuredV4 = line
				}
				if cleanV6 != "" && strings.Contains(line, cleanV6) {
					configuredV6 = line
				}
				if strings.Contains(line, "127.0.0.1") || strings.Contains(line, "localhost") {
					loopbackV4 = line
				}
				if strings.Contains(line, "[::1]") {
					loopbackV6 = line
				}
				if first == "" {
					first = line
				}
			}
			if configuredV4 != "" {
				return configuredV4
			}
			if configuredV6 != "" {
				return configuredV6
			}
			if loopbackV4 != "" {
				return loopbackV4
			}
			if loopbackV6 != "" {
				return loopbackV6
			}
			if first != "" {
				return first
			}

		}
	}
	return fallback
}


// NewDaemonClient builds a client for the WebUI of the local daemon.
// The auth token is read from the sidecar the daemon persists next to the
// config; if absent we fall back to any token embedded in the config file.
func NewDaemonClient(cfg *config.Config, configPath string) *DaemonClient {
	token := config.LoadWebUIToken(configPath)
	if token == "" && cfg != nil {
		token = cfg.WebUI.AuthToken
	}
	baseURL := resolveDaemonBaseURL(cfg, configPath)
	return &DaemonClient{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *DaemonClient) do(method, path string, body interface{}) (*http.Response, error) {
	resp, err := c.doRequest(method, path, body)
	if err != nil && globalConfigPath != "" {
		// Attempt dynamic target re-resolution if daemon re-bound or restarted
		c.refreshTarget(globalConfigPath)
		resp, err = c.doRequest(method, path, body)
	}
	return resp, err
}

func (c *DaemonClient) doRequest(method, path string, body interface{}) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.baseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.http.Do(req)
}

func (c *DaemonClient) refreshTarget(configPath string) {
	var cfg *config.Config
	if configPath != "" {
		if reloaded, err := config.LoadConfigFromFile(configPath); err == nil {
			cfg = reloaded
		}
	}
	c.baseURL = resolveDaemonBaseURL(cfg, configPath)
	token := config.LoadWebUIToken(configPath)
	if token == "" && cfg != nil {
		token = cfg.WebUI.AuthToken
	}
	c.token = token
}


// Reachable reports whether the daemon's API is up and we can authenticate.
func (c *DaemonClient) Reachable() bool {
	_, err := c.Stats()
	return err == nil
}

// Stats fetches the live node status snapshot.
func (c *DaemonClient) Stats() (*statsResponse, error) {
	resp, err := c.do(http.MethodGet, "/api/stats", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /api/stats: status %d", resp.StatusCode)
	}
	var s statsResponse
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

// SetExitNode routes all traffic through the given peer's exit node.
func (c *DaemonClient) SetExitNode(peerID, tapIP, tapIPv6 string) error {
	resp, err := c.do(http.MethodPost, "/api/exitnode", map[string]string{
		"action":        "set",
		"peer_id":       peerID,
		"exit_tap_ip":   tapIP,
		"exit_tap_ipv6": tapIPv6,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST /api/exitnode set: status %d", resp.StatusCode)
	}
	return nil
}

// ClearExitNode restores the default route.
func (c *DaemonClient) ClearExitNode() error {
	resp, err := c.do(http.MethodPost, "/api/exitnode", map[string]string{
		"action": "clear",
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST /api/exitnode clear: status %d", resp.StatusCode)
	}
	return nil
}
