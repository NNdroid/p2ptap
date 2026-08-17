//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

// NewDaemonClient builds a client for the loopback WebUI of the local daemon.
// The auth token is read from the sidecar the daemon persists next to the
// config; if absent we fall back to any token embedded in the config file.
func NewDaemonClient(cfg *config.Config, configPath string) *DaemonClient {
	port := cfg.WebUI.Port
	if port <= 0 {
		port = 80
	}
	token := config.LoadWebUIToken(configPath)
	if token == "" {
		token = cfg.WebUI.AuthToken
	}
	return &DaemonClient{
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		token:   token,
		http:    &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *DaemonClient) do(method, path string, body interface{}) (*http.Response, error) {
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
