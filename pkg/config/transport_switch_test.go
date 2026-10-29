package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestOmittedTransportSwitches pins the reporting rules behind the
// transports-block warning: only a partial block is worth reporting.
func TestOmittedTransportSwitches(t *testing.T) {
	tests := []struct {
		name string
		data string
		want []string
	}{
		{
			name: "no transports key is a deliberate defaults request",
			data: `{"node_name":"boot"}`,
			want: nil,
		},
		{
			name: "one switch set warns about the four it leaves to defaults",
			data: `{"transports":{"enable_webtransport":true}}`,
			want: []string{"enable_quic_reuse", "enable_webrtc", "enable_tcp_reuse", "enable_webrtc_signaling"},
		},
		{
			name: "all five stated leaves nothing to warn about",
			data: `{"transports":{"enable_quic_reuse":false,"enable_webrtc":false,"enable_webtransport":true,"enable_tcp_reuse":false,"enable_webrtc_signaling":false}}`,
			want: nil,
		},
		{
			name: "block setting only unrelated keys is not a transport-selection intent",
			data: `{"transports":{"tls_server_name":"example.net"}}`,
			want: nil,
		},
		{
			name: "malformed JSON is handled by the unmarshal error path, not here",
			data: `{nope`,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := omittedTransportSwitches([]byte(tt.data)); !slices.Equal(got, tt.want) {
				t.Errorf("omittedTransportSwitches(%s) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

// TestLoadConfigFromFileTransportMerge documents the behaviour the warning
// exists for: a switch absent from the transports block keeps the DefaultConfig
// value, which is true for all five transports. If the merge ever switches to
// whitelist semantics this test fails and the warning becomes dead code —
// change both together.
func TestLoadConfigFromFileTransportMerge(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "cfg.json")
	content := `{"transports":{"enable_webtransport":true}}`
	if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}
	if !cfg.Transports.EnableWebTransport {
		t.Error("enable_webtransport should be true")
	}
	for name, got := range map[string]bool{
		"enable_quic_reuse":       cfg.Transports.EnableQUICReuse,
		"enable_webrtc":           cfg.Transports.EnableWebRTC,
		"enable_tcp_reuse":        cfg.Transports.EnableTCPReuse,
		"enable_webrtc_signaling": cfg.Transports.EnableWebRTCSignaling,
	} {
		if !got {
			t.Errorf("%s is absent from the transports block and must keep the DefaultConfig value true", name)
		}
	}
}
