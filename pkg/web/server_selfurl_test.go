package web

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRecordBoundAddrs verifies that after a (re)bind the server records the
// real listen URLs, prefers loopback, and persists them to the sidecar so the
// Windows tray can open the dashboard at the correct address.
func TestRecordBoundAddrs(t *testing.T) {
	// Bind a loopback and a wildcard listener to capture real TCPAddrs.
	lnLoop, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	defer lnLoop.Close()
	lnWild, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen wildcard: %v", err)
	}
	defer lnWild.Close()

	dir := t.TempDir()
	s := &Server{configPath: filepath.Join(dir, "config.json")}
	s.recordBoundAddrs([]net.Listener{lnLoop, lnWild})

	urls := s.BoundWebUIURLs()
	if len(urls) != 2 {
		t.Fatalf("expected 2 bound URLs, got %d: %v", len(urls), urls)
	}
	// Wildcard v4 must be reported as loopback (always locally reachable).
	foundLoopback := false
	for _, u := range urls {
		if strings.Contains(u, "127.0.0.1") {
			foundLoopback = true
		}
	}
	if !foundLoopback {
		t.Fatalf("wildcard listener not normalized to 127.0.0.1: %v", urls)
	}
	// Preferred must be the loopback URL.
	pref := s.PreferredWebuiURL()
	if !strings.Contains(pref, "127.0.0.1") {
		t.Fatalf("PreferredWebuiURL should prefer loopback, got %q", pref)
	}

	// Sidecar must exist next to config and contain both URLs.
	data, err := os.ReadFile(filepath.Join(dir, webuiURLSidecar))
	if err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}
	content := string(data)
	for _, u := range urls {
		if !strings.Contains(content, u) {
			t.Fatalf("sidecar missing URL %q; content=%q", u, content)
		}
	}
}

// TestRecordBoundAddrsSpecificIP ensures a specific (non-loopback, non-wildcard)
// bind is reported verbatim — the tray must open that exact address because
// 127.0.0.1 would not reach it.
func TestRecordBoundAddrsSpecificIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	// Force a specific non-loopback-looking IP by checking the recorded host.
	s := &Server{configPath: filepath.Join(t.TempDir(), "config.json")}
	s.recordBoundAddrs([]net.Listener{ln})
	urls := s.BoundWebUIURLs()
	if len(urls) != 1 {
		t.Fatalf("expected 1 URL, got %v", urls)
	}
	if !strings.HasPrefix(urls[0], "http://127.0.0.1:") {
		t.Fatalf("loopback listener should record 127.0.0.1 host, got %q", urls[0])
	}
}
