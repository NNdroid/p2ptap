package libp2ptls

import (
	"strings"
	"testing"
)

// TestSniResolution locks the SNI mode precedence + per-peer label properties:
// suffix mode wins and yields a distinct, stable, DNS-safe "<label>.<suffix>"
// per peer; static mode applies the literal name; neither set means no SNI.
func TestSniResolution(t *testing.T) {
	const peerA = "12D3KooWPeerAAAA"
	const peerB = "12D3KooWPeerBBBB"

	// No config -> no SNI.
	SetDialServerName("")
	SetDialSNISuffix("")
	if got := resolveDialServerName(peerA); got != "" {
		t.Fatalf("empty config must yield no SNI, got %q", got)
	}

	// Static mode.
	SetDialServerName("www.example.com")
	if got := resolveDialServerName(peerA); got != "www.example.com" {
		t.Fatalf("static SNI = %q, want www.example.com", got)
	}

	// Suffix mode wins over static, and is per-peer distinct + stable.
	SetDialSNISuffix("cdn.example.net")
	sniA := resolveDialServerName(peerA)
	sniA2 := resolveDialServerName(peerA)
	sniB := resolveDialServerName(peerB)
	if !strings.HasSuffix(sniA, ".cdn.example.net") {
		t.Fatalf("suffix SNI %q must end with .cdn.example.net", sniA)
	}
	if sniA != sniA2 {
		t.Fatal("same peer must derive a stable SNI")
	}
	if sniA == sniB {
		t.Fatal("distinct peers must derive distinct SNIs")
	}
	// Label must be a single DNS-safe label (RFC1123-ish): lowercase hex, no
	// leading/trailing dash, no dots inside the prefix.
	label := strings.TrimSuffix(sniA, ".cdn.example.net")
	if label == "" || strings.Contains(label, ".") || label != strings.ToLower(label) {
		t.Fatalf("derived label %q is not a clean single DNS label", label)
	}
	for _, r := range label {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			t.Fatalf("label %q contains non [a-z0-9] char %q", label, r)
		}
	}

	// Suffix cleared -> falls back to static.
	SetDialSNISuffix("")
	if got := resolveDialServerName(peerA); got != "www.example.com" {
		t.Fatalf("after clearing suffix, SNI = %q, want static www.example.com", got)
	}
}
