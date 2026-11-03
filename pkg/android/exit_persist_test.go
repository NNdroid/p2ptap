package P2PTap

import (
	"os"
	"path/filepath"
	"testing"
)

// withStateDir points the engine's state resolution at a temp directory for the
// duration of one test. SetDataDir is process-global, so every test that uses it
// must restore it or the next one inherits a deleted path.
func withStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	SetDataDir(dir)
	t.Cleanup(func() { SetDataDir("") })
	return dir
}

// TestExitSelectionSurvivesRestart is the regression for "the app says the exit
// node is enabled but nothing works after a restart".
//
// GatewayManager keeps the active exit node in memory only; Stop() drops it. The
// selection therefore has to live in app-private storage, and Start() has to
// read it back. Before this existed, Start() looked for an exit_node_peer key
// that the engine never wrote, so every restart silently came back with no exit
// node while the UI still showed one.
func TestExitSelectionSurvivesRestart(t *testing.T) {
	dir := withStateDir(t)

	if got := loadExitSelection(); got != "" {
		t.Fatalf("a fresh state dir reported a persisted exit node: %q", got)
	}

	peerID := "12D3KooWEfbUJ1egqqtAVNRkHTicNVBskj2ffizsfbxDj81qyhqD"
	if err := saveExitSelection(peerID); err != nil {
		t.Fatalf("saveExitSelection: %v", err)
	}

	// The value must come back from DISK, not from anything in memory: a fresh
	// read is what a restarted process does.
	if got := loadExitSelection(); got != peerID {
		t.Fatalf("loadExitSelection = %q, want %q", got, peerID)
	}
	if _, err := os.Stat(filepath.Join(dir, exitSelectionFile)); err != nil {
		t.Fatalf("selection file not written under the state dir: %v", err)
	}
}

// TestExitSelectionNormalisesInput pins the two normalisations that matter: a
// trailing newline written by hand or by a previous version must not turn into
// part of the peer ID (peer.Decode would reject it), and surrounding whitespace
// from a config field must be dropped.
func TestExitSelectionNormalisesInput(t *testing.T) {
	withStateDir(t)

	peerID := "12D3KooWEfbUJ1egqqtAVNRkHTicNVBskj2ffizsfbxDj81qyhqD"
	if err := saveExitSelection("  " + peerID + "\n"); err != nil {
		t.Fatalf("saveExitSelection: %v", err)
	}
	if got := loadExitSelection(); got != peerID {
		t.Fatalf("loadExitSelection = %q, want %q", got, peerID)
	}

	// A file written without a trailing newline (older builds, manual edits)
	// must still load cleanly.
	p := exitSelectionFilePath()
	if err := os.WriteFile(p, []byte(peerID), 0o600); err != nil {
		t.Fatalf("write bare selection: %v", err)
	}
	if got := loadExitSelection(); got != peerID {
		t.Fatalf("bare-file loadExitSelection = %q, want %q", got, peerID)
	}
}

// TestClearExitSelectionIsIdempotent: deselecting twice (a UI that fires both a
// deselect callback and a config hot-reload) must not surface an error, and a
// cleared selection must read back as "no exit node" immediately.
func TestClearExitSelectionIsIdempotent(t *testing.T) {
	withStateDir(t)

	peerID := "12D3KooWEfbUJ1egqqtAVNRkHTicNVBskj2ffizsfbxDj81qyhqD"
	if err := saveExitSelection(peerID); err != nil {
		t.Fatalf("saveExitSelection: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := saveExitSelection(""); err != nil {
			t.Fatalf("clear attempt %d: %v", i, err)
		}
	}
	if got := loadExitSelection(); got != "" {
		t.Fatalf("a cleared selection still loads: %q", got)
	}
}
