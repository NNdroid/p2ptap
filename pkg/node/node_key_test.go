package node

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// writeTestNodeKey writes a freshly generated Ed25519 identity key to path with
// 0600 and returns the key and its peer ID string.
func writeTestNodeKey(t *testing.T, path string) (crypto.PrivKey, string) {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	data, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	pid, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("derive peer id: %v", err)
	}
	return priv, pid.String()
}

func TestNodeKeyModeAccepted(t *testing.T) {
	for _, tc := range []struct {
		osName string
		mode   os.FileMode
		want   bool
	}{
		{"linux", 0600, true},
		{"linux", 0700, true},
		{"linux", 0644, false},
		{"linux", 0666, false},
		{"darwin", 0600, true},
		{"darwin", 0664, false},
		// No platform reports restrictive bits here, so these must not refuse.
		{"windows", 0666, true},
		{"windows", 0644, true},
		{"android", 0666, true},
		{"android", 0644, true},
	} {
		if got := nodeKeyModeAccepted(tc.osName, tc.mode); got != tc.want {
			t.Errorf("nodeKeyModeAccepted(%s, %o) = %v, want %v", tc.osName, tc.mode, got, tc.want)
		}
	}
}

func TestWarnKeyMode(t *testing.T) {
	for _, tc := range []struct {
		osName string
		mode   os.FileMode
		want   bool
	}{
		{"android", 0644, true},
		{"android", 0666, true},
		{"android", 0600, false},
		// Linux refuses a permissive key outright, so there is nothing to warn.
		{"linux", 0644, false},
		// Windows reports 0666 for every file, so a warning would fire on
		// every start.
		{"windows", 0666, false},
		{"darwin", 0666, false},
	} {
		if got := warnKeyMode(tc.osName, tc.mode); got != tc.want {
			t.Errorf("warnKeyMode(%s, %o) = %v, want %v", tc.osName, tc.mode, got, tc.want)
		}
	}
}

// Regression test for the peer ID changing on every start.
//
// Android reaches the app's own data directory through the system symlink
// /data/user/0/<pkg> -> /data/data/<pkg>, so Context.getFileStreamPath() hands
// the engine a path whose resolved form differs from the requested one. The
// loader used to compare those two strings and refuse on any difference, so the
// key read failed and NewNodeWithTAP fell back to libp2p's ephemeral identity:
// a new Peer ID on every start, and every address a mesh peer had saved for
// this node left pointing at a dead identity.
func TestLoadOrGenerateNodeKeyLoadsThroughSymlinkedPath(t *testing.T) {
	t.Parallel()

	realDir := t.TempDir()
	keyFile := filepath.Join(realDir, "node.key")
	_, wantID := writeTestNodeKey(t, keyFile)

	paths := []struct {
		name string
		path string
	}{
		{
			name: "symlinked directory in path",
			path: func() string {
				linkDir := filepath.Join(t.TempDir(), "user0")
				if err := os.Symlink(realDir, linkDir); err != nil {
					t.Skipf("cannot create symlink (%v)", err)
				}
				return filepath.Join(linkDir, "node.key")
			}(),
		},
		{
			name: "symlinked key file",
			path: func() string {
				link := filepath.Join(t.TempDir(), "node.key")
				if err := os.Symlink(keyFile, link); err != nil {
					t.Skipf("cannot create symlink (%v)", err)
				}
				return link
			}(),
		},
	}

	for _, tc := range paths {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadOrGenerateNodeKey(tc.path)
			if err != nil {
				t.Fatalf("load through %q failed: %v", tc.path, err)
			}
			if got == nil {
				t.Fatalf("loaded nil key; the caller would fall back to an ephemeral identity")
			}
			id, err := peer.IDFromPrivateKey(got)
			if err != nil {
				t.Fatalf("derive peer id: %v", err)
			}
			if id.String() != wantID {
				t.Fatalf("loaded a different identity through %q: want %s, got %s", tc.path, wantID, id)
			}
		})
	}
}

// The symlink rejection that the path comparison used to provide must still
// stop a symlink that resolves to a world-readable file: that is the decoy
// attack the guard was introduced for, and stat'ing the opened fd keeps it
// covered.
func TestLoadOrGenerateNodeKeyRefusesWorldReadableTarget(t *testing.T) {
	t.Parallel()
	if nodeKeyModeAccepted(runtime.GOOS, 0644) {
		t.Skip("permission bits are not enforced on this platform")
	}

	base := t.TempDir()
	decoyPath := filepath.Join(base, "decoy.key")
	_, wantID := writeTestNodeKey(t, decoyPath)
	_ = os.Chmod(decoyPath, 0644)

	link := filepath.Join(base, "node.key")
	if err := os.Symlink(decoyPath, link); err != nil {
		t.Skipf("cannot create symlink (%v)", err)
	}

	got, err := loadOrGenerateNodeKey(link)
	if err == nil && got != nil {
		if id, _ := peer.IDFromPrivateKey(got); id.String() == wantID {
			t.Fatal("loaded a key whose target is world-readable; the decoy attack must be refused")
		}
	}
}

// A key file that exists but is too permissive must surface as an error, not be
// silently replaced by a freshly generated identity — the latter would strand a
// node under a new Peer ID and lose its mesh membership.
func TestLoadOrGenerateNodeKeyRefusesTooPermissive(t *testing.T) {
	t.Parallel()
	if nodeKeyModeAccepted(runtime.GOOS, 0644) {
		t.Skip("permission bits are not enforced on this platform")
	}

	path := filepath.Join(t.TempDir(), "node.key")
	writeTestNodeKey(t, path)
	_ = os.Chmod(path, 0644)

	if _, err := loadOrGenerateNodeKey(path); err == nil {
		t.Fatal("expected a refusal for a 0644 key file")
	}
}

// The missing-file path must still generate and persist a key, and a second
// call must load the same identity rather than minting another.
func TestLoadOrGenerateNodeKeyGeneratesOnceAndReloads(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "node.key")

	first, err := loadOrGenerateNodeKey(path)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if first == nil {
		t.Fatal("first load returned a nil key")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key was not persisted: %v", err)
	}

	second, err := loadOrGenerateNodeKey(path)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	firstID, err := peer.IDFromPrivateKey(first)
	if err != nil {
		t.Fatalf("peer id for first: %v", err)
	}
	secondID, err := peer.IDFromPrivateKey(second)
	if err != nil {
		t.Fatalf("peer id for second: %v", err)
	}
	if firstID != secondID {
		t.Fatalf("second load minted a different identity (%s vs %s); the key file was not re-read", secondID, firstID)
	}
}
