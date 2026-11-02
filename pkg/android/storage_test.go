package P2PTap

import (
	"path"
	"testing"
)

func TestAndroidPackageName(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cmdline string
		want    string
	}{
		{"plain process", "com.example.p2ptap\x00", "com.example.p2ptap"},
		{"secondary process", "com.example.p2ptap:remote\x00", "com.example.p2ptap"},
		{"extra argv", "com.example.p2ptap\x00--flag\x00", "com.example.p2ptap"},
		{"trailing newline", "com.example.p2ptap\n", "com.example.p2ptap"},
		// A process whose argv[0] is a path must not become a directory name.
		{"path argv0", "/system/bin/app_process\x00", ""},
		{"windows-style path", `C:\app\thing.exe` + "\x00", ""},
		{"empty", "", ""},
		{"only whitespace", " \x00", ""},
	} {
		if got := androidPackageName(tc.cmdline); got != tc.want {
			t.Errorf("%s: androidPackageName(%q) = %q, want %q", tc.name, tc.cmdline, got, tc.want)
		}
	}
}

// TestAppFilesDirFor pins the UID -> /data/user/<n> mapping. Android app UIDs are
// userId*100000 + appId, and using the wrong user directory is indistinguishable
// from "the disk is unwritable" once the failure reaches the identity loader.
func TestAppFilesDirFor(t *testing.T) {
	always := func(string) bool { return true }
	onlyAlias := func(dir string) bool { return dir == "/data/data/com.example.p2ptap/files" }
	none := func(string) bool { return false }

	if got := appFilesDirFor(10123, "com.example.p2ptap", always); got != "/data/user/0/com.example.p2ptap/files" {
		t.Errorf("owner profile = %q, want /data/user/0/com.example.p2ptap/files", got)
	}
	// 10 * perUserRange + 10123: a secondary Android user.
	if got := appFilesDirFor(10*perUserRange+10123, "com.example.p2ptap", always); got != "/data/user/10/com.example.p2ptap/files" {
		t.Errorf("secondary user = %q, want /data/user/10/com.example.p2ptap/files", got)
	}
	if got := appFilesDirFor(10123, "com.example.p2ptap", onlyAlias); got != "/data/data/com.example.p2ptap/files" {
		t.Errorf("alias fallback = %q, want /data/data/com.example.p2ptap/files", got)
	}
	if got := appFilesDirFor(10123, "com.example.p2ptap", none); got != "" {
		t.Errorf("no usable directory = %q, want empty", got)
	}
	if got := appFilesDirFor(10123, "", always); got != "" {
		t.Errorf("unknown package = %q, want empty", got)
	}
}

// TestResolveStatePath: relative engine paths must land in app-private storage,
// which is the whole point — a relative path resolves against the app process's
// working directory, and that is the read-only "/".
func TestResolveStatePath(t *testing.T) {
	const dir = "/data/user/0/com.example.p2ptap/files"
	SetDataDir(dir)
	t.Cleanup(func() { SetDataDir("") })

	if got, want := resolveStatePath("node.key"), path.Join(dir, "node.key"); got != want {
		t.Errorf("relative path = %q, want %q", got, want)
	}
	if got := resolveStatePath("/sdcard/p2ptap/node.key"); got != "/sdcard/p2ptap/node.key" {
		t.Errorf("absolute path was rewritten to %q", got)
	}
	if got := resolveStatePath(""); got != "" {
		t.Errorf("empty path = %q, want empty", got)
	}
}

// TestResolveStatePathWithoutDataDir: no known directory leaves the path alone
// rather than inventing one. The identity loader then reports the real errno.
func TestResolveStatePathWithoutDataDir(t *testing.T) {
	SetDataDir("")
	t.Cleanup(func() { SetDataDir("") })

	if got := resolveStatePath("node.key"); got != "node.key" {
		t.Errorf("path = %q, want it untouched", got)
	}
}

// TestParseConfigResolvesRelativeKeyPath is the end-to-end shape of the bug: the
// default config carries "node.key", and Start must hand the engine an absolute
// path inside the app's own storage.
func TestParseConfigResolvesRelativeKeyPath(t *testing.T) {
	const dir = "/data/user/0/com.example.p2ptap/files"
	SetDataDir(dir)
	t.Cleanup(func() { SetDataDir("") })

	cfg, err := parseConfig(`{"node_key_file":"node.key"}`)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if want := path.Join(dir, "node.key"); cfg.NodeKeyFile != want {
		t.Fatalf("NodeKeyFile = %q, want %q", cfg.NodeKeyFile, want)
	}
}

// TestParseConfigKeepsAbsoluteKeyPath: an app that already passes the absolute
// path from its own Context must keep full control.
func TestParseConfigKeepsAbsoluteKeyPath(t *testing.T) {
	SetDataDir("/data/user/0/com.example.p2ptap/files")
	t.Cleanup(func() { SetDataDir("") })

	const abs = "/data/user/0/com.example.p2ptap/no_backup/identity.key"
	cfg, err := parseConfig(`{"node_key_file":"` + abs + `"}`)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.NodeKeyFile != abs {
		t.Fatalf("NodeKeyFile = %q, want %q", cfg.NodeKeyFile, abs)
	}
}
