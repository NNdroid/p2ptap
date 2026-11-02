package P2PTap

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"

	"p2ptap/pkg/logger"
)

// perUserRange is Android's PER_USER_RANGE: an app UID is
// userId*PER_USER_RANGE + appId, with appIds starting at FIRST_APPLICATION_UID
// (10000). That makes os.Getuid()/perUserRange the Android *user* the process
// runs as, which is what picks the right /data/user/<n> profile directory.
const perUserRange = 100000

var (
	dataDirMu   sync.RWMutex
	dataDirPath string
)

// stateLog is separate from the var declared in android.go because this file
// carries no build tag: it stays compilable (and testable) on a host, where the
// android.go logger does not exist.
var stateLog = logger.New("Android")

// SetDataDir tells the engine where app-private storage lives, so relative
// engine paths (node_key_file by default) land somewhere writable. Call it with
// the host app's private files directory before Start.
//
// It exists because the engine cannot always answer this itself: an Android app
// process forked from zygote keeps the zygote working directory, which is the
// read-only "/". A relative path therefore resolves to "/node.key", every write
// fails, and the node is forced into an identity it cannot persist. The
// cmdline-based fallback below covers builds that never call this, but an
// explicit directory from the app is always the better answer.
func SetDataDir(dir string) {
	dir = strings.TrimSpace(dir)
	dataDirMu.Lock()
	dataDirPath = dir
	dataDirMu.Unlock()
	if dir != "" {
		stateLog.Info("android: engine state directory set to %s", dir)
	}
}

// stateDir returns the directory that relative engine paths resolve against, or
// "" when none is known. The cmdline-derived answer is cached only when it is
// unambiguous; an empty result is recomputed cheaply on the next call.
func stateDir() string {
	dataDirMu.RLock()
	d := dataDirPath
	dataDirMu.RUnlock()
	if d != "" || runtime.GOOS != "android" {
		return d
	}

	detected := androidAppFilesDir(os.Getuid(), readProcessCmdline())
	if detected == "" {
		return ""
	}
	dataDirMu.Lock()
	if dataDirPath == "" {
		dataDirPath = detected
	}
	d = dataDirPath
	dataDirMu.Unlock()
	stateLog.Info("android: derived engine state directory %s (no SetDataDir call)", d)
	return d
}

// resolveStatePath turns a relative engine path into an absolute one under the
// app's private storage. Absolute paths and "" are returned untouched, so a
// caller that already knows where its key lives keeps full control.
//
// It uses the slash-based "path" package rather than "path/filepath": the paths
// being resolved are Android paths, and filepath would both misjudge "/data/…"
// as relative and rewrite the separators when the engine is built (or tested)
// on Windows. Getting this wrong is not cosmetic — a key path judged relative
// stays under the read-only working directory.
func resolveStatePath(p string) string {
	if p == "" || path.IsAbs(p) {
		return p
	}
	dir := stateDir()
	if dir == "" {
		return p
	}
	return path.Join(dir, p)
}

// androidAppFilesDir maps a process to the "/data/user/<n>/<pkg>/files"
// directory it owns. usable reports whether a candidate's parent exists and is
// reachable; tests substitute it so the mapping can be checked without an
// Android filesystem.
//
// Both forms are tried because /data/user/<n> is the per-user path and
// /data/data is the historical alias for user 0. Returning "" is not an error
// path to log: on a device where neither exists the relative path stays
// relative, and the identity loader reports the unusable path with the errno
// that explains it.
func androidAppFilesDir(uid int, cmdline string) string {
	return appFilesDirFor(uid, androidPackageName(cmdline), func(dir string) bool {
		_, err := os.Stat(path.Dir(dir))
		return err == nil
	})
}

// appFilesDirFor is the pure half of androidAppFilesDir.
func appFilesDirFor(uid int, pkg string, usable func(string) bool) string {
	if pkg == "" {
		return ""
	}
	userID := uid / perUserRange
	for _, dir := range []string{
		fmt.Sprintf("/data/user/%d/%s/files", userID, pkg),
		fmt.Sprintf("/data/data/%s/files", pkg),
	} {
		if usable(dir) {
			return dir
		}
	}
	return ""
}

// androidPackageName extracts the package name from /proc/self/cmdline
// contents. argv[0] of an app process is the package name, with a ":suffix"
// when it is a secondary process (:remote, :push, ...); every process of one app
// shares the same private storage, so the suffix is dropped.
//
// Anything that looks like a path is rejected rather than turned into a
// directory name: a process started as "/system/bin/app_process" would
// otherwise be read as a package and produce a nonsense path.
func androidPackageName(cmdline string) string {
	if i := strings.IndexByte(cmdline, 0); i >= 0 {
		cmdline = cmdline[:i]
	}
	cmdline = strings.TrimSpace(cmdline)
	// Reject anything path-shaped BEFORE trimming the process suffix: splitting
	// "/system/bin/app_process" or "C:\app\x.exe" at the colon first would leave
	// a plausible-looking package name ("C") and send the key to a directory
	// that does not exist.
	if cmdline == "" || strings.ContainsAny(cmdline, "/\\ \t\n") {
		return ""
	}
	if i := strings.IndexByte(cmdline, ':'); i >= 0 {
		cmdline = cmdline[:i]
	}
	if cmdline == "" {
		return ""
	}
	return cmdline
}

// readProcessCmdline reads /proc/self/cmdline, returning "" on any platform or
// error that does not provide it.
func readProcessCmdline() string {
	data, err := os.ReadFile("/proc/self/cmdline")
	if err != nil {
		return ""
	}
	return string(data)
}
