//go:build !windows

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Non-Windows single-instance guard.
//
// Windows uses a named kernel mutex (service_windows.go). On Linux/macOS and
// other Unixes the equivalent is an advisory lock file taken with flock(2): the
// lock is released automatically by the OS when the process exits (even a hard
// kill / crash), so there is never a stale-lock problem the way a hand-rolled
// pidfile would have. Two daemons racing to open the same TAP device would
// otherwise corrupt each other's state — this keeps exactly one instance alive.
//
// The returned uintptr is the open lock-file descriptor; releaseDaemonMutex
// closes it (dropping the flock). Holding it open for the process lifetime is
// what keeps the lock held.

// daemonLockPath is where the single-instance lock file lives. We use the
// user's runtime dir when available (systemd private tmp, etc.) and fall back
// to the OS temp dir; both are guaranteed writable by the daemon user and do
// not require the config dir to exist yet (startNode can run before any config
// is laid down). The path must be identical across all instances so the flock
// actually serialises them.
var daemonLockPath = func() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "p2ptap-daemon.lock")
	}
	return filepath.Join(os.TempDir(), "p2ptap-daemon.lock")
}()

func acquireDaemonMutex(_ string) (uintptr, bool) {
	f, err := os.OpenFile(daemonLockPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		// Cannot even open the lock file — fail closed so two instances never
		// start concurrently; log is best-effort (stderr already wired by caller).
		return 0, false
	}
	// LOCK_EX|LOCK_NB: fail immediately if another instance holds the lock.
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return 0, false
	}
	// Record our pid in the file for operator diagnostics (content is advisory;
	// the flock is what actually guards).
	_, _ = f.Seek(0, 0)
	_ = f.Truncate(0)
	_, _ = f.WriteString(os.Args[0] + "\n")
	return uintptr(f.Fd()), true
}

func releaseDaemonMutex(h uintptr) {
	if h == 0 {
		return
	}
	_ = unix.Flock(int(h), unix.LOCK_UN)
	_ = os.NewFile(h, "p2ptap-daemon.lock").Close()
}
