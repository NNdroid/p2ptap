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

// daemonLockPath is where the single-instance lock file lives. It MUST be
// identical across all instances for the flock to serialise them — that is
// why XDG_RUNTIME_DIR is deliberately not consulted here: a systemd system
// daemon (no XDG_RUNTIME_DIR) and an interactive `p2ptap run` from a desktop
// login (XDG_RUNTIME_DIR=/run/user/UID) would otherwise pick two different
// files and both start. os.TempDir() resolves to /tmp for both.
var daemonLockPath = filepath.Join(os.TempDir(), "p2ptap-daemon.lock")

func acquireDaemonMutex(_ string) (uintptr, bool) {
	f, err := os.OpenFile(daemonLockPath, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0644)
	if err != nil {
		// Cannot even open the lock file — fail closed so two instances never
		// start concurrently; log is best-effort (stderr already wired by caller).
		//
		// O_NOFOLLOW is what makes this safe rather than merely unlikely: the
		// lock lives in a world-writable directory (/tmp) and this process runs
		// as root with CAP_NET_ADMIN, and the code below truncates and rewrites
		// what it just opened. Without O_NOFOLLOW a local user can pre-plant
		// "p2ptap-daemon.lock" as a symlink to any root-owned file, and the next
		// service start silently clobbers that target. Refusing to follow the
		// link fails the daemon instead — the safe direction, since two daemons
		// racing on one TAP device would corrupt each other's state anyway.
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
