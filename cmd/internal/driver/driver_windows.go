//go:build windows

// Package driver provides a GUI-agnostic Windows TAP/Wintun driver
// provisioning routine shared by the headless p2ptap service (cmd/p2ptap) and
// the interactive system tray (cmd/p2ptap-tray). Callers surface progress
// through the onStatus callback — a logger in headless mode, the tray
// tooltip/toast in GUI mode.
package driver

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"p2ptap/pkg/tap"
)

// CheckResult describes the state of the available TAP/Wintun drivers.
type CheckResult struct {
	TAPInstalled    bool
	WintunReady     bool
	TAPInstaller    string // path to tap-windows installer found alongside exe
	WintunDLL       string // path to wintun.dll found alongside exe
	PreferredDriver string // "tap" or "wintun"
}

// Check scans the system and the executable directory for usable drivers.
func Check() CheckResult {
	var r CheckResult

	r.TAPInstalled = tap.IsTAPDriverInstalled()

	exeDir := filepath.Dir(os.Args[0])
	candidates := []string{
		filepath.Join(exeDir, "tap-windows-installer.exe"),
		filepath.Join(exeDir, "tap-windows-9.21.2.exe"),
		filepath.Join(exeDir, "tapinstall.exe"),
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			r.TAPInstaller = c
			break
		}
	}

	r.WintunReady = tap.IsWintunAvailable()

	if !r.WintunReady {
		dll := filepath.Join(exeDir, "wintun.dll")
		if fi, err := os.Stat(dll); err == nil && !fi.IsDir() {
			r.WintunDLL = dll
		}
	}

	r.PreferredDriver = "wintun" // default fallback
	if r.TAPInstalled {
		r.PreferredDriver = "tap"
	} else if r.TAPInstaller != "" {
		r.PreferredDriver = "tap" // will try to install
	}

	return r
}

// Ensure makes sure a usable driver is present and returns the driver type that
// should be used ("tap" or "wintun"). onStatus, if non-nil, receives
// human-readable progress messages.
func Ensure(onStatus func(msg string)) string {
	notify := func(m string) {
		if onStatus != nil {
			onStatus(m)
		}
	}

	result := Check()

	if result.TAPInstalled {
		notify("TAP-Windows6 driver found, using native TAP adapter.")
		return "tap"
	}

	if result.TAPInstaller != "" {
		notify("Installing TAP-Windows6 driver...")
		time.Sleep(500 * time.Millisecond)

		if installTAPDriver(result.TAPInstaller) && tap.IsTAPDriverInstalled() {
			notify("TAP driver installed successfully.")
			return "tap"
		}
		notify("TAP driver not available, falling back to Wintun.")
	}

	if result.WintunReady {
		notify("No TAP driver found, using Wintun (zero-install).")
		return "wintun"
	}

	notify("No usable TAP or Wintun driver found.")
	return "wintun" // let downstream fail with a clear error
}

// installTAPDriver runs the TAP-Windows installer in silent mode and waits for
// it to complete. Returns true when the installer exits with code 0.
func installTAPDriver(installerPath string) bool {
	cmd := exec.Command(installerPath, "/S")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	if err := cmd.Start(); err != nil {
		return false
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return err == nil
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		return false
	}
}
