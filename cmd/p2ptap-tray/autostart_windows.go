//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	runKeyPath         = `Software\Microsoft\Windows\CurrentVersion\Run`
	autoStartValueName = "p2ptap"
	autoStartTaskName  = "p2ptap"
)

// isAutoStartEnabled reports whether p2ptap is configured to launch at user
// logon. It prefers the Task Scheduler task (UAC-safe, no console window) and
// also honours a legacy HKCU\Run value so upgrades from older builds keep
// showing the correct toggle state.
func isAutoStartEnabled() bool {
	if scheduledTaskMatchesCurrentExe() {
		return true
	}
	// Legacy registry value (older builds) — treat as enabled for compatibility.
	if k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE); err == nil {
		defer k.Close()
		if val, _, err := k.GetStringValue(autoStartValueName); err == nil && strings.TrimSpace(val) != "" {
			return true
		}
	}
	return false
}

// toggleAutoStart enables or disables user logon auto-start. The preferred
// mechanism is a Task Scheduler task (ONLOGON + highest privileges) which
// launches the GUI binary without a visible console window and without
// triggering a UAC prompt. A legacy HKCU\Run entry is removed on either toggle
// so we never launch twice.
func toggleAutoStart(enable bool) error {
	// Always clear the legacy registry value to avoid double launch.
	_ = deleteRunValue()

	if !enable {
		return deleteScheduledTask()
	}
	return createScheduledTask()
}

func createScheduledTask() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	if realExe, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = realExe
	}
	absConfigPath, _ := filepath.Abs(globalConfigPath)
	action := fmt.Sprintf(`"%s" -c "%s"`, exePath, absConfigPath)

	cmd := exec.Command("schtasks", "/Create",
		"/TN", autoStartTaskName,
		"/TR", action,
		"/SC", "ONLOGON",
		"/RL", "HIGHEST",
		"/F",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create scheduled task: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func deleteScheduledTask() error {
	cmd := exec.Command("schtasks", "/Delete", "/TN", autoStartTaskName, "/F")
	if out, err := cmd.CombinedOutput(); err != nil {
		lower := strings.ToLower(string(out))
		// A missing task is not an error.
		if strings.Contains(lower, "cannot find") || strings.Contains(lower, "does not exist") || strings.Contains(lower, "找不到") {
			return nil
		}
		return fmt.Errorf("failed to delete scheduled task: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// scheduledTaskMatchesCurrentExe reports whether the p2ptap auto-start task
// exists AND its action points at the current executable. A task left behind
// by a moved/renamed binary is treated as stale, which lets the menu show
// "off" and toggleAutoStart(true) recreate it cleanly. The check matches the
// exe path directly rather than a localized "Task To Run" label.
func scheduledTaskMatchesCurrentExe() bool {
	exePath, err := os.Executable()
	if err != nil {
		return false
	}
	if realExe, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = realExe
	}
	cmd := exec.Command("schtasks", "/Query", "/TN", autoStartTaskName, "/FO", "LIST", "/V")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false // task not found (or query failed)
	}
	exeNorm := strings.ToLower(strings.ReplaceAll(exePath, `\`, "/"))
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// Match any line that contains the current exe path. This is
		// locale-independent (avoids parsing "Task To Run:" / "要运行的任务:").
		if strings.Contains(strings.ToLower(strings.ReplaceAll(line, `\`, "/")), exeNorm) {
			return true
		}
	}
	return false
}

func deleteRunValue() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	_ = k.DeleteValue(autoStartValueName)
	return nil
}
