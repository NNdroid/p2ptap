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

// isAutoStartEnabled reports whether p2ptap is configured to launch at logon.
func isAutoStartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	val, _, err := k.GetStringValue(autoStartValueName)
	if err != nil {
		return false
	}
	return strings.TrimSpace(val) != ""
}

// toggleAutoStart enables or disables user logon auto-start via HKCU\Run.
func toggleAutoStart(enable bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open registry key HKCU\\%s: %w", runKeyPath, err)
	}
	defer k.Close()

	if !enable {
		_ = k.DeleteValue(autoStartValueName)
		_ = deleteScheduledTask()
		return nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	realExe, err := filepath.EvalSymlinks(exePath)
	if err == nil {
		exePath = realExe
	}

	absConfigPath, _ := filepath.Abs(globalConfigPath)
	cmdValue := fmt.Sprintf(`"%s" -c "%s"`, exePath, absConfigPath)

	if err := k.SetStringValue(autoStartValueName, cmdValue); err != nil {
		return fmt.Errorf("failed to write registry value: %w", err)
	}

	// Clean up any legacy scheduled task to prevent dual launches
	_ = deleteScheduledTask()
	return nil
}

func deleteScheduledTask() error {
	cmd := exec.Command("schtasks", "/Delete", "/TN", autoStartTaskName, "/F")
	return cmd.Run()
}
