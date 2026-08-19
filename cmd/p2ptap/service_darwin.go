//go:build darwin

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	darwinBinPath     = "/usr/local/bin/p2ptap"
	darwinWorkDir     = "/usr/local/etc/p2ptap"
	darwinConfigPath  = "/usr/local/etc/p2ptap/config.json"
	darwinPlistPath   = "/Library/LaunchDaemons/com.p2ptap.daemon.plist"
	darwinServiceName = "com.p2ptap.daemon"
	darwinOutLog      = "/var/log/p2ptap.log"
	darwinErrLog      = "/var/log/p2ptap.err.log"
)

func checkAndRunService() bool {
	// launchd executes the daemon in the foreground via "p2ptap run -c ...",
	// so no custom SCM loop is needed.
	return false
}

func handleServiceCommand(args []string) {
	if len(args) == 0 {
		printDarwinServiceUsage()
		return
	}

	action := args[0]
	switch action {
	case "install":
		configPath := ""
		for i, a := range args {
			if (a == "-c" || a == "--config") && i+1 < len(args) {
				configPath = args[i+1]
			}
		}
		if err := installDarwinService(configPath); err != nil {
			fmt.Printf("[-] Failed to install launchd service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] Successfully installed and started p2ptap macOS LaunchDaemon!")
		fmt.Println("    - Binary    : " + darwinBinPath)
		fmt.Println("    - WorkDir   : " + darwinWorkDir)
		fmt.Println("    - Config    : " + darwinConfigPath)
		fmt.Println("    - Plist     : " + darwinPlistPath)
		fmt.Println("    - Logs      : " + darwinOutLog)

	case "uninstall", "remove":
		if err := uninstallDarwinService(); err != nil {
			fmt.Printf("[-] Failed to uninstall launchd service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] Successfully stopped and uninstalled p2ptap macOS LaunchDaemon.")

	case "start":
		if err := runLaunchctl("start", darwinServiceName); err != nil {
			fmt.Printf("[-] Failed to start service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] p2ptap service started successfully.")

	case "stop":
		if err := runLaunchctl("stop", darwinServiceName); err != nil {
			fmt.Printf("[-] Failed to stop service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] p2ptap service stopped successfully.")

	case "restart":
		_ = runLaunchctl("stop", darwinServiceName)
		if err := runLaunchctl("start", darwinServiceName); err != nil {
			fmt.Printf("[-] Failed to restart service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] p2ptap service restarted successfully.")

	case "status":
		out, err := exec.Command("launchctl", "list", darwinServiceName).CombinedOutput()
		if err != nil {
			fmt.Printf("[-] p2ptap daemon is not running or not loaded: %s\n", strings.TrimSpace(string(out)))
		} else {
			fmt.Printf("[*] p2ptap LaunchDaemon status:\n%s\n", strings.TrimSpace(string(out)))
		}

	case "log", "logs":
		cmd := exec.Command("tail", "-f", "-n", "50", darwinOutLog, darwinErrLog)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		_ = cmd.Run()

	default:
		fmt.Printf("Unknown service action '%s'\n", action)
		printDarwinServiceUsage()
		os.Exit(1)
	}
}

func printDarwinServiceUsage() {
	fmt.Println("Usage: p2ptap service <action> [options]")
	fmt.Println()
	fmt.Println("Actions (requires root/sudo):")
	fmt.Println("  install [-c config.json]   Install binary to /usr/local/bin, config to /usr/local/etc/p2ptap, and start macOS LaunchDaemon")
	fmt.Println("  uninstall                  Stop and remove macOS LaunchDaemon")
	fmt.Println("  start                      Start p2ptap LaunchDaemon")
	fmt.Println("  stop                       Stop p2ptap LaunchDaemon")
	fmt.Println("  restart                    Restart p2ptap LaunchDaemon")
	fmt.Println("  status                     Show LaunchDaemon status")
	fmt.Println("  logs                       Tail p2ptap daemon log files")
}

func installDarwinService(customConfigPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required (please run with sudo)")
	}

	// 1. Create working directory /usr/local/etc/p2ptap
	if err := os.MkdirAll(darwinWorkDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s failed: %w", darwinWorkDir, err)
	}

	// 2. Install binary to /usr/local/bin/p2ptap
	currentExe, err := os.Executable()
	if err != nil {
		currentExe = os.Args[0]
	}
	realCurrentExe, err := filepath.EvalSymlinks(currentExe)
	if err == nil {
		currentExe = realCurrentExe
	}

	if currentExe != darwinBinPath {
		_ = os.MkdirAll(filepath.Dir(darwinBinPath), 0755)
		if err := copyDarwinFile(currentExe, darwinBinPath, 0755); err != nil {
			return fmt.Errorf("copy binary to %s failed: %w", darwinBinPath, err)
		}
	}

	// 3. Setup configuration in /usr/local/etc/p2ptap/config.json
	if customConfigPath != "" {
		absCustom, err := filepath.Abs(customConfigPath)
		if err != nil {
			absCustom = customConfigPath
		}
		if absCustom != darwinConfigPath {
			if err := copyDarwinFile(absCustom, darwinConfigPath, 0644); err != nil {
				return fmt.Errorf("copy config from %s to %s failed: %w", absCustom, darwinConfigPath, err)
			}
			// Copy node.key if present alongside custom config
			customDir := filepath.Dir(absCustom)
			customKey := filepath.Join(customDir, "node.key")
			targetKey := filepath.Join(darwinWorkDir, "node.key")
			if _, statErr := os.Stat(customKey); statErr == nil {
				_ = copyDarwinFile(customKey, targetKey, 0600)
			}
		}
	} else if _, statErr := os.Stat(darwinConfigPath); os.IsNotExist(statErr) {
		fmt.Printf("[*] No existing config found at %s, generating default...\n", darwinConfigPath)
		generateConfigFile(darwinConfigPath)
	}

	// 4. Write LaunchDaemon property list (plist)
	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>run</string>
        <string>-c</string>
        <string>%s</string>
    </array>
    <key>WorkingDirectory</key>
    <string>%s</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
`, darwinServiceName, darwinBinPath, darwinConfigPath, darwinWorkDir, darwinOutLog, darwinErrLog)

	if err := os.WriteFile(darwinPlistPath, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("write plist file %s failed: %w", darwinPlistPath, err)
	}

	// 5. Unload old daemon if present, then load and start
	_ = exec.Command("launchctl", "unload", "-w", darwinPlistPath).Run()
	if err := runLaunchctl("load", "-w", darwinPlistPath); err != nil {
		return fmt.Errorf("launchctl load failed: %w", err)
	}

	return nil
}

func uninstallDarwinService() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required (please run with sudo)")
	}

	_ = exec.Command("launchctl", "unload", "-w", darwinPlistPath).Run()
	_ = os.Remove(darwinPlistPath)
	return nil
}

func runLaunchctl(args ...string) error {
	cmd := exec.Command("launchctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func copyDarwinFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	_ = os.Remove(dst)
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
