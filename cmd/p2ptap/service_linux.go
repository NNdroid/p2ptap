//go:build linux

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
	linuxBinPath     = "/usr/local/bin/p2ptap"
	linuxWorkDir     = "/usr/local/etc/p2ptap"
	linuxConfigPath  = "/usr/local/etc/p2ptap/config.json"
	linuxSystemdPath = "/etc/systemd/system/p2ptap.service"
	linuxSystemdName = "p2ptap.service"
	linuxOpenRCPath  = "/etc/init.d/p2ptap"
	linuxOpenRCName  = "p2ptap"
	linuxOutLog      = "/var/log/p2ptap.log"
	linuxErrLog      = "/var/log/p2ptap.err.log"
)

func checkAndRunService() bool {
	return false
}

func isOpenRC() bool {
	if _, err := os.Stat("/sbin/openrc-run"); err == nil {
		return true
	}
	if _, err := os.Stat("/etc/alpine-release"); err == nil {
		return true
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		return true
	}
	return false
}

func handleServiceCommand(args []string) {
	if len(args) == 0 {
		printLinuxServiceUsage()
		return
	}

	action := args[0]
	useOpenRC := isOpenRC()

	switch action {
	case "install":
		configPath := ""
		for i, a := range args {
			if (a == "-c" || a == "--config") && i+1 < len(args) {
				configPath = args[i+1]
			}
		}
		if useOpenRC {
			if err := installOpenRCService(configPath); err != nil {
				fmt.Printf("[-] Failed to install OpenRC service: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("[+] Successfully installed and started p2ptap OpenRC service (Alpine Linux)!")
			fmt.Println("    - Binary    : " + linuxBinPath)
			fmt.Println("    - WorkDir   : " + linuxWorkDir)
			fmt.Println("    - Config    : " + linuxConfigPath)
			fmt.Println("    - Init file : " + linuxOpenRCPath)
			fmt.Println("    - Logs      : " + linuxOutLog)
		} else {
			if err := installSystemdService(configPath); err != nil {
				fmt.Printf("[-] Failed to install systemd service: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("[+] Successfully installed and started p2ptap systemd service!")
			fmt.Println("    - Binary    : " + linuxBinPath)
			fmt.Println("    - WorkDir   : " + linuxWorkDir)
			fmt.Println("    - Config    : " + linuxConfigPath)
			fmt.Println("    - Unit file : " + linuxSystemdPath)
		}

	case "uninstall", "remove":
		var err error
		if useOpenRC {
			err = uninstallOpenRCService()
		} else {
			err = uninstallSystemdService()
		}
		if err != nil {
			fmt.Printf("[-] Failed to uninstall service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] Successfully stopped and uninstalled p2ptap service.")

	case "start":
		var err error
		if useOpenRC {
			err = runCmd("rc-service", linuxOpenRCName, "start")
		} else {
			err = runCmd("systemctl", "start", linuxSystemdName)
		}
		if err != nil {
			fmt.Printf("[-] Failed to start service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] p2ptap service started successfully.")

	case "stop":
		var err error
		if useOpenRC {
			err = runCmd("rc-service", linuxOpenRCName, "stop")
		} else {
			err = runCmd("systemctl", "stop", linuxSystemdName)
		}
		if err != nil {
			fmt.Printf("[-] Failed to stop service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] p2ptap service stopped successfully.")

	case "restart":
		var err error
		if useOpenRC {
			err = runCmd("rc-service", linuxOpenRCName, "restart")
		} else {
			err = runCmd("systemctl", "restart", linuxSystemdName)
		}
		if err != nil {
			fmt.Printf("[-] Failed to restart service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] p2ptap service restarted successfully.")

	case "status":
		if useOpenRC {
			_ = runCmdWithOutput("rc-service", linuxOpenRCName, "status")
		} else {
			_ = runCmdWithOutput("systemctl", "status", linuxSystemdName)
		}

	case "log", "logs":
		if useOpenRC {
			cmd := exec.Command("tail", "-f", "-n", "50", linuxOutLog, linuxErrLog)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin
			_ = cmd.Run()
		} else {
			cmd := exec.Command("journalctl", "-u", linuxSystemdName, "-f", "-n", "50")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin
			_ = cmd.Run()
		}

	default:
		fmt.Printf("Unknown service action '%s'\n", action)
		printLinuxServiceUsage()
		os.Exit(1)
	}
}

func printLinuxServiceUsage() {
	fmt.Println("Usage: p2ptap service <action> [options]")
	fmt.Println()
	fmt.Println("Actions (requires root/sudo):")
	fmt.Println("  install [-c config.json]   Install binary to /usr/local/bin, config to /usr/local/etc/p2ptap, and start service")
	fmt.Println("  uninstall                  Stop and remove service (systemd / OpenRC)")
	fmt.Println("  start                      Start p2ptap service")
	fmt.Println("  stop                       Stop p2ptap service")
	fmt.Println("  restart                    Restart p2ptap service")
	fmt.Println("  status                     Show service status")
	fmt.Println("  logs                       Stream live service logs")
}

func prepareLinuxEnv(customConfigPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required (please run with sudo)")
	}

	// 1. Create working directory /usr/local/etc/p2ptap
	if err := os.MkdirAll(linuxWorkDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s failed: %w", linuxWorkDir, err)
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

	if currentExe != linuxBinPath {
		_ = os.MkdirAll(filepath.Dir(linuxBinPath), 0755)
		if err := copyFile(currentExe, linuxBinPath, 0755); err != nil {
			return fmt.Errorf("copy binary to %s failed: %w", linuxBinPath, err)
		}
	}

	// 3. Setup configuration in /usr/local/etc/p2ptap/config.json
	if customConfigPath != "" {
		absCustom, err := filepath.Abs(customConfigPath)
		if err != nil {
			absCustom = customConfigPath
		}
		if absCustom != linuxConfigPath {
			if err := copyFile(absCustom, linuxConfigPath, 0644); err != nil {
				return fmt.Errorf("copy config from %s to %s failed: %w", absCustom, linuxConfigPath, err)
			}
			customDir := filepath.Dir(absCustom)
			customKey := filepath.Join(customDir, "node.key")
			targetKey := filepath.Join(linuxWorkDir, "node.key")
			if _, statErr := os.Stat(customKey); statErr == nil {
				_ = copyFile(customKey, targetKey, 0600)
			}
		}
	} else if _, statErr := os.Stat(linuxConfigPath); os.IsNotExist(statErr) {
		fmt.Printf("[*] No existing config found at %s, generating default...\n", linuxConfigPath)
		generateConfigFile(linuxConfigPath)
	}

	return nil
}

func installSystemdService(customConfigPath string) error {
	if err := prepareLinuxEnv(customConfigPath); err != nil {
		return err
	}

	serviceContent := fmt.Sprintf(`[Unit]
Description=p2ptap P2P TAP VPN Node Daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
ExecStart=%s run -c %s
Restart=always
RestartSec=5s
LimitNOFILE=65536
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW

[Install]
WantedBy=multi-user.target
`, linuxWorkDir, linuxBinPath, linuxConfigPath)

	if err := os.WriteFile(linuxSystemdPath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("write systemd unit file %s failed: %w", linuxSystemdPath, err)
	}

	if err := runCmd("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload failed: %w", err)
	}
	if err := runCmd("systemctl", "enable", "--now", linuxSystemdName); err != nil {
		return fmt.Errorf("systemctl enable --now failed: %w", err)
	}

	return nil
}

func uninstallSystemdService() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required (please run with sudo)")
	}

	_ = runCmd("systemctl", "disable", "--now", linuxSystemdName)
	_ = os.Remove(linuxSystemdPath)
	_ = runCmd("systemctl", "daemon-reload")
	return nil
}

func installOpenRCService(customConfigPath string) error {
	if err := prepareLinuxEnv(customConfigPath); err != nil {
		return err
	}

	openRCContent := fmt.Sprintf(`#!/sbin/openrc-run
name="p2ptap"
description="p2ptap P2P TAP VPN Node Daemon"

command="%s"
command_args="run -c %s"
command_background="yes"
directory="%s"
pidfile="/run/${RC_SVCNAME}.pid"
output_log="%s"
error_log="%s"

depend() {
	need net
	after firewall
}
`, linuxBinPath, linuxConfigPath, linuxWorkDir, linuxOutLog, linuxErrLog)

	if err := os.WriteFile(linuxOpenRCPath, []byte(openRCContent), 0755); err != nil {
		return fmt.Errorf("write OpenRC init file %s failed: %w", linuxOpenRCPath, err)
	}

	_ = runCmd("rc-update", "add", linuxOpenRCName, "default")
	_ = runCmd("rc-service", linuxOpenRCName, "restart")
	return nil
}

func uninstallOpenRCService() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required (please run with sudo)")
	}

	_ = runCmd("rc-service", linuxOpenRCName, "stop")
	_ = runCmd("rc-update", "del", linuxOpenRCName, "default")
	_ = os.Remove(linuxOpenRCPath)
	return nil
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runCmdWithOutput(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func copyFile(src, dst string, mode os.FileMode) error {
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
