//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"p2ptap/pkg/logger"
	"p2ptap/pkg/tap"
)

var driverLog = logger.New("Driver")

// DriverCheckResult describes the state of available drivers.
type DriverCheckResult struct {
	TAPInstalled   bool
	WintunReady    bool
	TAPInstaller   string // path to tap-windows installer if found alongside exe
	WintunDLL      string // path to wintun.dll if found alongside exe
	PreferredDriver string // "tap" or "wintun"
}

// checkDrivers scans the system and the exe directory for usable TAP/Wintun drivers.
func checkDrivers() DriverCheckResult {
	var r DriverCheckResult

	// 1. Check TAP-Windows6 via registry
	r.TAPInstalled = tap.IsTAPDriverInstalled()

	// 2. Look for TAP installer in the same directory
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

	// 3. Check Wintun availability
	r.WintunReady = tap.IsWintunAvailable()

	// 4. If Wintun DLL is not loadable, check if the file exists
	if !r.WintunReady {
		dll := filepath.Join(exeDir, "wintun.dll")
		if fi, err := os.Stat(dll); err == nil && !fi.IsDir() {
			r.WintunDLL = dll
		}
	}

	// 5. Determine preferred driver: TAP first, then Wintun
	r.PreferredDriver = "wintun" // default fallback
	if r.TAPInstalled {
		r.PreferredDriver = "tap"
	} else if r.TAPInstaller != "" {
		r.PreferredDriver = "tap" // will try to install
	}

	return r
}

// ensureDriver is the main orchestration function.  It checks for available
// drivers, attempts installation if needed, and returns the driver type that
// should be used ("tap" or "wintun").  hwnd is the tray window handle for
// balloon/notification context (may be 0 before tray icon creation).
func ensureDriver(hwnd uintptr) string {
	result := checkDrivers()

	// Already have TAP → use it
	if result.TAPInstalled {
		updateTrayStatus("TAP-Windows6 driver found, using native TAP adapter.")
		if hwnd != 0 {
			showToastNotification("p2ptap", "TAP-Windows6 driver found, using native TAP adapter.", NIIF_INFO)
		}
		return "tap"
	}

	// TAP not installed but installer available → try to install
	if result.TAPInstaller != "" {
		updateTrayStatus("Installing TAP-Windows6 driver...")
		if hwnd != 0 {
			showToastNotification("p2ptap Installer", "Installing TAP-Windows6 driver, please wait...", NIIF_INFO)
		}
		time.Sleep(500 * time.Millisecond)

		if installTAPDriver(hwnd, result.TAPInstaller) {
			// Verify installation
			if tap.IsTAPDriverInstalled() {
				updateTrayStatus("TAP driver installed successfully.")
				if hwnd != 0 {
					showToastNotification("p2ptap", "TAP-Windows6 driver installed successfully.", NIIF_INFO)
				}
				return "tap"
			}
			// Installation reported success but registry check failed;
			// this can happen if the driver needs a reboot.
			driverLog.Debug("TAP driver install reported success but registry absent, falling back to Wintun")
		}

		driverLog.Debug("TAP driver not available, falling back to Wintun")
	}

	// Fallback to Wintun silently
	if result.WintunReady {
		driverLog.Debug("No TAP driver found, using Wintun (zero-install)")
		return "wintun"
	}

	// Neither driver is available — fatal
	updateTrayStatus("No usable TAP or Wintun driver found.")
	if hwnd != 0 {
		showToastNotification("p2ptap Error", "No usable TAP or Wintun driver found.\nPlease copy wintun.dll to the program directory.", NIIF_ERROR)
	}
	return "wintun" // let downstream fail with a clear error
}

// installTAPDriver runs the TAP-Windows installer in silent mode and waits
// for it to complete.  Returns true when the installer exits with code 0.
func installTAPDriver(hwnd uintptr, installerPath string) bool {
	updateTrayStatus("Running TAP installer (silent)...")

	// Many TAP-Windows installers support /S for silent install
	cmd := exec.Command(installerPath, "/S")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	if err := cmd.Start(); err != nil {
		updateTrayStatus("TAP installer: failed to start")
		return false
	}

	// Wait with a generous timeout (60 seconds)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			updateTrayStatus("TAP installer: exited with error")
			return false
		}
		updateTrayStatus("TAP installer completed successfully")
		return true
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		updateTrayStatus("TAP installer: timed out after 60s")
		return false
	}
}

// updateTrayStatus is a global function pointer set by main.go so that
// driver.go can update the tray tooltip during installation.
var updateTrayStatus = func(msg string) {}

// addDriverI18n registers driver-related i18n strings.
func addDriverI18n() {
	driverKeys := map[string]TrayDict{
		"zh-CN": {
			"driver_installing": "正在安装 TAP-Windows6 驱动，请稍候...",
			"driver_installed":  "TAP-Windows6 驱动安装成功。",
			"driver_failed":     "TAP 驱动安装失败，回退到 Wintun。",
			"driver_fallback":   "使用内置 Wintun 驱动（免安装）。",
		},
		"zh-TW": {
			"driver_installing": "正在安裝 TAP-Windows6 驅動，請稍候...",
			"driver_installed":  "TAP-Windows6 驅動安裝成功。",
			"driver_failed":     "TAP 驅動安裝失敗，退回至 Wintun。",
			"driver_fallback":   "使用內建 Wintun 驅動（免安裝）。",
		},
		"en": {
			"driver_installing": "Installing TAP-Windows6 driver, please wait...",
			"driver_installed":  "TAP-Windows6 driver installed successfully.",
			"driver_failed":     "TAP driver installation failed, falling back to Wintun.",
			"driver_fallback":   "Using built-in Wintun driver (zero-install).",
		},
		"ja": {
			"driver_installing": "TAP-Windows6ドライバーをインストール中...",
			"driver_installed":  "TAP-Windows6ドライバーがインストールされました。",
			"driver_failed":     "TAPドライバーのインストールに失敗、Wintunにフォールバックします。",
			"driver_fallback":   "内蔵Wintunドライバーを使用します。",
		},
		"de": {
			"driver_installing": "TAP-Windows6-Treiber wird installiert...",
			"driver_installed":  "TAP-Windows6-Treiber installiert.",
			"driver_failed":     "TAP-Treiberinstallation fehlgeschlagen, wechsle zu Wintun.",
			"driver_fallback":   "Verwende integrierten Wintun-Treiber.",
		},
		"es": {
			"driver_installing": "Instalando controlador TAP-Windows6...",
			"driver_installed":  "Controlador TAP-Windows6 instalado correctamente.",
			"driver_failed":     "Fallo en instalación del controlador TAP, usando Wintun.",
			"driver_fallback":   "Usando controlador Wintun integrado.",
		},
		"fr": {
			"driver_installing": "Installation du pilote TAP-Windows6...",
			"driver_installed":  "Pilote TAP-Windows6 installé avec succès.",
			"driver_failed":     "Échec de l'installation du pilote TAP, basculement vers Wintun.",
			"driver_fallback":   "Utilisation du pilote Wintun intégré.",
		},
	}
	for lang, dict := range driverKeys {
		if existing, ok := trayI18n[lang]; ok {
			for k, v := range dict {
				existing[k] = v
			}
		} else {
			trayI18n[lang] = dict
		}
	}
}
