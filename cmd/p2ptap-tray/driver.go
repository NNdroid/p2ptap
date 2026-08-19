//go:build windows

package main

import (
	"p2ptap/cmd/internal/driver"
	"p2ptap/pkg/logger"
)

var driverLog = logger.New("Driver")

// ensureDriver provisions the TAP/Wintun driver and returns the selected type
// ("tap" or "wintun"). hwnd is the tray window handle used for balloon
// notifications; pass 0 when the tray icon is not yet created (e.g. when invoked
// from the service entry point or a headless install). The actual driver
// detection and installation lives in cmd/internal/driver so the GUI-less
// p2ptap service can reuse the exact same logic.
func ensureDriver(hwnd uintptr) string {
	return driver.Ensure(func(msg string) {
		updateTrayStatus(msg)
		if hwnd != 0 {
			showToastNotification("p2ptap", msg, NIIF_INFO)
		}
	})
}

// updateTrayStatus is a global function pointer set by main.go so that driver
// provisioning can update the tray tooltip as it progresses.
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
