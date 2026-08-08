//go:build windows
// +build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
	"p2ptap/pkg/node"
	"p2ptap/pkg/version"
)

var (
	moduser32   = syscall.NewLazyDLL("user32.dll")
	modshell32  = syscall.NewLazyDLL("shell32.dll")
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procRegisterClassExW  = moduser32.NewProc("RegisterClassExW")
	procCreateWindowExW   = moduser32.NewProc("CreateWindowExW")
	procDefWindowProcW    = moduser32.NewProc("DefWindowProcW")
	procCreatePopupMenu   = moduser32.NewProc("CreatePopupMenu")
	procAppendMenuW       = moduser32.NewProc("AppendMenuW")
	procTrackPopupMenu    = moduser32.NewProc("TrackPopupMenu")
	procGetCursorPos      = moduser32.NewProc("GetCursorPos")
	procDestroyMenu       = moduser32.NewProc("DestroyMenu")
	procPostQuitMessage   = moduser32.NewProc("PostQuitMessage")
	procLoadIconW         = moduser32.NewProc("LoadIconW")
	procShell_NotifyIconW = modshell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandleW  = modkernel32.NewProc("GetModuleHandleW")
	procOpenClipboard     = moduser32.NewProc("OpenClipboard")
	procCloseClipboard    = moduser32.NewProc("CloseClipboard")
	procEmptyClipboard    = moduser32.NewProc("EmptyClipboard")
	procSetClipboardData  = moduser32.NewProc("SetClipboardData")
	procGlobalAlloc       = modkernel32.NewProc("GlobalAlloc")
	procGlobalLock        = modkernel32.NewProc("GlobalLock")
	procGlobalUnlock      = modkernel32.NewProc("GlobalUnlock")
	procCreateMutexW      = modkernel32.NewProc("CreateMutexW")

	procRegOpenKeyExW    = modadvapi32.NewProc("RegOpenKeyExW")
	procRegQueryValueExW = modadvapi32.NewProc("RegQueryValueExW")
	procRegSetValueExW   = modadvapi32.NewProc("RegSetValueExW")
	procRegDeleteValueW  = modadvapi32.NewProc("RegDeleteValueW")
	procRegCloseKey      = modadvapi32.NewProc("RegCloseKey")
)

const (
	WM_USER          = 0x0400
	WM_TRAYICON      = WM_USER + 1
	WM_DESTROY       = 0x0002
	WM_COMMAND       = 0x0111
	WM_RBUTTONUP     = 0x0205
	WM_LBUTTONDBLCLK = 0x0203

	NIM_ADD    = 0x00000000
	NIM_MODIFY = 0x00000001
	NIM_DELETE = 0x00000002

	NIF_MESSAGE = 0x00000001
	NIF_ICON    = 0x00000002
	NIF_TIP     = 0x00000004
	NIF_INFO    = 0x00000010

	NIIF_INFO    = 0x00000001
	NIIF_WARNING = 0x00000002
	NIIF_ERROR   = 0x00000003

	MF_STRING    = 0x00000000
	MF_SEPARATOR = 0x00000800
	MF_GRAYED    = 0x00000001

	TPM_RIGHTBUTTON = 0x0002

	GMEM_MOVEABLE  = 0x0002
	CF_UNICODETEXT = 13

	HKEY_CURRENT_USER = 0x80000001
	runKeyPath        = `Software\Microsoft\Windows\CurrentVersion\Run`
)

type WNDCLASSEXW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     syscall.Handle
	HIcon         syscall.Handle
	HCursor       syscall.Handle
	HbrBackground syscall.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       syscall.Handle
}

type NOTIFYICONDATAW struct {
	CbSize            uint32
	HWnd              syscall.Handle
	UID               uint32
	UFlags            uint32
	UCallbackMessage  uint32
	HIcon             syscall.Handle
	SzTip             [128]uint16
	DwState           uint32
	DwStateMask       uint32
	SzInfo            [256]uint16
	UTimeoutOrVersion uint32
	SzInfoTitle       [64]uint16
	DwInfoFlags       uint32
	GuidItem          [16]byte
	HBalloonIcon      syscall.Handle
}

type POINT struct {
	X int32
	Y int32
}

const (
	IDM_OPEN_WEBUI            = 1001
	IDM_COPY_IP               = 1002
	IDM_COPY_PEER             = 1003
	IDM_EDIT_CONF             = 1004
	IDM_SPEEDTEST             = 1005
	IDM_TOGGLE_AUTOSTART      = 1006
	IDM_TOGGLE_SERVICE        = 1007
	IDM_CLEAR_EXITNODE        = 1008
	IDM_COPY_IPV6             = 1009
	IDM_EXIT                  = 1099
	IDM_TOGGLE_EXITNODE_START = 2000
)

type peerExitInfo struct {
	PeerID            string
	TapIP             string
	NodeName          string
	PhysicalEndpoints []string
}

var (
	globalNode         *node.Node
	globalConfig       *config.Config
	globalConfigPath   string
	globalDriverStatus string
	hwndTray           syscall.Handle
	nid                NOTIFYICONDATAW
	log                = logger.New("Tray")
	iconGreen          syscall.Handle
	iconYellow         syscall.Handle
	currentIconState   string
	cachedPeerExits    []peerExitInfo
)

func main() {
	if exePath, err := os.Executable(); err == nil {
		_ = os.Chdir(filepath.Dir(exePath))
	}

	// Auto-elevate to Windows Administrator Privileges if needed for Wintun/TAP netsh configuration
	if !isAdministrator() {
		runAsAdmin()
		return
	}

	configPath := flag.String("c", "config.json", "Path to p2ptap configuration file")
	flag.Parse()

	// Parse flags and load configuration
	cfg, configLoadedPath, err := config.ParseFlagsAndLoadConfig(os.Args[1:])
	if err != nil {
		var loadErr error
		cfg, loadErr = config.LoadConfigFromFile(*configPath)
		if loadErr != nil {
			log.Warn("Failed to load config from %s: %v", *configPath, loadErr)
			cfg = config.DefaultConfig()
		} else {
			configLoadedPath = *configPath
		}
	}
	globalConfig = cfg
	globalConfigPath = configLoadedPath

	// Ensure single instance running using Win32 Mutex
	hMutex, isSingle := ensureSingleInstance("p2ptap_Tray_SingleInstance_Mutex")
	if !isSingle {
		showMessageBox("p2ptap", "p2ptap is already running.")
		openWebUI()
		os.Exit(0)
	}
	defer syscall.CloseHandle(hMutex)

	// Initialize global log level
	logger.SetGlobalLevel(logger.ParseLevel(cfg.LogLevel))

	// Initialize i18n for driver messages
	initTrayI18n()
	addDriverI18n()

	// Wire driver progress updates into the status display
	updateTrayStatus = func(msg string) {
		log.Info("Driver: %s", msg)
		// Update tray tooltip if icon already exists
		globalDriverStatus = msg
	}

	// Auto-detect and install TAP/Wintun driver before creating the TAP device
	// (hwnd=0 because the tray icon is created after the node starts)
	driverType := ensureDriver(0)

	// Override config's driver_type with what the auto-detection found;
	// if the user explicitly set "tap" or "wintun" in config, respect it.
	if cfg.DriverType == "" || cfg.DriverType == "auto" {
		cfg.DriverType = driverType
	}
	log.Info("Selected driver: %s", cfg.DriverType)

	// Notify user about driver choice
	if driverType == "wintun" && cfg.DriverType == "wintun" {
		driverLog.Debug("TAP-Windows6 driver not found, using built-in Wintun driver instead")
	}

	// Start P2P TAP Node
	n, err := node.NewNode(cfg)
	if err != nil {
		showErrorBox("p2ptap Startup Error", fmt.Sprintf("Failed to initialize P2P TAP Node:\n%v", err))
		os.Exit(1)
	}
	globalNode = n

	n.Start()
	node.PrintBanner(n)

	log.Info("Windows System Tray active for p2ptap (%s)", configLoadedPath)

	// Pre-generate dynamic status icons in memory
	iconGreen = generateStatusIcon("green")
	iconYellow = generateStatusIcon("yellow")

	// Run Win32 Message Loop & System Tray Icon
	runWin32TrayLoop()
}

func runWin32TrayLoop() {
	runtime.LockOSThread()

	procSetProcessDPIAware := moduser32.NewProc("SetProcessDPIAware")
	if procSetProcessDPIAware.Find() == nil {
		procSetProcessDPIAware.Call()
	}

	hInstance, _, _ := procGetModuleHandleW.Call(0)
	className, _ := syscall.UTF16PtrFromString("p2ptapSysTrayClass")

	wndProcCallback := syscall.NewCallback(wndProc)

	var wc WNDCLASSEXW
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	wc.LpfnWndProc = wndProcCallback
	wc.HInstance = syscall.Handle(hInstance)
	wc.LpszClassName = className
	wc.HIcon = iconGreen

	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("p2ptap SysTray"))),
		0x80000000, // WS_POPUP
		0, 0, 0, 0,
		0, 0, hInstance, 0,
	)
	hwndTray = syscall.Handle(hwnd)

	// Setup Notify Icon
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = hwndTray
	nid.UID = 1
	nid.UFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
	nid.UCallbackMessage = WM_TRAYICON
	nid.HIcon = iconYellow
	currentIconState = "yellow"

	updateTrayTooltip()
	procShell_NotifyIconW.Call(NIM_ADD, uintptr(unsafe.Pointer(&nid)))

	// Show startup notification toast
	showToastNotification("p2ptap is running", fmt.Sprintf("Node %s is active on %s", globalConfig.NodeName, globalConfig.TapIP))

	// Start background real-time ticker to update system tray tooltip and icon every 2 seconds
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			updateTrayTooltip()
			procShell_NotifyIconW.Call(NIM_MODIFY, uintptr(unsafe.Pointer(&nid)))
		}
	}()

	// Win32 Message Loop
	var msg struct {
		HWnd    syscall.Handle
		Message uint32
		WParam  uintptr
		LParam  uintptr
		Time    uint32
		Pt      POINT
	}

	procGetMessage := moduser32.NewProc("GetMessageW")
	procTranslateMessage := moduser32.NewProc("TranslateMessage")
	procDispatchMessage := moduser32.NewProc("DispatchMessageW")

	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if ret == 0 || int32(ret) == -1 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}

	// Clean up Tray Icon & Exit Node Gateway
	procShell_NotifyIconW.Call(NIM_DELETE, uintptr(unsafe.Pointer(&nid)))
	if globalNode != nil {
		_ = globalNode.Close()
	}
}

func updateTrayTooltip() {
	nid.UFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
	peerCount := 0
	txSpeed := "0 B/s"
	rxSpeed := "0 B/s"

	if globalNode != nil && globalNode.Collector != nil {
		stats := globalNode.Collector.GetResponse()
		peerCount = len(stats.ActivePeers)
		txSpeed = formatSpeed(stats.Speed.TxBytesPerSec)
		rxSpeed = formatSpeed(stats.Speed.RxBytesPerSec)
	}

	statusText := "Searching for peers..."
	if peerCount > 0 {
		statusText = fmt.Sprintf("%d peers online", peerCount)
		if currentIconState != "green" {
			nid.HIcon = iconGreen
			currentIconState = "green"
		}
	} else {
		if currentIconState != "yellow" {
			nid.HIcon = iconYellow
			currentIconState = "yellow"
		}
	}

	activeExit := ""
	if globalNode != nil && globalNode.Gateway != nil {
		activeExit = globalNode.Gateway.ActiveExitIP()
	}

	tipText := fmt.Sprintf("p2ptap VPN - %s\n%s\nSpeed: ↑ %s | ↓ %s", globalConfig.TapIP, statusText, txSpeed, rxSpeed)
	if activeExit != "" {
		tipText = fmt.Sprintf("p2ptap VPN (%s)\nExit Gateway: %s\n%s", globalConfig.TapIP, activeExit, statusText)
	}
	if len(tipText) > 126 {
		tipText = tipText[:126]
	}

	var szTip [128]uint16
	copy(szTip[:], syscall.StringToUTF16(tipText))
	nid.SzTip = szTip
}

func showToastNotification(title, msg string, flags ...uint32) {
	toastNid := nid
	toastNid.UFlags = NIF_INFO
	flag := uint32(NIIF_INFO)
	if len(flags) > 0 {
		flag = flags[0]
	}
	var szTitle [64]uint16
	var szInfo [256]uint16
	copy(szTitle[:], syscall.StringToUTF16(title))
	copy(szInfo[:], syscall.StringToUTF16(msg))
	toastNid.SzInfoTitle = szTitle
	toastNid.SzInfo = szInfo
	toastNid.DwInfoFlags = flag
	procShell_NotifyIconW.Call(NIM_MODIFY, uintptr(unsafe.Pointer(&toastNid)))
}

func wndProc(hwnd syscall.Handle, msg uint32, wParam uintptr, lParam uintptr) uintptr {
	switch msg {
	case WM_TRAYICON:
		evt := uint16(lParam & 0xffff)
		switch evt {
		case 0x0205, 0x0204, 0x0202, 0x007B: // WM_RBUTTONUP, WM_RBUTTONDOWN, WM_LBUTTONUP, WM_CONTEXTMENU
			showContextMenu(hwnd)
		case 0x0203: // WM_LBUTTONDBLCLK
			openWebUI()
		}
		return 0

	case WM_COMMAND:
		handleMenuCommand(uint16(wParam & 0xffff))
		return 0

	case WM_DESTROY:
		procPostQuitMessage.Call(0)
		return 0
	}

	ret, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return ret
}

func showContextMenu(hwnd syscall.Handle) {
	hMenu, _, _ := procCreatePopupMenu.Call()
	if hMenu == 0 {
		return
	}

	peerCount := 0
	txSpeed := "0 B/s"
	rxSpeed := "0 B/s"
	shortID := "unknown"
	cachedPeerExits = nil

	if globalNode != nil {
		fullID := globalNode.Host.ID().String()
		if len(fullID) > 12 {
			shortID = fullID[:12] + "..."
		} else {
			shortID = fullID
		}

		if globalNode.Collector != nil {
			stats := globalNode.Collector.GetResponse()
			peerCount = len(stats.ActivePeers)
			txSpeed = formatSpeed(stats.Speed.TxBytesPerSec)
			rxSpeed = formatSpeed(stats.Speed.RxBytesPerSec)

			for _, p := range stats.ActivePeers {
				if p.TapIP != "" {
					var physicalEPs []string
					pID, err := peer.Decode(p.PeerID)
					if err == nil {
						for _, addr := range globalNode.Host.Peerstore().Addrs(pID) {
							if ipStr, err := addr.ValueForProtocol(multiaddr.P_IP4); err == nil {
								physicalEPs = append(physicalEPs, ipStr)
							}
						}
					}
					// Add bootstrap relay IPs to protect routes
					for _, bStr := range globalConfig.BootstrapPeers {
						if ma, err := multiaddr.NewMultiaddr(bStr); err == nil {
							if ipStr, err := ma.ValueForProtocol(multiaddr.P_IP4); err == nil {
								physicalEPs = append(physicalEPs, ipStr)
							}
						}
					}

					cachedPeerExits = append(cachedPeerExits, peerExitInfo{
						PeerID:            p.PeerID,
						TapIP:             p.TapIP,
						NodeName:          p.NodeName,
						PhysicalEndpoints: physicalEPs,
					})
				}
			}
		}
	}

	titleText := fmt.Sprintf("⚡ p2ptap VPN %s", version.Version)
	ipText := fmt.Sprintf("📌 IPv4: %s", globalConfig.TapIP)
	ipv6Text := ""
	if globalConfig.TapIPv6 != "" {
		ipv6Text = fmt.Sprintf("🌐 IPv6: %s", globalConfig.TapIPv6)
	}
	peerText := fmt.Sprintf("🆔 Peer: %s", shortID)

	peerStatusText := "Searching for peers..."
	if peerCount > 0 {
		peerStatusText = fmt.Sprintf("%d peers online", peerCount)
	}
	speedText := fmt.Sprintf("Speed: ↑ %s | ↓ %s", txSpeed, rxSpeed)

	procAppendMenuW.Call(hMenu, MF_STRING|MF_GRAYED, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(titleText))))
	procAppendMenuW.Call(hMenu, MF_STRING|MF_GRAYED, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(ipText))))
	if ipv6Text != "" {
		procAppendMenuW.Call(hMenu, MF_STRING|MF_GRAYED, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(ipv6Text))))
	}
	procAppendMenuW.Call(hMenu, MF_STRING|MF_GRAYED, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(peerText))))
	procAppendMenuW.Call(hMenu, MF_SEPARATOR, 0, 0)

	procAppendMenuW.Call(hMenu, MF_STRING|MF_GRAYED, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(peerStatusText))))
	procAppendMenuW.Call(hMenu, MF_STRING|MF_GRAYED, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(speedText))))
	procAppendMenuW.Call(hMenu, MF_SEPARATOR, 0, 0)

	// Exit Node Gateway Section
	if globalNode != nil && globalNode.Gateway != nil {
		activeExit := globalNode.Gateway.ActiveExitIP()
		if activeExit != "" {
			activeExitText := fmt.Sprintf("Exit Gateway: %s", activeExit)
			procAppendMenuW.Call(hMenu, MF_STRING|MF_GRAYED, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(activeExitText))))
			procAppendMenuW.Call(hMenu, MF_STRING, IDM_CLEAR_EXITNODE, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Clear Exit Node"))))
			procAppendMenuW.Call(hMenu, MF_SEPARATOR, 0, 0)
		} else if len(cachedPeerExits) > 0 {
			// Submenu or dynamic list of online exit peers
			hSubMenu, _, _ := procCreatePopupMenu.Call()
			if hSubMenu != 0 {
				for i, p := range cachedPeerExits {
					itemText := fmt.Sprintf("🌐 %s (%s)", p.NodeName, p.TapIP)
					menuID := IDM_TOGGLE_EXITNODE_START + uint16(i)
					procAppendMenuW.Call(hSubMenu, MF_STRING, uintptr(menuID), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(itemText))))
				}
				subMenuTitle := "Set Exit Node"
				procAppendMenuW.Call(hMenu, 0x00000010 /* MF_POPUP */, hSubMenu, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subMenuTitle))))
				procAppendMenuW.Call(hMenu, MF_SEPARATOR, 0, 0)
			}
		}
	}

	procAppendMenuW.Call(hMenu, MF_STRING, IDM_OPEN_WEBUI, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Open WebUI"))))
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_SPEEDTEST, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Speed Test"))))
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_COPY_IP, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Copy IPv4"))))
	if globalConfig.TapIPv6 != "" {
		procAppendMenuW.Call(hMenu, MF_STRING, IDM_COPY_IPV6, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Copy IPv6"))))
	}
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_COPY_PEER, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Copy Peer ID"))))
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_EDIT_CONF, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Edit Config"))))
	procAppendMenuW.Call(hMenu, MF_SEPARATOR, 0, 0)

	// Auto-Start Menu Toggle Item
	if isAutoStartEnabled() {
		procAppendMenuW.Call(hMenu, MF_STRING, IDM_TOGGLE_AUTOSTART, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("✓ Auto-Start at boot"))))
	} else {
		procAppendMenuW.Call(hMenu, MF_STRING, IDM_TOGGLE_AUTOSTART, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("   Auto-Start at boot"))))
	}

	// Service Install Menu Item
	if isServiceInstalled() {
		procAppendMenuW.Call(hMenu, MF_STRING, IDM_TOGGLE_SERVICE, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Uninstall Service"))))
	} else {
		procAppendMenuW.Call(hMenu, MF_STRING, IDM_TOGGLE_SERVICE, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Install Service"))))
	}

	procAppendMenuW.Call(hMenu, MF_SEPARATOR, 0, 0)
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_EXIT, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Exit"))))

	var pt POINT
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))

	procSetForegroundWindow := moduser32.NewProc("SetForegroundWindow")
	procPostMessageW := moduser32.NewProc("PostMessageW")
	procTrackPopupMenuEx := moduser32.NewProc("TrackPopupMenuEx")

	procSetForegroundWindow.Call(uintptr(hwnd))

	retCmd, _, _ := procTrackPopupMenuEx.Call(
		hMenu,
		0x0100|0x0002, // TPM_RETURNCMD | TPM_RIGHTBUTTON
		uintptr(pt.X),
		uintptr(pt.Y),
		uintptr(hwnd),
		0,
	)

	procPostMessageW.Call(uintptr(hwnd), 0, 0, 0)
	procDestroyMenu.Call(hMenu)

	if retCmd != 0 {
		handleMenuCommand(uint16(retCmd))
	}
}

func handleMenuCommand(cmdID uint16) {
	switch cmdID {
	case IDM_OPEN_WEBUI:
		openWebUI()
	case IDM_COPY_IP:
		copyToClipboard(globalConfig.TapIP)
	case IDM_COPY_IPV6:
		copyToClipboard(globalConfig.TapIPv6)
	case IDM_COPY_PEER:
		if globalNode != nil {
			copyToClipboard(globalNode.Host.ID().String())
		}
	case IDM_EDIT_CONF:
		openConfigInEditor(globalConfigPath)
	case IDM_SPEEDTEST:
		runQuickSpeedTest()
	case IDM_TOGGLE_AUTOSTART:
		currentOn := isAutoStartEnabled()
		if err := toggleAutoStart(!currentOn); err != nil {
			showErrorBox("Auto-Start Setting Error", fmt.Sprintf("Failed to update Registry Run key:\n%v", err))
		} else {
			if !currentOn {
				showToastNotification("p2ptap", "Successfully enabled auto-start at boot!")
			} else {
				showToastNotification("p2ptap", "Disabled auto-start at boot.")
			}
		}
	case IDM_TOGGLE_SERVICE:
		installed := isServiceInstalled()
		if !installed {
			if err := installService(); err != nil {
				showErrorBox("p2ptap", fmt.Sprintf("Failed to install Windows service:\n%v\n\nHint: Please run p2ptap-tray.exe as Administrator!", err))
			} else {
				showToastNotification("p2ptap", "Successfully installed and started p2ptap Windows service!")
			}
		} else {
			if err := uninstallService(); err != nil {
				showErrorBox("p2ptap", fmt.Sprintf("Failed to uninstall Windows service:\n%v\n\nHint: Please run p2ptap-tray.exe as Administrator!", err))
			} else {
				showToastNotification("p2ptap", "Successfully stopped and uninstalled p2ptap service.")
			}
		}
	case IDM_CLEAR_EXITNODE:
		if globalNode != nil && globalNode.Gateway != nil {
			if err := globalNode.Gateway.ClearExitNode(); err != nil {
				showErrorBox("Exit Node Error", fmt.Sprintf("Failed to clear Exit Node gateway:\n%v", err))
			} else {
				showToastNotification("p2ptap", "Successfully restored local default gateway.")
			}
		}
	case IDM_EXIT:
		procShell_NotifyIconW.Call(NIM_DELETE, uintptr(unsafe.Pointer(&nid)))
		if globalNode != nil {
			_ = globalNode.Close()
		}
		procPostQuitMessage.Call(0)
	default:
		if cmdID >= IDM_TOGGLE_EXITNODE_START && cmdID < IDM_TOGGLE_EXITNODE_START+100 {
			idx := int(cmdID - IDM_TOGGLE_EXITNODE_START)
			if idx >= 0 && idx < len(cachedPeerExits) && globalNode != nil && globalNode.Gateway != nil {
				target := cachedPeerExits[idx]
				if err := globalNode.Gateway.SetExitNode(target.PeerID, target.TapIP, target.PhysicalEndpoints); err != nil {
					showErrorBox("Exit Node Error", fmt.Sprintf("Failed to set Exit Node %s (%s):\n%v\n\nHint: Setting system gateway requires running as Administrator!", target.NodeName, target.TapIP, err))
				} else {
					showToastNotification("p2ptap", fmt.Sprintf("Successfully set %s (%s) as system default gateway!\nP2P socket protection is now active.", target.NodeName, target.TapIP))
				}
			}
		}
	}
}

func runQuickSpeedTest() {
	if globalNode == nil || globalNode.Collector == nil {
		showToastNotification("p2ptap", "Node not ready.")
		return
	}
	stats := globalNode.Collector.GetResponse()
	peerCount := len(stats.ActivePeers)
	if peerCount == 0 {
		showToastNotification("p2ptap", "🟡 No online peers available, please try again later!")
		return
	}

	showToastNotification("p2ptap", fmt.Sprintf("Testing bandwidth for %d online peers...", peerCount))
	go func() {
		time.Sleep(2 * time.Second)
		latestStats := globalNode.Collector.GetResponse()
		txSpd := formatSpeed(latestStats.Speed.TxBytesPerSec)
		rxSpd := formatSpeed(latestStats.Speed.RxBytesPerSec)
		showToastNotification("p2ptap", fmt.Sprintf("⚡ p2ptap P2P Speed Test\nOnline Peers: %d\nSpeed: ↑ %s | ↓ %s", len(latestStats.ActivePeers), txSpd, rxSpd))
	}()
}

func isAutoStartEnabled() bool {
	var hKey syscall.Handle
	subKey, _ := syscall.UTF16PtrFromString(runKeyPath)
	ret, _, _ := procRegOpenKeyExW.Call(
		uintptr(HKEY_CURRENT_USER),
		uintptr(unsafe.Pointer(subKey)),
		0,
		0x20019, // KEY_READ
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret != 0 {
		return false
	}
	defer procRegCloseKey.Call(uintptr(hKey))

	valName, _ := syscall.UTF16PtrFromString("p2ptap")
	ret, _, _ = procRegQueryValueExW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(valName)),
		0,
		0,
		0,
		0,
	)
	return ret == 0
}

func toggleAutoStart(enable bool) error {
	var hKey syscall.Handle
	subKey, _ := syscall.UTF16PtrFromString(runKeyPath)
	ret, _, _ := procRegOpenKeyExW.Call(
		uintptr(HKEY_CURRENT_USER),
		uintptr(unsafe.Pointer(subKey)),
		0,
		0x20006, // KEY_WRITE
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret != 0 {
		return fmt.Errorf("failed to open registry key: %d", ret)
	}
	defer procRegCloseKey.Call(uintptr(hKey))

	valName, _ := syscall.UTF16PtrFromString("p2ptap")
	if enable {
		exePath, err := os.Executable()
		if err != nil {
			return err
		}
		absConfigPath, _ := filepath.Abs(globalConfigPath)
		cmdValue := fmt.Sprintf(`"%s" -c "%s"`, exePath, absConfigPath)
		utf16Val := syscall.StringToUTF16(cmdValue)

		ret, _, _ = procRegSetValueExW.Call(
			uintptr(hKey),
			uintptr(unsafe.Pointer(valName)),
			0,
			1, // REG_SZ
			uintptr(unsafe.Pointer(&utf16Val[0])),
			uintptr(len(utf16Val)*2),
		)
		if ret != 0 {
			return fmt.Errorf("failed to write registry value: %d", ret)
		}
	} else {
		procRegDeleteValueW.Call(
			uintptr(hKey),
			uintptr(unsafe.Pointer(valName)),
		)
	}
	return nil
}

func isServiceInstalled() bool {
	cmd := exec.Command("sc", "query", "p2ptap")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "p2ptap")
}

func installService() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	absConfigPath, _ := filepath.Abs(globalConfigPath)
	binPath := fmt.Sprintf(`"%s" -c "%s"`, exePath, absConfigPath)

	// Create service via sc
	cmdCreate := exec.Command("sc", "create", "p2ptap", "binPath=", binPath, "start=", "auto", "DisplayName=", "p2ptap P2P TAP VPN Service")
	if out, err := cmdCreate.CombinedOutput(); err != nil {
		return fmt.Errorf("sc create failed: %v (%s)", err, string(out))
	}

	// Start service
	cmdStart := exec.Command("sc", "start", "p2ptap")
	_ = cmdStart.Run()
	return nil
}

func uninstallService() error {
	// Stop service
	cmdStop := exec.Command("sc", "stop", "p2ptap")
	_ = cmdStop.Run()

	// Delete service
	cmdDelete := exec.Command("sc", "delete", "p2ptap")
	if out, err := cmdDelete.CombinedOutput(); err != nil {
		return fmt.Errorf("sc delete failed: %v (%s)", err, string(out))
	}
	return nil
}

func openWebUI() {
	port := globalConfig.WebUI.Port
	if port == 0 {
		port = 5857
	}
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	if runtime.GOOS == "windows" {
		_ = exec.Command("cmd", "/c", "start", url).Start()
	}
}

func formatSpeed(bytesPerSec uint64) string {
	b := float64(bytesPerSec)
	if b < 1024 {
		return fmt.Sprintf("%.0f B/s", b)
	} else if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB/s", b/1024)
	} else {
		return fmt.Sprintf("%.2f MB/s", b/(1024*1024))
	}
}

func copyToClipboard(text string) {
	if text == "" {
		return
	}
	ret, _, _ := procOpenClipboard.Call(0)
	if ret == 0 {
		return
	}
	defer procCloseClipboard.Call()

	procEmptyClipboard.Call()

	utf16Text := syscall.StringToUTF16(text)
	byteLen := uintptr(len(utf16Text) * 2)

	hMem, _, _ := procGlobalAlloc.Call(GMEM_MOVEABLE, byteLen)
	if hMem == 0 {
		return
	}

	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		return
	}

	for i, val := range utf16Text {
		*(*uint16)(unsafe.Pointer(ptr + uintptr(i*2))) = val
	}
	procGlobalUnlock.Call(hMem)

	procSetClipboardData.Call(CF_UNICODETEXT, hMem)
}

func showMessageBox(title, msg string) {
	procMessageBoxW := moduser32.NewProc("MessageBoxW")
	procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(msg))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))),
		0x00000040, // MB_ICONINFORMATION
	)
}

func showErrorBox(title, msg string) {
	procMessageBoxW := moduser32.NewProc("MessageBoxW")
	procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(msg))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))),
		0x00000010, // MB_ICONERROR
	)
}

func openConfigInEditor(configPath string) {
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		absPath = configPath
	}

	// 1. Check if notepad++.exe / notepad++ is in PATH
	if nppPath, err := exec.LookPath("notepad++.exe"); err == nil && nppPath != "" {
		if err := exec.Command(nppPath, absPath).Start(); err == nil {
			return
		}
	}
	if nppPath, err := exec.LookPath("notepad++"); err == nil && nppPath != "" {
		if err := exec.Command(nppPath, absPath).Start(); err == nil {
			return
		}
	}

	// 2. Check standard Notepad++ installation locations on Windows
	possibleNppPaths := []string{
		`C:\Program Files\Notepad++\notepad++.exe`,
		`C:\Program Files (x86)\Notepad++\notepad++.exe`,
		filepath.Join(os.Getenv("LocalAppData"), `Notepad++\notepad++.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Notepad++\notepad++.exe`),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Notepad++\notepad++.exe`),
	}

	for _, p := range possibleNppPaths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			if err := exec.Command(p, absPath).Start(); err == nil {
				return
			}
		}
	}

	// 3. Fallback: Windows default notepad.exe
	_ = exec.Command("notepad.exe", absPath).Start()
}

func ensureSingleInstance(mutexName string) (syscall.Handle, bool) {
	namePtr, _ := syscall.UTF16PtrFromString("Global\\" + mutexName)
	h, _, err := procCreateMutexW.Call(0, 1, uintptr(unsafe.Pointer(namePtr)))
	if h == 0 {
		return 0, false
	}
	if err == syscall.Errno(183) { // ERROR_ALREADY_EXISTS
		return syscall.Handle(h), false
	}
	return syscall.Handle(h), true
}

func isAdministrator() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	var isElevated uint32
	var retLen uint32
	err = windows.GetTokenInformation(
		token,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&isElevated)),
		uint32(unsafe.Sizeof(isElevated)),
		&retLen,
	)
	if err != nil {
		return false
	}
	return isElevated != 0
}

func runAsAdmin() {
	exePath, err := os.Executable()
	if err != nil {
		exePath = os.Args[0]
	}
	exeDir := filepath.Dir(exePath)

	verbPtr, _ := windows.UTF16PtrFromString("runas")
	exePtr, _ := windows.UTF16PtrFromString(exePath)
	cwdPtr, _ := windows.UTF16PtrFromString(exeDir)

	var args []string
	if len(os.Args) > 1 {
		args = os.Args[1:]
	}
	argsPtr, _ := windows.UTF16PtrFromString(strings.Join(args, " "))

	_ = windows.ShellExecute(0, verbPtr, exePtr, argsPtr, cwdPtr, windows.SW_HIDE)
	os.Exit(0)
}
