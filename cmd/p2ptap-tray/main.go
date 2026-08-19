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
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"p2ptap/cmd/internal/bootstrap"
	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
	"p2ptap/pkg/node"
	"p2ptap/pkg/version"
	"p2ptap/pkg/web"
)

var (
	moduser32   = syscall.NewLazyDLL("user32.dll")
	modshell32  = syscall.NewLazyDLL("shell32.dll")
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

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
	procGlobalFree        = modkernel32.NewProc("GlobalFree")
	procRtlMoveMemory     = modkernel32.NewProc("RtlMoveMemory")
	procCreateMutexW      = modkernel32.NewProc("CreateMutexW")
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

	runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
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
	TapIPv6           string
	NodeName          string
	PhysicalEndpoints []string
}

var (
	globalConfig       *config.Config
	globalConfigPath   string
	globalDriverStatus string
	hwndTray           syscall.Handle
	nid                NOTIFYICONDATAW
	log                = logger.New("Tray")
	iconGreen          syscall.Handle
	iconYellow         syscall.Handle
	iconBlue           syscall.Handle
	currentIconState   string

	// daemonClient is the thin control client for the p2ptap daemon (running as
	// a Windows service or, in standalone mode, the in-process node). The tray
	// always pulls status / issues control actions over the daemon's /api/*.
	daemonClient *DaemonClient

	// standaloneNode is the in-process node started when no p2ptap Windows
	// service is installed. It is nil in client mode (the node runs in the
	// separate service process). Quitting the tray in standalone mode tears this
	// node down; in client mode the VPN keeps running in the service.
	standaloneNode *node.Node

	// standaloneCollector is non-nil only when the tray is hosting its own
	// in-process node (fallback when no daemon is running). It is populated at
	// startup and never cleared, avoiding a race where the tray polling loop saw
	// "daemon offline" even while the node was clearly running.
	standaloneCollector *web.StatsCollector

	// standaloneMode records whether the tray is currently hosting the node.
	standaloneMode bool

	// trayCache holds the latest status snapshot polled from the daemon so the
	// tooltip and context menu can render without blocking on the network.
	trayCache = &trayStateCache{}
)

// trayStateCache is a concurrency-safe mirror of the daemon's /api/stats
// snapshot, refreshed on a background ticker.
type trayStateCache struct {
	mu         sync.RWMutex
	reachable  bool
	ownPeerID  string
	peerCount  int
	txSpeed    string
	rxSpeed    string
	activeExit string
	peerExits  []peerExitInfo
}

func (c *trayStateCache) set(s *statsResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reachable = true
	c.ownPeerID = s.PeerID
	c.peerCount = len(s.ActivePeers)
	c.txSpeed = formatSpeed(s.Speed.TxBytesPerSec)
	c.rxSpeed = formatSpeed(s.Speed.RxBytesPerSec)
	c.activeExit = s.ExitNode.ActiveExitTapIP
	exits := make([]peerExitInfo, 0, len(s.ActivePeers))
	for _, p := range s.ActivePeers {
		// Only peers that advertised themselves as Exit Node gateways
		// (config.json's `exit_node.enable = true`) are valid exit candidates.
		// TapIP/TapIPv6 alone are not enough — every peer has those because they
		// are the peer's own tunnel endpoint addresses.
		if p.IsExitNode {
			exits = append(exits, peerExitInfo{
				PeerID:   p.PeerID,
				TapIP:    p.TapIP,
				TapIPv6:  p.TapIPv6,
				NodeName: p.NodeName,
			})
		}
	}
	c.peerExits = exits
}

func (c *trayStateCache) setReachable(b bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reachable = b
}

func (c *trayStateCache) snapshot() (reachable bool, ownPeerID string, peerCount int, txSpeed, rxSpeed, activeExit string, exits []peerExitInfo) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.reachable, c.ownPeerID, c.peerCount, c.txSpeed, c.rxSpeed, c.activeExit, c.peerExits
}

func main() {
	// When launched by the Service Control Manager (i.e. we are installed as a
	// Windows service), run headless: start the node and honor SCM stop/shutdown.
	// Otherwise run the normal interactive system-tray UI.
	if isService, _ := svc.IsWindowsService(); isService {
		runService()
		return
	}
	runTray()
}

// runService is the entry point when p2ptap-tray.exe runs as a Windows service.
// It starts the P2P TAP node with no GUI and properly answers SCM control
// requests so the service can be stopped and uninstalled cleanly.
func runService() {
	// Resolve relative paths against the executable's directory.
	if exePath, err := os.Executable(); err == nil {
		_ = os.Chdir(filepath.Dir(exePath))
	}

	// Parse -c <config> manually to avoid re-defining the global flag set.
	configPath := "config.json"
	for i, a := range os.Args {
		if a == "-c" && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
		}
	}
	var configLoadedPath string
	cfg, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		log.Warn("Service mode: failed to load config from %s: %v (using defaults)", configPath, err)
		cfg = config.DefaultConfig()
		configLoadedPath = configPath
	} else {
		configLoadedPath = configPath
	}
	globalConfig = cfg
	globalConfigPath = configLoadedPath
	logger.SetGlobalLevel(logger.ParseLevel(cfg.LogLevel))

	log.Info("Running p2ptap as a Windows service (headless)...")

	if err := svc.Run("p2ptap", &p2ptapService{cfg: cfg}); err != nil {
		log.Error("svc.Run failed: %v", err)
		os.Exit(1)
	}
}

// p2ptapService implements svc.Execute so the binary can be driven by the SCM.
type p2ptapService struct {
	cfg *config.Config
}

func (s *p2ptapService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	// Ensure the TAP/Wintun driver is present before opening the TAP device.
	// The tray no longer installs the driver (it never hosts a node), so the
	// daemon — running in session 0 as a service — must do it here.
	driverType := ensureDriver(0)
	if s.cfg.DriverType == "" || s.cfg.DriverType == "auto" {
		s.cfg.DriverType = driverType
	}
	log.Info("Service mode: selected driver: %s", s.cfg.DriverType)

	n, _, initErr := bootstrap.Node(s.cfg)
	if n == nil {
		log.Error("Service mode: failed to start node: %v", initErr)
		return false, 1
	}
	n.Start()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			_ = n.Close()
			return false, 0
		default:
			// Ignore unsupported control codes.
		}
	}
	return false, 0
}

func runTray() {
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

	// Initialize i18n early so messages shown before the node starts
	// (e.g. the "already running" dialog) are localized.
	initTrayI18n()
	addDriverI18n()

	// Ensure single instance running using Win32 Mutex
	hMutex, isSingle := ensureSingleInstance("p2ptap_Tray_SingleInstance_Mutex")
	if !isSingle {
		showMessageBox("p2ptap", tT("already_running"))
		openWebUI()
		os.Exit(0)
	}
	defer syscall.CloseHandle(hMutex)

	// Initialize global log level
	logger.SetGlobalLevel(logger.ParseLevel(cfg.LogLevel))

	// Wire driver progress updates into the status display (the daemon may log
	// driver activity; in client mode this just records it).
	updateTrayStatus = func(msg string) {
		log.Info("Driver: %s", msg)
		globalDriverStatus = msg
	}

	// Decide how the tray should obtain a running node:
	//
	//   • If the p2ptap Windows service is installed, run as a PURE CLIENT and
	//     talk to that service (start it if it isn't already running). This is
	//     the "service + tray" path: exactly one node runs, in the service.
	//
	//   • If no service is installed, run in STANDALONE mode: the tray hosts the
	//     node in this very process and still serves /api/* on loopback, so the
	//     tray uses the exact same daemonClient code path. Double-clicking the
	//     tray "just works" without installing a service.
	//
	// Either way the tray only ever talks to ONE node, so we never get two
	// nodes fighting over the TAP adapter.
	if isServiceInstalled() {
		standaloneMode = false
		daemonClient = NewDaemonClient(cfg, configLoadedPath)
		ensureDaemonRunning()
		log.Info("Windows System Tray (client mode) active for p2ptap (%s)", configLoadedPath)
	} else {
		standaloneMode = true
		// Start the node in-process; its WebUI persists the auth token sidecar,
		// after which we build the client that talks to the local loopback API.
		startStandaloneNode(cfg, configLoadedPath)
		daemonClient = NewDaemonClient(cfg, configLoadedPath)
		log.Info("Windows System Tray (standalone mode) active for p2ptap (%s)", configLoadedPath)
	}

	// Pre-generate dynamic status icons in memory
	iconGreen = generateStatusIcon("green")
	iconYellow = generateStatusIcon("yellow")
	iconBlue = generateStatusIcon("blue")

	// Run Win32 Message Loop & System Tray Icon
	runWin32TrayLoop()
}

// startStandaloneNode bootstraps the p2ptap node inside the tray process. It is
// used when no Windows service is installed, so double-clicking the tray runs
// the VPN directly without any service plumbing. The node's WebUI still serves
// /api/* on loopback, which is why the tray can keep using the same daemonClient
// it would use against the service.
func startStandaloneNode(cfg *config.Config, configPath string) {
	if exePath, err := os.Executable(); err == nil {
		_ = os.Chdir(filepath.Dir(exePath))
	}
	// Point the node's persisted auth-token sidecar at the config we loaded, so
	// the daemonClient built afterwards reads the same token for /api/* auth.
	if configPath != "" {
		cfg.ConfigPath = configPath
	}

	// Ensure the TAP/Wintun driver is present (the tray is elevated to admin).
	driverType := ensureDriver(0)
	if cfg.DriverType == "" || cfg.DriverType == "auto" {
		cfg.DriverType = driverType
	}
	log.Info("Standalone mode: selected driver: %s", cfg.DriverType)

	n, coll, initErr := bootstrap.Node(cfg)
	if n == nil {
		showErrorBox(tT("err_startup_title"), fmt.Sprintf(tT("err_startup_msg"), initErr))
		os.Exit(1)
	}
	n.Start()
	standaloneNode = n
	// Keep the concrete collector so the tray can read status / drive Exit Node
	// control directly, bypassing the loopback HTTP entirely in standalone mode.
	if sc, ok := coll.(*web.StatsCollector); ok {
		standaloneCollector = sc
	}
}

// switchFromStandaloneToService tears down the in-process node and hands control
// to the freshly installed Windows service, so exactly one node ever owns the
// TAP adapter. The tray then becomes a plain client of that service. If the
// install fails we restart the node in-process so the VPN keeps working.
func switchFromStandaloneToService() error {
	if standaloneNode != nil {
		_ = standaloneNode.Close()
		standaloneNode = nil
		standaloneCollector = nil
	}
	if err := installService(); err != nil {
		// Roll back: bring the node back up in-process.
		startStandaloneNode(globalConfig, globalConfigPath)
		return err
	}
	standaloneMode = false
	// The service persisted a fresh token sidecar; rebuild the client so it
	// authenticates to the service's loopback API, and wait for it to come up.
	daemonClient = NewDaemonClient(globalConfig, globalConfigPath)
	for i := 0; i < 20; i++ {
		if daemonClient != nil && daemonClient.Reachable() {
			break
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

// fetchStats returns the latest node status snapshot using the most reliable
// source for the current mode: in standalone mode the tray reads the in-process
// collector directly (no HTTP); otherwise it calls the daemon's /api/stats.
func fetchStats() (*statsResponse, error) {
	if standaloneMode && standaloneCollector != nil {
		return standaloneStats()
	}
	if daemonClient != nil {
		return daemonClient.Stats()
	}
	return nil, fmt.Errorf("no status source available")
}

// standaloneStats maps the in-process collector's snapshot into the tray's
// statsResponse DTO. Reading directly avoids the loopback HTTP token/auth/bind
// fragility that previously left the tray stuck on "daemon offline".
func standaloneStats() (*statsResponse, error) {
	if standaloneCollector == nil {
		return nil, fmt.Errorf("collector not ready")
	}
	r := standaloneCollector.GetResponse()
	s := &statsResponse{
		PeerID:  r.PeerID,
		TapIP:   r.TapIP,
		TapIPv6: r.TapIPv6,
		ExitNode: exitNodeInfoDTO{
			ActiveExitPeerID: r.ExitNode.ActivePeerID,
			ActiveExitTapIP:  r.ExitNode.ActiveExitIP,
		},
		Speed: speedStatsDTO{
			TxBytesPerSec: r.Speed.TxBytesPerSec,
			RxBytesPerSec: r.Speed.RxBytesPerSec,
		},
	}
	for _, p := range r.ActivePeers {
		s.ActivePeers = append(s.ActivePeers, peerInfoDTO{
			PeerID:     p.PeerID,
			NodeName:   p.NodeName,
			TapIP:      p.TapIP,
			TapIPv6:    p.TapIPv6,
			IsExitNode: p.IsExitNode,
		})
	}
	return s, nil
}

// setExitNode routes all traffic through the given peer's exit node. In
// standalone mode it drives the in-process gateway directly; otherwise it uses
// the daemon's /api/exitnode.
func setExitNode(peerID, tapIP, tapIPv6 string) error {
	if standaloneMode && standaloneCollector != nil && standaloneCollector.Gateway != nil {
		return standaloneCollector.Gateway.SetExitNode(peerID, tapIP, tapIPv6, nil)
	}
	if daemonClient != nil {
		return daemonClient.SetExitNode(peerID, tapIP, tapIPv6)
	}
	return fmt.Errorf("no control path available")
}

// clearExitNode restores the default route. Mirrors setExitNode's mode split.
func clearExitNode() error {
	if standaloneMode && standaloneCollector != nil && standaloneCollector.Gateway != nil {
		return standaloneCollector.Gateway.ClearExitNode()
	}
	if daemonClient != nil {
		return daemonClient.ClearExitNode()
	}
	return fmt.Errorf("no control path available")
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
	wc.Style = 0x0008 // CS_DBLCLKS: enable WM_LBUTTONDBLCLK so left double-click opens WebUI
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
	showToastNotification(tT("toast_start_head"), fmt.Sprintf(tT("toast_start_msg"), globalConfig.NodeName, globalConfig.TapIP, globalConfig.TapIPv6))

	// Start background real-time ticker to refresh node status and update the
	// system tray tooltip/icon every 2 seconds. In standalone mode the status
	// comes straight from the in-process collector; in client mode it comes from
	// the daemon's /api/stats.
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if stats, err := fetchStats(); err == nil {
				trayCache.set(stats)
			} else {
				trayCache.setReachable(false)
			}
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

	// In standalone mode the node runs in this process, so quitting the tray
	// also stops the VPN. In client mode the node belongs to the service and is
	// intentionally left running.
	if standaloneNode != nil {
		log.Info("Standalone mode: shutting down in-process node...")
		_ = standaloneNode.Close()
		standaloneNode = nil
		standaloneCollector = nil
	}

	// Clean up Tray Icon.
	procShell_NotifyIconW.Call(NIM_DELETE, uintptr(unsafe.Pointer(&nid)))
}

func updateTrayTooltip() {
	nid.UFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP

	reachable, _, peerCount, txSpeed, rxSpeed, activeExit, _ := trayCache.snapshot()

	statusText := tT("daemon_offline")
	if reachable {
		statusText = tT("searching_peers")
		if peerCount > 0 {
			statusText = fmt.Sprintf(tT("peers_online"), peerCount)
		}
	}

	// Icon color priority: blue (exit node active) > green (peers online) > yellow (searching)
	switch {
	case activeExit != "":
		if currentIconState != "blue" {
			nid.HIcon = iconBlue
			currentIconState = "blue"
		}
	case peerCount > 0:
		if currentIconState != "green" {
			nid.HIcon = iconGreen
			currentIconState = "green"
		}
	default:
		if currentIconState != "yellow" {
			nid.HIcon = iconYellow
			currentIconState = "yellow"
		}
	}

	tipText := fmt.Sprintf("%s\n%s", statusText,
		fmt.Sprintf(tT("realtime_speed"), txSpeed, rxSpeed))
	if activeExit != "" {
		tipText = fmt.Sprintf("%s [%s]\n%s: %s", tT("exit_active"), activeExit, statusText,
			fmt.Sprintf(tT("realtime_speed"), txSpeed, rxSpeed))
	}

	// Truncate on UTF-16 code-unit boundaries (NOT raw bytes) so that CJK /
	// other multi-byte text never gets cut mid-character and turned into mojibake.
	u16 := syscall.StringToUTF16(tipText)
	const maxTip = 127 // SzTip holds 128 uint16 including the NUL terminator
	if len(u16) > maxTip {
		u16 = u16[:maxTip]
	}
	var szTip [128]uint16
	copy(szTip[:], u16)
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
		case 0x0205, 0x007B: // WM_RBUTTONUP, WM_CONTEXTMENU (keyboard) -> right-click menu only
			showContextMenu(hwnd)
		case 0x0203: // WM_LBUTTONDBLCLK -> open WebUI
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

	reachable, ownPeerID, peerCount, txSpeed, rxSpeed, activeExit, exits := trayCache.snapshot()

	shortID := "unknown"
	if len(ownPeerID) > 12 {
		shortID = ownPeerID[:12] + "..."
	} else if ownPeerID != "" {
		shortID = ownPeerID
	}

	// When the daemon is unreachable the cached peer list is stale/empty; do not
	// advertise a phantom exit-node list.
	if !reachable {
		exits = nil
	}

	titleText := fmt.Sprintf(tT("menu_title"), version.Version)
	ipText := fmt.Sprintf(tT("ipv4_label"), globalConfig.TapIP)
	ipv6Text := ""
	if globalConfig.TapIPv6 != "" {
		ipv6Text = fmt.Sprintf(tT("ipv6_label"), globalConfig.TapIPv6)
	}
	peerText := fmt.Sprintf(tT("peer_label"), shortID)

	peerStatusText := tT("searching_peers")
	if peerCount > 0 {
		peerStatusText = fmt.Sprintf(tT("peers_online"), peerCount)
	}
	speedText := fmt.Sprintf(tT("realtime_speed"), txSpeed, rxSpeed)

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

	// Exit Node Gateway Section — driven entirely by the cached daemon status.
	if reachable {
		if activeExit != "" {
			activeExitText := fmt.Sprintf(tT("active_exit"), activeExit)
			procAppendMenuW.Call(hMenu, MF_STRING|MF_GRAYED, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(activeExitText))))
			procAppendMenuW.Call(hMenu, MF_STRING, IDM_CLEAR_EXITNODE, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(tT("clear_exit_node")))))
			procAppendMenuW.Call(hMenu, MF_SEPARATOR, 0, 0)
		} else if len(exits) > 0 {
			// Submenu or dynamic list of online exit peers
			hSubMenu, _, _ := procCreatePopupMenu.Call()
			if hSubMenu != 0 {
				for i, p := range exits {
					itemText := fmt.Sprintf("🌐 %s (%s)", p.NodeName, p.TapIP)
					menuID := IDM_TOGGLE_EXITNODE_START + uint16(i)
					procAppendMenuW.Call(hSubMenu, MF_STRING, uintptr(menuID), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(itemText))))
				}
				subMenuTitle := tT("set_exit_node")
				procAppendMenuW.Call(hMenu, 0x00000010 /* MF_POPUP */, hSubMenu, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subMenuTitle))))
				procAppendMenuW.Call(hMenu, MF_SEPARATOR, 0, 0)
			}
		}
	}

	procAppendMenuW.Call(hMenu, MF_STRING, IDM_OPEN_WEBUI, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(tT("open_webui")))))
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_SPEEDTEST, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(tT("speedtest")))))
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_COPY_IP, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(tT("copy_ip")))))
	if globalConfig.TapIPv6 != "" {
		procAppendMenuW.Call(hMenu, MF_STRING, IDM_COPY_IPV6, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(tT("copy_ipv6")))))
	}
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_COPY_PEER, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(tT("copy_peer")))))
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_EDIT_CONF, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(tT("edit_conf")))))
	procAppendMenuW.Call(hMenu, MF_SEPARATOR, 0, 0)

	// Auto-Start Menu Toggle Item
	if isAutoStartEnabled() {
		procAppendMenuW.Call(hMenu, MF_STRING, IDM_TOGGLE_AUTOSTART, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(tT("autostart_on")))))
	} else {
		procAppendMenuW.Call(hMenu, MF_STRING, IDM_TOGGLE_AUTOSTART, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(tT("autostart_off")))))
	}

	// Service Install Menu Item
	if isServiceInstalled() {
		procAppendMenuW.Call(hMenu, MF_STRING, IDM_TOGGLE_SERVICE, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(tT("svc_uninstall")))))
	} else {
		procAppendMenuW.Call(hMenu, MF_STRING, IDM_TOGGLE_SERVICE, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(tT("svc_install")))))
	}

	procAppendMenuW.Call(hMenu, MF_SEPARATOR, 0, 0)
	procAppendMenuW.Call(hMenu, MF_STRING, IDM_EXIT, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(tT("exit")))))

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
		_, ownPeerID, _, _, _, _, _ := trayCache.snapshot()
		if ownPeerID != "" {
			copyToClipboard(ownPeerID)
		}
	case IDM_EDIT_CONF:
		openConfigInEditor(globalConfigPath)
	case IDM_SPEEDTEST:
		runQuickSpeedTest()
	case IDM_TOGGLE_AUTOSTART:
		currentOn := isAutoStartEnabled()
		if err := toggleAutoStart(!currentOn); err != nil {
			showErrorBox(tT("err_autostart_title"), fmt.Sprintf(tT("err_autostart_msg"), err))
		} else {
			if !currentOn {
				showToastNotification("p2ptap", tT("toast_autostart_on"))
			} else {
				showToastNotification("p2ptap", tT("toast_autostart_off"))
			}
		}
	case IDM_TOGGLE_SERVICE:
		installed := isServiceInstalled()
		if !installed {
			if err := switchFromStandaloneToService(); err != nil {
				showErrorBox(tT("err_svc_install_title"), fmt.Sprintf(tT("err_svc_install_msg"), err))
			} else {
				// The service already provides an always-on node, so disable
				// tray auto-start to avoid two nodes fighting over the TAP
				// adapter at boot. (Best-effort; ignore errors.)
				_ = toggleAutoStart(false)
				showToastNotification("p2ptap", tT("toast_svc_installed"))
			}
		} else {
			if err := uninstallService(); err != nil {
				showErrorBox(tT("err_svc_install_title"), fmt.Sprintf(tT("err_svc_uninstall_msg"), err))
			} else {
				showToastNotification("p2ptap", tT("toast_svc_uninstalled"))
			}
		}
	case IDM_CLEAR_EXITNODE:
		if err := clearExitNode(); err != nil {
			showErrorBox(tT("err_exitnode_title"), fmt.Sprintf(tT("err_clear_exit_msg"), err))
		} else {
			showToastNotification("p2ptap", tT("toast_gw_restored"))
		}
	case IDM_EXIT:
		// Quitting the tray never stops the daemon (the VPN keeps running).
		procShell_NotifyIconW.Call(NIM_DELETE, uintptr(unsafe.Pointer(&nid)))
		procPostQuitMessage.Call(0)
	default:
		if cmdID >= IDM_TOGGLE_EXITNODE_START && cmdID < IDM_TOGGLE_EXITNODE_START+100 {
			idx := int(cmdID - IDM_TOGGLE_EXITNODE_START)
			_, _, _, _, _, _, exits := trayCache.snapshot()
			if idx >= 0 && idx < len(exits) {
				target := exits[idx]
				if err := setExitNode(target.PeerID, target.TapIP, target.TapIPv6); err != nil {
					showErrorBox(tT("err_exitnode_title"), fmt.Sprintf(tT("err_set_exit_msg"), target.NodeName, target.TapIP, err))
				} else {
					showToastNotification("p2ptap", fmt.Sprintf(tT("toast_exit_set"), target.NodeName, target.TapIP))
				}
			}
		}
	}
}

func runQuickSpeedTest() {
	stats, err := fetchStats()
	if err != nil {
		showToastNotification("p2ptap", tT("toast_node_not_ready"))
		return
	}
	peerCount := len(stats.ActivePeers)
	if peerCount == 0 {
		showToastNotification("p2ptap", tT("toast_no_peers"))
		return
	}

	showToastNotification("p2ptap", fmt.Sprintf(tT("toast_speedtesting"), peerCount))
	go func() {
		time.Sleep(2 * time.Second)
		latest, lerr := fetchStats()
		if lerr != nil {
			return
		}
		txSpd := formatSpeed(latest.Speed.TxBytesPerSec)
		rxSpd := formatSpeed(latest.Speed.RxBytesPerSec)
		showToastNotification("p2ptap", fmt.Sprintf(tT("toast_speedtest_result"), len(latest.ActivePeers), txSpd, rxSpd))
	}()
}

func isAutoStartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	val, _, err := k.GetStringValue("p2ptap")
	if err != nil {
		return false
	}
	// Present and non-empty means auto-start is enabled.
	return strings.TrimSpace(val) != ""
}

func toggleAutoStart(enable bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open registry key: %w", err)
	}
	defer k.Close()

	if !enable {
		// Best-effort: ignore "value does not exist".
		_ = k.DeleteValue("p2ptap")
		return nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	absConfigPath, _ := filepath.Abs(globalConfigPath)
	cmdValue := fmt.Sprintf(`"%s" -c "%s"`, exePath, absConfigPath)
	if err := k.SetStringValue("p2ptap", cmdValue); err != nil {
		return fmt.Errorf("failed to write registry value: %w", err)
	}
	return nil
}

func isServiceInstalled() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()

	s, err := m.OpenService("p2ptap")
	if err != nil {
		return false
	}
	s.Close()
	return true
}

func installService() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	absConfigPath, _ := filepath.Abs(globalConfigPath)

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Service Control Manager: %w", err)
	}
	defer m.Disconnect()

	// Already installed — nothing to do.
	if s, err := m.OpenService("p2ptap"); err == nil {
		s.Close()
		return fmt.Errorf("service 'p2ptap' is already installed")
	}

	// svc/mgr quotes the executable path internally only if needed; pass it
	// quoted ourselves so paths with spaces (e.g. "Program Files") work. The
	// config path is also quoted so spaces there are handled.
	quotedExe := `"` + exePath + `"`
	s, err := m.CreateService(
		"p2ptap",
		quotedExe,
		mgr.Config{
			DisplayName: "p2ptap Service",
			Description: "P2P TAP VPN node — runs headless in the background.",
			StartType:   mgr.StartAutomatic,
		},
		"-c", `"`+absConfigPath+`"`,
	)
	if err != nil {
		return fmt.Errorf("CreateService failed: %w", err)
	}
	defer s.Close()

	// Configure recovery: restart on failure so an unexpected crash doesn't
	// leave the VPN silently down.
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 0)

	// Best-effort start; report but don't fail if it doesn't come up instantly.
	if err := s.Start(); err != nil {
		log.Warn("Service installed but failed to start immediately: %v", err)
	}
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Service Control Manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService("p2ptap")
	if err != nil {
		return fmt.Errorf("service 'p2ptap' is not installed: %w", err)
	}
	defer s.Close()

	// Ask the service to stop, then wait for it to actually reach STOPPED so
	// the delete succeeds (this is the step that used to hang with sc).
	_, _ = s.Control(svc.Stop)
	for i := 0; i < 30; i++ {
		status, qerr := s.Query()
		if qerr != nil {
			break
		}
		if status.State == svc.Stopped {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}
	return nil
}

// startService starts the already-installed p2ptap service (no re-create).
func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Service Control Manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService("p2ptap")
	if err != nil {
		return fmt.Errorf("service 'p2ptap' is not installed: %w", err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}
	// Wait for RUNNING so the caller can rely on the daemon being up.
	for i := 0; i < 30; i++ {
		status, qerr := s.Query()
		if qerr != nil {
			break
		}
		if status.State == svc.Running {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil
}

// ensureDaemonRunning brings the p2ptap daemon up if it isn't already. The tray
// is a pure client, so the VPN only works when the daemon (service, or a
// foreground process) is alive. We start the service if it's installed, or
// install + start it on first run, then wait briefly for it to accept API calls.
func ensureDaemonRunning() {
	if daemonClient != nil && daemonClient.Reachable() {
		return
	}

	var err error
	if isServiceInstalled() {
		err = startService()
	} else {
		// installService also starts the service.
		err = installService()
	}
	if err != nil {
		showErrorBox(tT("err_svc_install_title"), fmt.Sprintf(tT("err_svc_install_msg"), err))
		return
	}

	// Give the freshly started daemon a moment to come up and serve /api/stats.
	for i := 0; i < 20; i++ {
		if daemonClient != nil && daemonClient.Reachable() {
			return
		}
		time.Sleep(1 * time.Second)
	}
}

func openWebUI() {
	url := resolveWebuiURL()
	if runtime.GOOS == "windows" {
		_ = exec.Command("cmd", "/c", "start", url).Start()
	}
}

// resolveWebuiURL returns the URL the WebUI is actually listening on. It reads
// the sidecar the server rewrites on every (re)bind (.p2ptap_webui_url, next to
// config.json), preferring a loopback address. This makes the tray open the
// REAL dashboard address instead of a hardcoded 127.0.0.1:configPort, which is
// wrong when the WebUI binds to a specific interface IP or fell back to an
// alt-port after a bind collision. Falls back to the legacy loopback URL if the
// sidecar is missing/unreadable.
func resolveWebuiURL() string {
	fallback := "http://127.0.0.1:5857"
	if globalConfig != nil {
		if p := globalConfig.WebUI.Port; p != 0 {
			fallback = fmt.Sprintf("http://127.0.0.1:%d", p)
		}
	}
	if globalConfigPath == "" {
		return fallback
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(globalConfigPath), webuiURLSidecar))
	if err != nil {
		return fallback
	}
	preferred := ""
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "127.0.0.1") {
			return line // loopback is always locally reachable — use it directly
		}
		if preferred == "" {
			preferred = line
		}
	}
	if preferred != "" {
		return preferred
	}
	return fallback
}

// webuiURLSidecar mirrors the server-side sidecar filename; the server writes
// the actual bound WebUI URLs here (one per line) on every (re)bind.
const webuiURLSidecar = ".p2ptap_webui_url"

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
	byteLen := uintptr(len(utf16Text) * 2) // includes terminating NUL

	hMem, _, _ := procGlobalAlloc.Call(GMEM_MOVEABLE, byteLen)
	if hMem == 0 {
		return
	}
	// Until SetClipboardData succeeds, we still own hMem and must free it on
	// any failure path below.
	locked := false
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		procGlobalFree.Call(hMem)
		return
	}
	locked = true

	// Copy UTF-16 bytes (including NUL) into the locked memory via RtlMoveMemory.
	// Done in-kernel (no Go pointer arithmetic over the GMEM handle) so there is
	// no unsafe.Pointer lifetime risk.
	procRtlMoveMemory.Call(
		ptr,
		uintptr(unsafe.Pointer(&utf16Text[0])),
		byteLen,
	)
	procGlobalUnlock.Call(hMem)
	locked = false

	// On success the clipboard takes ownership of hMem; on failure free it.
	setRet, _, _ := procSetClipboardData.Call(CF_UNICODETEXT, hMem)
	if setRet == 0 {
		if locked {
			procGlobalUnlock.Call(hMem)
		}
		procGlobalFree.Call(hMem)
	}
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
