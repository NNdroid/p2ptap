//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"p2ptap/cmd/internal/bootstrap"
	"p2ptap/cmd/internal/driver"
	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
)

var (
	modkernel32      = windows.NewLazySystemDLL("kernel32.dll")
	procCreateMutexW = modkernel32.NewProc("CreateMutexW")
	procCloseHandle  = modkernel32.NewProc("CloseHandle")
)

func acquireDaemonMutex(mutexName string) (uintptr, bool) {
	namePtr, err := syscall.UTF16PtrFromString("Global\\" + mutexName)
	if err != nil {
		return 0, true
	}
	h, _, err := procCreateMutexW.Call(0, 1, uintptr(unsafe.Pointer(namePtr)))
	if h == 0 {
		return 0, true
	}
	if err == syscall.Errno(183) { // ERROR_ALREADY_EXISTS
		_, _, _ = procCloseHandle.Call(h)
		return 0, false
	}
	return h, true
}

func releaseDaemonMutex(h uintptr) {
	if h != 0 {
		_, _, _ = procCloseHandle.Call(h)
	}
}



const serviceName = "p2ptap"
const serviceDisplayName = "p2ptap Service"
const serviceDesc = "P2P TAP VPN node — runs headless in the background."

func checkAndRunService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return false
	}
	runDaemonService()
	return true
}

func runDaemonService() {
	configPath := "config.json"
	for i, a := range os.Args {
		if (a == "-c" || a == "--config") && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
		}
	}

	absConfig, err := filepath.Abs(configPath)
	if err == nil {
		configPath = absConfig
		_ = os.Chdir(filepath.Dir(absConfig))
	}

	logPath := filepath.Join(filepath.Dir(configPath), "p2ptap-service.log")
	if logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		os.Stdout = logFile
		os.Stderr = logFile
	}

	cfg, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		cfg = config.DefaultConfig()
	}
	cfg.ConfigPath = configPath
	logger.SetGlobalLevel(logger.ParseLevel(cfg.LogLevel))


	_ = svc.Run(serviceName, &p2ptapDaemonService{cfg: cfg, configPath: configPath})
}

type p2ptapDaemonService struct {
	cfg        *config.Config
	configPath string
}


func (s *p2ptapDaemonService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	hMutex, isSingle := acquireDaemonMutex("p2ptap_Daemon_SingleInstance_Mutex")
	if !isSingle {
		logger.New("Service").Error("Another p2ptap daemon is already running")
		return false, 1
	}
	defer releaseDaemonMutex(hMutex)

	driverType := driver.Ensure(func(msg string) {
		logger.New("Driver").Info("%s", msg)
	})

	if s.cfg.DriverType == "" || s.cfg.DriverType == "auto" {
		s.cfg.DriverType = driverType
	}

	n, _, initErr := bootstrap.Node(s.cfg)
	if n == nil {
		return false, 1
	}
	if initErr != nil {
		logger.New("Service").Error("Failed to setup WebUI: %v", initErr)
	}
	n.Start()


	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			done := make(chan struct{})
			go func() {
				_ = n.Close()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		default:
		}
	}
	return false, 0
}


func handleServiceCommand(args []string) {
	if len(args) == 0 {
		printServiceUsage()
		return
	}

	action := args[0]
	switch action {
	case "install":
		configPath := "config.json"
		for i, a := range args {
			if (a == "-c" || a == "--config") && i+1 < len(args) {
				configPath = args[i+1]
			}
		}
		if err := installDaemonService(configPath); err != nil {
			fmt.Printf("[-] Failed to install service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] Successfully installed and started p2ptap Windows Service!")

	case "uninstall", "remove":
		if err := uninstallDaemonService(); err != nil {
			fmt.Printf("[-] Failed to uninstall service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] Successfully stopped and uninstalled p2ptap Windows Service.")

	case "start":
		if err := startDaemonService(); err != nil {
			fmt.Printf("[-] Failed to start service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] p2ptap service started successfully.")

	case "stop":
		if err := stopDaemonService(); err != nil {
			fmt.Printf("[-] Failed to stop service: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] p2ptap service stopped successfully.")

	case "status":
		status, err := queryDaemonServiceStatus()
		if err != nil {
			fmt.Printf("[-] Status query failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] p2ptap service status: %s\n", status)

	default:
		fmt.Printf("Unknown service action '%s'\n", action)
		printServiceUsage()
		os.Exit(1)
	}
}

func printServiceUsage() {
	fmt.Println("Usage: p2ptap service <action> [options]")
	fmt.Println()
	fmt.Println("Actions:")
	fmt.Println("  install [-c config.json]   Install and start as Windows Service (auto-start on boot)")
	fmt.Println("  uninstall                  Stop and remove the Windows Service")
	fmt.Println("  start                      Start the p2ptap Windows Service")
	fmt.Println("  stop                       Stop the p2ptap Windows Service")
	fmt.Println("  status                     Query current service status")
}

func installDaemonService(configPath string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	absConfigPath, _ := filepath.Abs(configPath)

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM failed: %w (please run as Administrator)", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service '%s' is already installed", serviceName)
	}

	s, err := m.CreateService(
		serviceName,
		exePath,
		mgr.Config{
			DisplayName: serviceDisplayName,
			Description: serviceDesc,
			StartType:   mgr.StartAutomatic,
			// The node needs the TCP/IP stack (and whatever TAP/Wintun binds to
			// it) to be up before it opens sockets / the TAP device. Declaring
			// the dependency makes SCM order boot starts correctly instead of
			// racing tcpip.sys initialization.
			Dependencies: []string{"Tcpip"},
		},
		"-c", absConfigPath,
	)
	if err != nil {
		return fmt.Errorf("CreateService failed: %w", err)
	}
	defer s.Close()

	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 0)

	_ = s.Start()
	return nil
}

func uninstallDaemonService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM failed: %w (please run as Administrator)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service '%s' is not installed: %w", serviceName, err)
	}
	defer s.Close()

	_, _ = s.Control(svc.Stop)
	for i := 0; i < 30; i++ {
		status, qerr := s.Query()
		if qerr != nil || status.State == svc.Stopped {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	return s.Delete()
}

func startDaemonService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM failed: %w (please run as Administrator)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service '%s' is not installed: %w", serviceName, err)
	}
	defer s.Close()

	// If service is currently transitioning (e.g. StopPending), wait for it to reach Stopped
	for i := 0; i < 40; i++ {
		status, qerr := s.Query()
		if qerr == nil && status.State == svc.Running {
			return nil
		}
		if qerr == nil && status.State == svc.Stopped {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}

	if err := s.Start(); err != nil {
		return err
	}

	// Wait up to 10 seconds for service to reach Running state
	for i := 0; i < 40; i++ {
		status, qerr := s.Query()
		if qerr == nil && status.State == svc.Running {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil
}

func stopDaemonService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM failed: %w (please run as Administrator)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service '%s' is not installed: %w", serviceName, err)
	}
	defer s.Close()

	status, err := s.Query()
	if err == nil && status.State == svc.Stopped {
		return nil
	}

	_, _ = s.Control(svc.Stop)

	// Wait up to 10 seconds for service to reach Stopped state
	for i := 0; i < 40; i++ {
		status, qerr := s.Query()
		if qerr != nil || status.State == svc.Stopped {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil
}


func queryDaemonServiceStatus() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "Unknown", err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return "Not Installed", nil
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return "Error", err
	}
	switch status.State {
	case svc.Stopped:
		return "Stopped", nil
	case svc.StartPending:
		return "Start Pending", nil
	case svc.StopPending:
		return "Stop Pending", nil
	case svc.Running:
		return "Running", nil
	case svc.ContinuePending:
		return "Continue Pending", nil
	case svc.PausePending:
		return "Pause Pending", nil
	case svc.Paused:
		return "Paused", nil
	default:
		return "Unknown", nil
	}
}
