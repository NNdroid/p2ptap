//go:build windows

package tap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"p2ptap/pkg/logger"
)

var winTapLog = logger.New("TAP")

// Windows TAP IOCTL codes for TAP-Windows6 driver
const (
	tapIOCTLGetMAC         = 1
	tapIOCTLSetMediaStatus = 6
)

func ctlCode(deviceType, function, method, access uint32) uint32 {
	return (deviceType << 16) | (access << 14) | (function << 2) | method
}

func tapCtlCode(request uint32, method uint32) uint32 {
	return ctlCode(34, request, method, 0)
}

type WindowsTAPDevice struct {
	mu       sync.Mutex
	name     string
	handle   windows.Handle
	ipCIDR   string
	ipv6     string
	webUIIP  string
	mtu      int
	localMAC net.HardwareAddr
	localIP  net.IP
	localNet *net.IPNet
}

func getLUIDByName(name string) (winipcfg.LUID, error) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return 0, err
	}
	for _, a := range adapters {
		if strings.EqualFold(a.FriendlyName(), name) {
			return a.LUID, nil
		}
	}
	return 0, fmt.Errorf("adapter %q not found", name)
}

func createOSTAPDevice(tapName string, mtu int) (TAPDevice, error) {
	guid, err := findTAPAdapterGUID()
	if err != nil {
		return nil, fmt.Errorf("failed to find TAP-Windows6 adapter: %w", err)
	}

	devicePath := fmt.Sprintf(`\\.\Global\%s.tap`, guid)
	winTapLog.Debug("Opening Windows TAP device path '%s'...", devicePath)

	pathPtr, err := windows.UTF16PtrFromString(devicePath)
	if err != nil {
		return nil, err
	}

	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_SYSTEM|windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open TAP device %s: %w", devicePath, err)
	}

	// Bring TAP Media Status to Connected (1)
	status := uint32(1)
	var bytesReturned uint32
	err = windows.DeviceIoControl(
		handle,
		tapCtlCode(tapIOCTLSetMediaStatus, 0),
		(*byte)(unsafe.Pointer(&status)),
		uint32(unsafe.Sizeof(status)),
		nil,
		0,
		&bytesReturned,
		nil,
	)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("failed to set TAP media status to connected: %w", err)
	}

	// Fetch hardware MAC address from TAP driver
	var macBuf [6]byte
	err = windows.DeviceIoControl(
		handle,
		tapCtlCode(tapIOCTLGetMAC, 0),
		nil,
		0,
		(*byte)(unsafe.Pointer(&macBuf[0])),
		uint32(len(macBuf)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("failed to get TAP MAC address: %w", err)
	}

	mac := net.HardwareAddr(macBuf[:])
	winTapLog.Info("Windows TAP adapter opened: MAC=%s (fd=%d)", mac.String(), handle)

	dev := &WindowsTAPDevice{
		name:     tapName,
		handle:   handle,
		mtu:      mtu,
		localMAC: mac,
	}

	return dev, nil
}

// IsTAPDriverInstalled returns true when a TAP-Windows6 adapter (tap0901 or
// tap0801) is found in the Windows registry.
func IsTAPDriverInstalled() bool {
	_, err := findTAPAdapterGUID()
	return err == nil
}

// createPlatformTAPDevice tries to create a TAP device on Windows, falling
// back to Wintun when driverType=="auto" and TAP is unavailable.
func createPlatformTAPDevice(tapName, driverType string, mtu int) (TAPDevice, error) {
	switch driverType {
	case "wintun":
		dev, err := createWintunTAPDevice(tapName, "", mtu)
		if err != nil {
			return nil, fmt.Errorf("wintun: %w", err)
		}
		return dev, nil
	case "tap":
		return createOSTAPDevice(tapName, mtu)
	case "auto":
		fallthrough
	default:
		// Try TAP first
		dev, err := createOSTAPDevice(tapName, mtu)
		if err == nil {
			return dev, nil
		}
		winTapLog.Debug("TAP-Windows6 unavailable (%v), falling back to Wintun", err)
		// Fall back to Wintun
		wintunDev, wintunErr := createWintunTAPDevice(tapName, "", mtu)
		if wintunErr != nil {
			return nil, fmt.Errorf("TAP: %w; Wintun: %w", err, wintunErr)
		}
		return wintunDev, nil
	}
}

func findTAPAdapterGUID() (string, error) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`,
		registry.READ,
	)
	if err != nil {
		return "", fmt.Errorf("failed to open Network Adapters registry key: %w", err)
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return "", fmt.Errorf("failed to read adapter subkeys: %w", err)
	}

	for _, subkeyName := range subkeys {
		subKey, err := registry.OpenKey(key, subkeyName, registry.READ)
		if err != nil {
			continue
		}

		componentID, _, _ := subKey.GetStringValue("ComponentId")
		subKey.Close()

		if strings.EqualFold(componentID, "tap0901") || strings.EqualFold(componentID, "tap0801") {
			subKey, err := registry.OpenKey(key, subkeyName, registry.READ)
			if err != nil {
				continue
			}
			netCfgInstanceID, _, _ := subKey.GetStringValue("NetCfgInstanceId")
			subKey.Close()

			if netCfgInstanceID != "" {
				return netCfgInstanceID, nil
			}
		}
	}
	return "", fmt.Errorf("no TAP-Windows6 (tap0901) adapter installed")
}

func (w *WindowsTAPDevice) Name() string {
	return w.name
}

func (w *WindowsTAPDevice) SetMAC(mac string) error {
	if mac == "" {
		return nil
	}
	addr, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("invalid MAC address %q: %w", mac, err)
	}
	w.localMAC = addr
	winTapLog.Debug("Updated local MAC for Windows TAP: %s", mac)
	return nil
}

func (w *WindowsTAPDevice) SetMTU(mtu int) error {
	if mtu <= 0 {
		return nil
	}
	w.mtu = mtu
	return w.configureMTU()
}

func (w *WindowsTAPDevice) configureMTU() error {
	if w.mtu <= 0 {
		return nil
	}
	luid, err := getLUIDByName(w.name)
	if err != nil {
		return nil
	}
	if ipif, err := luid.IPInterface(windows.AF_INET); err == nil {
		ipif.NLMTU = uint32(w.mtu)
		_ = ipif.Set()
	}
	if ipif6, err := luid.IPInterface(windows.AF_INET6); err == nil {
		ipif6.NLMTU = uint32(w.mtu)
		_ = ipif6.Set()
	}
	return nil
}

func (w *WindowsTAPDevice) Read(b []byte) (int, error) {
	var readN uint32
	var overlapped windows.Overlapped

	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	overlapped.HEvent = event

	err = windows.ReadFile(w.handle, b, &readN, &overlapped)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		s, errWait := windows.WaitForSingleObject(event, 1000)
		if s == uint32(windows.WAIT_TIMEOUT) {
			_ = windows.CancelIo(w.handle)
			return 0, ErrReadTimeout
		}
		if errWait != nil {
			return 0, errWait
		}
		err = windows.GetOverlappedResult(w.handle, &overlapped, &readN, false)
	}

	if err != nil {
		return 0, err
	}
	return int(readN), nil
}

func (w *WindowsTAPDevice) Write(b []byte) (int, error) {
	if len(b) < 14 {
		return len(b), nil
	}

	ethType := binary.BigEndian.Uint16(b[12:14])
	if ethType == 0x0806 {
		if arpOpcode(b) == 1 {
			if err := w.handleProxyARP(b); err != nil {
				return 0, err
			}
			return len(b), nil
		}
	}

	var writtenN uint32
	var overlapped windows.Overlapped

	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	overlapped.HEvent = event

	err = windows.WriteFile(w.handle, b, &writtenN, &overlapped)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		s, _ := windows.WaitForSingleObject(event, 2000)
		if s == uint32(windows.WAIT_TIMEOUT) {
			_ = windows.CancelIo(w.handle)
			return 0, fmt.Errorf("windows TAP write timeout")
		}
		_ = windows.GetOverlappedResult(w.handle, &overlapped, &writtenN, false)
	}

	return int(writtenN), nil
}

func (w *WindowsTAPDevice) handleProxyARP(frame []byte) error {
	if len(frame) < 42 {
		return nil
	}

	op := arpOpcode(frame)
	if op != 1 {
		return nil
	}

	targetIP := net.IP(frame[38:42])
	senderIP := net.IP(frame[28:32])
	senderMAC := net.HardwareAddr(frame[22:28])

	var webUIVirtualIP net.IP
	if w.webUIIP != "" {
		webUIVirtualIP = net.ParseIP(strings.Split(w.webUIIP, "/")[0])
	}

	if !ShouldRespondToARP(targetIP, w.localIP, webUIVirtualIP, w.localNet) {
		return nil
	}

	reply := BuildARPReplyFrame(w.localMAC, senderMAC, targetIP, senderIP)
	return w.writeFrame(reply)
}

func (w *WindowsTAPDevice) writeFrame(frame []byte) error {
	var writtenN uint32
	var overlapped windows.Overlapped

	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(event)
	overlapped.HEvent = event

	err = windows.WriteFile(w.handle, frame, &writtenN, &overlapped)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		s, _ := windows.WaitForSingleObject(event, 2000)
		if s == uint32(windows.WAIT_TIMEOUT) {
			_ = windows.CancelIo(w.handle)
			return fmt.Errorf("windows TAP write timeout")
		}
		_ = windows.GetOverlappedResult(w.handle, &overlapped, &writtenN, false)
	}
	if err != nil {
		return err
	}
	return nil
}

func (w *WindowsTAPDevice) Close() error {
	winTapLog.Info("Closing Windows TAP device '%s'", w.name)
	return windows.CloseHandle(w.handle)
}

func (w *WindowsTAPDevice) ConfigureIP(ipCIDR string, ipv6CIDR string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.ipCIDR = ipCIDR
	w.ipv6 = ipv6CIDR
	if ipCIDR != "" {
		if ip, ipNet, err := net.ParseCIDR(ipCIDR); err == nil {
			w.localIP = ip
			w.localNet = ipNet
		}
	}

	luid, err := getLUIDByName(w.name)
	if err != nil {
		winTapLog.Warn("winipcfg getLUIDByName(%s) failed: %v", w.name, err)
		return nil
	}

	var prefixes []netip.Prefix
	if ipCIDR != "" {
		if p, err := netip.ParsePrefix(ipCIDR); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	if w.webUIIP != "" {
		if p, err := netip.ParsePrefix(w.webUIIP); err == nil {
			prefixes = append(prefixes, p)
		}
	}

	if len(prefixes) > 0 {
		winTapLog.Info("Setting static IPv4 %v on Windows TAP '%s' via winipcfg...", prefixes, w.name)
		if err := luid.SetIPAddresses(prefixes); err != nil {
			winTapLog.Warn("winipcfg SetIPAddresses failed: %v, falling back to netsh", err)
			// Fallback to netsh for IPv4
			for _, p := range prefixes {
				ipStr := p.Addr().String()
				if _, ipNet, err := net.ParseCIDR(p.String()); err == nil {
					maskStr := net.IP(ipNet.Mask).String()
					if ipStr != "" && maskStr != "" {
						winTapLog.Info("netsh fallback: set address %s %s on %s", ipStr, maskStr, w.name)
						_ = exec.Command("netsh", "interface", "ipv4", "set", "address",
							"name="+w.name, "static", ipStr, maskStr).Run()
					}
				}
			}
		}
		addWindowsFirewallRule("p2ptap ICMPv4 Allow", false)
	}

	if ipv6CIDR != "" {
		if p, err := netip.ParsePrefix(ipv6CIDR); err == nil {
			winTapLog.Info("Adding IPv6 %s on Windows TAP '%s' via winipcfg...", p, w.name)
			if err := luid.AddIPAddress(p); err != nil {
				winTapLog.Warn("winipcfg AddIPAddress IPv6 failed: %v", err)
			}
			addWindowsFirewallRule("p2ptap ICMPv6 Allow", true)
		}
	}

	if w.mtu > 0 {
		_ = w.configureMTU()
	}

	// Set interface metric = 1 via winipcfg
	if ipif, err := luid.IPInterface(windows.AF_INET); err == nil {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 1
		_ = ipif.Set()
	}
	if ipif6, err := luid.IPInterface(windows.AF_INET6); err == nil {
		ipif6.UseAutomaticMetric = false
		ipif6.Metric = 1
		_ = ipif6.Set()
	}

	// Ensure IPv4 subnet route is explicitly added so Windows knows to reach same-subnet peers via TAP
	if ipCIDR != "" {
		if ip, ipNet, err := net.ParseCIDR(ipCIDR); err == nil {
			networkIP := ip.Mask(ipNet.Mask)
			prefixLen, _ := ipNet.Mask.Size()
			routePrefix := fmt.Sprintf("%s/%d", networkIP.String(), prefixLen)
			winTapLog.Info("Adding IPv4 subnet route %s on Windows TAP '%s' via netsh...", routePrefix, w.name)
			_ = exec.Command("netsh", "interface", "ipv4", "delete", "route", routePrefix, "interface="+w.name).Run()
			_ = exec.Command("netsh", "interface", "ipv4", "add", "route", routePrefix, "interface="+w.name, "metric=1", "publish=yes").Run()
		}
	}

	winTapLog.Info("Windows TAP '%s' configured: IPv4=%s IPv6=%s", w.name, ipCIDR, ipv6CIDR)
	return nil
}

func addWindowsFirewallRule(name string, isIPv6 bool) {
	ole.CoInitialize(0)
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("HNetCfg.FwPolicy2")
	if err != nil {
		return
	}
	defer unknown.Release()

	fwPolicy, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return
	}
	defer fwPolicy.Release()

	rulesVar, err := oleutil.GetProperty(fwPolicy, "Rules")
	if err != nil {
		return
	}
	rules := rulesVar.ToIDispatch()
	defer rules.Release()

	ruleUnk, err := oleutil.CreateObject("HNetCfg.FwRule")
	if err != nil {
		return
	}
	defer ruleUnk.Release()

	rule, err := ruleUnk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return
	}
	defer rule.Release()

	protocol := 1 // ICMPv4
	if isIPv6 {
		protocol = 58 // ICMPv6
	}

	oleutil.PutProperty(rule, "Name", name)
	oleutil.PutProperty(rule, "Protocol", protocol)
	oleutil.PutProperty(rule, "Direction", 1) // IN
	oleutil.PutProperty(rule, "Action", 1)    // ALLOW
	oleutil.PutProperty(rule, "Enabled", true)

	_, _ = oleutil.CallMethod(rules, "Add", rule)
}
