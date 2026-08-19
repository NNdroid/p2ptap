//go:build windows

package tap

import (
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
	"p2ptap/pkg/packet"
)

var winTapLog = logger.New("TAP")

// Windows TAP IOCTL codes for TAP-Windows6 driver
const (
	tapIOCTLGetMAC         = 1
	tapIOCTLSetMediaStatus = 6
	// TAP_WIN_IOCTL_CONFIG_TUN (code 10, added in 8.2) obsoletes the old
	// CONFIG_POINT_TO_POINT. It is used both to enter layer-3 TUN mode (with an
	// address) and to explicitly declare layer-2 TAP mode (with a disabled /
	// all-zero TAP_TUN_ADDRESS). We send the latter so the adapter stays in the
	// Ethernet (TAP) mode our ARP-proxying code relies on, across driver versions.
	tapIOCTLConfigTUN = 10
)

// tapTUNHeader is the leading part of the TAP_TUN_ADDRESS struct passed to
// TAP_WIN_IOCTL_CONFIG_TUN. A type of 0 (TUN_UNDEF) means "stay in TAP mode".
type tapTUNHeader struct {
	AddrType uint16
	AddrLen  uint8
	_        uint8 // padding to 4-byte alignment
}

func ctlCode(deviceType, function, method, access uint32) uint32 {
	return (deviceType << 16) | (access << 14) | (function << 2) | method
}

func tapCtlCode(request uint32, method uint32) uint32 {
	return ctlCode(34, request, method, 0)
}

type WindowsTAPDevice struct {
	// mu serialises Read, Write and any concurrent Write callers against
	// each other. The single device-wide mutex is what makes the reusable
	// read/write Overlapped+event pairs safe (overlapped I/O on the same
	// kernel handle from two callers without serialisation is the classic
	// "STATUS_INVALID_PARAMETER" footgun on Windows). It is also the lever
	// the urgent / probe / normal-forwarding write paths use to coordinate.
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

	// Reusable overlapped I/O resources. Both Read and Write loop through
	// the same kernel handle, so a single Overlapped+event pair per direction
	// can be reused across every I/O call instead of allocating/freeing a
	// fresh kernel event+Overlapped per frame. The historical behaviour
	// paid ~1 µs each in cgo + a kernel object allocation per frame, which
	// capped TAP throughput well below the underlying driver capability at
	// sustained rates. The struct mutex above is what guarantees that a
	// pending Read and a pending Write can never share an Overlapped/event.
	readEvent       windows.Handle
	readOverlapped  windows.Overlapped
	writeEvent      windows.Handle
	writeOverlapped windows.Overlapped
}

func getLUIDByName(name string) (winipcfg.LUID, error) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return 0, err
	}
	for _, a := range adapters {
		if strings.EqualFold(a.FriendlyName(), name) ||
			strings.EqualFold(a.AdapterName(), name) ||
			strings.EqualFold(a.AdapterName(), "{"+name+"}") ||
			strings.EqualFold(a.Description(), name) {
			return a.LUID, nil
		}
	}
	lowerName := strings.ToLower(name)
	for _, a := range adapters {
		friendly := strings.ToLower(a.FriendlyName())
		desc := strings.ToLower(a.Description())
		if strings.Contains(friendly, lowerName) || strings.Contains(desc, lowerName) {
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

	// Reusable event for overlapped reads (single-threaded read loop).
	readEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("failed to create read event: %w", err)
	}

	// Reusable event for overlapped writes. Mirrors the read event: one kernel
	// event reused across every Write call avoids a CreateEvent+CloseHandle on
	// the per-frame hot path. The mutex below serialises Read vs Write and
	// concurrent Write callers, so the single event is safe.
	writeEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(handle)
		_ = windows.CloseHandle(readEvent)
		return nil, fmt.Errorf("failed to create write event: %w", err)
	}

	// Bring TAP Media Status to Connected (1)
	// OpenVPN specification requires passing status buffer for BOTH input and output
	// with METHOD_BUFFERED. Failing to provide output buffer causes ERROR_INVALID_PARAMETER (87).
	status := uint32(1)
	var bytesReturned uint32
	err = windows.DeviceIoControl(
		handle,
		tapCtlCode(tapIOCTLSetMediaStatus, 0),
		(*byte)(unsafe.Pointer(&status)),
		uint32(unsafe.Sizeof(status)),
		(*byte)(unsafe.Pointer(&status)),
		uint32(unsafe.Sizeof(status)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		// Non-fatal warning (matching OpenVPN client): some NDIS6/OEM TAP driver versions
		// manage media state automatically and reject user-mode SET_MEDIA_STATUS.
		winTapLog.Warn("TAP SET_MEDIA_STATUS warning (driver returned %v, continuing)", err)
	}

	// Explicitly declare layer-2 TAP (Ethernet) mode by sending a disabled
	// TAP_TUN_ADDRESS (addrType=0). This keeps the adapter in the Ethernet mode
	// our ARP-proxying depends on, regardless of driver default behaviour.
	tunHdr := tapTUNHeader{AddrType: 0, AddrLen: 0}
	err = windows.DeviceIoControl(
		handle,
		tapCtlCode(tapIOCTLConfigTUN, 0),
		(*byte)(unsafe.Pointer(&tunHdr)),
		uint32(unsafe.Sizeof(tunHdr)),
		(*byte)(unsafe.Pointer(&tunHdr)),
		uint32(unsafe.Sizeof(tunHdr)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		// Non-fatal: older drivers without CONFIG_TUN still default to TAP mode.
		winTapLog.Debug("TAP CONFIG_TUN (declare TAP mode) skipped: %v", err)
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
	mac := packet.DefaultTapMAC
	if err != nil {
		winTapLog.Warn("failed to get TAP MAC address from driver (%v), falling back to default MAC %s", err, mac.String())
	} else {
		mac = net.HardwareAddr(macBuf[:])
	}
	winTapLog.Info("Windows TAP adapter opened: MAC=%s (fd=%d)", mac.String(), handle)

	dev := &WindowsTAPDevice{
		name:            tapName,
		handle:          handle,
		mtu:             mtu,
		localMAC:        mac,
		readEvent:       readEvent,
		readOverlapped:  windows.Overlapped{HEvent: readEvent},
		writeEvent:      writeEvent,
		writeOverlapped: windows.Overlapped{HEvent: writeEvent},
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
		dev, err := createOSTAPDevice(tapName, mtu)
		if err != nil {
			winTapLog.Warn("TAP-Windows6 driver failed (%v), attempting Wintun fallback...", err)
			if wintunDev, werr := createWintunTAPDevice(tapName, "", mtu); werr == nil {
				return wintunDev, nil
			}
			return nil, fmt.Errorf("tap: %w", err)
		}
		return dev, nil
	case "auto":
		fallthrough
	default:
		// Try TAP first
		dev, err := createOSTAPDevice(tapName, mtu)
		if err == nil {
			return dev, nil
		}
		winTapLog.Warn("TAP-Windows6 unavailable (%v), falling back to Wintun...", err)
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

func (w *WindowsTAPDevice) MAC() string {
	return w.localMAC.String()
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
	// Hold the device mutex across Read so a concurrent Write (urgent / probe)
	// cannot submit a WriteFile against the same kernel handle while we are
	// mid-ReadFile; overlapping overlapped I/O on the same handle is the classic
	// "STATUS_INVALID_PARAMETER" footgun on Windows.
	w.mu.Lock()
	defer w.mu.Unlock()

	var readN uint32

	// Reuse the device's overlapped struct + event. The read loop is single-
	// threaded, so the previous Read has always fully completed before the next
	// one starts; resetting Internal/InternalHigh keeps the struct clean.
	w.readOverlapped.Internal = 0
	w.readOverlapped.InternalHigh = 0

	err := windows.ReadFile(w.handle, b, &readN, &w.readOverlapped)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		s, errWait := windows.WaitForSingleObject(w.readEvent, 1000)
		switch s {
		case uint32(windows.WAIT_OBJECT_0):
			// I/O completed normally; retrieve the result.
			err = windows.GetOverlappedResult(w.handle, &w.readOverlapped, &readN, false)
		case uint32(windows.WAIT_TIMEOUT):
			// Read timed out. Cancel the pending IRP and drain it. If a packet
			// actually arrived during cancellation, GetOverlappedResult returns
			// it (got > 0) — we MUST hand that data back instead of discarding
			// it, otherwise frames at the timeout boundary are silently lost.
			_ = windows.CancelIo(w.handle)
			var got uint32
			if ge := windows.GetOverlappedResult(w.handle, &w.readOverlapped, &got, true); ge == nil && got > 0 {
				return int(got), nil
			}
			return 0, ErrReadTimeout
		case uint32(windows.WAIT_FAILED):
			// Wait failed (e.g. invalid handle). Cancel the IRP so it does not
			// leak and surface the underlying wait error.
			_ = windows.CancelIo(w.handle)
			if errWait != nil {
				return 0, errWait
			}
			return 0, windows.ERROR_INVALID_HANDLE
		default:
			// Unexpected wait result: treat like a timeout to keep the loop alive.
			_ = windows.CancelIo(w.handle)
			var got uint32
			if ge := windows.GetOverlappedResult(w.handle, &w.readOverlapped, &got, true); ge == nil && got > 0 {
				return int(got), nil
			}
			return 0, ErrReadTimeout
		}
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

	// NOTE: ARP proxying (including resolving peer IPs to their real tunnel MACs)
	// is handled exclusively in the node layer (processTapFrame). The TAP device
	// used to intercept ARP requests here and answer same-subnet peer IPs with its
	// OWN MAC, which blackholed the Exit Node default route until the OS ARP cache
	// was flushed by disabling/re-enabling the adapter. Letting ARP frames flow
	// through to the node layer fixes that.

	// Serialise against Read and any concurrent Write: the device-level mutex
	// ensures we never have a ReadFile and a WriteFile pending on the SAME
	// reusable Overlapped/event pair at the same time. The event is stored
	// inside the device struct and reused across every Write call, eliminating
	// the per-frame CreateEvent+CloseHandle churn that capped TAP throughput.
	w.mu.Lock()
	defer w.mu.Unlock()

	w.writeOverlapped.Internal = 0
	w.writeOverlapped.InternalHigh = 0

	var writtenN uint32
	err := windows.WriteFile(w.handle, b, &writtenN, &w.writeOverlapped)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		s, errWait := windows.WaitForSingleObject(w.writeEvent, 2000)
		switch s {
		case uint32(windows.WAIT_OBJECT_0):
			// I/O completed normally; retrieve the result.
			err = windows.GetOverlappedResult(w.handle, &w.writeOverlapped, &writtenN, false)
		case uint32(windows.WAIT_TIMEOUT):
			// Write timed out. Cancel the pending IRP and drain it. If the
			// write actually completed during cancellation, GetOverlappedResult
			// returns it (got > 0) — we MUST hand those bytes back instead of
			// discarding them, otherwise frames at the timeout boundary are
			// silently truncated.
			_ = windows.CancelIo(w.handle)
			var got uint32
			if ge := windows.GetOverlappedResult(w.handle, &w.writeOverlapped, &got, true); ge == nil && got > 0 {
				return int(got), nil
			}
			return 0, fmt.Errorf("windows TAP write timeout")
		case uint32(windows.WAIT_FAILED):
			_ = windows.CancelIo(w.handle)
			if errWait != nil {
				return 0, errWait
			}
			return 0, windows.ERROR_INVALID_HANDLE
		default:
			_ = windows.CancelIo(w.handle)
			var got uint32
			if ge := windows.GetOverlappedResult(w.handle, &w.writeOverlapped, &got, true); ge == nil && got > 0 {
				return int(got), nil
			}
			return 0, fmt.Errorf("windows TAP write timeout")
		}
	}

	if err != nil {
		return 0, err
	}
	return int(writtenN), nil
}

func (w *WindowsTAPDevice) Close() error {
	winTapLog.Info("Closing Windows TAP device '%s'", w.name)
	if w.readEvent != 0 {
		_ = windows.CloseHandle(w.readEvent)
		w.readEvent = 0
	}
	if w.writeEvent != 0 {
		_ = windows.CloseHandle(w.writeEvent)
		w.writeEvent = 0
	}
	return windows.CloseHandle(w.handle)
}

// SelfTest verifies the Windows TAP write/read path (see runRealDeviceSelfTest).
func (w *WindowsTAPDevice) SelfTest() map[string]interface{} {
	return runRealDeviceSelfTest(w, "tap")
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

	// Set interface metric = 1, and enable forwarding/weak-host for subnet routing & multi-interface reachability
	if ipif, err := luid.IPInterface(windows.AF_INET); err == nil {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 1
		ipif.ForwardingEnabled = true
		ipif.WeakHostReceive = true
		ipif.WeakHostSend = true
		_ = ipif.Set()
	}
	if ipif6, err := luid.IPInterface(windows.AF_INET6); err == nil {
		ipif6.UseAutomaticMetric = false
		ipif6.Metric = 1
		ipif6.ForwardingEnabled = true
		ipif6.WeakHostReceive = true
		ipif6.WeakHostSend = true
		_ = ipif6.Set()
	}
	_ = exec.Command("netsh", "interface", "ipv4", "set", "interface", "name="+w.name, "metric=1", "forwarding=enabled", "weakhostreceive=enabled", "weakhostsend=enabled").Run()
	_ = exec.Command("netsh", "interface", "ipv6", "set", "interface", "name="+w.name, "metric=1", "forwarding=enabled", "weakhostreceive=enabled", "weakhostsend=enabled").Run()

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
	proto := "icmpv4"
	if isIPv6 {
		proto = "icmpv6"
	}
	// Always run netsh deletion and addition with profile=any to ensure Public/Private/Domain allow
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name).Run()
	_ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+name, "dir=in", "action=allow", "protocol="+proto, "profile=any").Run()

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

	// Remove old rule first so Add doesn't error on duplicate
	_, _ = oleutil.CallMethod(rules, "Remove", name)

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
	oleutil.PutProperty(rule, "Profiles", 0x7FFFFFFF) // NET_FW_PROFILE2_ALL

	_, _ = oleutil.CallMethod(rules, "Add", rule)
}
