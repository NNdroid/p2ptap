//go:build darwin
// +build darwin

package tap

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"

	"p2ptap/pkg/logger"
)

var darwinTapLog = logger.New("TAP")

type DarwinTAPDevice struct {
	mu     sync.Mutex
	name   string
	file   *os.File
	ipCIDR string
	ipv6   string
}

func createOSTAPDevice(tapName string, mtu int) (TAPDevice, error) {
	// macOS uses /dev/tap0, /dev/tap1 ... /dev/tap15 (tuntaposx / Tunnelblick TAP driver)
	var file *os.File
	var devName string
	var err error

	for i := 0; i < 16; i++ {
		path := fmt.Sprintf("/dev/tap%d", i)
		file, err = os.OpenFile(path, os.O_RDWR, 0)
		if err == nil {
			devName = fmt.Sprintf("tap%d", i)
			break
		}
	}

	if file == nil {
		return nil, fmt.Errorf("macOS TAP driver (/dev/tap0~15) unavailable. Install tuntaposx or Tunnelblick TAP driver: %w", err)
	}

	dev := &DarwinTAPDevice{
		name: devName,
		file: file,
	}

	if err = dev.SetMTU(mtu); err != nil {
		darwinTapLog.Warn("Failed to set MTU %d on '%s': %v", mtu, devName, err)
	}

	darwinTapLog.Info("macOS TAP device '%s' created via /dev/%s", devName, devName)
	return dev, nil
}

// createPlatformTAPDevice is a thin wrapper around createOSTAPDevice on
// non-Windows platforms where driver fallback is not applicable.
func createPlatformTAPDevice(tapName, driverType string, mtu int) (TAPDevice, error) {
	return createOSTAPDevice(tapName, mtu)
}

func (d *DarwinTAPDevice) Name() string {
	return d.name
}

func (d *DarwinTAPDevice) SetMAC(mac string) error {
	if mac == "" {
		return nil
	}
	darwinTapLog.Debug("Setting MAC %s on '%s'...", mac, d.name)
	if out, err := exec.Command("ifconfig", d.name, "ether", mac).CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig ether failed: %w (output: %s)", err, string(out))
	}
	return nil
}

func (d *DarwinTAPDevice) SetMTU(mtu int) error {
	if mtu <= 0 {
		return nil
	}
	darwinTapLog.Info("Setting MTU %d on macOS TAP '%s'...", mtu, d.name)
	if out, err := exec.Command("ifconfig", d.name, "mtu", fmt.Sprintf("%d", mtu)).CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig mtu failed: %w (output: %s)", err, string(out))
	}
	return nil
}

func (d *DarwinTAPDevice) Read(b []byte) (int, error) {
	return d.file.Read(b)
}

func (d *DarwinTAPDevice) Write(b []byte) (int, error) {
	return d.file.Write(b)
}

func (d *DarwinTAPDevice) Close() error {
	darwinTapLog.Info("Closing macOS TAP device '%s'", d.name)
	return d.file.Close()
}

func (d *DarwinTAPDevice) ConfigureIP(ipCIDR string, ipv6CIDR string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.ipCIDR = ipCIDR
	d.ipv6 = ipv6CIDR

	if ipCIDR != "" {
		ip, ipNet, err := net.ParseCIDR(ipCIDR)
		if err != nil {
			return fmt.Errorf("invalid IPv4 CIDR %s: %w", ipCIDR, err)
		}
		mask := net.IP(ipNet.Mask).String()
		darwinTapLog.Info("Configuring IPv4 %s netmask %s on '%s'...", ip, mask, d.name)
		if out, err := exec.Command("ifconfig", d.name, ip.String(), "netmask", mask, "up").CombinedOutput(); err != nil {
			return fmt.Errorf("ifconfig %s IPv4 failed: %w (output: %s)", d.name, err, string(out))
		}
	}

	if ipv6CIDR != "" {
		ip6, ipNet6, err := net.ParseCIDR(ipv6CIDR)
		if err == nil && ip6 != nil {
			ones, _ := ipNet6.Mask.Size()
			darwinTapLog.Info("Configuring IPv6 %s/%d on '%s'...", ip6, ones, d.name)
			_ = exec.Command("ifconfig", d.name, "inet6", fmt.Sprintf("%s/%d", ip6.String(), ones), "add").Run()
		}
	}

	return nil
}
