package tap

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ErrReadTimeout reports that a native TAP device remained readable-idle for
// its diagnostic polling interval. It is not a device failure.
var ErrReadTimeout = errors.New("TAP read timeout")

// EpollPoller provides efficient event-driven read readiness notification
// using Linux epoll.  On non-Linux platforms NewEpollPoller returns an
// error; the caller falls back to timer-based polling.
type EpollPoller struct {
	epfd, tapFd, wakeFd int
}

// TAPDevice is the interface for virtual TAP ethernet devices
type TAPDevice interface {
	io.ReadWriteCloser
	Name() string
	SetMAC(mac string) error
	// MAC returns the device's current hardware address as a string (e.g.
	// "02:00:5e:10:00:01"), or "" if unknown. It is used so the node can learn
	// and advertise the real TAP MAC to peers even when the config does not
	// explicitly specify one.
	MAC() string
	SetMTU(mtu int) error
	ConfigureIP(ipCIDR string, ipv6CIDR string) error
	// SelfTest performs a non-destructive read/write sanity check on the
	// device and returns a plain map so callers (e.g. the WebUI) can consume
	// the result without importing this package. The returned map always
	// contains the keys: "name", "device_type" ("tap"|"wintun"|"memtap"),
	// "write_ok" (bool), "read_ok" (bool), "write_ms" (float64),
	// "loopback" (bool), and "detail" (string).
	SelfTest() map[string]interface{}
}

// ActualMACProvider is implemented by TAP backends that can query the
// operating system for the interface's current hardware address.  MAC() is a
// general-purpose, best-effort accessor; this narrower interface lets callers
// enforce the stronger startup invariant where the platform supports it:
// packets rewritten for the local TAP must use the MAC the kernel currently
// owns, not merely the value that was requested during setup.
type ActualMACProvider interface {
	ActualMAC() (string, error)
}

// MemTAP is an in-memory virtual TAP interface pair for CI/CD testing and permissionless environments
type MemTAP struct {
	name       string
	ipCIDR     string
	ipv6CIDR   string
	mac        string
	readChan   chan []byte
	writeChan  chan []byte
	closed     bool
	closedChan chan struct{}
	closeOnce  *sync.Once
	mu         sync.Mutex
}

// NewMemTAPPair creates a pair of connected MemTAP devices (devA and devB)
func NewMemTAPPair(nameA, nameB string) (*MemTAP, *MemTAP) {
	chanAtoB := make(chan []byte, 1024)
	chanBtoA := make(chan []byte, 1024)
	closedChan := make(chan struct{})
	closeOnce := &sync.Once{}

	tapA := &MemTAP{
		name:       nameA,
		readChan:   chanBtoA,
		writeChan:  chanAtoB,
		closedChan: closedChan,
		closeOnce:  closeOnce,
	}
	tapB := &MemTAP{
		name:       nameB,
		readChan:   chanAtoB,
		writeChan:  chanBtoA,
		closedChan: closedChan,
		closeOnce:  closeOnce,
	}
	return tapA, tapB
}

func (m *MemTAP) Name() string {
	return m.name
}

func (m *MemTAP) MAC() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mac
}

func (m *MemTAP) SetMAC(mac string) error {
	if mac == "" {
		return nil
	}
	if _, err := net.ParseMAC(mac); err != nil {
		return fmt.Errorf("invalid MAC address %q: %w", mac, err)
	}

	m.mu.Lock()
	m.mac = mac
	m.mu.Unlock()
	return nil
}

func (m *MemTAP) SetMTU(mtu int) error {
	return nil
}

func (m *MemTAP) ConfigureIP(ipCIDR string, ipv6CIDR string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ipCIDR != "" {
		if _, _, err := net.ParseCIDR(ipCIDR); err != nil {
			return fmt.Errorf("invalid IPv4 CIDR %s: %w", ipCIDR, err)
		}
		m.ipCIDR = ipCIDR
	}
	if ipv6CIDR != "" {
		if _, _, err := net.ParseCIDR(ipv6CIDR); err != nil {
			return fmt.Errorf("invalid IPv6 CIDR %s: %w", ipv6CIDR, err)
		}
		m.ipv6CIDR = ipv6CIDR
	}
	return nil
}

func (m *MemTAP) Read(b []byte) (int, error) {
	select {
	case packet, ok := <-m.readChan:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, packet)
		// An in-memory device delivers whole frames via its channel. If the
		// caller's buffer is too small the remainder cannot be recovered here,
		// so signal it explicitly with io.ErrShortBuffer instead of silently
		// truncating the frame (which would corrupt the data path). Every real
		// caller passes a buffer >= MaxFrameSize, so this only fires on a
		// genuine caller bug.
		if n < len(packet) {
			return n, io.ErrShortBuffer
		}
		return n, nil
	case <-m.closedChan:
		return 0, io.EOF
	}
}

func (m *MemTAP) Write(b []byte) (int, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	m.mu.Unlock()

	pkt := make([]byte, len(b))
	copy(pkt, b)

	select {
	case m.writeChan <- pkt:
		return len(b), nil
	case <-m.closedChan:
		return 0, io.ErrClosedPipe
	}
}

func (m *MemTAP) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()

	if m.closeOnce != nil {
		m.closeOnce.Do(func() {
			close(m.closedChan)
		})
	}
	return nil
}

// SelfTest writes a crafted Ethernet frame and verifies it can be read back
// through the paired in-memory device (true loopback).
func (m *MemTAP) SelfTest() map[string]interface{} {
	res := map[string]interface{}{
		"name":        m.name,
		"device_type": "memtap",
		"write_ok":    false,
		"read_ok":     false,
		"write_ms":    0.0,
		"loopback":    true,
		"detail":      "",
	}
	m.mu.Lock()
	mac := m.mac
	m.mu.Unlock()
	if mac == "" {
		mac = "02:00:00:00:00:01"
	}
	srcMAC, _ := net.ParseMAC(mac)
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	// Build an IPv4 UDP frame destined to the peer side of the pair.
	payload := make([]byte, 64)
	copy(payload[0:6], dstMAC)
	copy(payload[6:12], srcMAC)
	payload[12] = 0x08
	payload[13] = 0x00 // IPv4
	for i := 14; i < len(payload); i++ {
		payload[i] = byte(i)
	}

	t0 := time.Now()
	n, err := m.Write(payload)
	writeMs := time.Since(t0).Seconds() * 1000.0
	res["write_ms"] = writeMs
	if err != nil || n != len(payload) {
		res["detail"] = fmt.Sprintf("write failed: n=%d err=%v", n, err)
		return res
	}
	res["write_ok"] = true

	// Read back from the device (MemTAP loopback delivers via the pair).
	rb := make([]byte, 1500)
	readN, rerr := m.Read(rb)
	if rerr != nil || readN < 14 {
		res["detail"] = fmt.Sprintf("write OK (%0.3f ms), but loopback read failed: %v", writeMs, rerr)
		return res
	}
	res["read_ok"] = true
	res["detail"] = fmt.Sprintf("loopback OK: wrote %d B, read %d B in %0.3f ms", n, readN, writeMs)
	return res
}

// CreateTAPDevice creates and configures a real OS TAP device.
//
// driverType controls which backend is used:
//   - "tap"    – only TAP-Windows6 (fails if not installed)
//   - "wintun" – only Wintun (fails if wintun.dll is missing)
//   - "auto"   – try TAP first, then fall back to Wintun (default)
//
// A failed native setup must be returned to the caller. Falling back to an
// in-memory device makes a successfully started VPN unable to carry host
// traffic, which is especially misleading in production.
func CreateTAPDevice(tapName, ipCIDR, ipv6CIDR, mac, driverType string, mtu int) (TAPDevice, error) {
	if driverType == "" {
		driverType = "auto" // default behavior
	}
	dev, err := createPlatformTAPDevice(tapName, driverType, mtu)
	if err != nil {
		return nil, fmt.Errorf("create TAP device %q: %w", tapName, err)
	}

	if err = dev.SetMAC(mac); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("configure MAC for TAP device %q: %w", tapName, err)
	}

	if err = dev.ConfigureIP(ipCIDR, ipv6CIDR); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("configure TAP device %q: %w", tapName, err)
	}

	return dev, nil
}

// runRealDeviceSelfTest is shared by the native OS-backed TAP implementations
// (Windows TAP, Wintun, Linux TUN/TAP, macOS). deviceType must be "tap" for
// Ethernet (L2) devices that loop frames back to themselves, or "wintun" for
// layer-3 tunnel devices that do NOT loop frames.
//
// For "tap" devices a true loopback read is expected: the written frame should
// be read back, so read_ok must be true for a PASS. For "wintun" devices the
// frame is consumed by the IP stack / peer and never looped back, so a
// read-side timeout is normal and the test only validates the write path and
// that the read call is callable.
func runRealDeviceSelfTest(dev TAPDevice, deviceType string) map[string]interface{} {
	res := map[string]interface{}{
		"name":        dev.Name(),
		"device_type": deviceType,
		"write_ok":    false,
		"read_ok":     false,
		"write_ms":    0.0,
		"loopback":    deviceType == "tap",
		"detail":      "",
	}
	// Craft a benign broadcast Ethernet frame (IPv4 UDP) to exercise Write.
	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = byte(i)
	}
	// Make it look like a real IPv4 Ethernet frame so the driver accepts it.
	payload[12], payload[13] = 0x08, 0x00

	t0 := time.Now()
	n, err := dev.Write(payload)
	writeMs := time.Since(t0).Seconds() * 1000.0
	res["write_ms"] = writeMs
	if err != nil || n != len(payload) {
		res["detail"] = fmt.Sprintf("write to %s failed: n=%d err=%v", deviceType, n, err)
		return res
	}
	res["write_ok"] = true

	// Probe the read path with a short timeout.
	rb := make([]byte, 1500)
	type rresult struct {
		n   int
		err error
	}
	ch := make(chan rresult, 1)
	go func() {
		rn, rerr := dev.Read(rb)
		ch <- rresult{rn, rerr}
	}()
	if deviceType == "wintun" {
		// Layer-3 tunnel: no loopback expected. A timeout / no-data is the
		// correct, healthy result; only treat a *successful read* as odd.
		select {
		case r := <-ch:
			if r.err == nil && r.n > 0 {
				res["read_ok"] = true
				res["detail"] = fmt.Sprintf("write OK (%0.3f ms); read path returned %d B (unexpected loopback on a Wintun tunnel)", writeMs, r.n)
			} else {
				res["detail"] = fmt.Sprintf("write OK (%0.3f ms); read path callable (no loopback — Wintun is an L3 tunnel, expected)", writeMs)
			}
		case <-time.After(150 * time.Millisecond):
			res["detail"] = fmt.Sprintf("write OK (%0.3f ms); read path idle (no loopback — Wintun is an L3 tunnel, expected)", writeMs)
		}
		return res
	}

	// Layer-2 TAP device: a true loopback read SHOULD succeed.
	select {
	case r := <-ch:
		if r.err == nil && r.n > 0 {
			res["read_ok"] = true
			res["detail"] = fmt.Sprintf("loopback OK: wrote %d B, read %d B (%0.3f ms)", n, r.n, writeMs)
		} else {
			res["detail"] = fmt.Sprintf("write OK (%0.3f ms), but loopback read FAILED: %v — TAP device is not echoing frames", writeMs, r.err)
		}
	case <-time.After(150 * time.Millisecond):
		res["detail"] = fmt.Sprintf("write OK (%0.3f ms), but no frame looped back within 150 ms — TAP device is not echoing frames", writeMs)
	}
	return res
}
