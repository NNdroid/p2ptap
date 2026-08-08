package tap

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
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
	SetMTU(mtu int) error
	ConfigureIP(ipCIDR string, ipv6CIDR string) error
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
