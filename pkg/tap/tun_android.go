//go:build android

// Package tap – Android TUN backend.
//
// Android's VpnService only provides a layer-3 (TUN) file descriptor, never a
// layer-2 (TAP) device. This file adapts that TUN fd into a tap.TAPDevice by
// using the tun<->tap converter in p2ptap/pkg/tuntap: incoming IP packets from
// the fd are wrapped into Ethernet frames for the node's L2 pipeline, and
// outgoing Ethernet frames have their header stripped before being written to
// the fd as raw IP packets.
package tap

import (
	"errors"
	"io"
	"net"
	"os"

	"p2ptap/pkg/tuntap"
)

// TunTAPDevice presents an Android VpnService TUN (L3) fd to the node as a TAP
// (L2) device. It implements tap.TAPDevice.
type TunTAPDevice struct {
	file   *os.File
	name   string
	mac    string
	mtu    int
	conv   *tuntap.Converter
	closed bool
}

// CreateTunTAPDevice wraps an already-detached Android TUN file descriptor
// (obtained via android.os.ParcelFileDescriptor.detachFd()) and returns a
// tap.TAPDevice. name/mac/mtu default sensibly when empty/zero.
func CreateTunTAPDevice(tunFd int, name, mac string, mtu int) (TAPDevice, error) {
	if tunFd <= 0 {
		return nil, errors.New("tun: invalid TUN fd (must be a detached VpnService fd)")
	}
	if name == "" {
		name = "tun"
	}
	if mac == "" {
		mac = "02:00:00:00:00:01"
	}
	if mtu <= 0 {
		mtu = 1500
	}
	f := os.NewFile(uintptr(tunFd), name)
	if f == nil {
		return nil, errors.New("tun: failed to wrap TUN fd")
	}
	return &TunTAPDevice{
		file: f,
		name: name,
		mac:  mac,
		mtu:  mtu,
		conv: tuntap.NewConverter(mustParseMAC(mac)),
	}, nil
}

func mustParseMAC(s string) net.HardwareAddr {
	if m, err := net.ParseMAC(s); err == nil {
		return m
	}
	return tuntap.DefaultMAC
}

func (d *TunTAPDevice) Name() string { return d.name }

func (d *TunTAPDevice) MAC() string { return d.mac }

func (d *TunTAPDevice) SetMAC(mac string) error {
	if mac == "" {
		return nil
	}
	m, err := net.ParseMAC(mac)
	if err != nil {
		return err
	}
	d.mac = mac
	d.conv = tuntap.NewConverter(m)
	return nil
}

func (d *TunTAPDevice) SetMTU(mtu int) error { d.mtu = mtu; return nil }

// ConfigureIP is a no-op: the Android VpnService establishes the tunnel
// address itself (builder.addAddress), so the node must not reconfigure it.
func (d *TunTAPDevice) ConfigureIP(ipCIDR, ipv6CIDR string) error { return nil }

func (d *TunTAPDevice) Close() error {
	if d.closed {
		return nil
	}
	d.closed = true
	return d.file.Close()
}

// Read pulls an L3 IP packet from the TUN fd and returns it wrapped as an
// Ethernet frame for the node's L2 pipeline. Non-IP packets (e.g. ARP) cannot
// traverse an L3 tunnel and are silently skipped (the loop retries).
func (d *TunTAPDevice) Read(b []byte) (int, error) {
	for {
		buf := make([]byte, d.mtu+64)
		n, err := d.file.Read(buf)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue
		}
		frame, err := d.conv.PacketToFrame(buf[:n])
		if err != nil {
			// Not an IP packet — skip it; the OS handles L2 neighbour
			// resolution itself, so dropping is correct and safe.
			continue
		}
		if len(frame) > len(b) {
			return 0, io.ErrShortBuffer
		}
		return copy(b, frame), nil
	}
}

// Write strips the Ethernet header from b and writes the inner IP packet to the
// TUN fd. Non-IP frames (e.g. ARP/GARP) are dropped, as the tunnel only carries
// L3 traffic.
func (d *TunTAPDevice) Write(b []byte) (int, error) {
	pkt, err := d.conv.FrameToPacket(b)
	if err != nil {
		return len(b), nil // drop non-IP frames; safe to skip on a TUN device
	}
	if _, err := d.file.Write(pkt); err != nil {
		return 0, err
	}
	return len(b), nil
}

// SelfTest reports device metadata. A TUN device is layer-3, so it never
// loops frames back to itself (loopback=false).
func (d *TunTAPDevice) SelfTest() map[string]interface{} {
	return map[string]interface{}{
		"name":        d.name,
		"device_type": "tun",
		"write_ok":    true,
		"read_ok":     false,
		"write_ms":    0.0,
		"loopback":    false,
		"detail":      "Android TUN (L3) device presented to the node as TAP via tun<->tap conversion",
	}
}
