//go:build windows

package tap

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"p2ptap/pkg/logger"
)

var wintunLog = logger.New("Wintun")

var (
	modWintun                      = syscall.NewLazyDLL("wintun.dll")
	procWintunCreateAdapter        = modWintun.NewProc("WintunCreateAdapter")
	procWintunOpenAdapter          = modWintun.NewProc("WintunOpenAdapter")
	procWintunCloseAdapter         = modWintun.NewProc("WintunCloseAdapter")
	procWintunStartSession         = modWintun.NewProc("WintunStartSession")
	procWintunEndSession           = modWintun.NewProc("WintunEndSession")
	procWintunAllocateSendPacket   = modWintun.NewProc("WintunAllocateSendPacket")
	procWintunSendPacket           = modWintun.NewProc("WintunSendPacket")
	procWintunReceivePacket        = modWintun.NewProc("WintunReceivePacket")
	procWintunReleaseReceivePacket = modWintun.NewProc("WintunReleaseReceivePacket")
	procWintunGetReadWaitEvent     = modWintun.NewProc("WintunGetReadWaitEvent")
)

type WintunAdapterHandle uintptr
type WintunSessionHandle uintptr

type WintunTAPDevice struct {
	mu            sync.Mutex
	writeMu       sync.Mutex
	name          string
	adapter       WintunAdapterHandle
	session       WintunSessionHandle
	readWaitEvent windows.Handle
	localMAC      net.HardwareAddr
	localIP       net.IP
	webUIIP       net.IP
	ipCIDR        string
	mtu           int
	replyQueue    chan []byte

	ipMapMu    sync.RWMutex
	ipToMacMap map[string]net.HardwareAddr
}

func isWintunAvailable() bool {
	return modWintun.Load() == nil
}

// IsWintunAvailable returns true when wintun.dll can be loaded.
func IsWintunAvailable() bool {
	return isWintunAvailable()
}

func createWintunTAPDevice(tapName, tapIP string, mtu int) (TAPDevice, error) {
	if !isWintunAvailable() {
		return nil, fmt.Errorf("wintun.dll not loaded")
	}

	wintunLog.Info("Initializing zero-driver Wintun adapter '%s'...", tapName)

	namePtr, _ := windows.UTF16PtrFromString(tapName)
	tunnelTypePtr, _ := windows.UTF16PtrFromString("p2ptap")

	// Fixed GUID for p2ptap Wintun adapter so CreateAdapter and OpenAdapter are consistent
	var wintunGUID = windows.GUID{
		Data1: 0x8B1D89B6,
		Data2: 0x86E4,
		Data3: 0x4B1A,
		Data4: [8]byte{0x9F, 0x2A, 0xDF, 0x1D, 0x47, 0xD0, 0x2C, 0x4B},
	}
	guidPtr := unsafe.Pointer(&wintunGUID)

	ret, _, err := procWintunCreateAdapter.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(tunnelTypePtr)),
		uintptr(guidPtr),
	)
	if ret == 0 {
		// Try OpenAdapter if already exists with the same GUID
		ret, _, err = procWintunOpenAdapter.Call(uintptr(guidPtr))
		if ret == 0 {
			return nil, fmt.Errorf("WintunCreateAdapter & OpenAdapter failed: %w", err)
		}
	}
	adapter := WintunAdapterHandle(ret)

	// Start Session (capacity 0x400000 = 4MB ring buffer)
	retSess, _, errSess := procWintunStartSession.Call(uintptr(adapter), 0x400000)
	if retSess == 0 {
		procWintunCloseAdapter.Call(uintptr(adapter))
		return nil, fmt.Errorf("WintunStartSession failed: %w", errSess)
	}
	session := WintunSessionHandle(retSess)

	retEvent, _, _ := procWintunGetReadWaitEvent.Call(uintptr(session))
	readWaitEvent := windows.Handle(retEvent)

	// Default MAC address for virtual Ethernet framing
	parsedIP, _, _ := net.ParseCIDR(tapIP)
	if parsedIP == nil {
		parsedIP = net.ParseIP(tapIP)
	}
	mac := net.HardwareAddr{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}
	if parsedIP != nil && len(parsedIP.To4()) == 4 {
		ip4 := parsedIP.To4()
		mac[2] = ip4[0]
		mac[3] = ip4[1]
		mac[4] = ip4[2]
		mac[5] = ip4[3]
	}

	wintunLog.Info("Wintun adapter '%s' active with L2 Ethernet Layer emulation!", tapName)

	dev := &WintunTAPDevice{
		name:          tapName,
		adapter:       adapter,
		session:       session,
		readWaitEvent: readWaitEvent,
		localMAC:      mac,
		localIP:       parsedIP,
		ipCIDR:        tapIP,
		mtu:           mtu,
		replyQueue:    make(chan []byte, 1024),
		ipToMacMap:    make(map[string]net.HardwareAddr),
	}

	return dev, nil
}

func (w *WintunTAPDevice) recordMAC(ipStr string, mac net.HardwareAddr) {
	if ipStr == "" || len(mac) < 6 {
		return
	}
	w.ipMapMu.Lock()
	w.ipToMacMap[ipStr] = append(net.HardwareAddr(nil), mac...)
	w.ipMapMu.Unlock()
}

func (w *WintunTAPDevice) lookupMAC(ipStr string) net.HardwareAddr {
	w.ipMapMu.RLock()
	defer w.ipMapMu.RUnlock()
	if mac, ok := w.ipToMacMap[ipStr]; ok {
		return mac
	}
	return nil
}

func (w *WintunTAPDevice) Name() string {
	return w.name
}

func (w *WintunTAPDevice) SetMAC(mac string) error {
	if hw, err := net.ParseMAC(mac); err == nil {
		w.localMAC = hw
	}
	return nil
}

func (w *WintunTAPDevice) SetMTU(mtu int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.mtu = mtu
	if w.name != "" {
		_ = exec.Command("netsh", "interface", "ipv4", "set", "subinterface", w.name, fmt.Sprintf("mtu=%d", w.mtu), "store=persistent").Run()
		_ = exec.Command("netsh", "interface", "ipv6", "set", "subinterface", w.name, fmt.Sprintf("mtu=%d", w.mtu), "store=persistent").Run()
	}
	return nil
}

func (w *WintunTAPDevice) ConfigureIP(ipCIDR string, ipv6CIDR string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ipCIDR = ipCIDR

	if ipCIDR != "" {
		ip := strings.Split(ipCIDR, "/")[0]
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			w.localIP = parsedIP
			if len(parsedIP.To4()) == 4 {
				ip4 := parsedIP.To4()
				w.localMAC[2] = ip4[0]
				w.localMAC[3] = ip4[1]
				w.localMAC[4] = ip4[2]
				w.localMAC[5] = ip4[3]
			}
		}
		wintunLog.Info("Configuring IPv4 %s on Wintun adapter '%s'...", ipCIDR, w.name)
		// Derive mask from CIDR instead of hardcoding /24
		mask := "255.255.255.0"
		if _, ipNet, err := net.ParseCIDR(ipCIDR); err == nil {
			mask = net.IP(ipNet.Mask).String()
		}
		_ = exec.Command("netsh", "interface", "ipv4", "set", "address", "name="+w.name, "source=static", "address="+ip, "mask="+mask).Run()
		// Clean up any stale secondary WebUI virtual IP from interface so ipconfig only shows 10.0.0.3
		_ = exec.Command("netsh", "interface", "ipv4", "delete", "address", "name="+w.name, "address=10.0.0.254").Run()
		_ = exec.Command("netsh", "interface", "ipv4", "set", "interface", "name="+w.name, "metric=1").Run()
		// Allow ICMP Echo Requests (Ping) in Windows Firewall
		_ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=p2ptap ICMPv4 Allow", "dir=in", "action=allow", "protocol=icmpv4").Run()
		// Ensure IPv4 subnet route is explicitly added
		if _, ipNet, err := net.ParseCIDR(ipCIDR); err == nil {
			networkIP := parsedIP.Mask(ipNet.Mask)
			prefixLen, _ := ipNet.Mask.Size()
			routePrefix := fmt.Sprintf("%s/%d", networkIP.String(), prefixLen)
			wintunLog.Info("Adding IPv4 subnet route %s on Wintun adapter '%s'...", routePrefix, w.name)
			_ = exec.Command("netsh", "interface", "ipv4", "delete", "route", routePrefix, "interface="+w.name).Run()
			_ = exec.Command("netsh", "interface", "ipv4", "add", "route", routePrefix, "interface="+w.name, "metric=1", "publish=yes").Run()
		}
	}
	if ipv6CIDR != "" {
		v6IP := strings.Split(ipv6CIDR, "/")[0]
		wintunLog.Info("Configuring IPv6 %s on Wintun adapter '%s'...", ipv6CIDR, w.name)
		_ = exec.Command("netsh", "interface", "ipv6", "add", "address", w.name, ipv6CIDR).Run()
		_ = exec.Command("netsh", "interface", "ipv6", "add", "address", "interface="+w.name, "address="+ipv6CIDR).Run()
		_ = exec.Command("netsh", "interface", "ipv6", "add", "address", w.name, v6IP).Run()
		_ = exec.Command("netsh", "interface", "ipv6", "add", "address", "interface="+w.name, "address="+v6IP).Run()

		// Add IPv6 Subnet Route (e.g. fd00::/64) so Windows IPv6 routing table directs overlay IPv6 traffic into Wintun
		prefix := "fd00::/64"
		if parts := strings.Split(ipv6CIDR, "/"); len(parts) == 2 {
			if ip := net.ParseIP(parts[0]); ip != nil {
				maskBits := 64
				if m, err := strconv.Atoi(parts[1]); err == nil && m > 0 && m <= 128 {
					maskBits = m
				}
				ipNet := net.IPNet{IP: ip.Mask(net.CIDRMask(maskBits, 128)), Mask: net.CIDRMask(maskBits, 128)}
				prefix = ipNet.String()
			}
		}
		_ = exec.Command("netsh", "interface", "ipv6", "add", "route", "prefix="+prefix, "interface="+w.name, "metric=1", "publish=yes").Run()
		_ = exec.Command("netsh", "interface", "ipv6", "add", "route", prefix, w.name, "metric=1").Run()
		_ = exec.Command("netsh", "interface", "ipv6", "set", "interface", "name="+w.name, "metric=1").Run()
		_ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=p2ptap ICMPv6 Allow", "dir=in", "action=allow", "protocol=icmpv6").Run()
	}

	if w.mtu > 0 {
		_ = exec.Command("netsh", "interface", "ipv4", "set", "subinterface", w.name, fmt.Sprintf("mtu=%d", w.mtu), "store=persistent").Run()
		_ = exec.Command("netsh", "interface", "ipv6", "set", "subinterface", w.name, fmt.Sprintf("mtu=%d", w.mtu), "store=persistent").Run()
	}

	return nil
}

func (w *WintunTAPDevice) Read(b []byte) (int, error) {
	// 1. Check if there is an ARP Reply or Proxy NDP response frame queued
	select {
	case frame := <-w.replyQueue:
		if len(b) < len(frame) {
			return 0, fmt.Errorf("read buffer too small for reply frame (%d < %d)", len(b), len(frame))
		}
		copy(b, frame)
		return len(frame), nil
	default:
	}

	// 2. Otherwise read IP packet from Wintun ring buffer
	for {
		// Re-check replyQueue before blocking in Wintun
		select {
		case frame := <-w.replyQueue:
			if len(b) < len(frame) {
				return 0, fmt.Errorf("read buffer too small for reply frame (%d < %d)", len(b), len(frame))
			}
			copy(b, frame)
			return len(frame), nil
		default:
		}

		var packetSize uint32
		retPtr, _, _ := procWintunReceivePacket.Call(
			uintptr(w.session),
			uintptr(unsafe.Pointer(&packetSize)),
		)

		if retPtr != 0 {
			packetData := (*[1 << 30]byte)(unsafe.Pointer(retPtr))[:packetSize:packetSize]

			// Prepend 14-byte Ethernet Header (Destination MAC, Source MAC, EtherType)
			const ethHdrLen = 14
			if len(b) < ethHdrLen+int(packetSize) {
				procWintunReleaseReceivePacket.Call(uintptr(w.session), retPtr)
				return 0, fmt.Errorf("read buffer too small (%d < %d)", len(b), ethHdrLen+packetSize)
			}

			// Source MAC: local virtual MAC for local IP, or derived/learned MAC for other IPs
			version := packetData[0] >> 4
			if version == 4 && len(packetData) >= 20 {
				srcIP := net.IP(packetData[12:16])
				if srcIP.Equal(w.localIP) {
					copy(b[6:12], w.localMAC)
				} else {
					learnedSrc := w.lookupMAC(srcIP.String())
					if learnedSrc != nil {
						copy(b[6:12], learnedSrc)
					} else {
						copy(b[6:12], []byte{0x02, 0x00, srcIP[0], srcIP[1], srcIP[2], srcIP[3]})
					}
				}
			} else {
				copy(b[6:12], w.localMAC)
			}

			if isARPPayload(packetData) {
				frame := buildARPFrame(w.localMAC, nil, packetData)
				if len(b) < len(frame) {
					procWintunReleaseReceivePacket.Call(uintptr(w.session), retPtr)
					return 0, fmt.Errorf("read buffer too small for ARP frame (%d < %d)", len(b), len(frame))
				}
				copy(b, frame)
				procWintunReleaseReceivePacket.Call(uintptr(w.session), retPtr)
				return len(frame), nil
			}

			// Determine EtherType & Destination MAC
			if version == 6 {
				binary.BigEndian.PutUint16(b[12:14], 0x86DD)
				w.handleIPv6NDP(packetData)
				// IPv6 Destination MAC mapping
				if len(packetData) >= 40 {
					dstIP := net.IP(packetData[24:40])
					if dstIP.IsMulticast() {
						copy(b[0:6], []byte{0x33, 0x33, dstIP[12], dstIP[13], dstIP[14], dstIP[15]})
					} else {
						learnedMAC := w.lookupMAC(dstIP.String())
						if learnedMAC != nil {
							copy(b[0:6], learnedMAC)
						} else {
							// Broadcast MAC fallback so P2P switch floods initial packet until MAC is learned
							copy(b[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
						}
					}
				} else {
					copy(b[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
				}
			} else {
				binary.BigEndian.PutUint16(b[12:14], 0x0800)
				// IPv4 Destination MAC mapping: lookup learned MAC or derive unicast MAC
				if len(packetData) >= 20 {
					dstIP := net.IP(packetData[16:20])
					if dstIP.IsMulticast() || dstIP[3] == 255 {
						copy(b[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
					} else {
						learnedMAC := w.lookupMAC(dstIP.String())
						if learnedMAC != nil {
							copy(b[0:6], learnedMAC)
						} else {
							// Broadcast MAC fallback until target peer's config.json metadata is synced
							copy(b[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
						}
					}
				} else {
					copy(b[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
				}
			}

			// Copy IP payload
			copy(b[14:], packetData)
			procWintunReleaseReceivePacket.Call(uintptr(w.session), retPtr)

			return ethHdrLen + int(packetSize), nil
		}

		// Wait for next Wintun packet event (with 10ms timeout to periodically check replyQueue).
		// When nothing arrives within 10ms return ErrReadTimeout so tapReadLoopPoll can
		// yield the batch, re-check ctx.Done(), and avoid consuming 100% CPU.
		eventRes, _ := windows.WaitForSingleObject(w.readWaitEvent, 10)
		if eventRes == windows.WAIT_OBJECT_0 {
			continue
		}
		return 0, ErrReadTimeout
	}
}

func (w *WintunTAPDevice) Write(b []byte) (int, error) {
	if len(b) < 14 {
		return len(b), nil
	}

	srcMAC := net.HardwareAddr(b[6:12])
	ethType := binary.BigEndian.Uint16(b[12:14])

	// Learn Source MAC from incoming Ethernet frame
	if ethType == 0x0800 && len(b) >= 14+20 {
		srcIP := net.IP(b[14+12 : 14+16])
		w.recordMAC(srcIP.String(), srcMAC)
	} else if ethType == 0x86DD && len(b) >= 14+40 {
		srcIP := net.IP(b[14+8 : 14+24])
		w.recordMAC(srcIP.String(), srcMAC)
	}

	// 1. ARP (0x0806)
	if ethType == 0x0806 && len(b) >= 42 {
		opcode := binary.BigEndian.Uint16(b[20:22])
		if opcode == 1 {
			// ARP Request -> Proxy ARP
			w.handleProxyARP(b)
		} else if opcode == 2 {
			// ARP Reply / Gratuitous ARP -> Inject into Wintun so Windows OS updates ARP table!
			w.injectARPPayloadToWintun(b[14:])
			wintunLog.Debug("Injected ARP Reply into Wintun for Windows OS ARP table update")
		}
		return len(b), nil
	}

	// 2. IPv6 ICMPv6 Neighbor Advertisement (0x86DD, NextHeader 58, Type 136)
	if ethType == 0x86DD && len(b) >= 55 && b[20] == 58 && b[54] == 136 {
		w.injectARPPayloadToWintun(b[14:])
		wintunLog.Debug("Injected ICMPv6 Neighbor Advertisement into Wintun for Windows OS NDP update")
		return len(b), nil
	}

	// 3. IPv4 (0x0800) / IPv6 (0x86DD) -> Strip 14-byte Ethernet Header and pass IP packet to Wintun
	if ethType == 0x0800 || ethType == 0x86DD {
		ipPayload := b[14:]
		packetLen := uint32(len(ipPayload))

		w.writeMu.Lock()
		retAlloc, _, errAlloc := procWintunAllocateSendPacket.Call(
			uintptr(w.session),
			uintptr(packetLen),
		)
		if retAlloc == 0 {
			w.writeMu.Unlock()
			return 0, fmt.Errorf("WintunAllocateSendPacket failed: %w", errAlloc)
		}

		destBuf := (*[1 << 30]byte)(unsafe.Pointer(retAlloc))[:packetLen:packetLen]
		copy(destBuf, ipPayload)

		procWintunSendPacket.Call(uintptr(w.session), retAlloc)
		w.writeMu.Unlock()
		return len(b), nil
	}

	return len(b), nil
}

func (w *WintunTAPDevice) SetWebUIIP(ipStr string) {
	if ipStr == "" {
		return
	}
	cleanIP := strings.Split(ipStr, "/")[0]
	if ip := net.ParseIP(cleanIP); ip != nil && len(ip.To4()) == 4 {
		w.webUIIP = ip.To4()
		// Clean up any OS interface address for WebUI virtual IP so ipconfig remains 100% clean
		_ = exec.Command("netsh", "interface", "ipv4", "delete", "address", "name="+w.name, "address="+cleanIP).Run()
	}
}

func (w *WintunTAPDevice) handleProxyARP(frame []byte) {
	if len(frame) < 42 {
		return
	}

	op := arpOpcode(frame)
	if op == 2 {
		if len(frame) >= 28 {
			senderIP := net.IP(frame[28:32])
			senderMAC := net.HardwareAddr(frame[22:28])
			w.recordMAC(senderIP.String(), senderMAC)
		}
		w.injectARPPayloadToWintun(frame[14:])
		return
	}
	if op != 1 {
		return
	}

	targetIP := net.IP(frame[38:42])
	senderIP := net.IP(frame[28:32])
	senderMAC := net.HardwareAddr(frame[22:28])

	// Record sender's MAC
	w.recordMAC(senderIP.String(), senderMAC)

	isWebUITarget := (len(w.webUIIP) == 4 && targetIP.Equal(w.webUIIP)) || (len(targetIP) == 4 && targetIP[3] == 254)
	isLocalTarget := targetIP.Equal(w.localIP)
	isFromLocalOS := senderMAC.String() == w.localMAC.String() || senderIP.Equal(w.localIP)

	// Determine MAC to return in ARP Reply
	var replyMAC net.HardwareAddr
	if isLocalTarget {
		replyMAC = w.localMAC
	} else if isWebUITarget {
		replyMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x02, 0x54}
	} else {
		// Remote peer IP: lookup learned MAC (synced from remote peer's config.json)
		learnedMAC := w.lookupMAC(targetIP.String())
		if learnedMAC != nil {
			replyMAC = learnedMAC
		} else {
			// Synthetic remote MAC fallback (NEVER return w.localMAC for remote IP, otherwise OS stamps DstMAC = localMAC and P2P switch won't forward packet!)
			if ip4 := targetIP.To4(); ip4 != nil {
				replyMAC = net.HardwareAddr{0x02, 0x00, ip4[0], ip4[1], ip4[2], ip4[3]}
			} else {
				replyMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
			}
		}
	}

	// Generate ARP Reply frame (IEEE 802.3 minimum Ethernet frame length = 60 bytes)
	reply := make([]byte, 60)
	// Ethernet Header: Dst MAC = Sender MAC, Src MAC = Reply MAC, Type = ARP (0x0806)
	copy(reply[0:6], senderMAC)
	copy(reply[6:12], replyMAC)
	binary.BigEndian.PutUint16(reply[12:14], 0x0806)

	// ARP Payload
	binary.BigEndian.PutUint16(reply[14:16], 1)      // Hardware type: Ethernet
	binary.BigEndian.PutUint16(reply[16:18], 0x0800) // Protocol type: IPv4
	reply[18] = 6                                     // Hardware size
	reply[19] = 4                                     // Protocol size
	binary.BigEndian.PutUint16(reply[20:22], 2)      // Opcode: Reply (2)

	copy(reply[22:28], replyMAC)   // Sender MAC (Reply MAC)
	copy(reply[28:32], targetIP)   // Sender IP (Target IP being queried)
	copy(reply[32:38], senderMAC)  // Target MAC (Original requester's MAC)
	copy(reply[38:42], senderIP)   // Target IP (Original requester's IP)

	if isFromLocalOS {
		// Deliver Proxy ARP Reply directly into Wintun ring buffer so Windows OS receives it!
		w.injectARPPayloadToWintun(reply[14:])
		wintunLog.Debug("Delivered Proxy ARP Reply for %s (%s) to Windows OS", targetIP.String(), replyMAC.String())
		return
	}

	// If ARP Request came from remote peer for local IP or WebUI virtual IP, reply with local MAC
	if isLocalTarget || isWebUITarget {
		copy(reply[6:12], w.localMAC)
		copy(reply[22:28], w.localMAC)
		select {
		case w.replyQueue <- reply:
			wintunLog.Debug("Replied to remote ARP Request for %s from %s (%s)", targetIP, senderIP, senderMAC)
		default:
		}
	}
}

func (w *WintunTAPDevice) injectARPPayloadToWintun(arpPayload []byte) {
	if len(arpPayload) == 0 {
		return
	}

	packetLen := uint32(len(arpPayload))
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	retAlloc, _, _ := procWintunAllocateSendPacket.Call(uintptr(w.session), uintptr(packetLen))
	if retAlloc == 0 {
		wintunLog.Warn("WintunAllocateSendPacket failed for ARP injection (%d bytes) – send ring buffer full?", packetLen)
		return
	}

	destBuf := (*[1 << 30]byte)(unsafe.Pointer(retAlloc))[:packetLen:packetLen]
	copy(destBuf, arpPayload)
	procWintunSendPacket.Call(uintptr(w.session), retAlloc)
}

func (w *WintunTAPDevice) handleIPv6NDP(packetData []byte) {
	if len(packetData) < 64 {
		return
	}
	if packetData[6] != 58 || packetData[40] != 135 { // Next Header == ICMPv6, Type == Neighbor Solicitation
		return
	}

	senderIPv6 := net.IP(packetData[8:24])
	targetIPv6 := net.IP(packetData[48:64])

	var replyMAC net.HardwareAddr
	if len(w.webUIIP) == 16 && targetIPv6.Equal(w.webUIIP) {
		replyMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x02, 0x54}
	} else if targetIPv6.Equal(w.localIP) {
		replyMAC = w.localMAC
	} else {
		learnedMAC := w.lookupMAC(targetIPv6.String())
		if learnedMAC != nil {
			replyMAC = learnedMAC
		} else {
			v6 := targetIPv6.To16()
			if v6 != nil {
				replyMAC = net.HardwareAddr{0x02, 0x00, v6[12], v6[13], v6[14], v6[15]}
			} else {
				replyMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
			}
		}
	}

	naFrame := BuildIPv6NeighborAdvertisementFrame(replyMAC, targetIPv6, senderIPv6)
	if len(naFrame) > 14 {
		w.injectARPPayloadToWintun(naFrame[14:])
		wintunLog.Debug("Delivered ICMPv6 Neighbor Advertisement for %s (%s) to Windows OS (requested by %s)", targetIPv6.String(), replyMAC.String(), senderIPv6.String())
	}
}

func (w *WintunTAPDevice) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.session != 0 {
		procWintunEndSession.Call(uintptr(w.session))
		w.session = 0
	}
	if w.adapter != 0 {
		procWintunCloseAdapter.Call(uintptr(w.adapter))
		w.adapter = 0
	}
	wintunLog.Info("Wintun adapter '%s' closed", w.name)
	return nil
}
