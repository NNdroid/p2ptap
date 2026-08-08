package node

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"p2ptap/pkg/web"
)

type ipStatItem struct {
	ip         string
	txBytes    uint64
	rxBytes    uint64
	txPackets  uint64
	rxPackets  uint64
	lastActive atomic.Int64
}

type IPTrafficTracker struct {
	mu    sync.RWMutex
	stats map[string]*ipStatItem
}

func NewIPTrafficTracker() *IPTrafficTracker {
	return &IPTrafficTracker{
		stats: make(map[string]*ipStatItem),
	}
}

func (t *IPTrafficTracker) getOrCreate(ipStr string) *ipStatItem {
	t.mu.RLock()
	item, ok := t.stats[ipStr]
	t.mu.RUnlock()
	if ok {
		return item
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	item, ok = t.stats[ipStr]
	if !ok {
		item = &ipStatItem{ip: ipStr}
		item.lastActive.Store(time.Now().Unix())
		t.stats[ipStr] = item
	}
	return item
}

func (t *IPTrafficTracker) RecordTx(ipStr string, bytes uint64) {
	if ipStr == "" || ipStr == "0.0.0.0" || ipStr == "<nil>" || ipStr == "::" {
		return
	}
	item := t.getOrCreate(ipStr)
	atomic.AddUint64(&item.txBytes, bytes)
	atomic.AddUint64(&item.txPackets, 1)
	item.lastActive.Store(time.Now().Unix())
}

func (t *IPTrafficTracker) RecordRx(ipStr string, bytes uint64) {
	if ipStr == "" || ipStr == "0.0.0.0" || ipStr == "<nil>" || ipStr == "::" {
		return
	}
	item := t.getOrCreate(ipStr)
	atomic.AddUint64(&item.rxBytes, bytes)
	atomic.AddUint64(&item.rxPackets, 1)
	item.lastActive.Store(time.Now().Unix())
}

func (t *IPTrafficTracker) ExtractAndRecord(frame []byte, isTx bool) {
	if len(frame) < 14 {
		return
	}
	etherType := uint16(frame[12])<<8 | uint16(frame[13])
	pktLen := uint64(len(frame))

	var srcIP, dstIP string
	if etherType == 0x0800 && len(frame) >= 34 { // IPv4
		srcIP = net.IP(frame[26:30]).String()
		dstIP = net.IP(frame[30:34]).String()
	} else if etherType == 0x86DD && len(frame) >= 54 { // IPv6
		srcIP = net.IP(frame[22:38]).String()
		dstIP = net.IP(frame[38:54]).String()
	} else {
		return
	}

	if isTx {
		t.RecordTx(srcIP, pktLen)
		t.RecordRx(dstIP, pktLen)
	} else {
		t.RecordRx(srcIP, pktLen)
		t.RecordTx(dstIP, pktLen)
	}
}

func (t *IPTrafficTracker) GetDTOs(peerMeta *sync.Map, localNodeName, localTapIP, localTapIPv6, localPeerID string) []web.IPInfoDTO {
	t.mu.RLock()
	defer t.mu.RUnlock()

	res := make([]web.IPInfoDTO, 0, len(t.stats))
	nowSec := time.Now().Unix()

	cleanIP := func(cidrStr string) string {
		parts := strings.Split(cidrStr, "/")
		return strings.TrimSpace(parts[0])
	}

	cleanLocalIPv4 := cleanIP(localTapIP)
	cleanLocalIPv6 := cleanIP(localTapIPv6)

	for ipStr, item := range t.stats {
		txB := atomic.LoadUint64(&item.txBytes)
		rxB := atomic.LoadUint64(&item.rxBytes)
		txP := atomic.LoadUint64(&item.txPackets)
		rxP := atomic.LoadUint64(&item.rxPackets)
		lastSec := item.lastActive.Load()

		agoSec := nowSec - lastSec
		agoStr := "just now"
		if agoSec > 0 {
			agoStr = fmt.Sprintf("%ds ago", agoSec)
		}

		nodeName := ""
		peerID := ""

		// 1. Check if IP matches Local Node's own IP
		if (cleanLocalIPv4 != "" && ipStr == cleanLocalIPv4) || (cleanLocalIPv6 != "" && ipStr == cleanLocalIPv6) {
			nodeName = localNodeName
			if nodeName == "" {
				nodeName = "Local Node"
			}
			peerID = localPeerID
		} else if isSpecialIP(ipStr) {
			// 2. Special description for Broadcast / Multicast / Link-Local IPs
			nodeName = describeSpecialIP(ipStr)
		} else if peerMeta != nil {
			// 3. Check Remote Peers in peerMeta (strip CIDR mask like /24 or /64)
			peerMeta.Range(func(key, value interface{}) bool {
				meta := value.(PeerMeta)
				peerIPv4 := cleanIP(meta.TapIP)
				peerIPv6 := cleanIP(meta.TapIPv6)

				if (peerIPv4 != "" && peerIPv4 == ipStr) || (peerIPv6 != "" && peerIPv6 == ipStr) {
					nodeName = meta.NodeName
					peerID = fmt.Sprintf("%v", key)
					return false
				}
				return true
			})
		}

		res = append(res, web.IPInfoDTO{
			IP:         ipStr,
			NodeName:   nodeName,
			PeerID:     peerID,
			TxBytes:    txB,
			RxBytes:    rxB,
			TotalBytes: txB + rxB,
			TxPackets:  txP,
			RxPackets:  rxP,
			LastActive: agoStr,
		})
	}
	return res
}

func isSpecialIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsMulticast() || ip.Equal(net.IPv4bcast) || ipStr == "255.255.255.255" || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return false
}

func describeSpecialIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip != nil && ip.IsLinkLocalUnicast() {
		return "IPv6 Link-Local"
	}
	if ipStr == "255.255.255.255" {
		return "Broadcast (IPv4)"
	}
	if ipStr == "224.0.0.251" || ipStr == "ff02::fb" {
		return "mDNS Multicast"
	}
	if ipStr == "224.0.0.252" || ipStr == "ff02::1:3" {
		return "LLMNR Multicast"
	}
	if strings.HasPrefix(ipStr, "224.") || strings.HasPrefix(ipStr, "239.") {
		return "IPv4 Multicast"
	}
	if strings.HasPrefix(ipStr, "ff") {
		return "IPv6 Multicast"
	}
	return "Broadcast / Multicast"
}
