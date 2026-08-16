package node

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"p2ptap/pkg/observer"
	"p2ptap/pkg/packet"
)

type ipStatItem struct {
	mu            sync.RWMutex
	ip            string
	mac           string
	txBytes       uint64
	rxBytes       uint64
	txPackets     uint64
	rxPackets     uint64
	lastTxBytes   uint64
	lastRxBytes   uint64
	txSpeed       uint64
	rxSpeed       uint64
	lastSpeedCalc int64
	lastActive    atomic.Int64
}

func (item *ipStatItem) updateSpeed(nowNano int64) (uint64, uint64) {
	lastCalc := atomic.LoadInt64(&item.lastSpeedCalc)
	if lastCalc == 0 {
		atomic.StoreInt64(&item.lastSpeedCalc, nowNano)
		atomic.StoreUint64(&item.lastTxBytes, atomic.LoadUint64(&item.txBytes))
		atomic.StoreUint64(&item.lastRxBytes, atomic.LoadUint64(&item.rxBytes))
		return 0, 0
	}
	elapsedNs := nowNano - lastCalc
	if elapsedNs >= int64(800*time.Millisecond) {
		curTx := atomic.LoadUint64(&item.txBytes)
		curRx := atomic.LoadUint64(&item.rxBytes)
		lastTx := atomic.LoadUint64(&item.lastTxBytes)
		lastRx := atomic.LoadUint64(&item.lastRxBytes)

		diffTx := uint64(0)
		if curTx >= lastTx {
			diffTx = curTx - lastTx
		}
		diffRx := uint64(0)
		if curRx >= lastRx {
			diffRx = curRx - lastRx
		}

		sec := float64(elapsedNs) / 1e9
		if sec > 0 {
			atomic.StoreUint64(&item.txSpeed, uint64(float64(diffTx)/sec))
			atomic.StoreUint64(&item.rxSpeed, uint64(float64(diffRx)/sec))
		}
		atomic.StoreUint64(&item.lastTxBytes, curTx)
		atomic.StoreUint64(&item.lastRxBytes, curRx)
		atomic.StoreInt64(&item.lastSpeedCalc, nowNano)
	}
	return atomic.LoadUint64(&item.txSpeed), atomic.LoadUint64(&item.rxSpeed)
}

type IPTrafficTracker struct {
	stats sync.Map // ipStr -> *ipStatItem
}

func NewIPTrafficTracker() *IPTrafficTracker {
	return &IPTrafficTracker{}
}

// ipStatMaxAgeSec is the rolling window for the per-IP traffic analytics.
// An IP idle longer than this is evicted so the table and its backing
// sync.Map stay bounded for long-running (never-restarted) nodes. This is
// what makes the WebUI's "24-Hour IP Traffic" view genuinely 24h-bounded
// instead of an ever-growing all-time accumulator.
const ipStatMaxAgeSec = int64(24 * 60 * 60)

func (t *IPTrafficTracker) getOrCreate(ipStr string) *ipStatItem {
	if v, ok := t.stats.Load(ipStr); ok {
		return v.(*ipStatItem)
	}
	item := &ipStatItem{ip: ipStr}
	item.lastActive.Store(time.Now().Unix())
	actual, _ := t.stats.LoadOrStore(ipStr, item)
	return actual.(*ipStatItem)
}

func (t *IPTrafficTracker) RecordTx(ipStr string, bytes uint64, mac ...string) {
	if ipStr == "" || ipStr == "0.0.0.0" || ipStr == "<nil>" || ipStr == "::" {
		return
	}
	item := t.getOrCreate(ipStr)
	atomic.AddUint64(&item.txBytes, bytes)
	atomic.AddUint64(&item.txPackets, 1)
	if len(mac) > 0 && mac[0] != "" && mac[0] != "ff:ff:ff:ff:ff:ff" && mac[0] != "00:00:00:00:00:00" {
		item.mu.Lock()
		if item.mac == "" || item.mac != mac[0] {
			item.mac = mac[0]
		}
		item.mu.Unlock()
	}
	item.lastActive.Store(time.Now().Unix())
}

func (t *IPTrafficTracker) RecordRx(ipStr string, bytes uint64, mac ...string) {
	if ipStr == "" || ipStr == "0.0.0.0" || ipStr == "<nil>" || ipStr == "::" {
		return
	}
	item := t.getOrCreate(ipStr)
	atomic.AddUint64(&item.rxBytes, bytes)
	atomic.AddUint64(&item.rxPackets, 1)
	if len(mac) > 0 && mac[0] != "" && mac[0] != "ff:ff:ff:ff:ff:ff" && mac[0] != "00:00:00:00:00:00" {
		item.mu.Lock()
		if item.mac == "" || item.mac != mac[0] {
			item.mac = mac[0]
		}
		item.mu.Unlock()
	}
	item.lastActive.Store(time.Now().Unix())
}

func (t *IPTrafficTracker) ExtractAndRecord(frame []byte, isTx bool) {
	if len(frame) < 14 {
		return
	}
	etherType := uint16(frame[12])<<8 | uint16(frame[13])
	pktLen := uint64(len(frame))

	var srcIP, dstIP string
	if etherType == packet.EtherTypeIPv4 && len(frame) >= 34 { // IPv4
		srcIP = net.IP(frame[26:30]).String()
		dstIP = net.IP(frame[30:34]).String()
	} else if etherType == packet.EtherTypeIPv6 && len(frame) >= 54 { // IPv6
		srcIP = net.IP(frame[22:38]).String()
		dstIP = net.IP(frame[38:54]).String()
	} else {
		return
	}

	srcMAC := net.HardwareAddr(frame[6:12]).String()
	dstMAC := net.HardwareAddr(frame[0:6]).String()

	if isTx {
		// Outbound frame emitted by local host:
		// srcIP is local transmitter (Tx)
		t.RecordTx(srcIP, pktLen, srcMAC)
		// dstIP is remote destination being transmitted to (Tx to dstIP)
		t.RecordTx(dstIP, pktLen, dstMAC)
	} else {
		// Inbound frame received from overlay / remote:
		// srcIP is remote transmitter (Rx from srcIP)
		t.RecordRx(srcIP, pktLen, srcMAC)
		// dstIP is local receiver (Rx)
		t.RecordRx(dstIP, pktLen, dstMAC)
	}
}

func (t *IPTrafficTracker) GetDTOs(peerMeta *sync.Map, localNodeName, localTapIP, localTapIPv6, localPeerID string, subnetRoutes []observer.SubnetRouteDTO, localExitPeerID string) []observer.IPInfoDTO {
	res := make([]observer.IPInfoDTO, 0, 32)
	nowSec := time.Now().Unix()
	nowNano := time.Now().UnixNano()

	cleanIP := func(cidrStr string) string {
		parts := strings.Split(cidrStr, "/")
		return strings.TrimSpace(parts[0])
	}

	cleanLocalIPv4 := cleanIP(localTapIP)
	cleanLocalIPv6 := cleanIP(localTapIPv6)

	// Identify whether the local node itself is an exit node.
	localIsExit := false
	if peerMeta != nil {
		if pID, err := peer.Decode(localPeerID); err == nil {
			if val, ok := peerMeta.Load(pID); ok {
				localIsExit = val.(PeerMeta).IsExitNode
			}
		}
	}

	// Precompute an IP->peer lookup once (O(M)) so the per-IP loop below is O(1)
	// instead of O(M) nested ranges. Critical for long runs where both the IP
	// set (N) and peer set (M) grow: without this GetDTOs is O(N*M) every poll.
	type peerLookup struct {
		name   string
		peerID string
		isExit bool
		mac    string
	}
	peerByIP := make(map[string]peerLookup, 64)
	if peerMeta != nil {
		peerMeta.Range(func(k, v interface{}) bool {
			pid, ok := k.(peer.ID)
			if !ok {
				return true
			}
			m, ok := v.(PeerMeta)
			if !ok {
				return true
			}
			pl := peerLookup{name: m.NodeName, peerID: pid.String(), isExit: m.IsExitNode, mac: m.TapMAC}
			if ip4 := cleanIP(m.TapIP); ip4 != "" {
				peerByIP[ip4] = pl
			}
			if ip6 := cleanIP(m.TapIPv6); ip6 != "" {
				peerByIP[ip6] = pl
			}
			return true
		})
	}

	t.stats.Range(func(key, value interface{}) bool {
		ipStr := key.(string)
		item := value.(*ipStatItem)
		txB := atomic.LoadUint64(&item.txBytes)
		rxB := atomic.LoadUint64(&item.rxBytes)
		txP := atomic.LoadUint64(&item.txPackets)
		rxP := atomic.LoadUint64(&item.rxPackets)
		lastSec := item.lastActive.Load()

		// Rolling 24h window: evict IPs idle longer than the window so the map
		// stays bounded for long-running nodes. Deleting during a sync.Map Range
		// is safe.
		if nowSec-lastSec > ipStatMaxAgeSec {
			t.stats.Delete(ipStr)
			return true
		}

		txSpd, rxSpd := item.updateSpeed(nowNano)

		item.mu.RLock()
		macAddr := item.mac
		item.mu.RUnlock()

		agoSec := nowSec - lastSec
		agoStr := "just now"
		if agoSec > 0 {
			agoStr = fmt.Sprintf("%ds ago", agoSec)
		}

		protocol := "IPv4"
		if strings.Contains(ipStr, ":") {
			protocol = "IPv6"
		}

		nodeName := ""
		peerID := ""
		var subnetCIDR, subnetOwner, subnetPeerID string
		isExitRoute := false
		ipType := "wan"

		// 1. Check if IP matches Local Node's own IP
		if (cleanLocalIPv4 != "" && ipStr == cleanLocalIPv4) || (cleanLocalIPv6 != "" && ipStr == cleanLocalIPv6) {
			nodeName = localNodeName
			if nodeName == "" {
				nodeName = "Local Node"
			}
			peerID = localPeerID
			isExitRoute = localIsExit
			ipType = "local"
		} else if isSpecialIP(ipStr) {
			// 2. Special description for Broadcast / Multicast / Link-Local IPs
			nodeName = describeSpecialIP(ipStr)
			ipType = "special"
		} else if peerMeta != nil {
			// 3. Check Remote Peers via the precomputed IP->peer lookup (O(1)).
			if pl, ok := peerByIP[ipStr]; ok {
				nodeName = pl.name
				peerID = pl.peerID
				isExitRoute = pl.isExit
				ipType = "peer"
				if macAddr == "" && pl.mac != "" {
					macAddr = pl.mac
				}
			}

			// 4. Fallback: match against advertised subnets via longest prefix.
			if nodeName == "" {
				subnetCIDR, subnetOwner, subnetPeerID, isExitRoute = matchAdvertisedSubnet(ipStr, subnetRoutes)
				if subnetOwner != "" {
					nodeName = subnetOwner
					peerID = subnetPeerID
					ipType = "subnet"
				}
			}

			// 5. Local Exit-Client egress fallback.
			if nodeName == "" && localExitPeerID != "" {
				if exitPID, err := peer.Decode(localExitPeerID); err == nil {
					if val, ok := peerMeta.Load(exitPID); ok {
						meta := val.(PeerMeta)
						if meta.NodeName != "" {
							nodeName = meta.NodeName
						}
					}
				}
				if nodeName == "" {
					nodeName = "Exit Node"
				}
				peerID = localExitPeerID
				isExitRoute = true
				ipType = "exit"
			}
		}

		// 6. Well-known public DNS identification if still unassigned
		if nodeName == "" {
			if publicName := describeKnownPublicIP(ipStr); publicName != "" {
				nodeName = publicName
				ipType = "wan"
			}
		}

		res = append(res, observer.IPInfoDTO{
			IP:           ipStr,
			MAC:          macAddr,
			Protocol:     protocol,
			IPType:       ipType,
			NodeName:     nodeName,
			PeerID:       peerID,
			SubnetCIDR:   subnetCIDR,
			SubnetOwner:  subnetOwner,
			SubnetPeerID: subnetPeerID,
			IsExitNode:   isExitRoute,
			TxBytes:      txB,
			RxBytes:      rxB,
			TotalBytes:   txB + rxB,
			TxPackets:    txP,
			RxPackets:    rxP,
			TxSpeed:      txSpd,
			RxSpeed:      rxSpd,
			LastActive:   agoStr,
		})
		return true
	})
	return res
}

func matchAdvertisedSubnet(ipStr string, subnets []observer.SubnetRouteDTO) (cidr, ownerName, ownerPeerID string, isExitNode bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", "", "", false
	}
	bestOnes := -1
	for _, s := range subnets {
		if s.SubnetCIDR == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(s.SubnetCIDR)
		if err != nil || ipNet == nil {
			continue
		}
		if !ipNet.Contains(ip) {
			continue
		}
		ones, _ := ipNet.Mask.Size()
		if ones > bestOnes {
			bestOnes = ones
			cidr = s.SubnetCIDR
			ownerName = s.NodeName
			ownerPeerID = s.PeerID
			isExitNode = s.IsExitNode
		}
	}
	return cidr, ownerName, ownerPeerID, isExitNode
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

func describeKnownPublicIP(ipStr string) string {
	switch ipStr {
	case "8.8.8.8", "8.8.4.4":
		return "Google Public DNS"
	case "1.1.1.1", "1.0.0.1":
		return "Cloudflare DNS"
	case "114.114.114.114", "114.114.115.115":
		return "114 DNS"
	case "223.5.5.5", "223.6.6.6":
		return "AliDNS"
	case "119.29.29.29", "182.254.116.116":
		return "DNSPod / Tencent DNS"
	case "9.9.9.9", "149.112.112.112":
		return "Quad9 DNS"
	case "208.67.222.222", "208.67.220.220":
		return "OpenDNS"
	case "2001:4860:4860::8888", "2001:4860:4860::8844":
		return "Google DNS IPv6"
	case "2606:4700:4700::1111", "2606:4700:4700::1001":
		return "Cloudflare DNS IPv6"
	case "2400:3200::1", "2400:3200:baba::1":
		return "AliDNS IPv6"
	default:
		return ""
	}
}
