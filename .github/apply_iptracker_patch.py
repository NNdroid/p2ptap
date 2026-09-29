from pathlib import Path

p = Path('pkg/node/ip_tracker.go')
s = p.read_text()

def one(old, new):
    global s
    n = s.count(old)
    if n != 1:
        raise SystemExit(f'expected 1 match, got {n}: {old[:120]!r}')
    s = s.replace(old, new, 1)

one(
'''type ipStatItem struct {
\tmu            sync.RWMutex
\tip            string
\tmac           string
\ttxBytes       uint64''',
'''type ipStatMAC struct {
\tvalue string
}

type ipStatItem struct {
\tip            string
\tmac           atomic.Pointer[ipStatMAC]
\ttxBytes       uint64''')

one(
'''func (t *IPTrafficTracker) RecordTx(ipStr string, bytes uint64, mac ...string) {
\tif ipStr == "" || ipStr == "0.0.0.0" || ipStr == "<nil>" || ipStr == "::" {
\t\treturn
\t}
\titem := t.getOrCreate(ipStr)
\tatomic.AddUint64(&item.txBytes, bytes)
\tatomic.AddUint64(&item.txPackets, 1)
\tif len(mac) > 0 && mac[0] != "" && mac[0] != "ff:ff:ff:ff:ff:ff" && mac[0] != "00:00:00:00:00:00" {
\t\titem.mu.RLock()
\t\tcur := item.mac
\t\titem.mu.RUnlock()
\t\tif cur != mac[0] {
\t\t\titem.mu.Lock()
\t\t\titem.mac = mac[0]
\t\t\titem.mu.Unlock()
\t\t}
\t}
\titem.lastActive.Store(time.Now().Unix())
}

func (t *IPTrafficTracker) RecordRx(ipStr string, bytes uint64, mac ...string) {
\tif ipStr == "" || ipStr == "0.0.0.0" || ipStr == "<nil>" || ipStr == "::" {
\t\treturn
\t}
\titem := t.getOrCreate(ipStr)
\tatomic.AddUint64(&item.rxBytes, bytes)
\tatomic.AddUint64(&item.rxPackets, 1)
\tif len(mac) > 0 && mac[0] != "" && mac[0] != "ff:ff:ff:ff:ff:ff" && mac[0] != "00:00:00:00:00:00" {
\t\titem.mu.RLock()
\t\tcur := item.mac
\t\titem.mu.RUnlock()
\t\tif cur != mac[0] {
\t\t\titem.mu.Lock()
\t\t\titem.mac = mac[0]
\t\t\titem.mu.Unlock()
\t\t}
\t}
\titem.lastActive.Store(time.Now().Unix())
}
''',
'''func validTrackedMAC(mac string) bool {
\treturn mac != "" && mac != "ff:ff:ff:ff:ff:ff" && mac != "00:00:00:00:00:00"
}

func (item *ipStatItem) updateMAC(mac string) {
\tif !validTrackedMAC(mac) {
\t\treturn
\t}
\tfor {
\t\tcur := item.mac.Load()
\t\tif cur != nil && cur.value == mac {
\t\t\treturn
\t\t}
\t\tnext := &ipStatMAC{value: mac}
\t\tif item.mac.CompareAndSwap(cur, next) {
\t\t\treturn
\t\t}
\t}
}

func (item *ipStatItem) macString() string {
\tif cur := item.mac.Load(); cur != nil {
\t\treturn cur.value
\t}
\treturn ""
}

func (t *IPTrafficTracker) recordTxAt(ipStr string, bytes uint64, mac string, nowSec int64) {
\tif ipStr == "" || ipStr == "0.0.0.0" || ipStr == "<nil>" || ipStr == "::" {
\t\treturn
\t}
\titem := t.getOrCreate(ipStr)
\tatomic.AddUint64(&item.txBytes, bytes)
\tatomic.AddUint64(&item.txPackets, 1)
\titem.updateMAC(mac)
\titem.lastActive.Store(nowSec)
}

func (t *IPTrafficTracker) recordRxAt(ipStr string, bytes uint64, mac string, nowSec int64) {
\tif ipStr == "" || ipStr == "0.0.0.0" || ipStr == "<nil>" || ipStr == "::" {
\t\treturn
\t}
\titem := t.getOrCreate(ipStr)
\tatomic.AddUint64(&item.rxBytes, bytes)
\tatomic.AddUint64(&item.rxPackets, 1)
\titem.updateMAC(mac)
\titem.lastActive.Store(nowSec)
}

func (t *IPTrafficTracker) RecordTx(ipStr string, bytes uint64, mac ...string) {
\tmacStr := ""
\tif len(mac) > 0 {
\t\tmacStr = mac[0]
\t}
\tt.recordTxAt(ipStr, bytes, macStr, time.Now().Unix())
}

func (t *IPTrafficTracker) RecordRx(ipStr string, bytes uint64, mac ...string) {
\tmacStr := ""
\tif len(mac) > 0 {
\t\tmacStr = mac[0]
\t}
\tt.recordRxAt(ipStr, bytes, macStr, time.Now().Unix())
}
''')

one(
'''\tif isTx {
\t\t// Outbound frame emitted by local host:
\t\t// srcIP is local transmitter (Tx)
\t\tt.RecordTx(srcIP, pktLen, srcMAC)
\t\t// dstIP is remote destination being transmitted to (Tx to dstIP)
\t\tt.RecordTx(dstIP, pktLen, dstMAC)
\t} else {
\t\t// Inbound frame received from overlay / remote:
\t\t// srcIP is remote transmitter (Rx from srcIP)
\t\tt.RecordRx(srcIP, pktLen, srcMAC)
\t\t// dstIP is local receiver (Rx)
\t\tt.RecordRx(dstIP, pktLen, dstMAC)
\t}
''',
'''\tnowSec := time.Now().Unix()
\tif isTx {
\t\t// Outbound frame emitted by local host. Reuse one clock read for both
\t\t// source and destination accounting on this Ethernet frame.
\t\tt.recordTxAt(srcIP, pktLen, srcMAC, nowSec)
\t\tt.recordTxAt(dstIP, pktLen, dstMAC, nowSec)
\t} else {
\t\t// Inbound frame received from overlay / remote.
\t\tt.recordRxAt(srcIP, pktLen, srcMAC, nowSec)
\t\tt.recordRxAt(dstIP, pktLen, dstMAC, nowSec)
\t}
''')

one(
'''\t\titem.mu.RLock()
\t\tmacAddr := item.mac
\t\titem.mu.RUnlock()
''',
'''\t\tmacAddr := item.macString()
''')

p.write_text(s)
