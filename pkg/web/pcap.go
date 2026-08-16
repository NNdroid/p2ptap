package web

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"p2ptap/pkg/packet"
)

// CaptureDir is the direction of a captured Ethernet frame relative to this node.
type CaptureDir string

const (
	// DirTx means the frame was injected by the local OS into the TAP device
	// (i.e. leaving this node toward the tunnel / peers).
	DirTx CaptureDir = "tx"
	// DirRx means the frame was received from a peer and written out to the
	// local TAP device (i.e. arriving at this node from the tunnel).
	DirRx CaptureDir = "rx"
)

// maxPcapPageSize caps how many frames a single /api/pcap/packets response may
// return. Every frame embeds a base64 copy of the full payload, so an
// unbounded page size would let one request pull tens of megabytes.
const maxPcapPageSize = 2000

// CapturedFrame is a single raw TAP/Ethernet frame captured by the pcap subsystem.
type CapturedFrame struct {
	Seq       uint64     `json:"seq"`               // monotonic capture sequence number
	Timestamp time.Time  `json:"ts"`                // capture time
	Dir       CaptureDir `json:"dir"`               // tx / rx
	Len       int        `json:"len"`               // total frame length in bytes
	SrcMAC    string     `json:"src_mac"`           // aa:bb:cc:dd:ee:ff
	DstMAC    string     `json:"dst_mac"`           // aa:bb:cc:dd:ee:ff
	EtherType string     `json:"ether_type"`        // hex, e.g. 0x0800
	Protocol  string     `json:"protocol"`          // human readable: ARP/IPv4/IPv6/ICMP/TCP/UDP/...
	VlanID    int        `json:"vlan_id,omitempty"` // 802.1Q VLAN id (0 = none)
	SrcIP     string     `json:"src_ip,omitempty"`
	DstIP     string     `json:"dst_ip,omitempty"`
	L4Proto   string     `json:"l4_proto,omitempty"`  // TCP / UDP / ICMP / ...
	SrcPort   int        `json:"src_port,omitempty"`  // L4 source port
	DstPort   int        `json:"dst_port,omitempty"`  // L4 destination port
	TTL       int        `json:"ttl,omitempty"`       // IP TTL / hop limit
	TCPFlags  string     `json:"tcp_flags,omitempty"` // e.g. "SYN", "SYN,ACK", "FIN,ACK"
	TCPSeq    uint32     `json:"tcp_seq,omitempty"`   // TCP sequence number
	TCPWin    int        `json:"tcp_win,omitempty"`   // TCP window size
	DNSQuery  string     `json:"dns_q,omitempty"`     // DNS query name (if this is a DNS packet)
	SNI       string     `json:"sni,omitempty"`       // TLS SNI server name (from ClientHello)
	ARPOP     string     `json:"arp_op,omitempty"`    // ARP: request / reply
	ARPSrcMAC string     `json:"arp_smac,omitempty"`  // ARP sender MAC
	ARPDstMAC string     `json:"arp_dmac,omitempty"`  // ARP target MAC
	Info      string     `json:"info,omitempty"`      // one-line protocol summary
	FromPeer  string     `json:"from_peer,omitempty"` // node that originated this frame (peer short ID, or "self"/"broadcast")
	ToPeer    string     `json:"to_peer,omitempty"`   // node this frame is destined for (peer short ID, or "self"/"broadcast")
	Hex       string     `json:"hex"`                 // first 64 bytes as hex (display)
	RawB64    string     `json:"raw,omitempty"`       // full frame base64 (for reload / deep inspection)
}

// PeerResolver maps an Ethernet MAC address to a human-readable node label
// (e.g. a short peer ID). It is supplied by the node layer to enrich captured
// frames with "from peer" / "to peer" information. Return "" if unknown.
type PeerResolver func(mac net.HardwareAddr) string

// PcapEvent is one delivery to a live subscriber. Exactly one of Frame /
// State / Cleared is non-nil per event. Frame is a value-type copy of the
// CapturedFrame (the underlying string buffers are immutable, so shallow is
// safe); State is a copy of the capture status; Cleared marks a Clear() call.
type PcapEvent struct {
	Frame   *CapturedFrame `json:"frame,omitempty"`
	State   *CaptureState  `json:"state,omitempty"`
	Cleared bool           `json:"cleared,omitempty"`
}

// PcapSubscriber is a single live-stream consumer registered with
// PacketCapture. Frames are delivered as PcapEvent values on Ch using a
// non-blocking send — when the channel buffer fills, the frame is dropped and
// the subscriber's Dropped counter is incremented. Callers should poll
// Dropped if they need to surface congestion.
type PcapSubscriber struct {
	Ch      chan PcapEvent
	Dropped atomic.Uint64
}

// PacketCapture is a lock-protected ring buffer of captured raw TAP frames.
// It is safe for concurrent use from the datapath (Add) and the HTTP API.
type PacketCapture struct {
	mu        sync.Mutex
	running   atomic.Bool
	seq       uint64
	cap       int // ring capacity
	buf       []CapturedFrame
	startTime time.Time
	filePath  string // where to persist captured frames (empty = disabled)
	lastSave  time.Time
	saveEvery time.Duration // throttle disk writes
	maxHex    int           // bytes rendered to Hex for display
	peerRes   PeerResolver  // resolves MAC -> node label (set by node layer)

	// subMu guards subs. We hold it only briefly to snapshot the current set
	// of subscribers before a non-blocking fan-out, so the datapath (which
	// calls AddWithPeers under p.mu) never blocks on a slow WebSocket peer.
	subMu sync.Mutex
	subs  map[*PcapSubscriber]struct{}
}

// NewPacketCapture builds a capture buffer. If filePath is non-empty, captured
// frames are persisted there (and reloaded on Load) so they survive restarts.
func NewPacketCapture(capacity int, filePath string) *PacketCapture {
	if capacity <= 0 {
		capacity = 20000
	}
	return &PacketCapture{
		cap:       capacity,
		buf:       make([]CapturedFrame, 0, capacity),
		filePath:  filePath,
		saveEvery: 2 * time.Second,
		maxHex:    64,
	}
}

// SetPersistFile updates the on-disk path used for load/save.
func (p *PacketCapture) SetPersistFile(path string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.filePath = path
}

// SetPeerResolver installs a MAC -> node-label resolver used to populate the
// FromPeer / ToPeer fields of captured frames.
func (p *PacketCapture) SetPeerResolver(r PeerResolver) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.peerRes = r
}

// Running reports whether capture is currently active.
func (p *PacketCapture) Running() bool {
	return p.running.Load()
}

// Start begins capturing (idempotent). Returns true if it actually (re)started.
func (p *PacketCapture) Start() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running.Load() {
		return false
	}
	p.running.Store(true)
	p.startTime = time.Now()
	return true
}

// Stop pauses capturing (keeps the buffered frames). Returns true if it changed.
func (p *PacketCapture) Stop() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running.Load() {
		return false
	}
	p.running.Store(false)
	p.saveLocked()
	return true
}

// Toggle flips the running state and returns the new state.
func (p *PacketCapture) Toggle() bool {
	if p.Running() {
		p.Stop()
	} else {
		p.Start()
	}
	return p.Running()
}

// Clear empties the buffer (but keeps the running state).
func (p *PacketCapture) Clear() {
	p.mu.Lock()
	p.buf = p.buf[:0]
	p.saveLocked()
	p.mu.Unlock()
	// Notify live subscribers AFTER releasing p.mu so a slow consumer cannot
	// stall the capture hot path.
	p.broadcast(PcapEvent{Cleared: true})
}

// Add captures one frame if running and the frame is a valid Ethernet frame.
// It is intentionally cheap (single alloc + lock) for the datapath.
func (p *PacketCapture) Add(dir CaptureDir, frame []byte) {
	p.AddWithPeers(dir, frame, "", "")
}

// AddWithPeers captures one frame and enriches it with explicit fromPeer and toPeer labels
// determined at the final dispatch or reception boundary.
func (p *PacketCapture) AddWithPeers(dir CaptureDir, frame []byte, fromPeer, toPeer string) {
	if !p.running.Load() {
		return
	}
	p.mu.Lock()
	if !p.running.Load() || len(frame) < 14 {
		p.mu.Unlock()
		return
	}
	cf := parseFrame(p.seq, dir, frame, p.maxHex, p.peerRes)
	if fromPeer != "" {
		cf.FromPeer = fromPeer
	}
	if toPeer != "" {
		cf.ToPeer = toPeer
	}
	p.seq++
	if len(p.buf) >= p.cap {
		// ring overwrite: drop oldest
		copy(p.buf[0:], p.buf[1:])
		p.buf[len(p.buf)-1] = cf
	} else {
		p.buf = append(p.buf, cf)
	}
	// Best-effort throttled persistence.
	if p.filePath != "" && time.Since(p.lastSave) > p.saveEvery {
		p.saveLocked()
	}
	p.mu.Unlock()

	// Fan out to live-stream subscribers. We copy cf into a fresh PcapEvent
	// so the consumer cannot mutate the buffer entry, and we drop on full
	// channel rather than ever block the datapath.
	cfCopy := cf
	p.broadcast(PcapEvent{Frame: &cfCopy})
}

// Snapshot returns frames with Seq > since (for incremental polling). When
// since == 0 it returns all buffered frames. A limit caps the response size.
func (p *PacketCapture) Snapshot(since uint64, limit int) []CapturedFrame {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]CapturedFrame, 0)
	for i := range p.buf {
		if p.buf[i].Seq > since {
			out = append(out, p.buf[i])
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out
}

// Subscribe registers a new live-stream consumer. The returned subscriber
// receives an unbounded series of events on its channel until Unsubscribe is
// called or the channel buffer fills — in which case frames are dropped and
// Dropped counts how many.
func (p *PacketCapture) Subscribe(bufSize int) *PcapSubscriber {
	if bufSize <= 0 {
		bufSize = 256
	}
	s := &PcapSubscriber{Ch: make(chan PcapEvent, bufSize)}
	p.subMu.Lock()
	if p.subs == nil {
		p.subs = make(map[*PcapSubscriber]struct{})
	}
	p.subs[s] = struct{}{}
	p.subMu.Unlock()
	return s
}

// Unsubscribe removes a previously registered subscriber. Safe to call any
// number of times.
func (p *PacketCapture) Unsubscribe(s *PcapSubscriber) {
	if s == nil {
		return
	}
	p.subMu.Lock()
	delete(p.subs, s)
	p.subMu.Unlock()
}

// SubscriberCount reports how many live consumers are currently attached.
// Used by tests and diagnostics.
func (p *PacketCapture) SubscriberCount() int {
	p.subMu.Lock()
	defer p.subMu.Unlock()
	return len(p.subs)
}

// broadcast fans a single event out to every registered subscriber. Holds
// subMu only briefly to snapshot the subscriber set; sends are non-blocking,
// so even a maliciously slow peer can never delay the data plane.
func (p *PacketCapture) broadcast(ev PcapEvent) {
	p.subMu.Lock()
	if len(p.subs) == 0 {
		p.subMu.Unlock()
		return
	}
	list := make([]*PcapSubscriber, 0, len(p.subs))
	for s := range p.subs {
		list = append(list, s)
	}
	p.subMu.Unlock()
	for _, s := range list {
		select {
		case s.Ch <- ev:
		default:
			s.Dropped.Add(1)
		}
	}
}

// State describes the current capture status for the WebUI.
type CaptureState struct {
	Running   bool   `json:"running"`
	Count     int    `json:"count"`
	Capacity  int    `json:"capacity"`
	StartSeq  uint64 `json:"start_seq"`
	LastSeq   uint64 `json:"last_seq"`
	StartTime string `json:"start_time,omitempty"`
	PersistOn bool   `json:"persist_on"`
}

// State returns a snapshot of the capture status.
func (p *PacketCapture) State() CaptureState {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := CaptureState{
		Running:   p.running.Load(),
		Count:     len(p.buf),
		Capacity:  p.cap,
		PersistOn: p.filePath != "",
	}
	if len(p.buf) > 0 {
		st.StartSeq = p.buf[0].Seq
		st.LastSeq = p.buf[len(p.buf)-1].Seq
	}
	if !p.startTime.IsZero() {
		st.StartTime = p.startTime.Format(time.RFC3339)
	}
	return st
}

// Load reads previously persisted frames from disk into the buffer. Existing
// buffered frames are replaced. The capture state (running) is left unchanged.
func (p *PacketCapture) Load() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.filePath == "" {
		return 0, nil
	}
	data, err := os.ReadFile(p.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var loaded []CapturedFrame
	if err := json.Unmarshal(data, &loaded); err != nil {
		return 0, err
	}
	if len(loaded) > p.cap {
		loaded = loaded[len(loaded)-p.cap:]
	}
	p.buf = loaded
	// Resume the sequence counter past the loaded frames.
	for _, f := range loaded {
		if f.Seq >= p.seq {
			p.seq = f.Seq + 1
		}
	}
	return len(loaded), nil
}

// saveLocked persists the buffer to disk. Caller must hold p.mu.
func (p *PacketCapture) saveLocked() {
	if p.filePath == "" {
		return
	}
	p.lastSave = time.Now()
	data, err := json.Marshal(p.buf)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(p.filePath), 0o755)
	_ = os.WriteFile(p.filePath, data, 0o644)
}

// parseFrame extracts the displayable fields from a raw Ethernet frame.
func parseFrame(seq uint64, dir CaptureDir, frame []byte, maxHex int, resolver PeerResolver) CapturedFrame {
	cf := CapturedFrame{
		Seq:       seq,
		Timestamp: time.Now(),
		Dir:       dir,
		Len:       len(frame),
	}
	if len(frame) >= 14 {
		srcMAC := net.HardwareAddr(frame[6:12])
		dstMAC := net.HardwareAddr(frame[0:6])
		cf.SrcMAC = srcMAC.String()
		cf.DstMAC = dstMAC.String()
		if resolver != nil {
			cf.FromPeer = resolver(srcMAC)
			cf.ToPeer = resolver(dstMAC)
		}
		// Offset past Ethernet header; handle optional 802.1Q VLAN tag.
		off := 14
		ethType := packet.EtherType(frame)
		if ethType == packet.EtherTypeVLAN && len(frame) >= off+4 {
			// 802.1Q: TPID(2) + PCP(3b)/DEI(1b)/VID(12b) + real EtherType(2)
			tci := binary.BigEndian.Uint16(frame[14:16])
			cf.VlanID = int(tci & 0x0fff)
			ethType = binary.BigEndian.Uint16(frame[16:18])
			off = 18
		}
		cf.EtherType = "0x" + hex16(ethType)
		cf.Protocol = ethTypeName(ethType)
		switch ethType {
		case packet.EtherTypeARP: // ARP
			if len(frame) >= off+28 {
				op := binary.BigEndian.Uint16(frame[off+6 : off+8])
				switch op {
				case 1:
					cf.ARPOP = "request (who-has)"
				case 2:
					cf.ARPOP = "reply (is-at)"
				case 3:
					cf.ARPOP = "RARP request"
				case 4:
					cf.ARPOP = "RARP reply"
				default:
					cf.ARPOP = "op-" + strconv.Itoa(int(op))
				}
				cf.ARPSrcMAC = net.HardwareAddr(frame[off+8 : off+14]).String()
				cf.ARPDstMAC = net.HardwareAddr(frame[off+18 : off+24]).String()
				cf.SrcIP = net.IP(frame[off+14 : off+18]).String()
				cf.DstIP = net.IP(frame[off+24 : off+28]).String()
				cf.Info = "ARP " + cf.ARPOP + " " + cf.SrcIP + " -> " + cf.DstIP
			}
		case packet.EtherTypeIPv4: // IPv4
			if len(frame) >= off+20 {
				verIhl := frame[off]
				ihl := int(verIhl&0x0f) * 4
				proto := frame[off+9]
				cf.TTL = int(frame[off+8])
				cf.SrcIP = net.IP(frame[off+12 : off+16]).String()
				cf.DstIP = net.IP(frame[off+16 : off+20]).String()
				cf.L4Proto = ipProtoName(proto)
				// A valid IPv4 header is 20..60 bytes; reject bogus IHL so the
				// L4 offset below can never point outside the frame.
				l4 := off + ihl
				validIHL := ihl >= 20 && l4 <= len(frame)
				if proto == 1 || proto == 58 { // ICMP / ICMPv6
					cf.Info = cf.L4Proto + " " + cf.SrcIP + " -> " + cf.DstIP
				} else if validIHL && (proto == 6 || proto == 17) && len(frame) >= l4+4 { // TCP / UDP
					cf.SrcPort = int(binary.BigEndian.Uint16(frame[l4 : l4+2]))
					cf.DstPort = int(binary.BigEndian.Uint16(frame[l4+2 : l4+4]))
					if proto == 6 { // TCP
						if len(frame) >= l4+20 { // full fixed TCP header
							cf.TCPFlags = tcpFlagsString(frame[l4+13])
							cf.TCPSeq = binary.BigEndian.Uint32(frame[l4+4 : l4+8])
							cf.TCPWin = int(binary.BigEndian.Uint16(frame[l4+14 : l4+16]))
							dataOff := int(frame[l4+12]>>4) * 4
							if dataOff < 20 {
								dataOff = 20
							}
							appStart := l4 + dataOff
							// Detect a TLS ClientHello: TCP PSH, common HTTPS ports,
							// record type 22 (handshake) + handshake type 1 (client_hello).
							if frame[l4+13]&0x08 != 0 && // PSH
								(cf.SrcPort == 443 || cf.SrcPort == 8443 || cf.DstPort == 443 || cf.DstPort == 8443) &&
								appStart >= 0 && len(frame) >= appStart+6 &&
								frame[appStart] == 0x16 && frame[appStart+5] == 0x01 {
								if sni, ok := parseTLSSNI(frame[appStart:]); ok {
									cf.SNI = sni
									cf.Info = "TLS " + cf.SrcIP + ":" + strconv.Itoa(cf.SrcPort) +
										" -> " + cf.DstIP + ":" + strconv.Itoa(cf.DstPort) +
										" SNI:" + sni
								}
							}
						}
						if cf.SNI == "" {
							cf.Info = "TCP " + cf.SrcIP + ":" + strconv.Itoa(cf.SrcPort) +
								" -> " + cf.DstIP + ":" + strconv.Itoa(cf.DstPort) +
								" [" + cf.TCPFlags + "]"
						}
					} else { // UDP
						cf.Info = "UDP " + cf.SrcIP + ":" + strconv.Itoa(cf.SrcPort) +
							" -> " + cf.DstIP + ":" + strconv.Itoa(cf.DstPort)
						if (cf.SrcPort == 53 || cf.DstPort == 53) && len(frame) >= l4+12 {
							if q, ok := parseDNSQuery(frame[l4:]); ok {
								cf.DNSQuery = q
								cf.Info += " DNS?" + q
							}
						}
					}
				} else {
					cf.Info = cf.L4Proto + " " + cf.SrcIP + " -> " + cf.DstIP
				}
			}
		case packet.EtherTypeIPv6: // IPv6
			if len(frame) >= off+40 {
				proto := frame[off+6]
				cf.TTL = int(frame[off+7])
				cf.SrcIP = net.IP(frame[off+8 : off+24]).String()
				cf.DstIP = net.IP(frame[off+24 : off+40]).String()
				cf.L4Proto = ipProtoName(proto)
				l4 := off + 40
				if proto == 6 || proto == 17 { // TCP / UDP
					if len(frame) >= l4+4 {
						cf.SrcPort = int(binary.BigEndian.Uint16(frame[l4 : l4+2]))
						cf.DstPort = int(binary.BigEndian.Uint16(frame[l4+2 : l4+4]))
					}
					if proto == 6 { // TCP
						if len(frame) >= l4+20 { // full fixed TCP header
							cf.TCPFlags = tcpFlagsString(frame[l4+13])
							cf.TCPSeq = binary.BigEndian.Uint32(frame[l4+4 : l4+8])
							cf.TCPWin = int(binary.BigEndian.Uint16(frame[l4+14 : l4+16]))
							dataOff := int(frame[l4+12]>>4) * 4
							if dataOff < 20 {
								dataOff = 20
							}
							appStart := l4 + dataOff
							if frame[l4+13]&0x08 != 0 &&
								(cf.SrcPort == 443 || cf.SrcPort == 8443 || cf.DstPort == 443 || cf.DstPort == 8443) &&
								appStart >= 0 && len(frame) >= appStart+6 &&
								frame[appStart] == 0x16 && frame[appStart+5] == 0x01 {
								if sni, ok := parseTLSSNI(frame[appStart:]); ok {
									cf.SNI = sni
									cf.Info = "TLS " + cf.SrcIP + ":" + strconv.Itoa(cf.SrcPort) +
										" -> " + cf.DstIP + ":" + strconv.Itoa(cf.DstPort) +
										" SNI:" + sni
								}
							}
						}
						if cf.SNI == "" {
							cf.Info = "TCP " + cf.SrcIP + ":" + strconv.Itoa(cf.SrcPort) +
								" -> " + cf.DstIP + ":" + strconv.Itoa(cf.DstPort) + " [" + cf.TCPFlags + "]"
						}
					} else { // UDP
						cf.Info = "UDP " + cf.SrcIP + ":" + strconv.Itoa(cf.SrcPort) +
							" -> " + cf.DstIP + ":" + strconv.Itoa(cf.DstPort)
						if (cf.SrcPort == 53 || cf.DstPort == 53) && len(frame) >= l4+12 {
							if q, ok := parseDNSQuery(frame[l4:]); ok {
								cf.DNSQuery = q
								cf.Info += " DNS?" + q
							}
						}
					}
				} else if proto == 58 { // ICMPv6
					cf.Info = "ICMPv6 " + cf.SrcIP + " -> " + cf.DstIP
				} else {
					cf.Info = cf.L4Proto + " " + cf.SrcIP + " -> " + cf.DstIP
				}
			}
		}
		if cf.Info == "" {
			cf.Info = cf.Protocol + " " + cf.SrcIP + " -> " + cf.DstIP
		}
	}
	if maxHex > len(frame) {
		maxHex = len(frame)
	}
	cf.Hex = hexDump(frame[:maxHex])
	cf.RawB64 = base64.StdEncoding.EncodeToString(frame)
	return cf
}

func ipProtoName(p byte) string {
	switch p {
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 89:
		return "OSPF"
	default:
		return "proto-" + strconv.Itoa(int(p))
	}
}

// tcpFlagsString renders the TCP control bits from the flags byte.
func tcpFlagsString(b byte) string {
	var parts []string
	if b&0x01 != 0 {
		parts = append(parts, "FIN")
	}
	if b&0x02 != 0 {
		parts = append(parts, "SYN")
	}
	if b&0x04 != 0 {
		parts = append(parts, "RST")
	}
	if b&0x08 != 0 {
		parts = append(parts, "PSH")
	}
	if b&0x10 != 0 {
		parts = append(parts, "ACK")
	}
	if b&0x20 != 0 {
		parts = append(parts, "URG")
	}
	if b&0x40 != 0 {
		parts = append(parts, "ECE")
	}
	if b&0x80 != 0 {
		parts = append(parts, "CWR")
	}
	if len(parts) == 0 {
		return "none"
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += "," + p
	}
	return out
}

// parseDNSQuery extracts the first query name from a DNS message (questions section).
// Supports only uncompressed names (the common case for queries).
func parseDNSQuery(b []byte) (string, bool) {
	// b must be the UDP payload starting at the DNS header.
	if len(b) < 12 {
		return "", false
	}
	qdcount := int(binary.BigEndian.Uint16(b[4:6]))
	if qdcount < 1 {
		return "", false
	}
	// Walk the question name starting at offset 12.
	pos := 12
	var name []byte
	for {
		if pos >= len(b) {
			return "", false
		}
		l := int(b[pos])
		if l == 0 {
			break
		}
		// Stop if a compression pointer (0xC0) is encountered (unsupported for simplicity).
		if l&0xc0 != 0 {
			return "", false
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		if pos+1+l > len(b) {
			return "", false
		}
		name = append(name, b[pos+1:pos+1+l]...)
		pos += 1 + l
	}
	if len(name) == 0 {
		return "", false
	}
	return string(name), true
}

// parseTLSSNI extracts the SNI server name from a TLS ClientHello record.
// b must start at the TLS record header (record type 0x16 already validated by caller).
func parseTLSSNI(b []byte) (string, bool) {
	// TLS record: type(1) version(2) length(2) -> handshake starts at 5
	if len(b) < 5 {
		return "", false
	}
	hsOff := 5
	if len(b) < hsOff+4 {
		return "", false
	}
	// handshake: type(1) length(3) version(2) ...
	if b[hsOff] != 0x01 { // client_hello
		return "", false
	}
	// skip handshake header(4) + client_version(2) = 6 -> session_id
	pos := hsOff + 4 + 2
	if len(b) < pos+1 {
		return "", false
	}
	sidLen := int(b[pos])
	pos += 1 + sidLen
	if len(b) < pos+2 {
		return "", false
	}
	cipherLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2 + cipherLen
	if len(b) < pos+2 {
		return "", false
	}
	compLen := int(b[pos])
	pos += 1 + compLen
	if len(b) < pos+2 {
		return "", false
	}
	extTotal := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	end := pos + extTotal
	if end > len(b) {
		end = len(b)
	}
	for pos+4 <= end {
		extType := int(binary.BigEndian.Uint16(b[pos : pos+2]))
		extLen := int(binary.BigEndian.Uint16(b[pos+2 : pos+4]))
		pos += 4
		if extType == 0x00 { // server_name
			if pos+2 > end {
				return "", false
			}
			snStart := pos + 2 // skip server_name_list length(2)
			if snStart+3 > end {
				return "", false
			}
			nameType := b[snStart]
			nameLen := int(binary.BigEndian.Uint16(b[snStart+1 : snStart+3]))
			nameStart := snStart + 3
			if nameType == 0 && nameStart+nameLen <= end {
				return string(b[nameStart : nameStart+nameLen]), true
			}
			return "", false
		}
		pos += extLen
	}
	return "", false
}

func ethTypeName(t uint16) string {
	switch t {
	case packet.EtherTypeARP:
		return "ARP"
	case packet.EtherTypeIPv4:
		return "IPv4"
	case packet.EtherTypeIPv6:
		return "IPv6"
	case packet.EtherTypeVLAN:
		return "VLAN"
	case 0x8847:
		return "MPLS"
	case 0x8863, 0x8864:
		return "PPPoE"
	default:
		return "0x" + hex16(t)
	}
}

func hex16(v uint16) string {
	const h = "0123456789abcdef"
	return string([]byte{h[v>>12], h[(v>>8)&0xf], h[(v>>4)&0xf], h[v&0xf]})
}

func hexDump(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, h[c>>4], h[c&0xf])
	}
	return string(out)
}
