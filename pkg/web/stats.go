package web

import (
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"p2ptap/pkg/config"
	"p2ptap/pkg/observer"
	"p2ptap/pkg/packet"
	"p2ptap/pkg/version"
)

type StatsCollector struct {
	mu                sync.RWMutex
	NodeName          string
	PeerID            string
	TapIP             string
	TapIPv6           string
	TransportStrategy string
	ListenAddrs       []string
	NATStatus         string
	ExitNode          ExitNodeInfoDTO
	Gateway           GatewayController
	Security          SecurityStatusDTO
	// resolvePeerLabel maps a peer MAC to a human-readable label; installed by
	// the node via SetPeerResolver so web handlers can annotate captured frames
	// and ARP/NDP tables with node names.
	resolvePeerLabel func(mac net.HardwareAddr) string
	StartTime        time.Time

	// ResolvePeerAddrs resolves a peer ID to its known physical IPv4/IPv6 endpoints.
	// Used by SetExitNode to install bypass host routes so P2P traffic is not routed into the TAP.
	ResolvePeerAddrs func(peerIDStr string) []string
	// OnExitNodeChanged is called after ExitNode config is hot-reloaded so NFTManager
	// can re-apply or tear down NAT rules.
	OnExitNodeChanged func()
	// OnObfuscationChanged is called after Obfuscation config is hot-reloaded
	// so FramePacker can update modes/disguise parameters without restart.
	OnObfuscationChanged func()
	// OnSubnetsChanged is called after AdvertisedSubnets/AcceptAdvertisedSubnets/
	// AllowedSubnetPeers config is hot-reloaded, so the node can re-broadcast its
	// updated LAN subnet advertisements over the peek-map channel.
	OnSubnetsChanged func()
	// OnConfigReload delivers the FULL new config on WebUI save. The node
	// publishes it atomically (SetConfig) then applies runtime side-effects, so
	// the data plane observes the freshly published snapshot.
	OnConfigReload func(*config.Config)
	// TestPeerMultiaddrs probes each known multiaddr of a peer for reachability
	// and measures per-address RTT.  Returns results sorted by RTT (fastest first).
	TestPeerMultiaddrs func(peerIDStr string) []MultiaddrTestResultEntry
	// DiagnoseLink performs a deep transport-layer link check on a single
	// multiaddr (validity → DNS → TCP/QUIC → libp2p transport → Noise/TLS →
	// peer-id match → connection).  Returns nil if not wired.
	DiagnoseLink func(multiaddrStr string) *LinkDiagnosis
	// ProbePeerConnectivity performs a real libp2p stream-level connectivity check
	// to the given peer, returning measured RTT and whether the stream succeeded.
	ProbePeerConnectivity func(peerIDStr string) *PeerConnectivityResult
	// ProbePeerEcho performs a real end-to-end P2P echo test over a dedicated stream,
	// sending random payload and measuring precise RTT and payload byte integrity.
	ProbePeerEcho      func(peerIDStr string) *PeerEchoResultDTO
	ProbePeerEchoAddr  func(peerIDStr string, targetAddrStr string) *PeerEchoResultDTO
	ProbePeerSpeedTest func(peerIDStr string) *SpeedTestResultDTO
	// ProbeTapForward performs an end-to-end TAP data-path forwarding test: a full
	// Ethernet frame (ICMP echo request) is injected into the overlay toward the
	// peer's TAP IP and the peer echoes back an ICMP echo reply frame. This
	// exercises the TAP -> overlay -> peer -> reply path a real ping uses.
	ProbeTapForward func(peerIDStr string) *TapProbeResultDTO
	ForceSeqSync    func(peerIDStr string) (int, error)
	AddStaticPeer   func(multiaddrStr string) error
	OnSubnetToggle  func(cidr string, enable bool) error
	// GetACLStatsFn is called on every /api/stats read. The node wires this
	// to Node.GetACLStats so the WebUI sees live firewall counters.
	GetACLStatsFn func() observer.ACLStatsDTO

	// TAPState holds a snapshot of the TAP interface configuration, populated
	// by the node at startup and refreshed on change.
	TAPState *TAPStateDTO

	ActivePeers      []PeerInfoDTO
	MACTable         []MACInfoDTO
	ARPTable         []ARPInfoDTO
	IPTable          []IPInfoDTO
	RoutesTable      []RouteInfoDTO
	SubnetRoutes     []SubnetRouteDTO
	PeerMetas        []observer.PeerMetaDTO
	MeshMatrix       []MeshMatrixCellDTO
	ProtocolChannels []ProtocolChannelDTO
	ActiveStreams    []ProtocolStreamDTO
	// DuplicateIPConflicts holds the latest duplicate-IP / overlapping-subnet
	// conflict set pushed by the node for dashboard display.
	DuplicateIPConflicts []observer.DuplicateIPConflictDTO
	speedHistory         []SpeedSampleDTO

	// peerSeqState holds per-peer sequence tracking, keyed by peer.ID string.
	// It is a sync.Map so the high-frequency datapath writers (RecordTxSeq /
	// RecordRxSeq / RecordPeerDedup) never contend on a single mutex with the
	// GetResponse read path: each write is a lock-free Store/Add on its own
	// *PeerSeqState, and GetResponse does a lock-free Load per active peer.
	peerSeqState sync.Map

	packetsSent   uint64
	packetsRecv   uint64
	bytesSent     uint64
	bytesRecv     uint64
	dedupCount    uint64
	DispatchDrops uint64 // set by Node for dispatch pool overflow

	ipv4Pkts  uint64
	ipv6Pkts  uint64
	arpPkts   uint64
	ndpPkts   uint64
	icmpPkts  uint64
	udpPkts   uint64
	tcpPkts   uint64
	otherPkts uint64

	// Per-packet-type directional counters (reset per sample window for the
	// PPS chart). These are swapped to 0 inside updateStats, so they must NOT be
	// read for cumulative totals — use the cum* fields below for that.
	txUnicastPkts   uint64
	txMulticastPkts uint64
	txBroadcastPkts uint64
	rxUnicastPkts   uint64
	rxMulticastPkts uint64
	rxBroadcastPkts uint64

	// Cumulative (never-reset) directional counters. The dashboard cards show
	// lifetime totals, which must survive the per-window reset above.
	cumTxUnicastPkts   uint64
	cumTxMulticastPkts uint64
	cumTxBroadcastPkts uint64
	cumRxUnicastPkts   uint64
	cumRxMulticastPkts uint64
	cumRxBroadcastPkts uint64

	// gatewayPkts counts every frame tunnelled through an Exit Node (client→
	// server on the client side, server→client on the server side). Single
	// atomic counter keeps the datapath lock-free and cheap.
	gatewayPkts uint64

	lastSpeedCalc time.Time
	lastTxBytes   uint64
	lastRxBytes   uint64
	lastTxPkts    uint64
	lastRxPkts    uint64
	txSpeed       uint64
	rxSpeed       uint64
	txPPS         uint64
	rxPPS         uint64

	// tapSelfTest, if set by the node, runs a non-destructive read/write
	// sanity check on the underlying TAP device. Stored as a func returning a
	// plain map to avoid an import cycle between the web and tap packages.
	tapSelfTest func() map[string]interface{}

	// Pcap is the raw-TAP-packet capture buffer surfaced in the WebUI.
	Pcap *PacketCapture
}

func (s *StatsCollector) SetNodeInfo(nodeName, peerID, tapIP, tapIPv6, strategy string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.NodeName = nodeName
	s.PeerID = peerID
	s.TapIP = tapIP
	s.TapIPv6 = tapIPv6
	s.TransportStrategy = strategy
}

// SetTAPSelfTest registers a TAP read/write self-test function provided by the node.
func (s *StatsCollector) SetTAPSelfTest(fn func() map[string]interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tapSelfTest = fn
}

// ——— observer.Collector interface implementation ————————————————
// These setters form the single seam through which the node pushes runtime
// state into the WebUI. The node depends only on the observer.Collector
// interface, never on the concrete StatsCollector.

// SetSecurity pushes the encryption/obfuscation status.
func (s *StatsCollector) SetSecurity(pskStatus, obfuscation, keyFingerprint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Security.PSKStatus = pskStatus
	s.Security.Obfuscation = obfuscation
	s.Security.KeyFingerprint = keyFingerprint
}

// SetPeerEncryption pushes the per-peer negotiated encryption snapshot so the
// WebUI can show, for every connected client, which algorithm is in use (or
// "none" if encryption was not negotiated).
func (s *StatsCollector) SetPeerEncryption(enc []observer.PeerObfInfoDTO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if enc == nil {
		enc = []observer.PeerObfInfoDTO{}
	}
	s.Security.Encryption = enc
}

// SetTAPState pushes a snapshot of the TAP interface configuration.
func (s *StatsCollector) SetTAPState(state *TAPStateDTO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TAPState = state
}

// SetPeerResolver registers a MAC→peer-label resolver used by web handlers.
func (s *StatsCollector) SetPeerResolver(fn func(mac net.HardwareAddr) string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resolvePeerLabel = fn
}

// SetCallbacks installs the wiring callbacks the node provides so web handlers
// can resolve/add peers and react to configuration hot-reloads.
func (s *StatsCollector) SetCallbacks(cfg observer.CollectorConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ResolvePeerAddrs = cfg.ResolvePeerAddrs
	s.OnExitNodeChanged = cfg.OnExitNodeChanged
	s.OnObfuscationChanged = cfg.OnObfuscationChanged
	s.OnSubnetsChanged = cfg.OnSubnetsChanged
	s.OnConfigReload = cfg.OnConfigReload
	s.GetACLStatsFn = cfg.GetACLStats
	s.TestPeerMultiaddrs = func(peerIDStr string) []MultiaddrTestResultEntry {
		if cfg.TestPeerMultiaddrs == nil {
			return nil
		}
		return cfg.TestPeerMultiaddrs(peerIDStr)
	}
	s.ProbePeerConnectivity = func(peerIDStr string) *PeerConnectivityResult {
		if cfg.ProbePeerConnectivity == nil {
			return nil
		}
		return cfg.ProbePeerConnectivity(peerIDStr)
	}
	s.ProbePeerEcho = func(peerIDStr string) *PeerEchoResultDTO {
		if cfg.ProbePeerEcho == nil {
			return nil
		}
		return cfg.ProbePeerEcho(peerIDStr)
	}
	s.ProbePeerEchoAddr = func(peerIDStr, targetAddrStr string) *PeerEchoResultDTO {
		if cfg.ProbePeerEchoAddr == nil {
			return nil
		}
		return cfg.ProbePeerEchoAddr(peerIDStr, targetAddrStr)
	}
	s.ProbePeerSpeedTest = func(peerIDStr string) *SpeedTestResultDTO {
		if cfg.ProbePeerSpeedTest == nil {
			return nil
		}
		return cfg.ProbePeerSpeedTest(peerIDStr)
	}
	s.ProbeTapForward = func(peerIDStr string) *TapProbeResultDTO {
		if cfg.ProbeTapForward == nil {
			return nil
		}
		return cfg.ProbeTapForward(peerIDStr)
	}
	s.ForceSeqSync = cfg.ForceSeqSync
	s.AddStaticPeer = cfg.AddStaticPeer
	s.DiagnoseLink = func(multiaddrStr string) *LinkDiagnosis {
		if cfg.DiagnoseLink == nil {
			return nil
		}
		return cfg.DiagnoseLink(multiaddrStr)
	}
	s.OnSubnetToggle = cfg.OnSubnetToggle
}

func (s *StatsCollector) UpdatePeers(peers []PeerInfoDTO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ActivePeers = peers
}

func (s *StatsCollector) UpdateMACTable(mac []MACInfoDTO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.MACTable = mac
}

func (s *StatsCollector) UpdateARPTable(arp []ARPInfoDTO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ARPTable = arp
}

func (s *StatsCollector) UpdateIPTable(ip []IPInfoDTO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.IPTable = ip
}

func (s *StatsCollector) UpdateRoutes(routes []RouteInfoDTO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RoutesTable = routes
}

func (s *StatsCollector) UpdateSubnetRoutes(routes []SubnetRouteDTO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SubnetRoutes = routes
}

func (s *StatsCollector) UpdateDuplicateIPConflicts(conflicts []observer.DuplicateIPConflictDTO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DuplicateIPConflicts = conflicts
}

func (s *StatsCollector) UpdatePeerMetas(metas []observer.PeerMetaDTO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PeerMetas = metas
}

func (s *StatsCollector) UpdateMeshMatrix(matrix []MeshMatrixCellDTO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.MeshMatrix = matrix
}

func (s *StatsCollector) UpdateProtocolChannels(channels []ProtocolChannelDTO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ProtocolChannels = channels
}

func (s *StatsCollector) UpdateActiveStreams(streams []ProtocolStreamDTO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ActiveStreams = streams
}

func (s *StatsCollector) UpdateListenAddrs(addrs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ListenAddrs = addrs
}

func (s *StatsCollector) UpdateNATStatus(status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.NATStatus = status
}

func (s *StatsCollector) UpdateExitNode(exit ExitNodeInfoDTO) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ExitNode = exit
}

// SetDispatchDrops records the number of frames dropped at dispatch.
func (s *StatsCollector) SetDispatchDrops(drops uint64) {
	atomic.StoreUint64(&s.DispatchDrops, drops)
}

// GetACLStats returns the live ACL firewall counters via the callback wired
// in CollectorConfig. Returns a zero-valued DTO when the node has not
// provided one (engine disabled or test mode).
func (s *StatsCollector) GetACLStats() observer.ACLStatsDTO {
	s.mu.RLock()
	fn := s.GetACLStatsFn
	s.mu.RUnlock()
	if fn == nil {
		return observer.ACLStatsDTO{}
	}
	return fn()
}

// PeekPeerID resolves a peer identifier (peer ID / TAP IP / TAP IPv6 / node name)
// to a connected peer ID. It lets the node's probe helpers query the WebUI peer
// table without reaching into the concrete collector fields.
func (s *StatsCollector) PeekPeerID(peerIDStr string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.ActivePeers {
		if p.PeerID == peerIDStr || p.TapIP == peerIDStr || p.TapIPv6 == peerIDStr || strings.EqualFold(p.NodeName, peerIDStr) {
			return p.PeerID, true
		}
	}
	return "", false
}

func NewStatsCollector() *StatsCollector {
	return &StatsCollector{
		ActivePeers:          make([]PeerInfoDTO, 0),
		MACTable:             make([]MACInfoDTO, 0),
		Pcap:                 NewPacketCapture(20000, ""),
		RoutesTable:          make([]RouteInfoDTO, 0),
		DuplicateIPConflicts: make([]observer.DuplicateIPConflictDTO, 0),
		SubnetRoutes:         make([]SubnetRouteDTO, 0),
		MeshMatrix:           make([]MeshMatrixCellDTO, 0),
		ProtocolChannels:     make([]ProtocolChannelDTO, 0),
		ActiveStreams:        make([]ProtocolStreamDTO, 0),
		speedHistory:         make([]SpeedSampleDTO, 0),
		ListenAddrs:          make([]string, 0),
		StartTime:            time.Now(),
		lastSpeedCalc:        time.Now(),
	}
}

func (s *StatsCollector) RecordSent(bytes int) {
	atomic.AddUint64(&s.packetsSent, 1)
	atomic.AddUint64(&s.bytesSent, uint64(bytes))
}

func (s *StatsCollector) RecordRecv(bytes int) {
	atomic.AddUint64(&s.packetsRecv, 1)
	atomic.AddUint64(&s.bytesRecv, uint64(bytes))
}

// RecordPacketDir classifies an Ethernet frame as unicast, multicast, or broadcast
// and increments the appropriate directional counter.
func (s *StatsCollector) RecordPacketDir(payload []byte, isTx bool) {
	if len(payload) < 14 {
		return
	}
	dstMAC := net.HardwareAddr(payload[0:6])
	if dstMAC[0]&1 == 0 {
		// Unicast: bit 0 of first byte is 0
		if isTx {
			atomic.AddUint64(&s.txUnicastPkts, 1)
			atomic.AddUint64(&s.cumTxUnicastPkts, 1)
		} else {
			atomic.AddUint64(&s.rxUnicastPkts, 1)
			atomic.AddUint64(&s.cumRxUnicastPkts, 1)
		}
	} else if dstMAC.String() == "ff:ff:ff:ff:ff:ff" {
		// Broadcast
		if isTx {
			atomic.AddUint64(&s.txBroadcastPkts, 1)
			atomic.AddUint64(&s.cumTxBroadcastPkts, 1)
		} else {
			atomic.AddUint64(&s.rxBroadcastPkts, 1)
			atomic.AddUint64(&s.cumRxBroadcastPkts, 1)
		}
	} else {
		// Multicast
		if isTx {
			atomic.AddUint64(&s.txMulticastPkts, 1)
			atomic.AddUint64(&s.cumTxMulticastPkts, 1)
		} else {
			atomic.AddUint64(&s.rxMulticastPkts, 1)
			atomic.AddUint64(&s.cumRxMulticastPkts, 1)
		}
	}
}

func (s *StatsCollector) RecordDedup() {
	atomic.AddUint64(&s.dedupCount, 1)
}

// RecordTxSeq records the latest sequence ID sent TO a peer. Cheap: a single
// atomic store; no map lookup on the hot Tx path.
func (s *StatsCollector) RecordTxSeq(peerID string, seq uint64) {
	if peerID == "" {
		return
	}
	atomic.StoreUint64(&s.getPeerSeq(peerID).TxSeq, seq)
}

// RecordRxSeq records the latest structured SeqID received FROM a peer, plus
// dedup-window diagnostics (max seq, replay drops, window re-anchors, and live
// window fill ratio). These let the UI surface window-skew blackholes and
// stale-replay drops at a glance.
func (s *StatsCollector) RecordRxSeq(peerID string, seq, winMax, replayDrops, windowResets uint64, winUtil float64) {
	if peerID == "" {
		return
	}
	st := s.getPeerSeq(peerID)
	atomic.StoreUint64(&st.RxSeq, seq)
	atomic.StoreUint64(&st.SeqWinMax, winMax)
	// Track the highest seq actually received (not from SyncFrom/re-anchor),
	// so the blackhole skew calculation is not skewed by handshake anchors.
	for {
		cur := atomic.LoadUint64(&st.RxSeqMax)
		if seq <= cur {
			break
		}
		if atomic.CompareAndSwapUint64(&st.RxSeqMax, cur, seq) {
			break
		}
	}
	atomic.StoreUint64(&st.ReplayDrops, replayDrops)
	atomic.StoreUint64(&st.WindowResets, windowResets)
	atomic.StoreUint64(&st.WinUtilScaled, uint64(winUtil*1000))
}

// RecordPeerDedup increments the duplicate-drop counter for a specific peer.
func (s *StatsCollector) RecordPeerDedup(peerID string) {
	if peerID == "" {
		return
	}
	atomic.AddUint64(&s.getPeerSeq(peerID).DedupDrops, 1)
}

// getPeerSeq returns (creating if needed) the PeerSeqState for a peer. It is
// lock-free: LoadOrStore installs a fresh entry only on first sight of a peer,
// so the datapath writers never block each other or GetResponse.
func (s *StatsCollector) getPeerSeq(peerID string) *PeerSeqState {
	if v, ok := s.peerSeqState.Load(peerID); ok {
		return v.(*PeerSeqState)
	}
	st := &PeerSeqState{}
	actual, _ := s.peerSeqState.LoadOrStore(peerID, st)
	return actual.(*PeerSeqState)
}

func (s *StatsCollector) RecordProtocol(ethType uint16) {
	switch ethType {
	case packet.EtherTypeIPv4: // IPv4
		atomic.AddUint64(&s.ipv4Pkts, 1)
	case packet.EtherTypeIPv6: // IPv6
		atomic.AddUint64(&s.ipv6Pkts, 1)
	case packet.EtherTypeARP: // ARP
		atomic.AddUint64(&s.arpPkts, 1)
	default:
		atomic.AddUint64(&s.otherPkts, 1)
	}
}

// RecordGatewayPacket marks one frame as an Exit Node gateway packet. Called
// once per tunnelled frame on both the client (Tx into the tunnel) and the
// server (Rx out of the tunnel) sides. The counter is a single atomic op so it
// is safe and cheap on the datapath hot path.
func (s *StatsCollector) RecordGatewayPacket() {
	atomic.AddUint64(&s.gatewayPkts, 1)
}

// CaptureFrame records one raw TAP frame into the pcap buffer if capture is
// active. dir is DirTx for frames injected by the local OS into the TAP device
// (leaving this node) and DirRx for frames received from peers and written to
// the local TAP device (arriving at this node).
func (s *StatsCollector) CaptureFrame(dir observer.FrameDirection, frame []byte) {
	s.CaptureFrameWithPeers(dir, frame, "", "")
}

func (s *StatsCollector) CaptureFrameWithPeers(dir observer.FrameDirection, frame []byte, fromPeer, toPeer string) {
	if s.Pcap == nil {
		return
	}
	var cd CaptureDir
	if dir == observer.DirTx {
		cd = DirTx
	} else {
		cd = DirRx
	}
	s.Pcap.AddWithPeers(cd, frame, fromPeer, toPeer)
}

func (s *StatsCollector) RecordFrame(frame []byte) {
	if len(frame) < 14 {
		atomic.AddUint64(&s.otherPkts, 1)
		return
	}
	ethType := packet.EtherType(frame)
	switch ethType {
	case packet.EtherTypeARP: // ARP
		atomic.AddUint64(&s.arpPkts, 1)
	case packet.EtherTypeIPv4: // IPv4
		atomic.AddUint64(&s.ipv4Pkts, 1)
		if len(frame) >= 14+20 {
			proto := frame[14+9]
			switch proto {
			case 1:
				atomic.AddUint64(&s.icmpPkts, 1)
			case 6:
				atomic.AddUint64(&s.tcpPkts, 1)
			case 17:
				atomic.AddUint64(&s.udpPkts, 1)
			}
		}
	case packet.EtherTypeIPv6: // IPv6
		atomic.AddUint64(&s.ipv6Pkts, 1)
		if len(frame) >= 14+40 {
			nextHdr := frame[14+6]
			switch nextHdr {
			case 58:
				atomic.AddUint64(&s.icmpPkts, 1)
				atomic.AddUint64(&s.ndpPkts, 1)
			case 6:
				atomic.AddUint64(&s.tcpPkts, 1)
			case 17:
				atomic.AddUint64(&s.udpPkts, 1)
			}
		}
	default:
		atomic.AddUint64(&s.otherPkts, 1)
	}
}

func (s *StatsCollector) RecordNDP() {
	atomic.AddUint64(&s.ndpPkts, 1)
}

type TxRxStats = observer.TxRxStats

func (s *StatsCollector) GetTxRxStats() TxRxStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return TxRxStats{
		TxSpeed: s.txSpeed,
		RxSpeed: s.rxSpeed,
		TotalTx: atomic.LoadUint64(&s.bytesSent),
		TotalRx: atomic.LoadUint64(&s.bytesRecv),
	}
}

// tickSpeed recomputes rolling throughput counters and appends a history
// sample. It is invoked from GetResponse (driven by the web UI's ~2s poll) and
// takes the collector's write lock only for this brief mutation. Keeping the
// only writes here lets GetResponse read the rest of the collector under a cheap
// RLock, eliminating head-of-line blocking against the data-path writers
// (UpdatePeers/UpdateRoutes/... in updateWebCollectorState) that also take s.mu
// for write. This is the key fix for the slow WebUI load in high-traffic
// (e.g. Exit Node) mode.
func (s *StatsCollector) tickSpeed(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	dur := now.Sub(s.lastSpeedCalc).Seconds()
	currTx := atomic.LoadUint64(&s.bytesSent)
	currRx := atomic.LoadUint64(&s.bytesRecv)
	currTxPkts := atomic.LoadUint64(&s.packetsSent)
	currRxPkts := atomic.LoadUint64(&s.packetsRecv)

	if dur >= 0.2 {
		s.txSpeed = uint64(float64(currTx-s.lastTxBytes) / dur)
		s.rxSpeed = uint64(float64(currRx-s.lastRxBytes) / dur)
		s.txPPS = uint64(float64(currTxPkts-s.lastTxPkts) / dur)
		s.rxPPS = uint64(float64(currRxPkts-s.lastRxPkts) / dur)
		s.lastTxBytes = currTx
		s.lastRxBytes = currRx
		s.lastTxPkts = currTxPkts
		s.lastRxPkts = currRxPkts
		s.lastSpeedCalc = now

		// Snapshot and reset per-type packet counters
		txU := atomic.SwapUint64(&s.txUnicastPkts, 0)
		txM := atomic.SwapUint64(&s.txMulticastPkts, 0)
		txB := atomic.SwapUint64(&s.txBroadcastPkts, 0)
		rxU := atomic.SwapUint64(&s.rxUnicastPkts, 0)
		rxM := atomic.SwapUint64(&s.rxMulticastPkts, 0)
		rxB := atomic.SwapUint64(&s.rxBroadcastPkts, 0)

		sample := SpeedSampleDTO{
			Timestamp:   now.Format("15:04:05"),
			TxSpeed:     s.txSpeed,
			RxSpeed:     s.rxSpeed,
			TxPPS:       s.txPPS,
			RxPPS:       s.rxPPS,
			TxUnicast:   uint64(float64(txU) / dur),
			TxMulticast: uint64(float64(txM) / dur),
			TxBroadcast: uint64(float64(txB) / dur),
			RxUnicast:   uint64(float64(rxU) / dur),
			RxMulticast: uint64(float64(rxM) / dur),
			RxBroadcast: uint64(float64(rxB) / dur),
		}
		s.speedHistory = append(s.speedHistory, sample)
		if len(s.speedHistory) > 60 {
			s.speedHistory = s.speedHistory[len(s.speedHistory)-60:]
		}
	}
}

func (s *StatsCollector) GetResponse() StatsResponse {
	var mStats runtime.MemStats
	runtime.ReadMemStats(&mStats)

	// Roll throughput counters forward (brief write lock, mutations only).
	s.tickSpeed(time.Now())

	s.mu.RLock()
	defer s.mu.RUnlock()

	txSpd := s.txSpeed
	rxSpd := s.rxSpeed
	historyCopy := make([]SpeedSampleDTO, len(s.speedHistory))
	copy(historyCopy, s.speedHistory)

	// byte counters for the packet-stats block (also read by tickSpeed; both use
	// atomic loads so reading here under RLock is safe).
	currTx := atomic.LoadUint64(&s.bytesSent)
	currRx := atomic.LoadUint64(&s.bytesRecv)

	// Local nil-coalescing so JSON never emits null; do NOT mutate shared state
	// while only holding the read lock.
	activePeers := s.ActivePeers
	if activePeers == nil {
		activePeers = []PeerInfoDTO{}
	}
	macTable := s.MACTable
	if macTable == nil {
		macTable = []MACInfoDTO{}
	}
	arpTable := s.ARPTable
	if arpTable == nil {
		arpTable = []ARPInfoDTO{}
	}
	ipTable := s.IPTable
	if ipTable == nil {
		ipTable = []IPInfoDTO{}
	}
	routesTable := s.RoutesTable
	if routesTable == nil {
		routesTable = []RouteInfoDTO{}
	}
	subnetRoutes := s.SubnetRoutes
	if subnetRoutes == nil {
		subnetRoutes = []SubnetRouteDTO{}
	}
	meshMatrix := s.MeshMatrix
	if meshMatrix == nil {
		meshMatrix = []MeshMatrixCellDTO{}
	}
	dupConflicts := s.DuplicateIPConflicts
	if dupConflicts == nil {
		dupConflicts = []observer.DuplicateIPConflictDTO{}
	}
	listenAddrs := s.ListenAddrs
	if listenAddrs == nil {
		listenAddrs = []string{}
	}

	sysHealth := SystemHealthDTO{
		HeapAllocMB:   float64(mStats.HeapAlloc) / (1024 * 1024),
		HeapInuseMB:   float64(mStats.HeapInuse) / (1024 * 1024),
		HeapObjects:   mStats.HeapObjects,
		StackInuseMB:  float64(mStats.StackInuse) / (1024 * 1024),
		NextGCMB:      float64(mStats.NextGC) / (1024 * 1024),
		SysMemMB:      float64(mStats.Sys) / (1024 * 1024),
		Goroutines:    runtime.NumGoroutine(),
		GCCount:       mStats.NumGC,
		LastGCPauseMS: float64(mStats.PauseNs[(mStats.NumGC+255)%256]) / 1e6,
		GCCPUFraction: mStats.GCCPUFraction,
		NumCPU:        runtime.NumCPU(),
		GOMAXPROCS:    runtime.GOMAXPROCS(0),
		UptimeSeconds: int64(time.Since(s.StartTime).Seconds()),
	}

	exitInfo := s.ExitNode
	if s.Gateway != nil {
		exitInfo.ActiveExitIP = s.Gateway.ActiveExitIP()
		exitInfo.ActiveExitTapIPv6 = s.Gateway.ActiveExitIP6()
		exitInfo.ActivePeerID = s.Gateway.ActiveExitPeerID()
	}
	// Derive runtime role + resolve active peer display fields.
	if exitInfo.ActivePeerID != "" {
		exitInfo.Active = true
		for _, p := range activePeers {
			if p.PeerID == exitInfo.ActivePeerID {
				exitInfo.ActiveExitPeerName = p.NodeName
				exitInfo.ActiveExitTapIP = strings.Split(p.TapIP, "/")[0]
				if p.TapIPv6 != "" {
					exitInfo.ActiveExitTapIPv6 = strings.Split(p.TapIPv6, "/")[0]
				}
				break
			}
		}
	}
	switch {
	case exitInfo.Enable && exitInfo.Active:
		exitInfo.Role = "both"
	case exitInfo.Enable:
		exitInfo.Role = "server"
	case exitInfo.Active:
		exitInfo.Role = "client"
	default:
		exitInfo.Role = ""
	}

	// Merge per-link seq tracking into the peer DTOs for the topology chart and
	// roll up node-wide diagnostics. peerSeqState is a sync.Map written
	// concurrently by the data path via getPeerSeq (lock-free per-peer Store /
	// Add), so each active peer is read with a single lock-free Load — no
	// shared mutex with the writers. We copy each peer into peersOut and apply
	// the seq fields on the copy to avoid aliasing the shared slice.
	var aggReplay, aggResets, aggDedup, aggUtil uint64
	var synced int
	peersOut := make([]PeerInfoDTO, len(activePeers))
	for i := range activePeers {
		p := activePeers[i]
		if v, ok := s.peerSeqState.Load(p.PeerID); ok && v != nil {
			st := v.(*PeerSeqState)
			p.TxSeq = atomic.LoadUint64(&st.TxSeq)
			p.RxSeq = atomic.LoadUint64(&st.RxSeq)
			p.DedupDrops = atomic.LoadUint64(&st.DedupDrops)
			p.SeqWinMax = atomic.LoadUint64(&st.SeqWinMax)
			p.ReplayDrops = atomic.LoadUint64(&st.ReplayDrops)
			p.WindowResets = atomic.LoadUint64(&st.WindowResets)
			p.WinUtilization = float64(atomic.LoadUint64(&st.WinUtilScaled)) / 1000.0

			aggReplay += atomic.LoadUint64(&st.ReplayDrops)
			aggResets += atomic.LoadUint64(&st.WindowResets)
			aggDedup += atomic.LoadUint64(&st.DedupDrops)
			aggUtil += atomic.LoadUint64(&st.WinUtilScaled)
			if atomic.LoadUint64(&st.SeqWinMax) > 0 {
				synced++
			}
		}
		peersOut[i] = p
	}
	var avgUtil float64
	if len(peersOut) > 0 {
		avgUtil = float64(aggUtil) / float64(len(peersOut)) / 1000.0
	}
	seqStats := SeqStatsDTO{
		ReplayDrops:    aggReplay,
		WindowResets:   aggResets,
		DedupDrops:     aggDedup,
		WinUtilization: avgUtil,
		SyncedPeers:    synced,
	}

	protoChannels := s.ProtocolChannels
	if protoChannels == nil {
		protoChannels = []ProtocolChannelDTO{}
	}
	activeStreams := s.ActiveStreams
	if activeStreams == nil {
		activeStreams = []ProtocolStreamDTO{}
	}

	resp := StatsResponse{
		NodeName:          s.NodeName,
		PeerID:            s.PeerID,
		Version:           version.Version,
		TapIP:             s.TapIP,
		TapIPv6:           s.TapIPv6,
		TransportStrategy: s.TransportStrategy,
		ListenAddrs:       listenAddrs,
		NATStatus:         s.NATStatus,
		ExitNode:          exitInfo,
		ActivePeers:       peersOut,
		MACTable:          macTable,
		ARPTable:          arpTable,
		IPTable:           ipTable,
		RoutesTable:       routesTable,
		PacketStats: PacketStatsDTO{
			PacketsSent:   atomic.LoadUint64(&s.packetsSent),
			PacketsRecv:   atomic.LoadUint64(&s.packetsRecv),
			BytesSent:     currTx,
			BytesRecv:     currRx,
			DedupCount:    atomic.LoadUint64(&s.dedupCount),
			DispatchDrops: atomic.LoadUint64(&s.DispatchDrops),
		},
		ProtocolStats: ProtocolStatsDTO{
			IPv4:  atomic.LoadUint64(&s.ipv4Pkts),
			IPv6:  atomic.LoadUint64(&s.ipv6Pkts),
			ARP:   atomic.LoadUint64(&s.arpPkts),
			NDP:   atomic.LoadUint64(&s.ndpPkts),
			ICMP:  atomic.LoadUint64(&s.icmpPkts),
			UDP:   atomic.LoadUint64(&s.udpPkts),
			TCP:   atomic.LoadUint64(&s.tcpPkts),
			Other: atomic.LoadUint64(&s.otherPkts),
		},
		GatewayPackets: GatewayPacketStatsDTO{
			Broadcast: atomic.LoadUint64(&s.cumTxBroadcastPkts) + atomic.LoadUint64(&s.cumRxBroadcastPkts),
			Multicast: atomic.LoadUint64(&s.cumTxMulticastPkts) + atomic.LoadUint64(&s.cumRxMulticastPkts),
			Gateway:   atomic.LoadUint64(&s.gatewayPkts),
		},
		Security:             s.Security,
		System:               sysHealth,
		SeqStats:             seqStats,
		ACL:                  s.GetACLStats(),
		Speed:                SpeedStatsDTO{TxBytesPerSec: txSpd, RxBytesPerSec: rxSpd},
		SpeedHistory:         historyCopy,
		SubnetRoutes:         subnetRoutes,
		PeerMetas:            s.PeerMetas,
		MeshMatrix:           meshMatrix,
		ProtocolChannels:     protoChannels,
		ActiveStreams:        activeStreams,
		DuplicateIPConflicts: dupConflicts,
	}
	return resp
}
