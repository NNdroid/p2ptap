// Package observer defines the decoupling interfaces and shared DTOs between the
// node (domain core) and the web UI (presentation layer).
//
// Historically pkg/node imported pkg/web directly so it could push metrics,
// captured frames and resolved peer metadata into the WebUI's StatsCollector.
// That created a compile-time dependency from the domain core onto a package
// that embeds HTML assets, an HTTP server and dozens of DTO types — making the
// node hard to unit test and impossible to reuse (e.g. a CLI/desktop client)
// without dragging in the whole web stack.
//
// This package breaks the cycle: node depends only on the small interfaces and
// the DTO types declared here. The web package reuses these DTOs via type
// aliases (type X = observer.X) and implements the interfaces. The cmd layer is
// responsible for wiring the concrete web implementation into the node at
// startup.
package observer

import (
	"net"
	"time"
)

// ————————————————————————————————————————————————————————————————
// Interfaces
// ————————————————————————————————————————————————————————————————

// FrameDirection identifies whether a TAP frame is leaving or arriving at the
// local node. It mirrors the previous web.DirTx / web.DirRx semantics.
type FrameDirection int

const (
	// DirTx is a frame injected by the local OS into the TAP device (leaving).
	DirTx FrameDirection = iota
	// DirRx is a frame received from peers and written to the local TAP device (arriving).
	DirRx
)

// InterceptorMAC is the virtual MAC address used by the userspace WebUI
// interceptor. It lives in the shared observer package because both the node
// (to detect interceptor-bound frames) and the web layer (to build replies)
// need it, without importing each other.
var InterceptorMAC = net.HardwareAddr{0x02, 0xca, 0xfe, 0x00, 0x02, 0x54}

// FrameSink receives raw TAP frames for capture / inspection. Implemented by
// the web packet-capture buffer, but node treats it purely as a sink so other
// backends (e.g. a Prometheus exporter) can be plugged in without touching node.
type FrameSink interface {
	CaptureFrame(dir FrameDirection, frame []byte)
	CaptureFrameWithPeers(dir FrameDirection, frame []byte, fromPeer, toPeer string)
}

// PacketWriter is the minimal write surface a FrameFilter needs to inject a
// reply frame back into the TAP device.
type PacketWriter interface {
	Write(b []byte) (int, error)
}

// FrameFilter inspects a frame and may handle it inline (e.g. answer ARP/NDP for
// a virtual IP). It returns true if the frame was consumed and should NOT be
// forwarded by the caller. This keeps the TAP interceptor logic behind an
// interface so node does not depend on the concrete web implementation.
type FrameFilter interface {
	MatchAndHandle(frame []byte, writer PacketWriter) bool
}

// WebServer is the minimal surface the node needs to shut the WebUI down.
type WebServer interface {
	Close() error
	// Rebind re-opens the HTTP listeners on the currently configured bind
	// addresses. It is used after a NIC change (roam) so the WebUI stays
	// reachable when it was bound to a specific interface IP that went away.
	// Listeners bound to 0.0.0.0/:: are unaffected. Implementations must close
	// the old listeners only after the new ones are successfully bound.
	Rebind() error
}

// GatewayController is implemented by the node's GatewayManager and consumed by
// the web layer to set/clear an Exit Node. Declared here (not in web) so the
// web package references the domain abstraction instead of the other way round.
type GatewayController interface {
	// SetExitNode installs the Exit Node default route(s) through the given
	// peer. exitTapIPv4 and exitTapIPv6 are the peer's TAP gateway addresses;
	// either may be empty, but at least one must be set. Each non-empty family
	// gets its own split-default (/1) routes installed on the TAP, so a
	// dual-stack peer routes BOTH IPv4 and IPv6 traffic through the exit while
	// the physical default route (and the P2P sockets bound to it) stays intact.
	SetExitNode(exitPeerID, exitTapIPv4, exitTapIPv6 string, endpoints []string) error
	ClearExitNode() error
	ActiveExitIP() string
	ActiveExitIP6() string
	ActiveExitPeerID() string
}

// Metrics is the observation surface the node pushes runtime telemetry into.
// Every method is safe to call on the hot datapath; implementations must stay
// lock-free / atomic on the write side. The node only depends on this
// interface, never on the concrete collector.
type Metrics interface {
	RecordSent(bytes int)
	RecordRecv(bytes int)
	RecordPacketDir(payload []byte, isTx bool)
	RecordFrame(frame []byte)
	RecordDedup()
	RecordPeerDedup(peerID string)
	RecordTxSeq(peerID string, seq uint64)
	RecordRxSeq(peerID string, seq, winMax, replayDrops, windowResets uint64, winUtil float64)
	RecordGatewayPacket()
	RecordNDP()
	RecordProtocol(ethType uint16)
}

// Collector bundles every capability the node needs from the WebUI collector.
// It is the single seam through which the domain core talks to the presentation
// layer: metrics, frame capture, gateway control and configuration callbacks.
type Collector interface {
	Metrics
	FrameSink

	SetNodeInfo(nodeName, peerID, tapIP, tapIPv6, transportStrategy string)
	SetSecurity(pskStatus, obfuscation, keyFingerprint string)
	SetPeerEncryption(enc []PeerObfInfoDTO)
	SetTAPState(state *TAPStateDTO)
	SetTAPSelfTest(fn func() map[string]interface{})
	SetPeerResolver(fn func(mac net.HardwareAddr) string)
	SetCallbacks(cfg CollectorConfig)
	GetTxRxStats() TxRxStats

	UpdatePeers(peers []PeerInfoDTO)
	UpdateMACTable(mac []MACInfoDTO)
	UpdateARPTable(arp []ARPInfoDTO)
	UpdateIPTable(ip []IPInfoDTO)
	UpdateRoutes(routes []RouteInfoDTO)
	UpdateSubnetRoutes(routes []SubnetRouteDTO)
	UpdatePeerMetas(metas []PeerMetaDTO)
	UpdateMeshMatrix(matrix []MeshMatrixCellDTO)
	UpdateProtocolChannels(channels []ProtocolChannelDTO)
	UpdateActiveStreams(streams []ProtocolStreamDTO)
	// UpdateDuplicateIPConflicts pushes the current duplicate-IP / overlapping-
	// subnet conflict set (and arbitration verdicts) for the WebUI to display.
	UpdateDuplicateIPConflicts(conflicts []DuplicateIPConflictDTO)
	UpdateListenAddrs(addrs []string)
	UpdateNATStatus(status string)
	UpdateExitNode(exit ExitNodeInfoDTO)
	// PeekPeerID resolves a user-supplied peer identifier (peer ID, TAP IP,
	// TAP IPv6 or node name) to a connected peer ID. It is used by the node's
	// probe helpers without exposing the concrete peer slice.
	PeekPeerID(peerIDStr string) (string, bool)
	// SetDispatchDrops records the number of frames dropped at dispatch.
	SetDispatchDrops(drops uint64)
	// GetACLStats returns the latest ACL firewall counters. Set by the
	// node via CollectorConfig; if unset, the ACL field in /api/stats
	// reports zero-valued counters (engine disabled or uninitialised).
	GetACLStats() ACLStatsDTO
	// GetResponse returns a full snapshot of current telemetry.  It is the
	// read side used by the cmd layer (e.g. tray tooltip) which cannot depend
	// on the concrete collector type.
	GetResponse() StatsResponse
}

// CollectorConfig carries the wiring callbacks the node provides to the web
// collector so web handlers can resolve/add peers and react to hot-reload.
type CollectorConfig struct {
	ResolvePeerAddrs      func(peerIDStr string) []string
	OnExitNodeChanged     func()
	OnObfuscationChanged  func()
	OnSubnetsChanged      func()
	TestPeerMultiaddrs    func(peerIDStr string) []MultiaddrTestResultEntry
	ProbePeerConnectivity func(peerIDStr string) *PeerConnectivityResult
	ProbePeerEcho         func(peerIDStr string) *PeerEchoResultDTO
	ProbePeerEchoAddr     func(peerIDStr string, targetAddrStr string) *PeerEchoResultDTO
	ProbeTapForward       func(peerIDStr string) *TapProbeResultDTO
	AddStaticPeer         func(multiaddrStr string) error
	// DiagnoseLink performs a deep transport-layer link check on a single
	// multiaddr (validity → DNS → TCP/QUIC → libp2p transport → Noise/TLS →
	// peer-id match → connection). Returns nil if the node has not wired it.
	DiagnoseLink          func(multiaddrStr string) *LinkDiagnosis
	OnSubnetToggle        func(cidr string, enable bool) error
	// GetACLStats is called on every /api/stats read. The node wires this
	// to Node.GetACLStats so the WebUI sees live firewall counters without
	// the web package having to import node.
	GetACLStats func() ACLStatsDTO
}

// ————————————————————————————————————————————————————————————————
// Shared DTO types (wire shape). The web package aliases these so JSON
// contracts stay identical while the node never imports web.
// ————————————————————————————————————————————————————————————————

// TxRxStats carries simple TX/RX counters exchanged between peers in metadata
// sync.
type TxRxStats struct {
	TxSpeed uint64 `json:"tx_speed"`
	RxSpeed uint64 `json:"rx_speed"`
	TotalTx uint64 `json:"total_tx"`
	TotalRx uint64 `json:"total_rx"`
}

type PeerInfoDTO struct {
	PeerID          string   `json:"peer_id"`
	NodeName        string   `json:"node_name"`
	Role            string   `json:"role"` // "Bootstrap", "Static", "Peer"
	IsRelayed       bool     `json:"is_relayed"`
	// RelayOnly is true when the peer has NO usable direct path (its known
	// addresses are private/loopback/unreachable) and is only reachable through
	// a circuit or overlay relay. It is derived from the node's internal
	// relayOnlyPeers set, which is marked on circuit-relay connect and cleared
	// once a direct transport appears. Exposing it lets the WebUI tell the
	// operator "this peer can never go direct" instead of just "relayed".
	RelayOnly       bool `json:"relay_only"`
	IsExitNode      bool     `json:"is_exit_node"`
	ExitNAT         bool     `json:"exit_nat"`
	TxSpeed         uint64   `json:"tx_speed"`
	RxSpeed         uint64   `json:"rx_speed"`
	TotalTx         uint64   `json:"total_tx"`
	TotalRx         uint64   `json:"total_rx"`
	TapIP           string   `json:"tap_ip"`
	TapIPv6         string   `json:"tap_ipv6"`
	OSArch          string   `json:"os_arch"`
	Version         string   `json:"version"`
	Uptime          string   `json:"uptime"`
	ConnectedAt     string   `json:"connected_at"`
	ConnectedSince  string   `json:"connected_since"`
	LastSeen        string   `json:"last_seen"`
	Reachability    string   `json:"reachability"`
	Addr            string   `json:"addr"`
	AllAddrs        []string `json:"all_addrs"`
	Transport       string   `json:"transport"`
	RTTMs           int64    `json:"rtt_ms"`
	JitterMs        float64  `json:"jitter_ms"`
	LossRatePercent float64  `json:"loss_rate_percent"`
	GeoLocation     string   `json:"geo_location"`
	// Per-link sequence tracking (for topology star-chart visualization).
	TxSeq      uint64 `json:"tx_seq"`      // latest seqID sent TO this peer
	RxSeq      uint64 `json:"rx_seq"`      // latest seqID received FROM this peer
	DedupDrops uint64 `json:"dedup_drops"` // frames from this peer marked duplicate
	SeqWinMax  uint64 `json:"seq_win_max"` // dedup window max (diagnostic for blackhole)
	// Structured-seq diagnostics:
	ReplayDrops    uint64  `json:"replay_drops"`    // stale/replayed frames dropped
	WindowResets   uint64  `json:"window_resets"`   // window re-anchors (sync/jump)
	WinUtilization float64 `json:"win_utilization"` // 0..1 live window fill
	// Per-peer encryption/obfuscation (negotiated via SeqSync ECDH handshake):
	ObfNegotiated bool   `json:"obf_negotiated"` // true if a cipher was established
	ObfAlgo       string `json:"obf_algo"`       // "none" | "aes-gcm" | "chacha20"
	ObfEncrypted  bool   `json:"obf_encrypted"`  // true if a real AEAD is in use (not plaintext)
	// SeqSyncConvergeMs is the measured handshake convergence latency: time from
	// the first SeqSync handshake attempt to the link becoming usable (ready).
	// 0 means unknown/not yet measured. High/unknown values under relay/NAT are a
	// useful signal that the crypto handshake is flaky for this peer.
	SeqSyncConvergeMs uint64 `json:"seqsync_converge_ms"`
	// ConnState aggregates every connectivity/encryption stage into one verdict so
	// the WebUI can show "how far the handshake got and whether real traffic flows".
	//   ok            – connected, app protocol negotiated, encrypted, data flows
	//   relay_ok      – reachable only via relay hop, encrypted, data flows through relay
	//   connecting    – connection in progress, no verdict yet
	//   proto_mismatch– connected but app protocol (/p2ptap/application/1.0.0) not shared
	//                   (e.g. mixed old/new versions); data cannot flow
	//   obf_failed    – connected + protocol OK but encryption negotiation/decryption fails
	//   unreachable   – no usable connection (direct or relay)
	ConnState  string `json:"conn_state"`
	ConnStage  int    `json:"conn_stage"`  // 0..4 completed stages (1 conn, 2 proto, 3 obf, 4 data)
	ConnDetail string `json:"conn_detail"` // human-readable supplement (algo, relay hop, error)
	// ReturnPath exposes the ASYMMETRIC-ROUTING return-path liveness for this
	// peer, kept deliberately separate from the outbound-connectivity ConnState
	// verdict. In a mesh where each node picks its outbound and return paths
	// independently, a healthy outbound path proves nothing about whether the
	// peer can route frames back to us. Values:
	//   ok    – we received inbound frames from the peer within the liveness
	//           window, so the return path is alive
	//   dead  – no inbound frames within the window even though the outbound
	//           path may be healthy: a classic asymmetric-routing break AT the
	//           peer (its relay stream / TAP egress is stuck), not a local
	//           outbound failure
	//   idle  – no return-path sample yet (peer just connected, no frames seen)
	ReturnPath       string `json:"return_path"`
	ReturnPathDetail string `json:"return_path_detail"` // e.g. "回程正常 · 3 秒前收到帧" / "回程断 · 18 秒无回程帧"
	LastRxISO        string `json:"last_rx_iso"`        // RFC3339 of last inbound frame; "" if never received
}

type SpeedTestResultDTO struct {
	PeerID          string  `json:"peer_id"`
	NodeName        string  `json:"node_name"`
	Mbps            float64 `json:"mbps"`
	RTTMin          float64 `json:"rtt_min"`
	RTTAvg          float64 `json:"rtt_avg"`
	RTTMax          float64 `json:"rtt_max"`
	Jitter          float64 `json:"jitter"`
	PacketLoss      float64 `json:"packet_loss"`
	QualityGrade    string  `json:"quality_grade"`
	MeasurementNote string  `json:"measurement_note"`
	// IsRelayed reports whether the underlying libp2p connection to the peer
	// actually traverses a circuit relay (/p2p-circuit), classified from the
	// real connection transport — NOT inferred from RTT. This is the field the
	// WebUI must use to decide between "Direct P2P" and "Circuit Relay".
	IsRelayed bool `json:"is_relayed"`
}

// TracerouteHop is a single node along an overlay (LSA-path) routing trace.
// Index 0 is the local origin; the last index is the destination; any nodes
// in between are relay/transit hops the traffic physically traverses. Each hop
// carries both its own identity and the properties of the leg that *reaches*
// it from the previous hop (omitted for the local origin).
type TracerouteHop struct {
	Index       int    `json:"index"`
	PeerID      string `json:"peer_id"`
	PeerIDShort string `json:"peer_id_short"`
	NodeName    string `json:"node_name"`
	TapIP       string `json:"tap_ip,omitempty"`
	TapIPv6     string `json:"tap_ipv6,omitempty"`
	Role        string `json:"role"`       // "local" | "relay" | "destination"
	IsExitNode  bool   `json:"is_exit_node"` // hops that are running an Exit Node
	IsRelayHop  bool   `json:"is_relay_hop"` // true for intermediate transit nodes
	// Link TO this hop from the previous hop (empty for index 0):
	LinkClass       string `json:"link_class,omitempty"`        // "direct" | "circuit-relay"
	LinkRTTMs       int64  `json:"link_rtt_ms,omitempty"`       // observed latency of this leg
	IsRelayedLeg    bool   `json:"is_relayed_leg,omitempty"`    // leg traverses a libp2p circuit
	CumulativeRTTMs int64  `json:"cumulative_rtt_ms,omitempty"` // sum of leg RTTs up to and including this hop
	TransportAddr   string `json:"transport_addr,omitempty"`    // best libp2p multiaddr reaching this hop
}

// TracerouteResultDTO is the outcome of an overlay traceroute to a peer. libp2p
// core has no native traceroute, so p2ptap traces the LSA/Dijkstra routing path
// (the exact sequence of mesh nodes a frame is forwarded through), enriched
// with the per-leg transport class and observed latency from the link-state
// graph.
type TracerouteResultDTO struct {
	DestPeer      string          `json:"dest_peer"`
	DestName      string          `json:"dest_name"`
	DestTapIP     string          `json:"dest_tap_ip,omitempty"`
	IsDirect      bool            `json:"is_direct"`
	TransportPath string          `json:"transport_path"` // "direct" | "circuit-relay" | "overlay-relay"
	TotalRTTMs    int64           `json:"total_rtt_ms"`
	DirectRTTMs   int64           `json:"direct_rtt_ms"`
	SavedRTTMs    int64           `json:"saved_rtt_ms"`
	HopCount      int             `json:"hop_count"`
	Hops          []TracerouteHop `json:"hops"`
	ResolvedFrom  string          `json:"resolved_from"` // what the user input matched (tap_ip / name / peer_id)
	Source        string          `json:"source"`        // "live-router" | "cached-route" | "not-found"
}

// PingResultDTO is the outcome of a real libp2p-layer ping to a peer. Unlike
// /api/speedtest (which reports a cached EWMA estimate), this endpoint actually
// opens a libp2p ping stream and samples live RTTs, then classifies the
// underlying transport (direct vs circuit-relay) from the real connection's
// multiaddr so "Direct" vs "Relay" can never be inferred from RTT alone.
type PingResultDTO struct {
	PeerID        string   `json:"peer_id"`
	PeerIDShort   string   `json:"peer_id_short"`
	NodeName      string   `json:"node_name"`
	TapIP         string   `json:"tap_ip,omitempty"`
	TapIPv6       string   `json:"tap_ipv6,omitempty"`
	Success       bool     `json:"success"`
	Probes        int      `json:"probes"`          // number of ping samples attempted
	RTTMinMs      float64  `json:"rtt_min_ms"`      // 0 if no replies
	RTTAvgMs      float64  `json:"rtt_avg_ms"`
	RTTMaxMs      float64  `json:"rtt_max_ms"`
	JitterMs      float64  `json:"jitter_ms"`       // avg absolute RTT deviation
	PacketLoss    float64  `json:"packet_loss"`     // 0..1 fraction of lost probes
	IsRelayed     bool     `json:"is_relayed"`      // underlying conn traverses a circuit relay
	TransportPath string   `json:"transport_path"`  // "direct" | "circuit-relay" | "overlay-relay"
	TransportAddr string   `json:"transport_addr,omitempty"` // remote libp2p multiaddr
	RelayPath     []string `json:"relay_path,omitempty"`      // relay peer IDs traversed (excl. dest)
	Error         string   `json:"error,omitempty"`
}

// MultiaddrTestResultEntry holds the per-address probe result for one multiaddr.
type MultiaddrTestResultEntry struct {
	Addr      string `json:"addr"`
	Reachable bool   `json:"reachable"`
	RTTMs     int64  `json:"rtt_ms"`
	Error     string `json:"error,omitempty"`
	IsActive  bool   `json:"is_active"`
	// Note carries an *estimate* (rather than a measured value) for addresses
	// that cannot be independently timed — currently relay/circuit paths, where
	// the backend surfaces the cached peer-level EWMA as an estimate instead of
	// pretending each relay leg was probed. UI must render this distinctly (e.g.
	// purple "≈1045ms*") so it is not mistaken for a per-path measured RTT.
	Note string `json:"note,omitempty"`
}

// LinkStep is one stage of the deep transport-level multiaddr link diagnosis.
// The 7 canonical stages are:
//   1 multiaddr valid (parse)        5 Noise/TLS handshake
//   2 DNS resolves                   6 Peer ID matches expected
//   3 TCP/QUIC socket established    7 libp2p connection success
//   4 libp2p transport success
type LinkStep struct {
	Index      int    `json:"index"`       // 1..7 (stable stage number)
	Key        string `json:"key"`         // stable machine key, e.g. "multiaddr_valid"
	Passed     bool   `json:"passed"`      // true when the stage succeeded
	Skipped    bool   `json:"skipped"`     // true when the stage is not applicable (e.g. no /p2p/ peer id)
	Detail     string `json:"detail"`      // human-readable result / failure reason
	DurationMs int64  `json:"duration_ms"` // wall time spent on this stage
}

// LinkDiagnosis is the full result of a transport-layer link check on a single
// multiaddr. Overall is one of "ok", "partial" or "fail":
//   ok      – all applicable stages passed
//   partial – some stages passed but at least one was skipped (e.g. no peer id)
//   fail    – at least one applicable stage failed
type LinkDiagnosis struct {
	Input       string     `json:"input"`
	TargetPeer  string     `json:"target_peer,omitempty"` // resolved peer id (from /p2p/<id>), if present
	Transport   string     `json:"transport,omitempty"`   // detected transport, e.g. "tcp", "quic-v1"
	ResolvedIPs []string   `json:"resolved_ips,omitempty"` // IPs from DNS expansion
	Overall     string     `json:"overall"`
	Summary     string     `json:"summary,omitempty"`
	Steps       []LinkStep `json:"steps"`
}

// PeerConnectivityResult is the outcome of a real libp2p stream-level connectivity probe.
type PeerConnectivityResult struct {
	PeerID     string                     `json:"peer_id"`
	Reachable  bool                       `json:"reachable"`
	RTTMs      int64                      `json:"rtt_ms"`
	StreamsOk  int                        `json:"streams_ok"`
	StreamsErr int                        `json:"streams_err"`
	Error      string                     `json:"error,omitempty"`
	ProbedAt   time.Time                  `json:"probed_at"`
	DirectOk   bool                       `json:"direct_ok"`
	RelayOk    bool                       `json:"relay_ok"`
	Results    []MultiaddrTestResultEntry `json:"results"`
}

// PeerEchoResultDTO holds the result of a real end-to-end P2P echo stream test.
type PeerEchoResultDTO struct {
	PeerID         string    `json:"peer_id"`
	NodeName       string    `json:"node_name"`
	// RequestedAddr is the multiaddr that the caller explicitly asked to be
	// tested (empty when only the peer's any-working address was probed).
	// Always populated alongside TransportAddr so the WebUI can show the
	// "requested vs actually-used" delta when libp2p's NewStream reuses an
	// existing connection on a different transport.
	RequestedAddr  string    `json:"requested_addr,omitempty"`
	Success        bool      `json:"success"`
	RTTMs          float64   `json:"rtt_ms"`
	BytesSent      int       `json:"bytes_sent"`
	BytesRecv      int       `json:"bytes_recv"`
	PayloadMatched bool      `json:"payload_matched"`
	TransportAddr  string    `json:"transport_addr"`
	IsRelayed      bool      `json:"is_relayed"`
	Error          string    `json:"error,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
}

// TapProbeResultDTO holds the result of an end-to-end TAP data-path forwarding
// test: a full Ethernet frame (ICMP echo request) is injected into the overlay
// toward the peer's TAP IP and the peer echoes back an ICMP echo reply frame.
// This exercises the TAP -> overlay -> peer -> reply path that a real ping uses,
// which a plain application-layer echo (PeerEchoResultDTO) does NOT cover.
type TapProbeResultDTO struct {
	PeerID    string `json:"peer_id"`
	PeerName  string `json:"peer_name"`
	TapIP     string `json:"tap_ip"`
	Success   bool   `json:"success"`
	RTTMills  int64  `json:"rtt_ms"`
	SentBytes int    `json:"sent_bytes"`
	Error     string `json:"error,omitempty"`
}

type PeerMetaDTO struct {
	PeerID            string   `json:"peer_id"`
	NodeName          string   `json:"node_name"`
	TapIP             string   `json:"tap_ip"`
	TapIPv6           string   `json:"tap_ipv6"`
	TapMAC            string   `json:"tap_mac"`
	OSArch            string   `json:"os_arch"`
	Version           string   `json:"version"`
	IsExitNode        bool     `json:"is_exit_node"`
	ExitNAT           bool     `json:"exit_nat"`
	AdvertisedSubnets []string `json:"advertised_subnets"`
	SyncSource        string   `json:"sync_source"`
	LastSync          string   `json:"last_sync"`
	UptimeSec         int64    `json:"uptime_sec"`
}

// TAPStateDTO captures the TAP interface configuration at runtime.
type TAPStateDTO struct {
	InterfaceName   string `json:"interface_name"`
	IPv4            string `json:"ipv4"`
	IPv6            string `json:"ipv6"`
	MAC             string `json:"mac"`
	MTU             int    `json:"mtu"`
	IsUp            bool   `json:"is_up"`
	RouteConfigured bool   `json:"route_configured"`
}

type MACInfoDTO struct {
	MAC        string `json:"mac"`
	PeerID     string `json:"peer_id"`
	Origin     string `json:"origin"`       // MACOriginSelf | MACOriginLAN
	LastSeen   string `json:"last_seen"`    // human-readable, e.g. "2m3s ago"
	LastSeenTS int64  `json:"last_seen_ts"` // unix seconds, for client-side freshness
}

// MAC entry origin: distinguishes a peer's OWN virtual TAP interface MAC from
// MACs of devices on that peer's LAN whose traffic is forwarded through it.
const (
	// MACOriginSelf is the peer's own configured TAP interface MAC (locally
	// administered, starts 02:xx:…). A healthy peer contributes exactly one.
	MACOriginSelf = "self"
	// MACOriginLAN is a device on the peer's LAN (bridged / forwarded), NOT the
	// peer itself. Several of these mean the peer is relaying its LAN traffic.
	MACOriginLAN = "lan"
)

type ARPInfoDTO struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	PeerID   string `json:"peer_id"`
	NodeName string `json:"node_name"`
	Type     string `json:"type"`
	LastSeen string `json:"last_seen"`
}

type IPInfoDTO struct {
	IP           string `json:"ip"`
	MAC          string `json:"mac,omitempty"`
	Protocol     string `json:"protocol,omitempty"` // "IPv4" or "IPv6"
	IPType       string `json:"ip_type,omitempty"`  // "local", "peer", "subnet", "exit", "special", "wan"
	NodeName     string `json:"node_name"`
	PeerID       string `json:"peer_id"`
	// SubnetCIDR / SubnetOwner / SubnetPeerID are populated when this IP falls
	// inside a peer's advertised subnet (the longest matching prefix wins).
	// They let the UI label e.g. "192.168.100.3 → 192.168.100.0/24 via fah0-vm0-ndbbd0"
	// even when the IP itself is not the peer's TAP address.
	SubnetCIDR   string `json:"subnet_cidr,omitempty"`
	SubnetOwner  string `json:"subnet_owner,omitempty"`
	SubnetPeerID string `json:"subnet_peer_id,omitempty"`
	// IsExitNode is true when the matched subnet owner is running as an exit
	// node. The UI uses it to highlight "via Exit Node" — IPs on the exit
	// node's LAN (or the exit node's TAP itself) are reachable only because
	// the operator chose to route through that gateway.
	IsExitNode bool   `json:"is_exit_node,omitempty"`
	TxBytes    uint64 `json:"tx_bytes"`
	RxBytes    uint64 `json:"rx_bytes"`
	TotalBytes uint64 `json:"total_bytes"`
	TxPackets  uint64 `json:"tx_packets"`
	RxPackets  uint64 `json:"rx_packets"`
	TxSpeed    uint64 `json:"tx_speed"`
	RxSpeed    uint64 `json:"rx_speed"`
	LastActive string `json:"last_active"`
}

type RouteInfoDTO struct {
	DestPeer    string   `json:"dest_peer"`
	DestName    string   `json:"dest_name"`
	TapIP       string   `json:"tap_ip"`
	TapIPv6     string   `json:"tap_ipv6"`
	NextHopPeer string   `json:"next_hop_peer"`
	NextHopName string   `json:"next_hop_name"`
	Path        []string `json:"path"`
	PathNames   []string `json:"path_names"`
	IsDirect    bool     `json:"is_direct"`
	// TransportPath is the ACTUAL transport path of the route, independent of
	// the overlay IsDirect flag. A circuit-relayed peer is registered as a
	// direct link (IsDirect=true) for routing, but its bytes physically hop
	// through a libp2p relay — so without this field the WebUI would wrongly
	// show "Direct" for a 500ms+ relayed peer. Values: "direct" | "circuit-relay"
	// | "overlay-relay".
	TransportPath string             `json:"transport_path"`
	TotalRTTMs    int64              `json:"total_rtt_ms"`
	DirectRTTMs   int64              `json:"direct_rtt_ms"`
	SavedRTTMs    int64              `json:"saved_rtt_ms"`
	Candidates    []CandidatePathDTO `json:"candidates"`
}

type CandidatePathDTO struct {
	PathNames []string `json:"path_names"`
	TotalRTT  int64    `json:"total_rtt"`
	IsOptimal bool     `json:"is_optimal"`
	IsDirect  bool     `json:"is_direct"`
	Reason    string   `json:"reason"`
}

type ProtocolStatsDTO struct {
	IPv4  uint64 `json:"ipv4"`
	IPv6  uint64 `json:"ipv6"`
	ARP   uint64 `json:"arp"`
	NDP   uint64 `json:"ndp"`
	ICMP  uint64 `json:"icmp"`
	UDP   uint64 `json:"udp"`
	TCP   uint64 `json:"tcp"`
	Other uint64 `json:"other"`
}

// GatewayPacketStatsDTO holds the high-level packet classification the live
// "Ethernet Protocol & Packet Inspector" card renders.
type GatewayPacketStatsDTO struct {
	Broadcast uint64 `json:"broadcast"`
	Multicast uint64 `json:"multicast"`
	Gateway   uint64 `json:"gateway"`
}

type SecurityStatusDTO struct {
	PSKStatus      string `json:"psk_status"`
	Obfuscation    string `json:"obfuscation"`
	KeyFingerprint string `json:"key_fingerprint"` // local ECDH pubkey fingerprint
	// Encryption lists per-peer negotiated state so the WebUI can show, for
	// every connected client, which algorithm is actually in use (or "none"
	// if encryption was not negotiated).
	Encryption []PeerObfInfoDTO `json:"encryption"`
}

// PeerObfInfoDTO is the per-peer encryption snapshot surfaced in the WebUI and
// is decoupled from the node package to keep the observer interface stable.
type PeerObfInfoDTO struct {
	PeerID     string `json:"peer_id"`
	Negotiated bool   `json:"negotiated"`
	Algo       string `json:"algo"`      // "none" | "aes-gcm" | "chacha20"
	Encrypted  bool   `json:"encrypted"` // true if a real AEAD is in use

	// --- Negotiated-key details (operator visibility into per-pair ciphers) ---
	// TxKeyFP / RxKeyFP are short fingerprints (first 8 hex chars of SHA-256) of
	// the per-direction AEAD keys. They are distinct per peer pair and per
	// direction, which is exactly what an operator wants to confirm on the WebUI.
	TxKeyFP string `json:"tx_key_fp,omitempty"`
	RxKeyFP string `json:"rx_key_fp,omitempty"`
	// ConnEpoch (peer's) and LocalEpoch (ours) are the 24-bit handshake epochs
	// embedded in every SeqID nonce; they must match between the two peers for
	// the connection to be valid.
	ConnEpoch  uint64 `json:"conn_epoch,omitempty"`
	LocalEpoch uint64 `json:"local_epoch,omitempty"`
	// PFS tells whether the cipher was derived from a one-shot ECDH ephemeral key
	// (true = forward secret) or fell back to the long-lived node key (false).
	PFS bool `json:"pfs"`
	// PFSPubKeyFP is the fingerprint of the peer's ephemeral ECDH public key;
	// empty when PFS is false / plaintext.
	PFSPubKeyFP string `json:"pfs_pubkey_fp,omitempty"`
}

type SystemHealthDTO struct {
	HeapAllocMB   float64 `json:"heap_alloc_mb"`
	HeapInuseMB   float64 `json:"heap_inuse_mb"`
	HeapObjects   uint64  `json:"heap_objects"`
	StackInuseMB  float64 `json:"stack_inuse_mb"`
	NextGCMB      float64 `json:"next_gc_mb"`
	SysMemMB      float64 `json:"sys_mem_mb"`
	Goroutines    int     `json:"goroutines"`
	GCCount       uint32  `json:"gc_count"`
	LastGCPauseMS float64 `json:"last_gc_pause_ms"`
	GCCPUFraction float64 `json:"gc_cpu_fraction"`
	NumCPU        int     `json:"num_cpu"`
	GOMAXPROCS    int     `json:"gomaxprocs"`
	UptimeSeconds int64   `json:"uptime_seconds"`
}

type SpeedStatsDTO struct {
	TxBytesPerSec uint64 `json:"tx_bytes_per_sec"`
	RxBytesPerSec uint64 `json:"rx_bytes_per_sec"`
}

type PacketStatsDTO struct {
	PacketsSent   uint64 `json:"packets_sent"`
	PacketsRecv   uint64 `json:"packets_recv"`
	BytesSent     uint64 `json:"bytes_sent"`
	BytesRecv     uint64 `json:"bytes_recv"`
	DedupCount    uint64 `json:"dedup_count"`
	DispatchDrops uint64 `json:"dispatch_drops"`
}

type ExitNodeInfoDTO struct {
	Enable        bool   `json:"enable"`
	NATMasquerade bool   `json:"nat_masquerade"`
	WANInterface  string `json:"wan_interface"`
	ActiveExitIP  string `json:"active_exit_ip"`
	ActivePeerID  string `json:"active_peer_id"`
	// Active reports whether this node currently has an Exit Node tunnel up.
	Active bool `json:"active"`
	// Role is the node's runtime Exit Node role: "server" / "client" / "both" / "".
	Role               string `json:"role"`
	ActiveExitPeerName string `json:"active_exit_peer_name"`
	ActiveExitTapIP    string `json:"active_exit_tap_ip"`
	ActiveExitTapIPv6  string `json:"active_exit_tap_ipv6"`
}

type SpeedSampleDTO struct {
	Timestamp   string `json:"timestamp"`
	TxSpeed     uint64 `json:"tx_speed"`
	RxSpeed     uint64 `json:"rx_speed"`
	TxPPS       uint64 `json:"tx_pps"`
	RxPPS       uint64 `json:"rx_pps"`
	TxUnicast   uint64 `json:"tx_unicast"`
	TxMulticast uint64 `json:"tx_multicast"`
	TxBroadcast uint64 `json:"tx_broadcast"`
	RxUnicast   uint64 `json:"rx_unicast"`
	RxMulticast uint64 `json:"rx_multicast"`
	RxBroadcast uint64 `json:"rx_broadcast"`
}

type SubnetRouteDTO struct {
	SubnetCIDR  string `json:"subnet_cidr"`
	PeerID      string `json:"peer_id"`
	NodeName    string `json:"node_name"`
	GatewayIP   string `json:"gateway_ip"`
	GatewayIPv6 string `json:"gateway_ipv6"`
	Status      string `json:"status"`
	Disabled    bool   `json:"disabled"`
	// IsExitNode is true when the subnet was advertised by a peer running as
	// an exit node. It lets the UI label IPs reachable via this subnet as
	// "via Exit Node" so the operator can distinguish plain LAN-routed IPs
	// from those flowing out through an exit-node gateway.
	IsExitNode bool `json:"is_exit_node,omitempty"`
}

type MeshMatrixCellDTO struct {
	SrcPeerID string `json:"src_peer_id"`
	SrcName   string `json:"src_name"`
	DstPeerID string `json:"dst_peer_id"`
	DstName   string `json:"dst_name"`
	RTTMs     int64  `json:"rtt_ms"`
	Hops      int    `json:"hops"`
	IsDirect  bool   `json:"is_direct"`
}

// DuplicateIPConflictDTO is the WebUI-facing snapshot of a duplicate-IP or
// overlapping-subnet conflict and its arbitration verdict. It mirrors the
// node-internal DuplicateIPConflict but is safe to embed in the stats response
// and decoupled from the node package.
type DuplicateIPConflictDTO struct {
	// ResourceType is "tap_ip_v4", "tap_ip_v6", "advertised_subnet", or
	// "advertised_subnet_overlap".
	ResourceType string `json:"resource_type"`
	// Resource is the duplicated/overlapping address, e.g. "10.0.0.5" or
	// "192.168.1.0/24".
	Resource string `json:"resource"`
	// Claimants lists every peer that advertised the resource.
	Claimants []string `json:"claimants"`
	// Winner is the peer that won the arbitration and keeps the route.
	Winner string `json:"winner"`
	// Losers are the suppressed peers (their index/route entry is dropped).
	Losers []string `json:"losers"`
	// Reason explains the verdict in terms of the allowed_subnet_peers order.
	Reason string `json:"reason"`
	// DetectedAt is the RFC3339 timestamp the conflict was last observed.
	DetectedAt string `json:"detected_at"`
}

// PeerSeqState tracks per-link sequence numbers for the topology star-chart.
type PeerSeqState struct {
	TxSeq          uint64  `json:"tx_seq"`
	RxSeq          uint64  `json:"rx_seq"`
	DedupDrops     uint64  `json:"dedup_drops"`
	SeqWinMax      uint64  `json:"seq_win_max"`
	RxSeqMax       uint64  `json:"rx_seq_max"`
	ReplayDrops    uint64  `json:"replay_drops"`
	WindowResets   uint64  `json:"window_resets"`
	WinUtilScaled  uint64  `json:"-"`
	WinUtilization float64 `json:"win_utilization"`
}

// SeqStatsDTO is the node-wide roll-up of structured-SeqID diagnostics.
type SeqStatsDTO struct {
	ReplayDrops    uint64  `json:"replay_drops"`
	WindowResets   uint64  `json:"window_resets"`
	DedupDrops     uint64  `json:"dedup_drops"`
	WinUtilization float64 `json:"win_utilization"`
	SyncedPeers    int     `json:"synced_peers"`
}

// ACLStatsDTO is the WebUI-facing snapshot of the live ACL firewall counters.
// See pkg/node/acl_stats.go for the engine side.
type ACLStatsDTO struct {
	Enabled     bool         `json:"enabled"`
	Accepted    uint64       `json:"accepted"`
	Dropped     uint64       `json:"dropped"`
	UptimeSec   int64        `json:"uptime_sec"`
	RuleCount   int          `json:"rule_count"`
	DefaultAct  string       `json:"default_action"`
	RuleHits    []ACLRuleHit `json:"rule_hits"`
	RecentDrops []ACLDropDTO `json:"recent_drops"`
}

type ACLRuleHit struct {
	RuleID string `json:"rule_id"`
	Hits   uint64 `json:"hits"`
}

type ACLDropDTO struct {
	Time    time.Time `json:"time"`
	PeerID  string    `json:"peer_id"`
	RuleID  string    `json:"rule_id"`
	Reason  string    `json:"reason"`
	Proto   string    `json:"protocol"`
	SrcIP   string    `json:"src_ip"`
	DstIP   string    `json:"dst_ip"`
	DstPort int       `json:"dst_port"`
	Dir     string    `json:"direction"`
}

// ProtocolChannelDTO captures high-level status and metrics of a P2P protocol subsystem/channel.
type ProtocolChannelDTO struct {
	ID              string `json:"id"`               // e.g. "seqsync", "lsa", "peekmap", "data", "auth", "dcutr", "echo"
	Name            string `json:"name"`             // Friendly name, e.g. "Sequence Sync (SeqSync)"
	Protocol        string `json:"protocol"`         // e.g. "/p2ptap/seqsync/1.0.0"
	Category        string `json:"category"`         // "sync" | "routing" | "pubsub" | "data" | "security" | "transport" | "diagnostics"
	Status          string `json:"status"`           // "active" | "running" | "idle" | "standby"
	ActiveStreams   int    `json:"active_streams"`   // total active open streams count
	InboundStreams  int    `json:"inbound_streams"`  // inbound streams
	OutboundStreams int    `json:"outbound_streams"` // outbound streams
	Details         string `json:"details"`          // summary metrics
}

// ProtocolStreamDTO captures runtime details of an active stream/channel on a live P2P connection.
type ProtocolStreamDTO struct {
	Protocol     string `json:"protocol"`      // e.g. "/p2ptap/seqsync/1.0.0"
	ProtocolName string `json:"protocol_name"` // Friendly name, e.g. "SeqSync"
	PeerID       string `json:"peer_id"`
	PeerIDShort  string `json:"peer_id_short"`
	PeerName     string `json:"peer_name"`
	Direction    string `json:"direction"`     // "inbound" | "outbound"
	Transport    string `json:"transport"`     // "QUIC" / "TCP" / "Relay"
	RemoteAddr   string `json:"remote_addr"`
	Status       string `json:"status"`        // "active" | "established"
}

type StatsResponse struct {
	NodeName             string                   `json:"node_name"`
	PeerID               string                   `json:"peer_id"`
	Version              string                   `json:"version"`
	TapIP                string                   `json:"tap_ip"`
	TapIPv6              string                   `json:"tap_ipv6"`
	TransportStrategy    string                   `json:"transport_strategy"`
	ListenAddrs          []string                 `json:"listen_addrs"`
	NATStatus            string                   `json:"nat_status"`
	ExitNode             ExitNodeInfoDTO          `json:"exit_node"`
	ActivePeers          []PeerInfoDTO            `json:"active_peers"`
	MACTable             []MACInfoDTO             `json:"mac_table"`
	ARPTable             []ARPInfoDTO             `json:"arp_table"`
	IPTable              []IPInfoDTO              `json:"ip_table"`
	RoutesTable          []RouteInfoDTO           `json:"routes_table"`
	PacketStats          PacketStatsDTO           `json:"packet_stats"`
	ProtocolStats        ProtocolStatsDTO         `json:"protocol_stats"`
	GatewayPackets       GatewayPacketStatsDTO    `json:"gateway_packets"`
	SeqStats             SeqStatsDTO              `json:"seq_stats"`
	Security             SecurityStatusDTO        `json:"security"`
	ACL                  ACLStatsDTO              `json:"acl"`
	System               SystemHealthDTO          `json:"system"`
	Speed                SpeedStatsDTO            `json:"speed"`
	SpeedHistory         []SpeedSampleDTO         `json:"speed_history"`
	SubnetRoutes         []SubnetRouteDTO         `json:"subnet_routes"`
	PeerMetas            []PeerMetaDTO            `json:"peer_metas"`
	MeshMatrix           []MeshMatrixCellDTO      `json:"mesh_matrix"`
	ProtocolChannels     []ProtocolChannelDTO     `json:"protocol_channels"`
	ActiveStreams        []ProtocolStreamDTO      `json:"active_streams"`
	// DuplicateIPConflicts surfaces duplicate-IP and overlapping-subnet
	// conflicts (with arbitration verdicts) detected by the node.
	DuplicateIPConflicts []DuplicateIPConflictDTO `json:"duplicate_ip_conflicts"`
}
