package bootweb

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"p2ptap/pkg/version"
)

// ServerInfoDTO holds metadata about this bootstrap server.
type ServerInfoDTO struct {
	NodeName       string   `json:"node_name"`
	PeerID         string   `json:"peer_id"`
	ShortID        string   `json:"short_id"`
	Version        string   `json:"version"`
	UptimeSec      int64    `json:"uptime_sec"`
	ListenAddrs    []string `json:"listen_addrs"`
	OS             string   `json:"os"`
	Arch           string   `json:"arch"`
	NumGoroutines  int      `json:"num_goroutines"`
	MemoryAllocMB  float64  `json:"memory_alloc_mb"`
	HeapAllocMB    float64  `json:"heap_alloc_mb"`
	StackInUseMB   float64  `json:"stack_in_use_mb"`
	NumGC          uint32   `json:"num_gc"`
	GCPauseAvgMs   float64  `json:"gc_pause_avg_ms"`
	PSKEnabled     bool     `json:"psk_enabled"`
	ConfiguredPSKs int      `json:"configured_psks"`
}

// PeerItemDTO represents a single connected client peer.
type PeerItemDTO struct {
	PeerID            string   `json:"peer_id"`
	ShortID           string   `json:"short_id"`
	NodeName          string   `json:"node_name"`
	RemoteMultiaddr   string   `json:"remote_multiaddr"`
	PhysicalIP        string   `json:"physical_ip"`
	Transport         string   `json:"transport"` // QUIC / TCP / WebRTC / WebTransport
	Direction         string   `json:"direction"` // Inbound / Outbound
	ConnectedTime     string   `json:"connected_time"`
	ConnectedDuration string   `json:"connected_duration"`
	IsAuthenticated   bool     `json:"is_authenticated"`
	NetworkID         string   `json:"network_id"`
	HasPeekMapStream  bool     `json:"has_peek_map_stream"`
	HasBootRelay      bool     `json:"has_boot_relay"`
	LatencyMs         int64    `json:"latency_ms"`
	TapIP             string   `json:"tap_ip"`
	TapIPv6           string   `json:"tap_ipv6"`
	TapMAC            string   `json:"tap_mac"`
	OS                string   `json:"os"`
	Arch              string   `json:"arch"`
	Version           string   `json:"version"`
	AdvertisedSubnets []string `json:"advertised_subnets"`
	IsExitNode        bool     `json:"is_exit_node"`
	AllMultiaddrs     []string `json:"all_multiaddrs"`
	ObfsAlgo          string   `json:"obfs_algo"`
	ObfsMode          string   `json:"obfs_mode"`
}

// SubnetRouteDTO represents an advertised subnet route learned from a client node.
type SubnetRouteDTO struct {
	Subnet    string `json:"subnet"`
	PeerID    string `json:"peer_id"`
	ShortID   string `json:"short_id"`
	NodeName  string `json:"node_name"`
	TapIP     string `json:"tap_ip"`
	TapIPv6   string `json:"tap_ipv6,omitempty"`
	NetworkID string `json:"network_id"`
}

// RelayStatsDTO holds Circuit Relay v2 stats and resource limits.
type RelayStatsDTO struct {
	MaxCircuits        int `json:"max_circuits"`
	MaxReservations    int `json:"max_reservations"`
	ActiveReservations int `json:"active_reservations"`
	MaxPerPeer         int `json:"max_per_peer"`
	MaxPerIP           int `json:"max_per_ip"`
	DurationLimitSec   int `json:"duration_limit_sec"`
	DataLimitMB        int `json:"data_limit_mb"`
}

// PeekMapStatsDTO holds pub/sub topology channel status.
type PeekMapStatsDTO struct {
	ActiveListeners int `json:"active_listeners"`
	TotalPeersSeen  int `json:"total_peers_seen"`
}

// MeshPeerDTO holds backbone interconnect status with a peer boot.
type MeshPeerDTO struct {
	PeerID            string   `json:"peer_id"`
	ShortID           string   `json:"short_id"`
	Addrs             []string `json:"addrs"`
	IsConnected       bool     `json:"is_connected"`
	HasBackboneStream bool     `json:"has_backbone_stream"`
	LatencyMs         int64    `json:"latency_ms"`
}

// AlertEventDTO represents a diagnostic or security alert event.
type AlertEventDTO struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`  // "warn" | "error" | "info"
	Type      string `json:"type"`   // see alert type constants in main.go
	PeerID    string `json:"peer_id"`
	Message   string `json:"message"`
}

// NetworkGroup groups peers by their PSK Network ID.
type NetworkGroup struct {
	NetworkID string   `json:"network_id"`
	PeerCount int      `json:"peer_count"`
	PeerIDs   []string `json:"peer_ids"`
}

// TrafficPoint is one per-minute time-series sample for the traffic sparkline chart.
type TrafficPoint struct {
	Time       string `json:"time"`        // "HH:MM"
	PeerCount  int    `json:"peer_count"`
	RelayCount int    `json:"relay_count"`
}

// RelaySessionDTO represents one active Circuit Relay v2 session.
type RelaySessionDTO struct {
	SrcPeerID   string `json:"src_peer_id"`
	SrcShortID  string `json:"src_short_id"`
	SrcName     string `json:"src_name"`
	DstPeerID   string `json:"dst_peer_id"`
	DstShortID  string `json:"dst_short_id"`
	DstName     string `json:"dst_name"`
	NetworkID   string `json:"network_id"`
	StartTime   string `json:"start_time"`
	DurationSec int64  `json:"duration_sec"`
}

// GeoNodeDTO is a peer annotated with geographic coordinates for the 3D globe.
type GeoNodeDTO struct {
	PeerID     string  `json:"peer_id"`
	ShortID    string  `json:"short_id"`
	NodeName   string  `json:"node_name"`
	PhysicalIP string  `json:"physical_ip"`
	Country    string  `json:"country"`
	City       string  `json:"city"`
	Lat        float64 `json:"lat"`
	Lon        float64 `json:"lon"`
	NetworkID  string  `json:"network_id"`
	IsAuthed   bool    `json:"is_authenticated"`
	LatencyMs  int64   `json:"latency_ms"`
	IsBoot     bool    `json:"is_boot"`
}

// GeoArcDTO represents a relay connection arc between two geographic points.
type GeoArcDTO struct {
	SrcLat    float64 `json:"src_lat"`
	SrcLon    float64 `json:"src_lon"`
	DstLat    float64 `json:"dst_lat"`
	DstLon    float64 `json:"dst_lon"`
	NetworkID string  `json:"network_id"`
	SrcName   string  `json:"src_name"`
	DstName   string  `json:"dst_name"`
}

// HealthIssue is a single detected health problem.
type HealthIssue struct {
	Severity string `json:"severity"` // "warn" | "error"
	Message  string `json:"message"`
}

// HealthCheckDTO is the result of a network health scan.
type HealthCheckDTO struct {
	Healthy     bool          `json:"healthy"`
	TotalPeers  int           `json:"total_peers"`
	AuthedPeers int           `json:"authed_peers"`
	OrphanPeers int           `json:"orphan_peers"` // connected but no active streams
	Issues      []HealthIssue `json:"issues"`
}

// ConfigSummaryDTO provides read-only configuration info for the WebUI.
type ConfigSummaryDTO struct {
	NodeName        string   `json:"node_name"`
	PSKCount        int      `json:"psk_count"`
	MeshPeerCount   int      `json:"mesh_peer_count"`
	ListenAddrs     []string `json:"listen_addrs"`
	RelayTTLSec     int      `json:"relay_ttl_sec"`
	SessionLimitSec int      `json:"session_limit_sec"`
	DataLimitMB     int      `json:"data_limit_mb"`
	GeoIPPath       string   `json:"geoip_path"`
	GeoIPAvailable  bool     `json:"geoip_available"`
}

// BootDashboardDTO is the complete JSON response returned by GET /api/stats.
type BootDashboardDTO struct {
	Server         ServerInfoDTO     `json:"server"`
	Relay          RelayStatsDTO     `json:"relay"`
	PeekMap        PeekMapStatsDTO   `json:"peek_map"`
	Peers          []PeerItemDTO     `json:"peers"`
	SubnetRoutes   []SubnetRouteDTO  `json:"subnet_routes"`
	Mesh           []MeshPeerDTO     `json:"mesh"`
	Alerts         []AlertEventDTO   `json:"alerts"`
	Networks       []NetworkGroup    `json:"networks"`
	RelaySessions  []RelaySessionDTO `json:"relay_sessions"`
	GeoNodes       []GeoNodeDTO      `json:"geo_nodes"`
	GeoArcs        []GeoArcDTO       `json:"geo_arcs"`
	TrafficHistory []TrafficPoint    `json:"traffic_history"`
	Health         HealthCheckDTO    `json:"health"`
	Config         ConfigSummaryDTO  `json:"config"`
}

// BootDataProvider provides an interface for extracting live data from the boot server.
type BootDataProvider interface {
	GetHost() host.Host
	GetNodeName() string
	GetStartTime() time.Time
	IsPSKEnabled() bool
	GetPSKCount() int
	IsPeerAuthenticated(p peer.ID) bool
	GetPeerNetworkID(p peer.ID) string
	HasPeekMapListener(p peer.ID) bool
	GetPeekMapListenerCount() int
	HasBootRelayClient(p peer.ID) bool
	GetPeerNodeInfo(p peer.ID) (nodeName, tapIP, tapIPv6, tapMAC, osStr, archStr, verStr string, subnets []string, isExit bool, obfsAlgo, obfsMode string)
	GetMeshPeers() []MeshPeerInfo
	GetRecentAlerts() []AlertEventDTO
	// New methods for enhanced dashboard modules
	GetRelaySessions() []RelaySessionDTO
	GetGeoNodes() []GeoNodeDTO
	GetGeoArcs() []GeoArcDTO
	GetTrafficHistory() []TrafficPoint
	GetHealth(peers []PeerItemDTO) HealthCheckDTO
	GetConfigSummary() ConfigSummaryDTO
}

// MeshPeerInfo holds static info about a configured mesh boot.
type MeshPeerInfo struct {
	ID    peer.ID
	Addrs []multiaddr.Multiaddr
}

// AlertBuffer is a thread-safe ring buffer for diagnostic alert events.
type AlertBuffer struct {
	mu     sync.RWMutex
	alerts []AlertEventDTO
	max    int
}

// NewAlertBuffer creates an AlertBuffer with capacity.
func NewAlertBuffer(max int) *AlertBuffer {
	if max <= 0 {
		max = 300
	}
	return &AlertBuffer{
		alerts: make([]AlertEventDTO, 0, max),
		max:    max,
	}
}

// Add appends an alert to the ring buffer, evicting the oldest when full.
func (ab *AlertBuffer) Add(level, alertType, peerID, message string) {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	ev := AlertEventDTO{
		Timestamp: time.Now().Format("15:04:05"),
		Level:     level,
		Type:      alertType,
		PeerID:    peerID,
		Message:   message,
	}
	if len(ab.alerts) >= ab.max {
		ab.alerts = ab.alerts[1:]
	}
	ab.alerts = append(ab.alerts, ev)
}

// GetAll returns a copy of all alerts in reverse chronological order (newest first).
func (ab *AlertBuffer) GetAll() []AlertEventDTO {
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	out := make([]AlertEventDTO, len(ab.alerts))
	for i, a := range ab.alerts {
		out[len(ab.alerts)-1-i] = a
	}
	return out
}

// gcPauseAvgMs computes the average GC pause duration in milliseconds from the
// runtime MemStats circular pause buffer (last 256 pauses).
func gcPauseAvgMs(m *runtime.MemStats) float64 {
	if m.NumGC == 0 {
		return 0
	}
	count := int(m.NumGC)
	if count > 256 {
		count = 256
	}
	var total uint64
	for i := 0; i < count; i++ {
		total += m.PauseNs[i]
	}
	return float64(total) / float64(count) / 1e6
}

// CollectDashboard aggregates all live data into a BootDashboardDTO.
func CollectDashboard(p BootDataProvider) BootDashboardDTO {
	h := p.GetHost()
	now := time.Now()
	uptime := int64(now.Sub(p.GetStartTime()).Seconds())

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	listenAddrs := make([]string, 0)
	if h != nil {
		for _, a := range h.Addrs() {
			listenAddrs = append(listenAddrs, fmt.Sprintf("%s/p2p/%s", a.String(), h.ID()))
		}
	}

	serverInfo := ServerInfoDTO{
		NodeName:       p.GetNodeName(),
		PeerID:         "",
		ShortID:        "",
		Version:        version.Version,
		UptimeSec:      uptime,
		ListenAddrs:    listenAddrs,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		NumGoroutines:  runtime.NumGoroutine(),
		MemoryAllocMB:  float64(m.Alloc) / (1024 * 1024),
		HeapAllocMB:    float64(m.HeapAlloc) / (1024 * 1024),
		StackInUseMB:   float64(m.StackInuse) / (1024 * 1024),
		NumGC:          m.NumGC,
		GCPauseAvgMs:   gcPauseAvgMs(&m),
		PSKEnabled:     p.IsPSKEnabled(),
		ConfiguredPSKs: p.GetPSKCount(),
	}
	if h != nil {
		serverInfo.PeerID = h.ID().String()
		serverInfo.ShortID = formatShortPeerID(h.ID())
	}

	// Connected peers
	peersList := make([]PeerItemDTO, 0)
	subnetRoutesList := make([]SubnetRouteDTO, 0)
	netGroupsMap := make(map[string][]string)

	if h != nil {
		for _, pid := range h.Network().Peers() {
			if pid == h.ID() {
				continue
			}

			conns := h.Network().ConnsToPeer(pid)
			remoteAddrStr := ""
			physicalIP := ""
			transport := "unknown"
			direction := "inbound"
			allMultiaddrs := make([]string, 0, len(conns))

			for _, c := range conns {
				ma := c.RemoteMultiaddr()
				allMultiaddrs = append(allMultiaddrs, ma.String())
			}

			if len(conns) > 0 {
				c := conns[0]
				ma := c.RemoteMultiaddr()
				remoteAddrStr = ma.String()
				if ip, err := manet.ToIP(ma); err == nil {
					physicalIP = ip.String()
				} else {
					physicalIP = extractIPFromMultiaddr(remoteAddrStr)
				}

				if strings.Contains(remoteAddrStr, "quic") {
					transport = "QUIC"
				} else if strings.Contains(remoteAddrStr, "webrtc") {
					transport = "WebRTC"
				} else if strings.Contains(remoteAddrStr, "webtransport") {
					transport = "WebTransport"
				} else if strings.Contains(remoteAddrStr, "tcp") {
					transport = "TCP"
				}

				if c.Stat().Direction == network.DirOutbound {
					direction = "outbound"
				}
			}

			isAuthed := p.IsPeerAuthenticated(pid)
			netID := p.GetPeerNetworkID(pid)
			if netID != "" {
				netGroupsMap[netID] = append(netGroupsMap[netID], pid.String())
			} else if !isAuthed {
				netGroupsMap["unauthenticated"] = append(netGroupsMap["unauthenticated"], pid.String())
			}

			hasPeekMap := p.HasPeekMapListener(pid)
			hasBootRelay := p.HasBootRelayClient(pid)

			nodeName, tapIP, tapIPv6, tapMAC, osStr, archStr, verStr, subnets, isExit, obfsAlgo, obfsMode := p.GetPeerNodeInfo(pid)

			rttMs := int64(0)
			latency := h.Peerstore().LatencyEWMA(pid)
			if latency > 0 {
				rttMs = latency.Milliseconds()
			}

			item := PeerItemDTO{
				PeerID:            pid.String(),
				ShortID:           formatShortPeerID(pid),
				NodeName:          nodeName,
				RemoteMultiaddr:   remoteAddrStr,
				PhysicalIP:        physicalIP,
				Transport:         transport,
				Direction:         direction,
				ConnectedTime:     "",
				ConnectedDuration: "",
				IsAuthenticated:   isAuthed,
				NetworkID:         netID,
				HasPeekMapStream:  hasPeekMap,
				HasBootRelay:      hasBootRelay,
				LatencyMs:         rttMs,
				TapIP:             tapIP,
				TapIPv6:           tapIPv6,
				TapMAC:            tapMAC,
				OS:                osStr,
				Arch:              archStr,
				Version:           verStr,
				AdvertisedSubnets: subnets,
				IsExitNode:        isExit,
				AllMultiaddrs:     allMultiaddrs,
				ObfsAlgo:          obfsAlgo,
				ObfsMode:          obfsMode,
			}
			peersList = append(peersList, item)

			for _, sub := range subnets {
				targetTapIP := tapIP
				if strings.Contains(sub, ":") && tapIPv6 != "" {
					targetTapIP = tapIPv6
				}
				subnetRoutesList = append(subnetRoutesList, SubnetRouteDTO{
					Subnet:    sub,
					PeerID:    pid.String(),
					ShortID:   formatShortPeerID(pid),
					NodeName:  nodeName,
					TapIP:     targetTapIP,
					TapIPv6:   tapIPv6,
					NetworkID: netID,
				})
			}
		}
	}

	// Networks list
	netGroups := make([]NetworkGroup, 0, len(netGroupsMap))
	for nID, pList := range netGroupsMap {
		netGroups = append(netGroups, NetworkGroup{
			NetworkID: nID,
			PeerCount: len(pList),
			PeerIDs:   pList,
		})
	}

	// Mesh peers
	meshList := make([]MeshPeerDTO, 0)
	for _, mp := range p.GetMeshPeers() {
		addrs := make([]string, 0, len(mp.Addrs))
		for _, a := range mp.Addrs {
			addrs = append(addrs, a.String())
		}
		isConn := false
		if h != nil && h.Network().Connectedness(mp.ID) == network.Connected {
			isConn = true
		}
		latencyMs := int64(0)
		if h != nil {
			if lat := h.Peerstore().LatencyEWMA(mp.ID); lat > 0 {
				latencyMs = lat.Milliseconds()
			}
		}
		meshList = append(meshList, MeshPeerDTO{
			PeerID:            mp.ID.String(),
			ShortID:           formatShortPeerID(mp.ID),
			Addrs:             addrs,
			IsConnected:       isConn,
			HasBackboneStream: isConn,
			LatencyMs:         latencyMs,
		})
	}

	// Collect new module data
	relaySessions := p.GetRelaySessions()
	geoNodes := p.GetGeoNodes()
	geoArcs := p.GetGeoArcs()
	trafficHistory := p.GetTrafficHistory()
	health := p.GetHealth(peersList)
	config := p.GetConfigSummary()

	return BootDashboardDTO{
		Server: serverInfo,
		Relay: RelayStatsDTO{
			MaxCircuits:        1024,
			MaxReservations:    1024,
			ActiveReservations: len(peersList),
			MaxPerPeer:         16,
			MaxPerIP:           64,
			DurationLimitSec:   300,
			DataLimitMB:        512,
		},
		PeekMap: PeekMapStatsDTO{
			ActiveListeners: p.GetPeekMapListenerCount(),
			TotalPeersSeen:  len(peersList),
		},
		Peers:          peersList,
		SubnetRoutes:   subnetRoutesList,
		Mesh:           meshList,
		Alerts:         p.GetRecentAlerts(),
		Networks:       netGroups,
		RelaySessions:  relaySessions,
		GeoNodes:       geoNodes,
		GeoArcs:        geoArcs,
		TrafficHistory: trafficHistory,
		Health:         health,
		Config:         config,
	}
}

func formatShortPeerID(pid peer.ID) string {
	s := pid.String()
	if len(s) <= 16 {
		return s
	}
	return s[:7] + "..." + s[len(s)-6:]
}

func extractIPFromMultiaddr(maStr string) string {
	parts := strings.Split(maStr, "/")
	for i, p := range parts {
		if (p == "ip4" || p == "ip6") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
