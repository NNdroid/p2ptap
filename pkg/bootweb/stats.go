package bootweb

import (
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"p2ptap/pkg/maddrutil"
	"p2ptap/pkg/node"
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

	// LastSeenPublicAddrs is this boot's PERSISTENT record of the peer's direct
	// endpoints, from the peer address store. It survives a disconnect and a
	// restart, unlike RemoteMultiaddr / AllMultiaddrs which describe only live
	// connections and the live peerstore.
	LastSeenPublicAddrs []string `json:"last_seen_public_addrs"`
	FirstSeenAt         string   `json:"first_seen_at"`
	LastSeenAt          string   `json:"last_seen_at"`
	DirectSeenCount     int      `json:"direct_seen_count"`
}

// ObservedAddrsDTO is the boot's persistent record of the public source
// addresses it has seen a peer connect from. It is the display form of the
// peer address store entry.
type ObservedAddrsDTO struct {
	Addrs       []string `json:"addrs"`
	Transports  []string `json:"transports"`
	NetworkID   string   `json:"network_id"`
	FirstSeenAt string   `json:"first_seen_at"`
	LastSeenAt  string   `json:"last_seen_at"`
	SeenCount   int      `json:"seen_count"`
}

// LastSeenPeerDTO describes a peer the boot has observed a direct connection
// from but which is not currently connected. It is how the operator still sees
// history after a restart, and it is the only place a peer whose STUN is fully
// blocked shows up at all.
type LastSeenPeerDTO struct {
	PeerID      string   `json:"peer_id"`
	ShortID     string   `json:"short_id"`
	NodeName    string   `json:"node_name"`
	Addrs       []string `json:"addrs"`
	Transports  []string `json:"transports"`
	NetworkID   string   `json:"network_id"`
	FirstSeenAt string   `json:"first_seen_at"`
	LastSeenAt  string   `json:"last_seen_at"`
	LastSeenAgo string   `json:"last_seen_ago"`
	SeenCount   int      `json:"seen_count"`
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
	Enabled            bool `json:"enabled"`
	MaxCircuits        int  `json:"max_circuits"`
	MaxReservations    int  `json:"max_reservations"`
	ActiveReservations int  `json:"active_reservations"`
	MaxPerPeer         int  `json:"max_per_peer"`
	MaxPerIP           int  `json:"max_per_ip"`
	MaxPerASN          int  `json:"max_per_asn"`
	ReservationTTLSec  int  `json:"reservation_ttl_sec"`
	DurationLimitSec   int  `json:"duration_limit_sec"`
	DataLimitMB        int  `json:"data_limit_mb"`
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
	Level     string `json:"level"` // "warn" | "error" | "info"
	Type      string `json:"type"`  // see alert type constants in main.go
	PeerID    string `json:"peer_id"`
	Message   string `json:"message"`
}

// UnauthEventDTO represents a single rejected/dropped unauthenticated data event.
type UnauthEventDTO struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	PeerID    string `json:"peer_id"`
	Detail    string `json:"detail"`
}

// UnauthStatsDTO holds aggregate counters and recent events for unauthenticated data.
type UnauthStatsDTO struct {
	TotalDropped int64              `json:"total_dropped"`
	ByType       map[string]int64   `json:"by_type"`
	RecentEvents []UnauthEventDTO   `json:"recent_events"`
}

// NetworkGroup groups peers by their PSK Network ID.
type NetworkGroup struct {
	NetworkID string   `json:"network_id"`
	PeerCount int      `json:"peer_count"`
	PeerIDs   []string `json:"peer_ids"`
}

// TrafficPoint is one per-minute time-series sample for the traffic sparkline chart.
type TrafficPoint struct {
	Time       string `json:"time"` // "HH:MM"
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
	LastSeenPeers  []LastSeenPeerDTO `json:"last_seen_peers"`
	UnauthStats    UnauthStatsDTO    `json:"unauth_stats"`
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
	GetUnauthStats() UnauthStatsDTO
	// New methods for enhanced dashboard modules
	GetRelaySessions() []RelaySessionDTO
	GetRelayLimits() RelayStatsDTO
	GetGeoNodes() []GeoNodeDTO
	GetGeoArcs() []GeoArcDTO
	GetTrafficHistory() []TrafficPoint
	GetHealth(peers []PeerItemDTO) HealthCheckDTO
	GetConfigSummary() ConfigSummaryDTO
	// GetPeerObservedAddrs returns the boot's persistent record of the public
	// addresses observed for p, or nil if the peer has never been seen directly.
	// Nil-safe: implementations may return nil when the cache is disabled.
	GetPeerObservedAddrs(p peer.ID) *ObservedAddrsDTO
	// GetPeerConnectedSince returns when p first connected in this process, for
	// the duration column. false means "no such record", which renders as "".
	GetPeerConnectedSince(p peer.ID) (time.Time, bool)
	// GetLastSeenPeers returns peers that have a cached address record but are
	// not currently connected, most recently seen first, capped at limit.
	GetLastSeenPeers(limit int) []LastSeenPeerDTO
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
			listenAddrs = append(listenAddrs, node.WithPeerID(a, h.ID()))
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
			allMultiaddrs := make([]string, 0)
			seenAddrs := make(map[string]bool)

			for _, c := range conns {
				maStr := c.RemoteMultiaddr().String()
				if !seenAddrs[maStr] {
					seenAddrs[maStr] = true
					allMultiaddrs = append(allMultiaddrs, maStr)
				}
			}

			for _, ma := range h.Peerstore().Addrs(pid) {
				maStr := ma.String()
				if !seenAddrs[maStr] {
					seenAddrs[maStr] = true
					allMultiaddrs = append(allMultiaddrs, maStr)
				}
			}

			if len(conns) > 0 {
				c := conns[0]
				ma := c.RemoteMultiaddr()
				remoteAddrStr = ma.String()
				// Only a DIRECT connection reveals the peer's real public IP. On
				// a circuit-relayed link the source IP is the boot's own relay
				// IP, so attributing it to the peer puts the boot's location on
				// every peer routed through it. "" is the honest answer.
				for _, cc := range conns {
					cma := cc.RemoteMultiaddr()
					if cma == nil || maddrutil.IsCircuitRelay(cma) {
						continue
					}
					if ip := node.ExtractIP(cma); ip != nil {
						physicalIP = ip.String()
						break
					}
				}

				switch node.TransportOfConn(c) {
				case "quic":
					transport = "QUIC"
				case "webrtc":
					transport = "WebRTC"
				case "webtransport":
					transport = "WebTransport"
				case "tcp":
					transport = "TCP"
				case "circuit":
					transport = "Circuit Relay"
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

			// Connection duration. These two columns used to be hard-coded "" —
			// the boot records the connect time in gPeerConnectTimes but nothing
			// ever read it for the dashboard.
			connectedTime, connectedDuration := "", ""
			if since, ok := p.GetPeerConnectedSince(pid); ok {
				connectedTime = since.Format("2006-01-02 15:04:05")
				connectedDuration = now.Sub(since).Round(time.Second).String()
			}

			// The persistent, restart-surviving record of this peer's public
			// addresses. nil-safe: an empty ObservedAddrsDTO renders all-empty,
			// which is the right answer for a peer only ever seen over the relay.
			lastSeenAddrs := ObservedAddrsDTO{}
			if o := p.GetPeerObservedAddrs(pid); o != nil {
				lastSeenAddrs = *o
			}

			item := PeerItemDTO{
				PeerID:              pid.String(),
				ShortID:             formatShortPeerID(pid),
				NodeName:            nodeName,
				RemoteMultiaddr:     remoteAddrStr,
				PhysicalIP:          physicalIP,
				Transport:           transport,
				Direction:           direction,
				ConnectedTime:       connectedTime,
				ConnectedDuration:   connectedDuration,
				IsAuthenticated:     isAuthed,
				NetworkID:           netID,
				HasPeekMapStream:    hasPeekMap,
				HasBootRelay:        hasBootRelay,
				LatencyMs:           rttMs,
				TapIP:               tapIP,
				TapIPv6:             tapIPv6,
				TapMAC:              tapMAC,
				OS:                  osStr,
				Arch:                archStr,
				Version:             verStr,
				AdvertisedSubnets:   subnets,
				IsExitNode:          isExit,
				AllMultiaddrs:       allMultiaddrs,
				ObfsAlgo:            obfsAlgo,
				ObfsMode:            obfsMode,
				LastSeenPublicAddrs: lastSeenAddrs.Addrs,
				FirstSeenAt:         lastSeenAddrs.FirstSeenAt,
				LastSeenAt:          lastSeenAddrs.LastSeenAt,
				DirectSeenCount:     lastSeenAddrs.SeenCount,
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
	relayLimits := p.GetRelayLimits()
	geoNodes := p.GetGeoNodes()
	geoArcs := p.GetGeoArcs()
	trafficHistory := p.GetTrafficHistory()
	health := p.GetHealth(peersList)
	config := p.GetConfigSummary()

	return BootDashboardDTO{
		Server: serverInfo,
		Relay: RelayStatsDTO{
			// Limits come from the live relay.Resources the relay was built with,
			// not from a copy of libp2p's DefaultResources(). These used to be
			// hard-coded to 16/128/1/8/120s/0MB while the boot sized the relay at
			// 1024/1024/64/256/300s/512MiB, so the dashboard showed a relay that
			// looked nearly saturated when it was carrying under 1% of capacity —
			// the operator reads "out of relay slots" into a completely empty
			// reservation table.
			Enabled:            relayLimits.Enabled,
			MaxCircuits:        relayLimits.MaxCircuits,
			MaxReservations:    relayLimits.MaxReservations,
			ActiveReservations: len(peersList),
			MaxPerPeer:         relayLimits.MaxPerPeer,
			MaxPerIP:           relayLimits.MaxPerIP,
			MaxPerASN:          relayLimits.MaxPerASN,
			ReservationTTLSec:  relayLimits.ReservationTTLSec,
			DurationLimitSec:   relayLimits.DurationLimitSec,
			DataLimitMB:        relayLimits.DataLimitMB,
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
		LastSeenPeers:  p.GetLastSeenPeers(lastSeenPeersLimit),
		UnauthStats:    p.GetUnauthStats(),
	}
}

// lastSeenPeersLimit caps the "previously seen" list. It is a display cap, not
// a data cap — the store keeps everything, so a larger cache still works and
// the operator just sees the most recent portion.
const lastSeenPeersLimit = 200

func formatShortPeerID(pid peer.ID) string {
	s := pid.String()
	if len(s) <= 16 {
		return s
	}
	return s[:7] + "..." + s[len(s)-6:]
}
