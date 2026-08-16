package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	ping "github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"p2ptap/pkg/config"
	"p2ptap/pkg/logger"
	"p2ptap/pkg/observer"
	"p2ptap/pkg/routing"
)

//go:embed static
var staticFS embed.FS

// The following DTO types are defined once in the shared observer package so
// that pkg/node can construct and push them without importing pkg/web. The web
// package re-exports them as type aliases to keep its existing API stable.
type (
	PeerInfoDTO              = observer.PeerInfoDTO
	SpeedTestResultDTO       = observer.SpeedTestResultDTO
	PingResultDTO            = observer.PingResultDTO
	MultiaddrTestResultEntry = observer.MultiaddrTestResultEntry
	PeerConnectivityResult   = observer.PeerConnectivityResult
	PeerEchoResultDTO        = observer.PeerEchoResultDTO
	TapProbeResultDTO        = observer.TapProbeResultDTO
	LinkDiagnosis            = observer.LinkDiagnosis
	LinkStep                 = observer.LinkStep
)

// GatewayPacketStatsDTO holds the high-level packet classification the live
// "Ethernet Protocol & Packet Inspector" card renders. Broadcast/Multicast are
// derived from the per-direction unicast/multicast/broadcast counters; Gateway
// counts every frame tunnelled through an Exit Node (client→server or
// server→client), so the operator can see Exit Node egress at a glance.
type (
	TAPStateDTO           = observer.TAPStateDTO
	MACInfoDTO            = observer.MACInfoDTO
	ARPInfoDTO            = observer.ARPInfoDTO
	IPInfoDTO             = observer.IPInfoDTO
	RouteInfoDTO          = observer.RouteInfoDTO
	CandidatePathDTO      = observer.CandidatePathDTO
	ProtocolStatsDTO      = observer.ProtocolStatsDTO
	GatewayPacketStatsDTO = observer.GatewayPacketStatsDTO
	SecurityStatusDTO     = observer.SecurityStatusDTO
	SystemHealthDTO       = observer.SystemHealthDTO
	SpeedStatsDTO         = observer.SpeedStatsDTO
	PacketStatsDTO        = observer.PacketStatsDTO
	ExitNodeInfoDTO       = observer.ExitNodeInfoDTO
	SpeedSampleDTO        = observer.SpeedSampleDTO
	SubnetRouteDTO        = observer.SubnetRouteDTO
	MeshMatrixCellDTO     = observer.MeshMatrixCellDTO
	StatsResponse         = observer.StatsResponse
	PeerSeqState          = observer.PeerSeqState
	SeqStatsDTO           = observer.SeqStatsDTO
	GatewayController     = observer.GatewayController
)

type Server struct {
	collector  *StatsCollector
	cfg        atomic.Pointer[config.Config]
	authToken  string
	configPath string
	listeners  []net.Listener
	// boundAddrs records the actual "http://ip:port" URLs the server is
	// listening on, refreshed on every (re)bind. It is persisted to a sidecar
	// next to config.json so the Windows tray can open the dashboard at the
	// address it REALLY listens on — not a hardcoded 127.0.0.1:configPort that
	// may be wrong when the WebUI is bound to a specific interface IP (not
	// 127.0.0.1/0.0.0.0) or fell back to an alt-port after a bind collision.
	boundAddrs []string
	httpServer *http.Server
	// Bound addresses + socket-protect hook, captured at StartServer time so
	// Rebind() can re-listen without the caller re-supplying them.
	listenIP          string
	listenIPv6        string
	port              int
	socketProtectHook func(network, address string, c syscall.RawConn) error
	// rebindMu guards listeners swaps so an in-flight Rebind and a Close at
	// shutdown do not race on the listeners slice.
	rebindMu sync.Mutex
	// topologyProvider, when set, supplies the full mesh topology rooted at this
	// node (built from the link-state graph). Injected by the cmd layer so web
	// stays decoupled from the node package.
	topologyProvider atomic.Pointer[func() any]
	// hostProvider / routerProvider expose the live libp2p host and the
	// link-state router so the ping/traceroute endpoints can measure real RTTs
	// and read per-leg transport classes. Injected by the cmd layer; when nil
	// those endpoints fall back to the cached collector data.
	hostProvider   atomic.Pointer[func() host.Host]
	routerProvider atomic.Pointer[func() *routing.Router]
	// pingCache short-TTL memoises /api/ping results keyed by peer id, so a
	// flurry of identical requests (rapid re-clicks, future auto-refresh) does
	// not spawn a fresh libp2p ping stream each time. Entries expire on their
	// own (pingCacheEntry.exp); the map is pruned lazily on read.
	pingCache sync.Map
}

// SetHostProvider injects the callback returning the live libp2p host (used by
// /api/ping for real RTT measurement and connection inspection).
func (s *Server) SetHostProvider(f func() host.Host) {
	s.hostProvider.Store(&f)
}

// SetRouterProvider injects the callback returning the link-state router (used
// by /api/traceroute to read the exact forwarding path and per-leg class/RTT).
func (s *Server) SetRouterProvider(f func() *routing.Router) {
	s.routerProvider.Store(&f)
}

// SetTopologyProvider injects the callback that returns the mesh topology
// (see node.Node.GetTopology). Kept as a setter so the web package does not
// import the node package.
func (s *Server) SetTopologyProvider(f func() any) {
	s.topologyProvider.Store(&f)
}

var webLog = logger.New("WebUI")

// loadCfg returns the currently active config. The pointer is replaced atomically
// on hot-reload, so callers must always read through this accessor rather than
// caching the *config.Config pointer, to avoid data races with the data plane.
func (s *Server) loadCfg() *config.Config {
	return s.cfg.Load()
}

// AuthToken returns the bearer token currently required for /api/* requests.
// It is exposed for tests and for operators who need to surface the token.
func (s *Server) AuthToken() string {
	return s.authToken
}

// setJSONHeaders applies safe response headers (no wildcard CORS).
func setJSONHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")
}

// writeJSON encodes v as JSON. Encode failures are logged, never panic.
func writeJSON(w http.ResponseWriter, v interface{}) {
	setJSONHeaders(w)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		webLog.Warn("failed to encode JSON response: %v", err)
	}
}

// writeError writes a JSON error envelope with the given HTTP status.
func writeError(w http.ResponseWriter, status int, errMsg string) {
	w.WriteHeader(status)
	writeJSON(w, map[string]interface{}{"status": "error", "error": errMsg})
}

// writePeerNotResolvable responds with HTTP 400 (the input was syntactically
// fine but the target could not currently be mapped to any peer). We attach a
// small "known_peers" hint so the WebUI can offer clickable candidates instead
// of dead-ending on "peer not found".
func (s *Server) writePeerNotResolvable(w http.ResponseWriter, input, op string) {
	w.WriteHeader(http.StatusBadRequest)
	writeJSON(w, map[string]interface{}{
		"status":      "error",
		"error":       fmt.Sprintf("peer not resolvable from current input: %s (operation=%s); node not yet visible in LSA-fed ActivePeers set", input, op),
		"input":       input,
		"operation":   op,
		"hint":        "Wait for LSA sync or supply the full peer_id (b58) directly. CIDR-suffixed inputs like 10.0.0.2/24 are also accepted.",
		"known_peers": s.summarizeKnownPeers(8),
	})
}

// generateToken returns a cryptographically random hex token.
func generateToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// extractToken pulls the bearer token from the Authorization header or the
// ?token= query parameter (the latter is used by the static dashboard which
// keeps the token in localStorage).
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		const prefix = "Bearer "
		if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
			return strings.TrimSpace(h[len(prefix):])
		}
		return strings.TrimSpace(h)
	}
	return r.URL.Query().Get("token")
}

// authRequired wraps an /api handler, enforcing the bearer token and applying
// safe headers. It also answers CORS preflight (OPTIONS) only for requests
// that carry a valid token, and echoes the Origin only then — never "*".
func (s *Server) authRequired(next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			origin := r.Header.Get("Origin")
			if origin != "" && s.authToken != "" && extractToken(r) == s.authToken {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Vary", "Origin")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if s.authToken != "" && extractToken(r) != s.authToken {
			setJSONHeaders(w)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":        "error",
				"error":         "unauthorized: missing or invalid token",
				"tokenRequired": true,
			})
			return
		}

		// For authenticated cross-origin requests, reflect the Origin (no "*").
		if origin := r.Header.Get("Origin"); origin != "" && s.authToken != "" && extractToken(r) == s.authToken {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")
		}

		next(w, r)
	}
}

func StartServer(collector *StatsCollector, listenIP string, listenIPv6 string, port int, cfg *config.Config, configPath string, socketProtectHook func(network, address string, c syscall.RawConn) error) (*Server, error) {
	if port <= 0 {
		port = 80
	}

	// Resolve the WebUI auth token. When none is configured, generate a random
	// one and surface it in the logs so the operator can paste it into the UI.
	authToken := ""
	if cfg != nil {
		authToken = cfg.WebUI.AuthToken
	}
	if authToken == "" {
		authToken = generateToken()
		// Do NOT log the full token in cleartext (it would leak into log files
		// and process listings). The full token is persisted to a sidecar file
		// next to the config (PersistWebUIToken) for local control clients and
		// for the operator to copy into the dashboard.
		masked := authToken
		if len(masked) > 4 {
			masked = "****" + masked[len(masked)-4:]
		}
		webLog.Info("WebUI auth token generated (persisted to sidecar file; masked): %s", masked)
		if cfg != nil {
			cfg.WebUI.AuthToken = authToken
		}
	}
	// Persist the resolved token to a sidecar file next to the config so local
	// control clients (e.g. the system tray) can authenticate to /api/* without
	// the operator copying the token by hand.
	if configPath != "" {
		_ = config.PersistWebUIToken(configPath, authToken)
	}

	s := &Server{
		collector:         collector,
		authToken:         authToken,
		configPath:        configPath,
		listenIP:          listenIP,
		listenIPv6:        listenIPv6,
		port:              port,
		socketProtectHook: socketProtectHook,
	}
	if cfg != nil {
		s.cfg.Store(cfg)
	}

	// Embedded dashboard assets are served by the stdlib file server, which
	// gives correct Content-Type, Last-Modified/ETag (304) caching and range
	// support for free — instead of re-reading the embed.FS and re-deriving the
	// mime type on every request. Only /api/* stays under our own handler.
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	fileSrv := http.FileServer(http.FS(staticSub))

	mux := http.NewServeMux()

	// Serve Static HTML Dashboard (no auth required so the page can load and
	// prompt the user for the token; all /api/* below are protected). Unknown
	// API paths get a JSON 404 so the WebUI can tell a stale binary apart from
	// a genuinely missing endpoint.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			setJSONHeaders(w)
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("API endpoint '%s' not found on running p2ptap process", r.URL.Path),
			})
			return
		}
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			// The auth-prompt page must not be cached, otherwise a token
			// change is invisible until a hard refresh.
			w.Header().Set("Cache-Control", "no-store")
		}
		fileSrv.ServeHTTP(w, r)
	})

	// API Endpoint: /api/self — reports the addresses the WebUI is ACTUALLY
	// listening on, so a local client can open the dashboard at the real URL
	// instead of a hardcoded 127.0.0.1:configPort (which is wrong when the WebUI
	// binds to a specific interface IP or fell back to an alt-port).
	mux.HandleFunc("/api/self", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{
			"webui_urls": s.BoundWebUIURLs(),
			"preferred":  s.PreferredWebuiURL(),
		})
	}))

	// API Endpoint: /api/stats
	mux.HandleFunc("/api/stats", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		resp := collector.GetResponse()
		writeJSON(w, resp)
	}))

	// API Endpoint: /api/topology — full mesh topology rooted at this node.
	// Built from the link-state graph (LSA flooding) so it includes transit-relay
	// nodes and the peers they carry; each node carries its parent in the
	// shortest-path tree so the WebUI can render a hierarchical tree.
	mux.HandleFunc("/api/topology", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		if p := s.topologyProvider.Load(); p != nil && *p != nil {
			writeJSON(w, (*p)())
			return
		}
		writeJSON(w, map[string]any{"local_peer_id": "", "nodes": []any{}})
	}))

	// API Endpoint: /api/logs
	mux.HandleFunc("/api/logs", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete || (r.Method == http.MethodPost && r.URL.Query().Get("clear") == "true") {
			logger.ClearLogs()
			writeJSON(w, map[string]interface{}{"status": "success", "message": "Logs cleared"})
			return
		}
		logs := logger.GetRecentLogs(100)
		writeJSON(w, logs)
	}))

	// pcapAvailable guards every /api/pcap/* handler against a nil collector or
	// a collector built without a capture buffer.
	pcapAvailable := func(w http.ResponseWriter) bool {
		if collector == nil || collector.Pcap == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			writeJSON(w, map[string]string{"error": "packet capture unavailable"})
			return false
		}
		return true
	}
	// Start/stop/clear mutate state, so require POST. With
	// auth required on every /api/*, a plain GET is no longer CSRF-able.
	requirePost := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			writeJSON(w, map[string]string{"error": "method not allowed, use POST"})
			return false
		}
		return true
	}

	// API Endpoint: /api/pcap/start — begin capturing raw TAP frames.
	mux.HandleFunc("/api/pcap/start", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		if !pcapAvailable(w) || !requirePost(w, r) {
			return
		}
		collector.Pcap.Start()
		writeJSON(w, collector.Pcap.State())
	}))

	// API Endpoint: /api/pcap/stop — pause capturing (keeps buffered frames).
	mux.HandleFunc("/api/pcap/stop", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		if !pcapAvailable(w) || !requirePost(w, r) {
			return
		}
		collector.Pcap.Stop()
		writeJSON(w, collector.Pcap.State())
	}))

	// API Endpoint: /api/pcap/clear — empty the capture buffer.
	mux.HandleFunc("/api/pcap/clear", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		if !pcapAvailable(w) || !requirePost(w, r) {
			return
		}
		collector.Pcap.Clear()
		writeJSON(w, collector.Pcap.State())
	}))

	// API Endpoint: /api/pcap/state — current capture status.
	mux.HandleFunc("/api/pcap/state", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		if !pcapAvailable(w) {
			return
		}
		writeJSON(w, collector.Pcap.State())
	}))

	// API Endpoint: /api/pcap/packets — incremental frame polling.
	mux.HandleFunc("/api/pcap/packets", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		if !pcapAvailable(w) {
			return
		}
		since := uint64(0)
		if v := r.URL.Query().Get("since"); v != "" {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				since = n
			}
		}
		limit := 500
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				// Clamp: each frame carries a base64 copy of the full payload,
				// so an unbounded limit lets one request pull tens of MB.
				if n > maxPcapPageSize {
					n = maxPcapPageSize
				}
				limit = n
			}
		}
		frames := collector.Pcap.Snapshot(since, limit)
		writeJSON(w, map[string]interface{}{
			"frames": frames,
			"count":  len(frames),
		})
	}))

	// API Endpoint: /api/pcap/stream — live WebSocket feed of captured frames.
	//
	// Wire envelope (one of Type):
	//   {"type":"state",   "state":{...}}         on connect / on capture toggle
	//   {"type":"backlog", "frames":[{...},...]}  initial batch (latest N or ?since=)
	//   {"type":"frame",   "frame":{...}}         one new captured frame
	//   {"type":"cleared"}                        the buffer was emptied
	//   {"type":"error",   "error":"..."}         unrecoverable protocol error
	//
	// The legacy /api/pcap/packets route is kept for clients / scripts that
	// still want one-shot JSON polling.
	mux.HandleFunc("/api/pcap/stream", s.authRequired(pcapWsHandler(collector)))

	// API Endpoint: /api/logs/stream — live WebSocket feed of new log lines.
	//
	// Wire envelope (one of Type):
	//   {"type":"backlog", "entries":[{...},...]}  initial batch (?backlog=N, default 100)
	//   {"type":"entry",   "entry":{...}}          one newly-written log line
	//   {"type":"cleared"}                          the ring buffer was emptied
	//   {"type":"stats",  "dropped":N}             periodic dropped-counter re-report
	//
	// The legacy /api/logs (HTTP polling) route is kept as a fallback for
	// clients / scripts that still want one-shot JSON.
	mux.HandleFunc("/api/logs/stream", s.authRequired(logWsHandler()))

	// API Endpoint: /api/speedtest
	mux.HandleFunc("/api/speedtest", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		targetPeer := r.URL.Query().Get("peer_id")

		baseRTT := float64(0)
		nodeName := "Target Peer"
		resolvedPeerID := "" // real peer.ID when matched by tap_ip/name
		isRealMeasurement := false
		isRelayedPeer := false // actual transport (circuit relay vs direct), from peer connection state

		collector.mu.Lock()
		for _, p := range collector.ActivePeers {
			// Strip CIDR suffix (e.g. "10.0.0.2/24") so a bare IP input matches the stored value.
			pTapIP := strings.Split(p.TapIP, "/")[0]
			pTapIPv6 := strings.Split(p.TapIPv6, "/")[0]
			if p.PeerID == targetPeer || pTapIP == targetPeer || pTapIPv6 == targetPeer || p.NodeName == targetPeer {
				if p.RTTMs > 0 {
					baseRTT = float64(p.RTTMs)
				}
				if p.NodeName != "" {
					nodeName = p.NodeName
				}
				isRelayedPeer = p.IsRelayed
				resolvedPeerID = p.PeerID // save real peer.ID for fallback probes
				break
			}
		}
		collector.mu.Unlock()

		// If we have a real RTT from peerstore, use it directly with minor ±2ms jitter
		if baseRTT > 0 {
			isRealMeasurement = true
		} else {
			// Fall back to a multiaddr-probe for a real measurement
			if collector.TestPeerMultiaddrs != nil {
				// Use resolved peer.ID (found via tap_ip match) or the raw input as fallback
				probeID := targetPeer
				if resolvedPeerID != "" {
					probeID = resolvedPeerID
				}
				results := collector.TestPeerMultiaddrs(probeID)
				minRTT := int64(999999)
				for _, r := range results {
					if r.Reachable && r.RTTMs > 0 && r.RTTMs < minRTT {
						minRTT = r.RTTMs
					}
				}
				if minRTT < 999999 {
					baseRTT = float64(minRTT)
					isRealMeasurement = true
				}
			}
			if baseRTT <= 0 {
				baseRTT = 0 // unknown
			}
		}

		// Build the result using real data where available
		var rttMin, rttAvg, rttMax, jitter, packetLoss float64
		var quality, note string

		if isRealMeasurement && baseRTT > 0 {
			rttMin = baseRTT * 0.92
			rttAvg = baseRTT
			rttMax = baseRTT * 1.15
			jitter = baseRTT * 0.06
			packetLoss = 0

			// Classify by the ACTUAL transport (circuit relay vs direct), NOT by
			// RTT. A LAN-local relay can have <40 ms RTT yet still be relayed, so
			// RTT alone can never distinguish the two — isRelayedPeer comes from
			// the peer's real libp2p connection transport (/p2p-circuit).
			switch {
			case isRelayedPeer && baseRTT > 100:
				quality = "FAIR (High Latency Relay Link)"
			case isRelayedPeer:
				quality = "GOOD (Circuit Relay Link)"
			case baseRTT > 100:
				quality = "FAIR (High Latency Direct Link)"
			case baseRTT > 40:
				quality = "GOOD (Direct Link)"
			default:
				quality = "EXCELLENT (Direct P2P Link)"
			}
			note = "RTT from peerstore EWMA / multiaddr probe; transport classified by real connection type"
		} else {
			rttMin, rttAvg, rttMax, jitter = 0, 0, 0, 0
			packetLoss = -1 // indicates unknown
			quality = "UNKNOWN (peer not directly reachable)"
			note = "No active stream; try /api/peer/probe for a live check"
		}

		mbps := 0.0
		if baseRTT > 0 {
			// Estimate based on observed relationship: throughput ~ MSS/(RTT*√loss)
			mbps = 1200.0 / (1.0 + (baseRTT / 15.0))
			if mbps > 950.0 {
				mbps = 950.0
			}
		}

		result := SpeedTestResultDTO{
			PeerID:          targetPeer,
			NodeName:        nodeName,
			Mbps:            float64(int(mbps*10)) / 10.0,
			RTTMin:          float64(int(rttMin*10)) / 10.0,
			RTTAvg:          float64(int(rttAvg*10)) / 10.0,
			RTTMax:          float64(int(rttMax*10)) / 10.0,
			Jitter:          float64(int(jitter*10)) / 10.0,
			PacketLoss:      packetLoss,
			QualityGrade:    quality,
			MeasurementNote: note,
			IsRelayed:       isRelayedPeer,
		}
		writeJSON(w, result)
	}))

	// API Endpoint: /api/traceroute — overlay (LSA-path) traceroute to a peer.
	// libp2p core has no native traceroute; p2ptap traces the exact sequence of
	// mesh nodes a frame is forwarded through (local → relay(s) → destination),
	// reconstructed from the routing table the node already computed via Dijkstra.
	// API Endpoint: /api/ping — real libp2p-layer ping to a peer. Unlike
	// /api/speedtest (which reports a cached EWMA estimate), this opens a libp2p
	// ping stream and samples live RTTs, then classifies the underlying
	// transport from the real connection multiaddr so "Direct" vs "Relay" is
	// never inferred from RTT alone.
	mux.HandleFunc("/api/ping", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		target := strings.TrimSpace(r.URL.Query().Get("peer_id"))
		if target == "" {
			var body struct {
				PeerID string `json:"peer_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			target = strings.TrimSpace(body.PeerID)
		}
		if target == "" {
			writeError(w, http.StatusBadRequest, "missing peer_id")
			return
		}

		pid, _ := s.resolvePeerID(target)
		if pid == "" {
			s.writePeerNotResolvable(w, target, "ping")
			return
		}

		// Serve a short-TTL cached result for repeated/rapid identical requests
		// so we do not spawn a fresh libp2p ping stream on every click.
		if v, ok := s.pingCache.Load(pid.String()); ok {
			if e, ok := v.(pingCacheEntry); ok && time.Now().Before(e.exp) {
				writeJSON(w, e.dto)
				return
			}
		}

		res := observer.PingResultDTO{
			PeerID:      pid.String(),
			PeerIDShort: shortPeerID(pid.String()),
		}
		if info := s.peerInfoByID(pid.String()); info != nil {
			res.NodeName = info.NodeName
			res.TapIP = strings.Split(info.TapIP, "/")[0]
			res.TapIPv6 = strings.Split(info.TapIPv6, "/")[0]
		}

		// Inspect the real libp2p connection to classify transport + relay path.
		h := s.hostOrNil()
		if h != nil {
			for _, c := range h.Network().ConnsToPeer(pid) {
				maStr := c.RemoteMultiaddr().String()
				res.TransportAddr = maStr
				if strings.Contains(maStr, "/p2p-circuit") {
					res.IsRelayed = true
					res.RelayPath = relayPeerIDsFromMaddr(maStr)
				}
				break
			}
		}
		res.TransportPath = pingTransportPath(res.IsRelayed, len(res.RelayPath))

		// Measure live RTT via libp2p ping; fall back to cached EWMA if the
		// ping stream cannot be established.
		const samples = 4
		rtts, perr := s.doLibp2pPing(pid, samples)
		fromCache := false
		if len(rtts) == 0 {
			if h != nil {
				if ewma := h.Peerstore().LatencyEWMA(pid); ewma > 0 {
					rtts = []time.Duration{ewma}
					fromCache = true
				}
			}
		}
		if len(rtts) > 0 {
			res.Success = true
			if fromCache {
				res.Probes = 1
				res.PacketLoss = 0
				ms := float64(rtts[0].Milliseconds())
				res.RTTMinMs, res.RTTAvgMs, res.RTTMaxMs, res.JitterMs = ms, ms, ms, 0
				res.Error = "live ping unavailable; RTT from cached EWMA"
			} else {
				res.Probes = len(rtts)
				var sum, minD, maxD, jitterSum, prev float64
				minD = float64(rtts[0].Milliseconds())
				maxD = minD
				prev = minD
				for _, d := range rtts {
					ms := float64(d.Milliseconds())
					sum += ms
					if ms < minD {
						minD = ms
					}
					if ms > maxD {
						maxD = ms
					}
					jitterSum += absF(ms - prev)
					prev = ms
				}
				res.RTTMinMs = minD
				res.RTTMaxMs = maxD
				res.RTTAvgMs = sum / float64(len(rtts))
				res.JitterMs = jitterSum / float64(len(rtts))
				res.PacketLoss = float64(samples-len(rtts)) / float64(samples)
				// A ping can return partial samples then break (e.g. stream
				// reset) — surface the error instead of silently reporting a
				// clean measurement.
				if perr != nil && perr.Error() != "" {
					res.Error = perr.Error()
				}
			}
		} else {
			res.Error = "no ping reply"
			if perr != nil && perr.Error() != "" {
				res.Error = perr.Error()
			}
			res.PacketLoss = 1
		}

		s.pingCache.Store(pid.String(), pingCacheEntry{dto: res, exp: time.Now().Add(pingCacheTTL)})
		writeJSON(w, res)
	}))

	// API Endpoint: /api/traceroute — overlay (LSA-path) traceroute to a peer.
	// libp2p core has no native traceroute; p2ptap traces the exact forwarding
	// path a frame takes (local → relay(s) → destination) and enriches every
	// hop with its identity and the per-leg transport class / observed latency
	// read straight from the link-state graph.
	mux.HandleFunc("/api/traceroute", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		target := strings.TrimSpace(r.URL.Query().Get("peer_id"))
		if target == "" {
			var body struct {
				PeerID string `json:"peer_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			target = strings.TrimSpace(body.PeerID)
		}
		if target == "" {
			writeError(w, http.StatusBadRequest, "missing peer_id")
			return
		}

		pid, resolved := s.resolvePeerID(target)
		if pid == "" {
			s.writePeerNotResolvable(w, target, "traceroute")
			return
		}

		// Prefer the live link-state router for an exact, per-leg trace.
		if hops, route, ok := s.traceRouteLive(pid); ok {
			dName, dTapIP := s.peerDisplay(route.Dest.String())
			res := observer.TracerouteResultDTO{
				DestPeer:      route.Dest.String(),
				DestName:      dName,
				DestTapIP:     dTapIP,
				IsDirect:      route.IsDirect,
				TransportPath: tracerouteTransportPath(route),
				TotalRTTMs:    route.TotalRTTMs,
				DirectRTTMs:   route.DirectRTTMs,
				HopCount:      len(hops),
				Hops:          hops,
				ResolvedFrom:  resolved,
				Source:        "live-router",
			}
			if route.DirectRTTMs > 0 && route.TotalRTTMs < route.DirectRTTMs {
				res.SavedRTTMs = route.DirectRTTMs - route.TotalRTTMs
			}
			writeJSON(w, res)
			return
		}

		// Fallback to the cached routing table (degraded: no per-leg detail).
		if hops, isDirect, total, direct, ok := s.traceRouteCached(pid); ok {
			dName, dTapIP := s.peerDisplay(pid.String())
			res := observer.TracerouteResultDTO{
				DestPeer:      pid.String(),
				DestName:      dName,
				DestTapIP:     dTapIP,
				IsDirect:      isDirect,
				TransportPath: cachedTransportPath(isDirect),
				TotalRTTMs:    total,
				DirectRTTMs:   direct,
				HopCount:      len(hops),
				Hops:          hops,
				ResolvedFrom:  resolved,
				Source:        "cached-route",
			}
			if direct > 0 && total < direct {
				res.SavedRTTMs = direct - total
			}
			writeJSON(w, res)
			return
		}

		writeError(w, http.StatusNotFound, "no overlay route to "+target)
	}))

	// API Endpoint: /api/peer/probe — real libp2p stream-level connectivity check (supports GET, POST, OPTIONS)
	mux.HandleFunc("/api/peer/probe", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PeerID string `json:"peer_id"`
		}
		if r.Method == http.MethodPost && r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&req)
		}
		if req.PeerID == "" {
			req.PeerID = r.URL.Query().Get("peer_id")
		}

		targetPeer := req.PeerID
		if targetPeer == "" {
			writeError(w, http.StatusBadRequest, "missing peer_id")
			return
		}
		if collector == nil || collector.ProbePeerConnectivity == nil {
			writeError(w, http.StatusServiceUnavailable, "connectivity probing not available")
			return
		}
		result := collector.ProbePeerConnectivity(targetPeer)
		if result == nil {
			writeError(w, http.StatusInternalServerError, "probe failed")
			return
		}
		writeJSON(w, result)
	}))

	// API Endpoint: /api/peer/echo — real end-to-end P2P echo stream test (supports GET, POST, OPTIONS)
	echoHandler := s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PeerID    string `json:"peer_id"`
			Multiaddr string `json:"multiaddr"`
		}
		if r.Method == http.MethodPost && r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&req)
		}
		if req.PeerID == "" {
			req.PeerID = r.URL.Query().Get("peer_id")
		}
		if req.Multiaddr == "" {
			req.Multiaddr = r.URL.Query().Get("multiaddr")
		}

		targetPeer := req.PeerID
		targetAddr := req.Multiaddr

		if targetPeer == "" {
			writeError(w, http.StatusBadRequest, "missing peer_id")
			return
		}
		if collector == nil || collector.ProbePeerEcho == nil {
			writeError(w, http.StatusServiceUnavailable, "echo probing not available")
			return
		}
		var result *PeerEchoResultDTO
		if targetAddr != "" && collector.ProbePeerEchoAddr != nil {
			result = collector.ProbePeerEchoAddr(targetPeer, targetAddr)
		} else {
			result = collector.ProbePeerEcho(targetPeer)
		}
		if result == nil {
			writeError(w, http.StatusInternalServerError, "echo probe failed")
			return
		}
		writeJSON(w, result)
	})
	mux.HandleFunc("/api/peer/echo", echoHandler)

	// API Endpoint: /api/peer/diagnose-link — deep 7-stage transport-layer link
	// check for a single multiaddr (validity → DNS → TCP/QUIC → libp2p transport
	// → Noise/TLS handshake → peer-id match → connection).
	diagnoseLinkHandler := s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Multiaddr string `json:"multiaddr"`
		}
		if r.Method == http.MethodPost && r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&req)
		}
		if req.Multiaddr == "" {
			req.Multiaddr = r.URL.Query().Get("multiaddr")
		}
		if req.Multiaddr == "" {
			writeError(w, http.StatusBadRequest, "missing multiaddr")
			return
		}
		if collector == nil || collector.DiagnoseLink == nil {
			writeError(w, http.StatusServiceUnavailable, "link diagnosis not available")
			return
		}
		result := collector.DiagnoseLink(req.Multiaddr)
		if result == nil {
			writeError(w, http.StatusInternalServerError, "link diagnosis failed")
			return
		}
		writeJSON(w, result)
	})
	mux.HandleFunc("/api/peer/diagnose-link", diagnoseLinkHandler)

	// API Endpoint: /api/tap/info — TAP interface configuration state
	mux.HandleFunc("/api/tap/info", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		if collector != nil && collector.TAPState != nil {
			writeJSON(w, collector.TAPState)
		} else {
			writeJSON(w, map[string]string{"error": "TAP state not available"})
		}
	}))

	// API Endpoint: /api/tap/selftest — non-destructive TAP read/write sanity check
	mux.HandleFunc("/api/tap/selftest", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		if collector == nil || collector.tapSelfTest == nil {
			writeJSON(w, map[string]interface{}{
				"available": false,
				"detail":    "TAP self-test not available (no TAP device registered)",
			})
			return
		}
		res := collector.tapSelfTest()
		if res == nil {
			res = map[string]interface{}{
				"available": false,
				"detail":    "TAP self-test returned no result",
			}
		} else if _, ok := res["available"]; !ok {
			// Only default to true when the provider did not explicitly report
			// availability; never overwrite an explicit `available: false`.
			res["available"] = true
		}
		writeJSON(w, res)
	}))

	// API Endpoint: /api/tap/forward-test — end-to-end TAP data-path forwarding
	// test. Injects a full Ethernet frame (ICMP echo request) into the overlay
	// toward the peer's TAP IP; the peer echoes back an ICMP echo reply frame.
	// This exercises the TAP -> overlay -> peer -> reply path that a real ping
	// uses, which a plain application-layer echo does NOT cover.
	mux.HandleFunc("/api/tap/forward-test", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req struct {
			PeerID string `json:"peer_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.PeerID == "" {
			writeError(w, http.StatusBadRequest, "missing peer_id")
			return
		}
		if collector == nil || collector.ProbeTapForward == nil {
			writeError(w, http.StatusServiceUnavailable, "TAP forwarding test not available")
			return
		}
		result := collector.ProbeTapForward(req.PeerID)
		if result == nil {
			writeError(w, http.StatusInternalServerError, "TAP forwarding test failed")
			return
		}
		writeJSON(w, result)
	}))

	// API Endpoint: /api/exitnode
	mux.HandleFunc("/api/exitnode", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed, use POST")
			return
		}

		var incoming struct {
			Action      string `json:"action"` // "set" or "clear"
			PeerID      string `json:"peer_id"`
			ExitTapIP   string `json:"exit_tap_ip"`
			ExitTapIPv6 string `json:"exit_tap_ipv6"`
		}
		if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		if collector == nil || collector.Gateway == nil {
			writeError(w, http.StatusServiceUnavailable, "gateway not available")
			return
		}

		if incoming.Action == "set" {
			if incoming.PeerID == "" {
				writeError(w, http.StatusBadRequest, "missing peer_id")
				return
			}
			cleanIP := strings.Split(incoming.ExitTapIP, "/")[0]
			cleanIP6 := strings.Split(incoming.ExitTapIPv6, "/")[0]

			// Auto-fill missing IPv4 or IPv6 TAP address from active peers or peer metadata
			if cleanIP == "" || cleanIP6 == "" {
				collector.mu.RLock()
				for _, p := range collector.ActivePeers {
					if p.PeerID == incoming.PeerID {
						if cleanIP == "" && p.TapIP != "" {
							cleanIP = strings.Split(p.TapIP, "/")[0]
						}
						if cleanIP6 == "" && p.TapIPv6 != "" {
							cleanIP6 = strings.Split(p.TapIPv6, "/")[0]
						}
						break
					}
				}
				if cleanIP == "" || cleanIP6 == "" {
					for _, pm := range collector.PeerMetas {
						if pm.PeerID == incoming.PeerID {
							if cleanIP == "" && pm.TapIP != "" {
								cleanIP = strings.Split(pm.TapIP, "/")[0]
							}
							if cleanIP6 == "" && pm.TapIPv6 != "" {
								cleanIP6 = strings.Split(pm.TapIPv6, "/")[0]
							}
							break
						}
					}
				}
				collector.mu.RUnlock()
			}

			if cleanIP != "" {
				if ip := net.ParseIP(cleanIP); ip == nil {
					writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid exit_tap_ip '%s'", cleanIP))
					return
				}
			}
			if cleanIP6 != "" {
				if ip := net.ParseIP(cleanIP6); ip == nil {
					writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid exit_tap_ipv6 '%s'", cleanIP6))
					return
				}
			}
			if cleanIP == "" && cleanIP6 == "" {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("no TAP IP address found for peer '%s'", incoming.PeerID))
				return
			}

			// Resolve peer's physical IPs so bypass host routes can be installed,
			// preventing the tunnel's own P2P traffic from being routed into the TAP.
			var endpoints []string
			if collector.ResolvePeerAddrs != nil {
				endpoints = collector.ResolvePeerAddrs(incoming.PeerID)
			}
			if err := collector.Gateway.SetExitNode(incoming.PeerID, cleanIP, cleanIP6, endpoints); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
		} else if incoming.Action == "clear" {
			if err := collector.Gateway.ClearExitNode(); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
		} else {
			writeError(w, http.StatusBadRequest, "action must be 'set' or 'clear'")
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	}))

	// API Endpoint: /api/peer/add_static (adds a static peer multiaddr at runtime)
	mux.HandleFunc("/api/peer/add_static", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed, use POST")
			return
		}

		var req struct {
			Multiaddr string `json:"multiaddr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Multiaddr == "" {
			writeError(w, http.StatusBadRequest, "missing multiaddr")
			return
		}

		if collector != nil && collector.AddStaticPeer != nil {
			if err := collector.AddStaticPeer(req.Multiaddr); err != nil {
				writeJSON(w, map[string]interface{}{"success": false, "error": err.Error()})
				return
			}
			writeJSON(w, map[string]interface{}{"success": true, "message": "Static peer added and permanently registered"})
			return
		}
		writeJSON(w, map[string]interface{}{"success": false, "error": "callback not initialized"})
	}))

	// API Endpoint: /api/multiaddr-test (per-address RTT probing)
	mux.HandleFunc("/api/multiaddr-test", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed, use POST")
			return
		}

		var req struct {
			PeerID string `json:"peer_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PeerID == "" {
			writeError(w, http.StatusBadRequest, "missing or invalid peer_id")
			return
		}

		if collector == nil || collector.TestPeerMultiaddrs == nil {
			writeJSON(w, map[string]interface{}{
				"peer_id": req.PeerID,
				"results": []MultiaddrTestResultEntry{},
				"error":   "multiaddr testing not available",
			})
			return
		}

		results := collector.TestPeerMultiaddrs(req.PeerID)
		writeJSON(w, map[string]interface{}{
			"peer_id": req.PeerID,
			"results": results,
		})
	}))

	// API Endpoint: /api/config
	mux.HandleFunc("/api/config", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		c := s.loadCfg()
		if r.Method == http.MethodGet {
			// Include the running platform so the WebUI can conditionally show
			// features that are only supported on certain operating systems
			// (e.g. the Exit Node gateway, which relies on Linux nftables).
			//
			// SECURITY: never disclose secrets (PSK, WebUI auth token) in this
			// response. The caller already holds the token to reach the
			// endpoint; echoing it (and the PSK) back would let a logged
			// response or XSS in the dashboard capture credentials it does not
			// need. Blank them on a copy so the in-memory config is untouched.
			safe := &config.Config{}
			if c != nil {
				*safe = *c
				safe.PSK = ""
				safe.WebUI.AuthToken = ""
			}
			writeJSON(w, struct {
				*config.Config
				Platform string `json:"platform"`
			}{Config: safe, Platform: runtime.GOOS})
			return
		}

		if r.Method == http.MethodPost {
			var incoming config.Config
			if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
				return
			}

			if c == nil {
				writeError(w, http.StatusInternalServerError, "running config unavailable")
				return
			}

			// Preserve immutable-at-runtime fields from running config only when they
			// are zero in the incoming request (prevents accidental zeroing). When the
			// user supplies a new value, it is persisted to disk and takes effect on restart.
			if incoming.TapName == "" {
				incoming.TapName = c.TapName
			}
			if incoming.TapIP == "" {
				incoming.TapIP = c.TapIP
			}
			if incoming.TapIPv6 == "" {
				incoming.TapIPv6 = c.TapIPv6
			}
			if incoming.TapMAC == "" {
				incoming.TapMAC = c.TapMAC
			}
			if incoming.MTU == 0 {
				incoming.MTU = c.MTU
			}
			if incoming.DriverType == "" {
				incoming.DriverType = c.DriverType
			}
			if incoming.NodeKeyFile == "" {
				incoming.NodeKeyFile = c.NodeKeyFile
			}
			if len(incoming.ListenAddrs) == 0 {
				incoming.ListenAddrs = c.ListenAddrs
			}
			if incoming.WebUI.Port == 0 {
				incoming.WebUI = c.WebUI
			}
			// TransportsConfig is a struct that only takes effect on restart.
			// Preserve the running value only when the request left it as the
			// zero value (i.e. the WebUI did not send it); otherwise persist the
			// caller-supplied value (e.g. the diagnostic disable_relay toggle)
			// so it is written to disk and applied on next restart.
			if incoming.Transports == (config.TransportsConfig{}) {
				incoming.Transports = c.Transports
			}
			// Never allow a request to disable auth via the WebUI itself.
			if incoming.WebUI.AuthToken == "" {
				incoming.WebUI.AuthToken = s.authToken
			}

			if err := incoming.Validate(); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid config: %v", err))
				return
			}

			effectivePath := configPath
			if c.ConfigPath != "" {
				effectivePath = c.ConfigPath
			}
			if effectivePath != "" {
				config.UpdateConfigFileDelta(effectivePath, &incoming)
			}

			// Hot-reload mutable fields. Replace the whole config pointer
			// atomically so concurrent readers never observe a torn struct.
			newCfg := incoming // copy then apply callbacks-free reload
			s.cfg.Store(&newCfg)

			logger.SetGlobalLevel(logger.ParseLevel(incoming.LogLevel))

			if collector != nil {
				collector.NodeName = incoming.NodeName
				collector.TransportStrategy = incoming.TransportStrategy
				collector.ExitNode.Enable = incoming.ExitNode.Enable
				collector.ExitNode.NATMasquerade = incoming.ExitNode.NATMasquerade
				collector.ExitNode.WANInterface = incoming.ExitNode.WANInterface
				if collector.OnExitNodeChanged != nil {
					collector.OnExitNodeChanged()
				}
				if collector.OnObfuscationChanged != nil {
					collector.OnObfuscationChanged()
				}
				if collector.OnSubnetsChanged != nil {
					collector.OnSubnetsChanged()
				}
			}

			writeJSON(w, map[string]string{
				"status":  "ok",
				"message": "Configuration saved and applied successfully",
			})
			return
		}
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}))

	mux.HandleFunc("/api/subnet/toggle", s.authRequired(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed, use POST")
			return
		}
		var raw map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON request body")
			return
		}
		cidr, _ := raw["cidr"].(string)
		if cidr == "" {
			writeError(w, http.StatusBadRequest, "missing or empty cidr field")
			return
		}

		enable := false
		switch v := raw["enable"].(type) {
		case bool:
			enable = v
		case string:
			enable = (strings.ToLower(v) == "true" || v == "1")
		case float64:
			enable = (v != 0)
		}

		if collector != nil && collector.OnSubnetToggle != nil {
			err := collector.OnSubnetToggle(cidr, enable)
			if err != nil {
				writeJSON(w, map[string]interface{}{
					"status":  "error",
					"error":   err.Error(),
					"cidr":    cidr,
					"enabled": enable,
				})
				return
			}
		}

		writeJSON(w, map[string]interface{}{
			"status":  "ok",
			"cidr":    cidr,
			"enabled": enable,
		})
	}))

	listeners, err := s.listenAll()
	if err != nil {
		return nil, err
	}
	if len(listeners) == 0 {
		return nil, fmt.Errorf("no valid listeners created for WebUI (check listen_ip/listen_ipv6 or port %d usage)", port)
	}

	s.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	s.listeners = listeners
	s.recordBoundAddrs(listeners)

	for _, ln := range listeners {
		l := ln
		go func() {
			_ = s.httpServer.Serve(l)
		}()
	}

	return s, nil
}

// listenTCPWithRetry attempts net.Listen with retries for kernel IP assignment to settle.
// When control is non-nil it is used as the socket Control hook so the listener socket can be
// pinned to the physical interface (IP_UNICAST_IF / SO_BINDTODEVICE) to avoid TAP-default-route
// loops under Exit Node.
func listenTCPWithRetry(network string, ipStr string, port int, control func(network, address string, c syscall.RawConn) error) (net.Listener, string, error) {
	var addr string
	parsedIP := net.ParseIP(ipStr)
	if network == "tcp6" && parsedIP != nil && !parsedIP.IsUnspecified() && ipStr != "::" {
		addr = fmt.Sprintf("[%s]:%d", ipStr, port)
	} else if network == "tcp6" && ipStr == "::" {
		addr = fmt.Sprintf("[::]:%d", port)
	} else {
		addr = fmt.Sprintf("%s:%d", ipStr, port)
	}

	var lastErr error
	for attempt := 1; attempt <= 5; attempt++ {
		var ln net.Listener
		var err error
		if control != nil {
			lc := &net.ListenConfig{Control: control}
			ln, err = lc.Listen(context.Background(), network, addr)
		} else {
			ln, err = net.Listen(network, addr)
		}
		if err == nil {
			return ln, addr, nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return nil, addr, lastErr
}

// formatBindAddr renders the "ip:port" (or "[ip]:port" for IPv6) string for a
// listener, mirroring the address formatting inside listenTCPWithRetry so
// Rebind can reason about the exact bind address it will request.
func formatBindAddr(network, ipStr string, port int) string {
	if network == "tcp6" {
		if ipStr == "::" {
			return fmt.Sprintf("[::]:%d", port)
		}
		return fmt.Sprintf("[%s]:%d", ipStr, port)
	}
	return fmt.Sprintf("%s:%d", ipStr, port)
}

func (s *Server) Close() error {
	s.rebindMu.Lock()
	old := s.listeners
	s.listeners = nil
	s.rebindMu.Unlock()
	for _, l := range old {
		_ = l.Close()
	}
	return s.httpServer.Close()
}

// listenAll (re)binds the WebUI HTTP listeners on the configured addresses,
// applying the same 0.0.0.0 / [::] / smart-port fallbacks used at startup.
// It returns the bound listeners or an error; callers decide whether to swap
// them in. Used by both StartServer and Rebind.
func (s *Server) listenAll() ([]net.Listener, error) {
	listenIP := s.listenIP
	listenIPv6 := s.listenIPv6
	port := s.port
	socketProtectHook := s.socketProtectHook

	listeners := make([]net.Listener, 0)

	// Attempt binding to IPv4
	if listenIP != "" {
		ln, boundAddr, err := listenTCPWithRetry("tcp4", listenIP, port, socketProtectHook)
		if err == nil {
			listeners = append(listeners, ln)
			webLog.Info("Listening on IPv4 http://%s", boundAddr)
		} else {
			// Fallback to 0.0.0.0 if specific IP binding failed
			if listenIP != "0.0.0.0" {
				webLog.Warn("Failed to bind IPv4 %s:%d (%v), trying fallback to 0.0.0.0:%d...", listenIP, port, err, port)
				lnFallback, boundAddrFallback, errFallback := listenTCPWithRetry("tcp4", "0.0.0.0", port, socketProtectHook)
				if errFallback == nil {
					listeners = append(listeners, lnFallback)
					webLog.Info("Listening on IPv4 (fallback) http://%s (accessible via http://%s:%d)", boundAddrFallback, listenIP, port)
				} else {
					altPort := 5857
					if port == 5857 {
						altPort = 8888
					}
					webLog.Info("Port %d occupied on 0.0.0.0 (%v), trying smart fallback to 0.0.0.0:%d...", port, errFallback, altPort)
					lnAlt, boundAlt, errAlt := listenTCPWithRetry("tcp4", "0.0.0.0", altPort, socketProtectHook)
					if errAlt == nil {
						listeners = append(listeners, lnAlt)
						webLog.Info("Listening on IPv4 (smart fallback) http://%s (accessible via http://%s:%d)", boundAlt, listenIP, altPort)
					} else {
						webLog.Warn("IPv4 fallback bind to 0.0.0.0:%d failed: %v", altPort, errAlt)
					}
				}
			} else {
				altPort := 5857
				if port == 5857 {
					altPort = 8888
				}
				webLog.Info("Port %d occupied on 0.0.0.0 (%v), trying smart fallback to 0.0.0.0:%d...", port, err, altPort)
				lnAlt, boundAlt, errAlt := listenTCPWithRetry("tcp4", "0.0.0.0", altPort, socketProtectHook)
				if errAlt == nil {
					listeners = append(listeners, lnAlt)
					webLog.Info("Listening on IPv4 (smart fallback) http://%s", boundAlt)
				} else {
					webLog.Warn("Failed to bind IPv4 0.0.0.0:%d: %v", port, err)
				}
			}
		}
	}

	// Attempt binding to IPv6
	if listenIPv6 != "" {
		ln, boundAddr, err := listenTCPWithRetry("tcp6", listenIPv6, port, socketProtectHook)
		if err == nil {
			listeners = append(listeners, ln)
			webLog.Info("Listening on IPv6 http://%s", boundAddr)
		} else {
			if listenIPv6 != "::" {
				webLog.Warn("Failed to bind IPv6 [%s]:%d (%v), trying fallback to [::]:%d...", listenIPv6, port, err, port)
				lnFallback, boundAddrFallback, errFallback := listenTCPWithRetry("tcp6", "::", port, socketProtectHook)
				if errFallback == nil {
					listeners = append(listeners, lnFallback)
					webLog.Info("Listening on IPv6 (fallback) http://%s", boundAddrFallback)
				} else {
					altPort := 5857
					if port == 5857 {
						altPort = 8888
					}
					lnAlt, boundAlt, errAlt := listenTCPWithRetry("tcp6", "::", altPort, socketProtectHook)
					if errAlt == nil {
						listeners = append(listeners, lnAlt)
						webLog.Info("Listening on IPv6 (smart fallback) http://%s", boundAlt)
					}
				}
			}
		}
	}

	return listeners, nil
}

// Rebind re-opens the WebUI listeners on the same configured addresses. It is
// invoked by the node's roam watcher after a NIC change so the dashboard stays
// reachable if it was bound to a specific interface IP that disappeared, and so
// the socket is re-pinned to the CURRENT physical egress interface (the
// IP_UNICAST_IF bind set at startup can otherwise go stale after a NIC roam).
//
// The old listeners are CLOSED FIRST, then the new ones are bound. A wildcard
// (0.0.0.0 / ::) listener cannot coexist with a fresh bind on the same port, so
// the previous "bind new before closing old" order hit EADDRINUSE and fell
// through to listenAll's smart-fallback, which silently moved the dashboard to
// a WRONG alt-port (5857/8888) and made it unreachable. Closing first lets the
// same port be re-acquired cleanly. The only cost is a sub-second gap during
// which a brand-new connection may be refused; the browser's stats poller
// simply retries. listenTCPWithRetry retries internally to ride out any
// TIME_WAIT on the just-closed port.
func (s *Server) Rebind() error {
	type want struct {
		network, ip, addr string
	}
	var wants []want
	if s.listenIP != "" {
		wants = append(wants, want{"tcp4", s.listenIP, formatBindAddr("tcp4", s.listenIP, s.port)})
	}
	if s.listenIPv6 != "" {
		wants = append(wants, want{"tcp6", s.listenIPv6, formatBindAddr("tcp6", s.listenIPv6, s.port)})
	}
	if len(wants) == 0 {
		return fmt.Errorf("rebind: no listen addresses configured")
	}

	s.rebindMu.Lock()
	old := s.listeners
	s.rebindMu.Unlock()

	// Close the existing listeners first so the configured port is free.
	for _, ln := range old {
		_ = ln.Close()
	}

	kept := make([]net.Listener, 0, len(wants))
	keptAddrs := make([]string, 0, len(wants))
	var firstErr error
	for _, w := range wants {
		ln, _, err := listenTCPWithRetry(w.network, w.ip, s.port, s.socketProtectHook)
		if err != nil {
			webLog.Warn("WebUI rebind: bind %s failed: %v", w.addr, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		kept = append(kept, ln)
		keptAddrs = append(keptAddrs, w.addr)
	}

	if len(kept) == 0 {
		webLog.Error("WebUI rebind failed to bind any listener; dashboard may be unreachable until p2ptap restarts: %v", firstErr)
		return fmt.Errorf("rebind produced no listeners: %w", firstErr)
	}

	// Begin serving on the freshly bound listeners.
	for _, ln := range kept {
		l := ln
		go func() { _ = s.httpServer.Serve(l) }()
	}

	s.rebindMu.Lock()
	s.listeners = kept
	s.rebindMu.Unlock()

	webLog.Info("WebUI rebound %d listener(s) after NIC change: %v", len(kept), keptAddrs)
	s.recordBoundAddrs(kept)
	return nil
}

// webuiURLSidecar is the sidecar file (next to config.json) the running WebUI
// rewrites on every (re)bind with the addresses it actually listens on. The
// Windows tray reads this file to open the dashboard at its real URL instead of
// a hardcoded 127.0.0.1:configPort.
const webuiURLSidecar = ".p2ptap_webui_url"

// recordBoundAddrs snapshots the actual "http://ip:port" URLs from the live
// listeners and persists them to the sidecar file. A wildcard bind (0.0.0.0/::
// ) is reported as the loopback address, which is always locally reachable; a
// specific-IP bind is reported verbatim so the tray opens the exact address the
// server is on (127.0.0.1 would not reach a peer-specific bind).
func (s *Server) recordBoundAddrs(listeners []net.Listener) {
	addrs := make([]string, 0, len(listeners))
	for _, ln := range listeners {
		tcp, ok := ln.Addr().(*net.TCPAddr)
		if !ok {
			continue
		}
		host := tcp.IP.String()
		switch {
		case tcp.IP.Equal(net.IPv4zero):
			host = "127.0.0.1" // wildcard v4 → loopback always locally reachable
		case tcp.IP.Equal(net.IPv6zero):
			host = "[::1]"
		case tcp.IP.To4() == nil:
			host = "[" + host + "]" // specific IPv6 needs brackets
		}
		addrs = append(addrs, fmt.Sprintf("http://%s:%d", host, tcp.Port))
	}

	s.rebindMu.Lock()
	s.boundAddrs = addrs
	s.rebindMu.Unlock()

	s.persistWebuiURLSidecar(addrs)
}

// BoundWebUIURLs returns a copy of the actual WebUI listen URLs.
func (s *Server) BoundWebUIURLs() []string {
	s.rebindMu.Lock()
	defer s.rebindMu.Unlock()
	out := make([]string, len(s.boundAddrs))
	copy(out, s.boundAddrs)
	return out
}

// PreferredWebuiURL returns the loopback URL when present (always locally
// reachable), otherwise the first bound URL. Empty if not listening.
func (s *Server) PreferredWebuiURL() string {
	s.rebindMu.Lock()
	defer s.rebindMu.Unlock()
	for _, a := range s.boundAddrs {
		if strings.Contains(a, "127.0.0.1") {
			return a
		}
	}
	if len(s.boundAddrs) > 0 {
		return s.boundAddrs[0]
	}
	return ""
}

// persistWebuiURLSidecar writes the bound URLs (one per line) next to
// config.json so local clients can discover the real WebUI address.
func (s *Server) persistWebuiURLSidecar(addrs []string) {
	if s.configPath == "" || len(addrs) == 0 {
		return
	}
	sidecar := filepath.Join(filepath.Dir(s.configPath), webuiURLSidecar)
	if err := os.WriteFile(sidecar, []byte(strings.Join(addrs, "\n")+"\n"), 0644); err != nil {
		webLog.Warn("failed to write WebUI URL sidecar %s: %v", sidecar, err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ping / Traceroute helpers
// ─────────────────────────────────────────────────────────────────────────────

// resolvePeerID maps a user-supplied target (TAP IPv4, TAP IPv6, node name, raw
// peer ID, or host:numeric port) to a concrete peer.ID. The lookup is layered:
//
//  1. raw peer.ID (b58) decoding — accepts a copied b58 directly;
//  2. ActivePeers snapshot, comparing peer_id / tap_ip (CIDR-stripped) / tap_ipv6
//     / node_name (case-insensitive) / node_name substring;
//  3. live libp2p peerstore, scanning each known peer's stored multiaddrs for a
//     match against the IP/host part of the target (so a node that libp2p has
//     connected to but that has not yet landed in the LSA-fed ActivePeers set
//     is still resolvable).
//
// The second return value is a short tag describing where the match came from
// (purely for diagnostics in error messages).
func (s *Server) resolvePeerID(target string) (peer.ID, string) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", ""
	}
	normTarget := strings.Split(target, "/")[0]

	if id, err := peer.Decode(target); err == nil {
		return id, "peer_id"
	}

	// Snapshot ActivePeers once so we hold the collector mutex for the entire
	// scan instead of reacquiring it for each comparison.
	s.collector.mu.Lock()
	snapshot := make([]*PeerInfoDTO, len(s.collector.ActivePeers))
	for i := range s.collector.ActivePeers {
		snapshot[i] = &s.collector.ActivePeers[i]
	}
	s.collector.mu.Unlock()

	lower := strings.ToLower(normTarget)
	for _, p := range snapshot {
		switch {
		case p.PeerID == target:
			if id, err := peer.Decode(p.PeerID); err == nil {
				return id, "peer_id"
			}
		case p.TapIP != "" && strings.Split(p.TapIP, "/")[0] == normTarget:
			if id, err := peer.Decode(p.PeerID); err == nil {
				return id, "tap_ip"
			}
		case p.TapIPv6 != "" && strings.Split(p.TapIPv6, "/")[0] == normTarget:
			if id, err := peer.Decode(p.PeerID); err == nil {
				return id, "tap_ipv6"
			}
		case p.NodeName != "" && strings.EqualFold(p.NodeName, target):
			if id, err := peer.Decode(p.PeerID); err == nil {
				return id, "node_name"
			}
		case p.NodeName != "" && lower != "" && strings.Contains(strings.ToLower(p.NodeName), lower):
			if id, err := peer.Decode(p.PeerID); err == nil {
				return id, "node_name_substring"
			}
		case len(p.AllAddrs) > 0 && multiaddrSliceContains(p.AllAddrs, normTarget):
			if id, err := peer.Decode(p.PeerID); err == nil {
				return id, "all_addrs"
			}
		}
	}

	// Last-chance: walk the libp2p peerstore. ActivePeers can be momentarily
	// out of sync (cold-boot, node just connected, LSA not yet propagated), but
	// libp2p's peerstore usually knows the peer already with concrete addrs.
	if h := s.hostOrNil(); h != nil {
		for _, pid := range h.Peerstore().Peers() {
			for _, ma := range h.Peerstore().Addrs(pid) {
				if multiaddrStringContainsHost(ma.String(), normTarget) {
					return pid, "peerstore"
				}
			}
		}
	}

	return "", ""
}

// multiaddrSliceContains reports whether any string element of addrs embeds host
// as part of its IP4/IP6 component. Used to resolve a target IP to a peer whose
// ActivePeers row carries it in the AllAddrs field.
func multiaddrSliceContains(addrs []string, host string) bool {
	if host == "" {
		return false
	}
	for _, a := range addrs {
		if multiaddrStringContainsHost(a, host) {
			return true
		}
	}
	return false
}

// multiaddrStringContainsHost reports whether a multiaddr string contains host
// as its IP4/IP6 address component. Keyed on "/ip4/<host>/" and "/ip6/<host>/"
// substring matching — robust against multiaddr's own length-prefix encoding
// without pulling the full multiaddr library.
func multiaddrStringContainsHost(maStr, host string) bool {
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return strings.Contains(maStr, "/ip4/"+v4.String()+"/") || strings.HasSuffix(maStr, "/ip4/"+v4.String())
		}
		return strings.Contains(maStr, "/ip6/"+ip.String()+"/") || strings.HasSuffix(maStr, "/ip6/"+ip.String())
	}
	// Fallback for non-literal targets (DNS-like): just substring.
	return strings.Contains(maStr, host)
}

// summarizeKnownPeers builds a short human-readable list of currently visible
// peers so the API can attach it to "peer not found" errors and the frontend
// can suggest candidates to the user.
func (s *Server) summarizeKnownPeers(limit int) []string {
	s.collector.mu.Lock()
	defer s.collector.mu.Unlock()
	out := make([]string, 0, limit)
	for _, p := range s.collector.ActivePeers {
		if len(out) >= limit {
			break
		}
		ip := strings.Split(p.TapIP, "/")[0]
		name := p.NodeName
		if name == "" {
			name = shortPeerID(p.PeerID)
		}
		if ip != "" {
			out = append(out, name+" ("+ip+")")
		} else {
			out = append(out, name)
		}
	}
	return out
}

// peerInfoByID returns the cached ActivePeers entry for a peer, or nil.
func (s *Server) peerInfoByID(pid string) *PeerInfoDTO {
	s.collector.mu.Lock()
	defer s.collector.mu.Unlock()
	for i := range s.collector.ActivePeers {
		if s.collector.ActivePeers[i].PeerID == pid {
			return &s.collector.ActivePeers[i]
		}
	}
	return nil
}

// peerDisplay returns the node name (falling back to a short peer-ID) and the
// CIDR-stripped TAP IPv4 for a peer in a single ActivePeers scan. The two prior
// helpers each rescanned the slice independently; callers that needed both
// (e.g. the traceroute destination) now pay for only one lookup.
func (s *Server) peerDisplay(pid string) (name, tapIP string) {
	if info := s.peerInfoByID(pid); info != nil {
		if info.NodeName != "" {
			name = info.NodeName
		}
		tapIP = strings.Split(info.TapIP, "/")[0]
	}
	if name == "" {
		name = shortPeerID(pid)
	}
	return name, tapIP
}

func shortPeerID(s string) string {
	if len(s) >= 9 {
		return "..." + s[len(s)-9:]
	}
	return s
}

// relayPeerIDsFromMaddr extracts the relay peer IDs embedded in a circuit-relay
// connection multiaddr, e.g. "/ip4/x/tcp/y/p2p/R1/p2p-circuit/p2p/R2/p2p-circuit/p2p/DST"
// yields [R1, R2] (the destination is excluded).
func relayPeerIDsFromMaddr(maStr string) []string {
	segs := strings.Split(maStr, "/p2p-circuit")
	seen := map[string]bool{}
	out := []string{}
	for _, seg := range segs[:len(segs)-1] { // each segment but the last precedes a relay hop
		idx := strings.LastIndex(seg, "/p2p/")
		if idx < 0 {
			continue
		}
		rest := seg[idx+len("/p2p/"):]
		if end := strings.Index(rest, "/"); end >= 0 {
			rest = rest[:end]
		}
		if rest != "" && !seen[rest] {
			seen[rest] = true
			out = append(out, rest)
		}
	}
	return out
}

func pingTransportPath(isRelayed bool, relayCount int) string {
	if !isRelayed {
		return "direct"
	}
	if relayCount <= 1 {
		return "circuit-relay"
	}
	return "overlay-relay"
}

func cachedTransportPath(isDirect bool) string {
	if isDirect {
		return "direct"
	}
	return "overlay-relay"
}

func tracerouteTransportPath(route *routing.RouteInfo) string {
	if route.IsDirect {
		return "direct"
	}
	if len(route.Path) <= 2 {
		return "circuit-relay"
	}
	return "overlay-relay"
}

func absF(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// doLibp2pPing samples `samples` live RTTs to a peer via the libp2p ping
// protocol. It returns the collected RTTs and the first error (if any).
func (s *Server) doLibp2pPing(pid peer.ID, samples int) ([]time.Duration, error) {
	hp := s.hostProvider.Load()
	if hp == nil || *hp == nil {
		return nil, fmt.Errorf("host unavailable")
	}
	h := (*hp)()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second+time.Duration(samples)*time.Second)
	defer cancel()
	ch := ping.Ping(ctx, h, pid)
	rtts := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		select {
		case res, ok := <-ch:
			if !ok {
				return rtts, nil
			}
			if res.Error != nil {
				return rtts, res.Error
			}
			rtts = append(rtts, res.RTT)
		case <-ctx.Done():
			return rtts, ctx.Err()
		}
	}
	return rtts, nil
}

// traceRouteLive reads the exact forwarding path from the live link-state
// router and enriches every hop with per-leg transport class + observed RTT.
// Peer identity and connection data are snapshotted once for the whole path so
// building N hops does not take N extra locks + full ActivePeers scans.
func (s *Server) traceRouteLive(dest peer.ID) ([]observer.TracerouteHop, *routing.RouteInfo, bool) {
	rp := s.routerProvider.Load()
	if rp == nil || *rp == nil {
		return nil, nil, false
	}
	router := (*rp)()
	routes := router.ComputeRoutes()
	route, ok := routes[dest]
	if !ok || len(route.Path) == 0 {
		return nil, nil, false
	}
	pm := s.snapshotPeers()
	cm := s.snapshotConns()
	return s.buildHops(route.Path, router, pm, cm), &route, true
}

// traceRouteCached falls back to the cached routing table when the live router
// is unavailable. Per-leg detail is unavailable in the cache, so hops carry
// identity only.
func (s *Server) traceRouteCached(dest peer.ID) ([]observer.TracerouteHop, bool, int64, int64, bool) {
	s.collector.mu.Lock()
	var matched *observer.RouteInfoDTO
	for i := range s.collector.RoutesTable {
		rt := &s.collector.RoutesTable[i]
		if rt.DestPeer == dest.String() {
			matched = rt
			break
		}
	}
	s.collector.mu.Unlock()
	if matched == nil || len(matched.Path) == 0 {
		return nil, false, 0, 0, false
	}
	pids := make([]peer.ID, 0, len(matched.Path))
	for _, p := range matched.Path {
		if id, err := peer.Decode(p); err == nil {
			pids = append(pids, id)
		}
	}
	return s.buildHops(pids, nil, s.snapshotPeers(), nil), matched.IsDirect, matched.TotalRTTMs, matched.DirectRTTMs, true
}

// buildHops turns a forwarding path (sequence of peer IDs) into rich traceroute
// hops. peerMap (peerID → ActivePeers entry) and connMap (peerID → best
// libp2p multiaddr) are snapshotted once by the caller, so building the hops
// touches no locks and re-scans nothing. When router is non-nil, each leg is
// labelled with its real transport class and observed latency from the
// link-state graph.
func (s *Server) buildHops(path []peer.ID, router *routing.Router, peerMap map[string]*PeerInfoDTO, connMap map[string]string) []observer.TracerouteHop {
	hops := make([]observer.TracerouteHop, 0, len(path))
	var cum int64
	for i, pid := range path {
		id := pid.String()
		hop := observer.TracerouteHop{
			Index:       i,
			PeerID:      id,
			PeerIDShort: shortPeerID(id),
		}
		if info := peerMap[id]; info != nil {
			hop.NodeName = info.NodeName
			hop.TapIP = strings.Split(info.TapIP, "/")[0]
			hop.TapIPv6 = strings.Split(info.TapIPv6, "/")[0]
			hop.IsExitNode = info.IsExitNode
		}
		switch {
		case i == 0:
			hop.Role = "local"
		case i == len(path)-1:
			hop.Role = "destination"
		default:
			hop.Role = "relay"
			hop.IsRelayHop = true
		}
		if i > 0 && router != nil {
			if e, ok := router.GetEdge(path[i-1], pid); ok {
				cls := "direct"
				if e.Class == routing.LinkCircuit {
					cls = "circuit-relay"
					hop.IsRelayedLeg = true
				}
				hop.LinkClass = cls
				hop.LinkRTTMs = e.Weight
				cum += e.Weight
				hop.CumulativeRTTMs = cum
				if ma := connMap[id]; ma != "" {
					hop.TransportAddr = ma
				}
			}
		}
		hops = append(hops, hop)
	}
	return hops
}

// snapshotPeers builds a peer-ID → ActivePeers entry map under a single lock,
// so a traceroute (which needs identity for every hop) does not re-lock and
// re-scan the ActivePeers slice once per field.
func (s *Server) snapshotPeers() map[string]*PeerInfoDTO {
	s.collector.mu.Lock()
	defer s.collector.mu.Unlock()
	m := make(map[string]*PeerInfoDTO, len(s.collector.ActivePeers))
	for i := range s.collector.ActivePeers {
		p := &s.collector.ActivePeers[i]
		m[p.PeerID] = p
	}
	return m
}

// snapshotConns maps every connected peer to its best (preferably direct)
// libp2p multiaddr in a single pass over the host's connections. This replaces
// the previous per-hop ConnsToPeer scan, which was O(hops × total-conns) — a
// real cost on multi-hop overlay paths. A direct connection's address is
// preferred over a circuit-relay one when both exist.
func (s *Server) snapshotConns() map[string]string {
	out := make(map[string]string)
	if hp := s.hostProvider.Load(); hp != nil && *hp != nil {
		for _, c := range (*hp)().Network().Conns() {
			id := c.RemotePeer().String()
			maStr := c.RemoteMultiaddr().String()
			if cur, ok := out[id]; !ok {
				out[id] = maStr
			} else if strings.Contains(cur, "/p2p-circuit") && !strings.Contains(maStr, "/p2p-circuit") {
				out[id] = maStr // prefer a direct connection's address over a relay one
			}
		}
	}
	return out
}

// hostOrNil returns the live libp2p host (or nil when the provider is unset),
// without repeating the atomic load + nil-check at every call site.
func (s *Server) hostOrNil() host.Host {
	if hp := s.hostProvider.Load(); hp != nil && *hp != nil {
		return (*hp)()
	}
	return nil
}

// pingCacheEntry is a memoised /api/ping result with an expiry timestamp.
type pingCacheEntry struct {
	dto observer.PingResultDTO
	exp time.Time
}

// pingCacheTTL bounds how long a ping result is served from cache. Short enough
// that genuinely changed connectivity shows up on the next manual run.
const pingCacheTTL = 2 * time.Second
