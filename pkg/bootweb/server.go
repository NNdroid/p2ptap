package bootweb

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"p2ptap/pkg/logger"
)

//go:embed static
var staticFS embed.FS

var log = logger.New("BootWeb")

// Server is the HTTP server providing the WebUI dashboard for p2ptap-boot.
type Server struct {
	provider   BootDataProvider
	listenAddr string
	authToken  string
	httpServer *http.Server
	listener   net.Listener
	mu         sync.Mutex

	// /api/auth/verify throttle: the verify endpoint is the only way to
	// check a token guess, so per-source attempts are rate-limited (a
	// fixed ~1/minute window per IP). Without it any web page could drive
	// the operator's browser against a LAN-reachable boot dashboard
	// (brute-force + ok:true/false oracle).
	verifyMu       sync.Mutex
	verifyAttempts map[string]verifyWindow
}

type verifyWindow struct {
	count int
	start time.Time
}

const (
	verifyMaxPerWindow  = 10
	verifyWindowSeconds = 60
)

// allowVerifyAttempt consumes one attempt for ip and reports whether the
// request may proceed. Stale entries are swept opportunistically so the map
// stays bounded by active sources.
func (s *Server) allowVerifyAttempt(ip string) bool {
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()
	if s.verifyAttempts == nil {
		s.verifyAttempts = make(map[string]verifyWindow)
	}
	now := time.Now()
	for k, v := range s.verifyAttempts {
		if now.Sub(v.start) > verifyWindowSeconds*time.Second {
			delete(s.verifyAttempts, k)
		}
	}
	w := s.verifyAttempts[ip]
	if now.Sub(w.start) > verifyWindowSeconds*time.Second {
		w = verifyWindow{count: 0, start: now}
	}
	if w.count >= verifyMaxPerWindow {
		s.verifyAttempts[ip] = w
		return false
	}
	w.count++
	s.verifyAttempts[ip] = w
	return true
}

// NewServer creates a new boot WebUI server.
func NewServer(provider BootDataProvider, listenAddr, authToken string) *Server {
	if listenAddr == "" {
		listenAddr = ":8080"
	}
	// If authToken is empty, generate a random 48-hex-char (192-bit) secure
	// token. Entropy matches the main WebUI's generateToken: this token gates
	// live topology/log views and is checkable via /api/auth/verify.
	if authToken == "" {
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		authToken = hex.EncodeToString(b)
	}
	return &Server{
		provider:   provider,
		listenAddr: listenAddr,
		authToken:  authToken,
	}
}

// GetAuthToken returns the effective authentication token.
func (s *Server) GetAuthToken() string {
	return s.authToken
}

// GetListenAddr returns the configured listen address.
func (s *Server) GetListenAddr() string {
	return s.listenAddr
}

// Start launches the HTTP server in a background goroutine.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bindAddr := s.listenAddr
	// If bound to "0.0.0.0:port", convert to ":port" so Go binds dual-stack IPv4+IPv6!
	if strings.HasPrefix(bindAddr, "0.0.0.0:") {
		bindAddr = ":" + strings.TrimPrefix(bindAddr, "0.0.0.0:")
	}

	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("boot webui listen %s failed: %w", s.listenAddr, err)
	}
	s.listener = ln

	mux := http.NewServeMux()

	// Static web assets
	mux.HandleFunc("/", s.handleIndex)

	// API endpoints
	mux.HandleFunc("/api/auth/verify", s.handleAuthVerify)
	mux.HandleFunc("/api/stats", s.requireAuth(s.handleStats))
	mux.HandleFunc("/api/logs", s.requireAuth(s.handleLogs))

	s.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	go func() {
		if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Warn("Boot WebUI server error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	data, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "Index file not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) checkAuth(r *http.Request) bool {
	if s.authToken == "" {
		return true
	}
	tokenBytes := []byte(s.authToken)
	// 1. Query param
	if token := r.URL.Query().Get("token"); token != "" {
		if subtle.ConstantTimeCompare([]byte(token), tokenBytes) == 1 {
			return true
		}
	}
	// 2. Authorization header: Bearer <token>
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		if subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(authHeader, "Bearer ")), tokenBytes) == 1 {
			return true
		}
	}
	// 3. X-Auth-Token header
	if token := r.Header.Get("X-Auth-Token"); token != "" {
		if subtle.ConstantTimeCompare([]byte(token), tokenBytes) == 1 {
			return true
		}
	}
	return false
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		// No CORS here or on /api/auth/verify: the ONLY consumers are the
		// dashboard's own same-origin fetches (static/index.html). Widening
		// to "*" made every endpoint (and the token oracle) reachable from
		// any web page the operator's browser visits.
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if !s.checkAuth(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
			return
		}
		next(w, r)
	}
}

type authVerifyReq struct {
	Token string `json:"token"`
}

type authVerifyResp struct {
	OK bool `json:"ok"`
}

func (s *Server) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Rate-limit the verify oracle before touching the token.
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	if !s.allowVerifyAttempt(ip) {
		w.Header().Set("Retry-After", "60")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(authVerifyResp{OK: false})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	var req authVerifyReq
	_ = json.Unmarshal(body, &req)

	ok := false
	if s.authToken == "" || subtle.ConstantTimeCompare([]byte(req.Token), []byte(s.authToken)) == 1 {
		ok = true
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(authVerifyResp{OK: ok})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	dashboard := CollectDashboard(s.provider)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dashboard)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	logs := logger.GetRecentLogs(100)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(logs)
}
