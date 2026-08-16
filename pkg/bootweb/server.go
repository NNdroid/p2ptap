package bootweb

import (
	"context"
	"crypto/rand"
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
}

// NewServer creates a new boot WebUI server.
func NewServer(provider BootDataProvider, listenAddr, authToken string) *Server {
	if listenAddr == "" {
		listenAddr = ":8080"
	}
	// If authToken is empty, generate a random 16-character secure token
	if authToken == "" {
		b := make([]byte, 8)
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
	// 1. Query param
	if token := r.URL.Query().Get("token"); token != "" {
		if token == s.authToken {
			return true
		}
	}
	// 2. Authorization header: Bearer <token>
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		if strings.TrimPrefix(authHeader, "Bearer ") == s.authToken {
			return true
		}
	}
	// 3. X-Auth-Token header
	if r.Header.Get("X-Auth-Token") == s.authToken {
		return true
	}
	return false
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Auth-Token")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Auth-Token")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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
	if s.authToken == "" || req.Token == s.authToken {
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
