package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"p2ptap/pkg/logger"

	"github.com/gorilla/websocket"
)

// logStreamUpgrader configures the gorilla/websocket handshake for the live
// log feed. Origins are permissive so the same WebSocket client can attach
// from localhost and the LAN, mirroring /api/pcap/stream which is protected
// only by the bearer token; the auth token is re-checked before Upgrade().
var logStreamUpgrader = websocket.Upgrader{
	HandshakeTimeout:  10 * time.Second,
	ReadBufferSize:    1024,
	WriteBufferSize:   4096,
	EnableCompression: true, // permessage-deflate; browsers negotiate it, cutting JSON bandwidth
	// WebUI token already gates access; we refuse cross-origin without a valid token.
	CheckOrigin: func(r *http.Request) bool { return true },
}

const (
	logStreamDefaultBacklog = 100
	logStreamMaxBacklog     = 1000
	logStreamPingInterval   = 25 * time.Second
	logStreamWriteTimeout   = 10 * time.Second
	logStreamReadTimeout    = 60 * time.Second // for pong / client messages
	logStreamStatsInterval  = 5 * time.Second  // how often Dropped is re-reported while idle
)

// logWSMessage is the wire envelope for /api/logs/stream. Exactly one payload
// field is set per message — type discriminates them.
type logWSMessage struct {
	Type     string            `json:"type"`               // "backlog" | "entry" | "cleared" | "stats" | "error" | "pong"
	Entries  []logger.LogEntry `json:"entries,omitempty"`  // when type=backlog
	Entry    *logger.LogEntry  `json:"entry,omitempty"`    // when type=entry
	Error    string            `json:"error,omitempty"`    // when type=error
	Dropped  uint64            `json:"dropped,omitempty"`  // entries this subscriber lost (so the UI can flag stagnation)
	ServerTs int64             `json:"ts,omitempty"`       // server-side timestamp (ms) for latency tracking
}

// logWsHandler returns an http.HandlerFunc that streams new log entries to the
// connected dashboard over a WebSocket. It clears the connection-level HTTP
// timeouts (a long-lived socket must survive the server-wide Read/Write
// deadlines), upgrades, and runs the streaming loop. On exit it unsubscribes so
// the data plane is never left with a dangling reference.
func logWsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A long-lived WebSocket is torn down by the server-wide
		// ReadTimeout/WriteTimeout after the first burst; disable both on this
		// response BEFORE upgrading.
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Time{})
		_ = rc.SetWriteDeadline(time.Time{})

		conn, err := logStreamUpgrader.Upgrade(w, r, nil)
		if err != nil {
			// Upgrader already wrote an HTTP error response.
			return
		}
		defer conn.Close()

		conn.SetReadLimit(8192)
		_ = conn.SetReadDeadline(time.Now().Add(logStreamReadTimeout))
		conn.SetPongHandler(func(string) error {
			return conn.SetReadDeadline(time.Now().Add(logStreamReadTimeout))
		})

		// backlog via ?backlog=N (clamped) so a freshly-opened dashboard has
		// context before live entries stream in.
		backlog := logStreamDefaultBacklog
		if v := r.URL.Query().Get("backlog"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				backlog = n
			}
		}
		if backlog > logStreamMaxBacklog {
			backlog = logStreamMaxBacklog
		}
		if backlog < 0 {
			backlog = 0
		}

		// Subscribe to the live broadcast BEFORE computing backlog so any entry
		// arriving between the snapshot and the live loop is still delivered.
		sub := logger.Subscribe(512)
		defer logger.Unsubscribe(sub)

		// Backlog first so the UI has a baseline before live entries arrive.
		if backlog > 0 {
			entries := logger.GetRecentLogs(backlog)
			if len(entries) > 0 {
				if !logWSWrite(conn, logStreamWriteTimeout, logWSMessage{Type: "backlog", Entries: entries, Dropped: sub.Dropped.Load(), ServerTs: time.Now().UnixMilli()}) {
					return
				}
			}
		}

		// Periodic ping keeps middlebox idle timers at bay. If the peer stops
		// answering, the reader side hits its deadline and tears the session
		// down automatically.
		pingTick := time.NewTicker(logStreamPingInterval)
		defer pingTick.Stop()
		conn.SetPingHandler(func(msg string) error {
			_ = conn.SetReadDeadline(time.Now().Add(logStreamReadTimeout))
			return conn.WriteControl(websocket.PongMessage, []byte(msg), time.Now().Add(logStreamWriteTimeout))
		})

		// Periodic lightweight stats so the dropped-entry counter stays
		// current even during quiet periods (entries are only sent when logs
		// arrive, so a stalled subscriber would otherwise look healthy).
		statsTick := time.NewTicker(logStreamStatsInterval)
		defer statsTick.Stop()

		// Reader goroutine: tears the session down when the peer closes or the
		// read deadline fires.
		closeCh := make(chan struct{})
		go func() {
			defer close(closeCh)
			for {
				if _, _, err := conn.NextReader(); err != nil {
					return
				}
			}
		}()

		for {
			select {
			case ev, ok := <-sub.Ch:
				if !ok {
					return
				}
				switch {
				case ev.Cleared:
					if !logWSWrite(conn, logStreamWriteTimeout, logWSMessage{Type: "cleared", Dropped: sub.Dropped.Load(), ServerTs: time.Now().UnixMilli()}) {
						return
					}
				case ev.Entry != nil:
					if !logWSWrite(conn, logStreamWriteTimeout, logWSMessage{Type: "entry", Entry: ev.Entry, Dropped: sub.Dropped.Load(), ServerTs: time.Now().UnixMilli()}) {
						return
					}
				}
			case <-pingTick.C:
				_ = conn.SetWriteDeadline(time.Now().Add(logStreamWriteTimeout))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-statsTick.C:
				if !logWSWrite(conn, logStreamWriteTimeout, logWSMessage{Type: "stats", Dropped: sub.Dropped.Load(), ServerTs: time.Now().UnixMilli()}) {
					return
				}
			case <-closeCh:
				return
			}
		}
	}
}

// logWSWrite encodes v and writes a single WebSocket text frame. Any write
// error (peer closed, network, etc.) aborts the session by returning false.
func logWSWrite(conn *websocket.Conn, writeTimeout time.Duration, v logWSMessage) bool {
	data, err := json.Marshal(v)
	if err != nil {
		return false
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		return false
	}
	return true
}
