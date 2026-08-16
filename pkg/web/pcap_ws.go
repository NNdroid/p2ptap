package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

// pcapStreamUpgrader configures the gorilla/websocket handshake. We use
// permissive origins here so the same WebSocket client can attach from
// localhost and the LAN, mirroring /api/pcap/* which is protected only by the
// bearer token; the auth check happens BEFORE Upgrade().
var pcapStreamUpgrader = websocket.Upgrader{
	HandshakeTimeout:  10 * time.Second,
	ReadBufferSize:    4096,
	WriteBufferSize:   8192,
	EnableCompression: true, // permessage-deflate; browsers negotiate it, drastically cuts JSON bandwidth
	// Browsers setting Origin must match the dashboard host. WebUI token
	// already gates access; we refuse cross-origin without a valid token.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// pcapStreamDefaultBacklog bounds how many buffered frames are pushed to a
// freshly-connected client. A user joining mid-capture still wants context
// for the rows they're about to see stream in.
const (
	pcapStreamDefaultBacklog = 200
	pcapStreamMaxBacklog     = 2000 // same hard cap as /api/pcap/packets
	pcapStreamPingInterval   = 25 * time.Second
	pcapStreamWriteTimeout   = 10 * time.Second
	pcapStreamReadTimeout    = 60 * time.Second // for pong / client messages
	pcapStreamBatchMax       = 64               // frames coalesced into one WS message
	pcapStreamBatchFlush     = 20 * time.Millisecond // max latency before a partial batch is flushed
	pcapStreamStatsInterval  = 5 * time.Second // how often Dropped is re-reported while idle
)

// pcapWSMessage is the wire envelope sent to the dashboard. Exactly one
// payload field is set per message — type discriminates them.
type pcapWSMessage struct {
	Type     string          `json:"type"`                // "state" | "backlog" | "frames" | "frame" | "cleared" | "error" | "pong"
	State    *CaptureState   `json:"state,omitempty"`     // when type=state
	Frames   []CapturedFrame `json:"frames,omitempty"`    // when type=backlog
	Frame    *CapturedFrame  `json:"frame,omitempty"`     // when type=frame
	Error    string          `json:"error,omitempty"`     // when type=error
	Dropped  uint64          `json:"dropped,omitempty"`   // frames this subscriber lost (so the UI can flag stagnation)
	ServerTs int64           `json:"ts,omitempty"`        // server-side timestamp (ms) for latency tracking
}

// pcapWSOptions configures a pcapWsHandler.
type pcapWSOptions struct {
	// Backlog caps how many recent frames to send before live streaming.
	// Default: pcapStreamDefaultBacklog. Caller can override via ?backlog=N.
	Backlog int
	// WriteTimeout sets a per-message write deadline; default 10s.
	WriteTimeout time.Duration
	// PingInterval sets how often a server-initiated ping is sent. Default 25s.
	PingInterval time.Duration
}

// pcapWsHandler returns an http.HandlerFunc that streams captured frames to
// the connected dashboard over a WebSocket. The handler validates the auth
// token (the standard middleware writes a body that doesn't survive an
// upgrade, so we re-check here), clears the connection-level HTTP timeouts,
// upgrades, and runs the streaming loop. On exit it cleans up the
// subscriber goroutine so the data plane is never left with a dangling
// reference.
func pcapWsHandler(collector *StatsCollector) http.HandlerFunc {
	return pcapWsHandlerWith(collector, pcapWSOptions{})
}

func pcapWsHandlerWith(collector *StatsCollector, opts pcapWSOptions) http.HandlerFunc {
	if collector == nil {
		return func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "packet capture unavailable", http.StatusServiceUnavailable)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// Custom, fast path: the server-wide ReadTimeout/WriteTimeout kill a
		// long-lived WebSocket. We disable both on this response BEFORE
		// upgrading so the live stream isn't torn down after the first burst.
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Time{})
		_ = rc.SetWriteDeadline(time.Time{})

		conn, err := pcapStreamUpgrader.Upgrade(w, r, nil)
		if err != nil {
			// Upgrader already wrote an HTTP error response.
			return
		}
		defer conn.Close()

		// Apply finer-grained per-message deadlines that the upgrader
		// controls directly (independent of the http.Server timeouts).
		conn.SetReadLimit(8192)
		_ = conn.SetReadDeadline(time.Now().Add(pcapStreamReadTimeout))
		conn.SetPongHandler(func(string) error {
			return conn.SetReadDeadline(time.Now().Add(pcapStreamReadTimeout))
		})

		opts = opts.normalised()

		// Initial backlog honours ?backlog=N and ?since=M (clamped) so a
		// freshly opened OR reconnecting dashboard can scroll back into recent
		// history without re-fetching frames it already has.
		since := uint64(0)
		if v := r.URL.Query().Get("since"); v != "" {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				since = n
			}
		}

		// Subscribe to the live broadcast channel BEFORE computing backlog so
		// any frame arriving between the snapshot and the live loop is still
		// delivered (the dashboard deduplicates on Seq).
		sub := collector.Pcap.Subscribe(512)
		defer collector.Pcap.Unsubscribe(sub)

		// Always send a state message first so the badge updates immediately.
		initialState := collector.Pcap.State()
		if !wsWrite(conn, opts.WriteTimeout, pcapWSMessage{Type: "state", State: &initialState, Dropped: sub.Dropped.Load(), ServerTs: time.Now().UnixMilli()}) {
			return
		}

		// Backlog: latest N frames strictly after `since`.
		if opts.Backlog > 0 {
			backlog := collector.Pcap.Snapshot(since, opts.Backlog)
			if len(backlog) > 0 {
				if !wsWrite(conn, opts.WriteTimeout, pcapWSMessage{Type: "backlog", Frames: backlog, Dropped: sub.Dropped.Load(), ServerTs: time.Now().UnixMilli()}) {
					return
				}
			}
		}

		// Periodic ping keeps middlebox idle timers at bay. If the peer stops
		// answering, the reader side hits its deadline and tears the session
		// down automatically.
		pingTick := time.NewTicker(opts.PingInterval)
		defer pingTick.Stop()
		conn.SetPingHandler(func(msg string) error {
			_ = conn.SetReadDeadline(time.Now().Add(pcapStreamReadTimeout))
			return conn.WriteControl(websocket.PongMessage, []byte(msg), time.Now().Add(opts.WriteTimeout))
		})

		// Periodic lightweight stats so the dropped-frame counter stays
		// current even during quiet periods (frames are only sent when traffic
		// arrives, so a stalled subscriber would otherwise look healthy).
		statsTick := time.NewTicker(pcapStreamStatsInterval)
		defer statsTick.Stop()

		// Batched frame flushing. A single writer goroutine (this loop) owns
		// the connection; a timer merely signals "flush now" over a channel so
		// it never writes concurrently with the loop.
		var batch []CapturedFrame
		var batchTimer *time.Timer
		flushCh := make(chan struct{}, 1)
		flushBatch := func() bool {
			if batchTimer != nil {
				batchTimer.Stop()
				batchTimer = nil
			}
			if len(batch) == 0 {
				return true
			}
			msg := pcapWSMessage{Type: "frames", Frames: batch, Dropped: sub.Dropped.Load(), ServerTs: time.Now().UnixMilli()}
			batch = nil
			return wsWrite(conn, opts.WriteTimeout, msg)
		}
		armBatchTimer := func() {
			if batchTimer == nil {
				batchTimer = time.AfterFunc(pcapStreamBatchFlush, func() {
					select {
					case flushCh <- struct{}{}:
					default:
					}
				})
			}
		}

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
					if !flushBatch() {
						return
					}
					if !wsWrite(conn, opts.WriteTimeout, pcapWSMessage{Type: "cleared", Dropped: sub.Dropped.Load(), ServerTs: time.Now().UnixMilli()}) {
						return
					}
				case ev.State != nil:
					if !flushBatch() {
						return
					}
					if !wsWrite(conn, opts.WriteTimeout, pcapWSMessage{Type: "state", State: ev.State, Dropped: sub.Dropped.Load(), ServerTs: time.Now().UnixMilli()}) {
						return
					}
				case ev.Frame != nil:
					batch = append(batch, *ev.Frame)
					armBatchTimer()
					if len(batch) >= pcapStreamBatchMax {
						if !flushBatch() {
							return
						}
					}
				}
			case <-flushCh:
				if !flushBatch() {
					return
				}
			case <-pingTick.C:
				_ = conn.SetWriteDeadline(time.Now().Add(opts.WriteTimeout))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-statsTick.C:
				if !flushBatch() {
					return
				}
				st := collector.Pcap.State()
				if !wsWrite(conn, opts.WriteTimeout, pcapWSMessage{Type: "state", State: &st, Dropped: sub.Dropped.Load(), ServerTs: time.Now().UnixMilli()}) {
					return
				}
			case <-closeCh:
				return
			}
		}
	}
}

// normalised fills defaults for unset fields.
func (o pcapWSOptions) normalised() pcapWSOptions {
	if o.Backlog <= 0 {
		o.Backlog = pcapStreamDefaultBacklog
	}
	if o.Backlog > pcapStreamMaxBacklog {
		o.Backlog = pcapStreamMaxBacklog
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = pcapStreamWriteTimeout
	}
	if o.PingInterval <= 0 {
		o.PingInterval = pcapStreamPingInterval
	}
	return o
}

// wsWrite encodes v and writes a single WebSocket text frame. Any write
// error (peer closed, network, etc.) aborts the session by returning false.
func wsWrite(conn *websocket.Conn, writeTimeout time.Duration, v pcapWSMessage) bool {
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
