package logger

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Level represents the severity of a log message
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var levelNames = map[Level]string{
	LevelDebug: "DEBUG",
	LevelInfo:  "INFO",
	LevelWarn:  "WARN",
	LevelError: "ERROR",
}

var levelColors = map[Level]string{
	LevelDebug: "\033[36m", // Cyan
	LevelInfo:  "\033[32m", // Green
	LevelWarn:  "\033[33m", // Yellow
	LevelError: "\033[31m", // Red
}

const colorReset = "\033[0m"

// Logger is a simple leveled logger
type Logger struct {
	mu       sync.Mutex
	level    Level
	module   string
	colorize bool
}

var (
	globalLevel atomic.Int32
	colorize    atomic.Bool
)

func init() {
	globalLevel.Store(int32(LevelInfo))
	// Colorize only when stderr is a real console (a character device). When
	// output is redirected to a file or pipe (systemd/journald, `> log 2>&1`,
	// a service daemon that rewires os.Stderr to a file), ANSI escape codes
	// would be embedded literally and corrupt the log. Callers that redirect
	// stderr AFTER init (e.g. the Windows service) must additionally call
	// SetColorize(false), which this default cannot see at init time.
	colorize.Store(stderrIsTerminal())
}

// stderrIsTerminal reports whether os.Stderr points at a character device (a
// console). Pipes, regular files and sockets are NOT character devices, so this
// correctly disables color when logging to anything that is not an interactive
// terminal. Portable across Unix and Windows without extra dependencies.
func stderrIsTerminal() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// SetGlobalLevel sets the minimum log level for all loggers
func SetGlobalLevel(level Level) {
	globalLevel.Store(int32(level))
}

// SetColorize enables or disables terminal colorization
func SetColorize(c bool) {
	colorize.Store(c)
}

// ParseLevel parses a string log level (case-insensitive)
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error", "err":
		return LevelError
	default:
		return LevelInfo
	}
}

// New creates a new Logger for the given module
func New(module string) *Logger {
	return &Logger{
		module: module,
	}
}

func (l *Logger) getLevel() Level {
	return Level(globalLevel.Load())
}

func (l *Logger) getColorize() bool {
	return colorize.Load()
}

// LogEntry represents a structured log line for WebUI live streaming
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Module    string `json:"module"`
	Message   string `json:"message"`
}

const ringBufferMax = 150

var (
	ringEntries  = make([]LogEntry, ringBufferMax)
	ringStart    = 0
	ringCount    = 0
	ringBufferMu sync.RWMutex
)

// LogEvent is one delivery to a live-log subscriber. Exactly one of Entry /
// Cleared is set per event: Entry carries a newly-written log line; Cleared
// marks a ClearLogs() call so the UI can reset its buffer.
type LogEvent struct {
	Entry   *LogEntry `json:"entry,omitempty"`
	Cleared bool      `json:"cleared,omitempty"`
}

// LogSubscriber is a single live-stream consumer registered with the global
// logger. Entries are delivered as LogEvent values on Ch using a non-blocking
// send — when the channel buffer fills, the entry is dropped and Dropped is
// incremented. The logger is package-global (not a struct) so its subscriber
// set is a package-level map, mirroring PacketCapture but without the
// per-instance state.
type LogSubscriber struct {
	Ch      chan LogEvent
	Dropped atomic.Uint64
}

var (
	logSubMu sync.Mutex
	logSubs  map[*LogSubscriber]struct{}
)

// Subscribe registers a new live-log consumer. The returned subscriber
// receives an unbounded series of events on its channel until Unsubscribe is
// called or the channel buffer fills — in which case entries are dropped and
// Dropped counts how many.
func Subscribe(bufSize int) *LogSubscriber {
	if bufSize <= 0 {
		bufSize = 256
	}
	s := &LogSubscriber{Ch: make(chan LogEvent, bufSize)}
	logSubMu.Lock()
	if logSubs == nil {
		logSubs = make(map[*LogSubscriber]struct{})
	}
	logSubs[s] = struct{}{}
	logSubMu.Unlock()
	return s
}

// Unsubscribe removes a previously registered subscriber. Safe to call any
// number of times.
func Unsubscribe(s *LogSubscriber) {
	if s == nil {
		return
	}
	logSubMu.Lock()
	delete(logSubs, s)
	logSubMu.Unlock()
}

// broadcastLog fans a single event out to every registered subscriber. Holds
// logSubMu only briefly to snapshot the subscriber set; sends are non-blocking
// so a slow WebSocket peer can never delay the logger's hot path.
func broadcastLog(ev LogEvent) {
	logSubMu.Lock()
	if len(logSubs) == 0 {
		logSubMu.Unlock()
		return
	}
	list := make([]*LogSubscriber, 0, len(logSubs))
	for s := range logSubs {
		list = append(list, s)
	}
	logSubMu.Unlock()
	for _, s := range list {
		select {
		case s.Ch <- ev:
		default:
			s.Dropped.Add(1)
		}
	}
}

func pushLogEntry(entry LogEntry) {
	ringBufferMu.Lock()
	if ringCount < ringBufferMax {
		ringEntries[(ringStart+ringCount)%ringBufferMax] = entry
		ringCount++
	} else {
		ringEntries[ringStart] = entry
		ringStart = (ringStart + 1) % ringBufferMax
	}
	ringBufferMu.Unlock()
	// Fan out to live-stream subscribers. We copy entry onto the heap so a
	// delayed reader can never observe a stale stack slot, then broadcast with
	// a non-blocking send: a slow consumer drops the line and bumps its own
	// Dropped counter, and the logger hot path never blocks on a WebSocket
	// peer.
	cp := entry
	broadcastLog(LogEvent{Entry: &cp})
}

// GetRecentLogs retrieves up to limit recent log entries
func GetRecentLogs(limit int) []LogEntry {
	ringBufferMu.RLock()
	defer ringBufferMu.RUnlock()
	if limit <= 0 || limit > ringCount {
		limit = ringCount
	}
	res := make([]LogEntry, limit)
	startIdx := (ringStart + ringCount - limit) % ringBufferMax
	for i := 0; i < limit; i++ {
		res[i] = ringEntries[(startIdx+i)%ringBufferMax]
	}
	return res
}

// ClearLogs clears all entries in the log ring buffer
func ClearLogs() {
	ringBufferMu.Lock()
	ringStart = 0
	ringCount = 0
	ringBufferMu.Unlock()
	// Notify live subscribers AFTER releasing ringBufferMu so a slow consumer
	// cannot stall the caller.
	broadcastLog(LogEvent{Cleared: true})
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	// Drop below-threshold messages BEFORE any allocation. This is the key CPU
	// fix: previously every call (including the hot-path Debug spam) paid a
	// time.Now().Format + fmt.Sprintf allocation and an unconditional global
	// ringBufferMu.Lock() + O(N) slice shift, even when the level was suppressed.
	// Now a suppressed Debug line costs a single RLock read and returns.
	if level < l.getLevel() {
		return
	}

	now := time.Now().Format("2006-01-02 15:04:05.000")
	msg := fmt.Sprintf(format, args...)
	levelName := levelNames[level]

	pushLogEntry(LogEntry{
		Timestamp: now,
		Level:     levelName,
		Module:    l.module,
		Message:   msg,
	})

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.getColorize() {
		color := levelColors[level]
		fmt.Fprintf(os.Stderr, "%s %s[%-5s]%s [%s] %s\n", now, color, levelName, colorReset, l.module, msg)
	} else {
		fmt.Fprintf(os.Stderr, "%s [%-5s] [%s] %s\n", now, levelName, l.module, msg)
	}
}

// Debug logs a debug-level message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(LevelDebug, format, args...)
}

// Info logs an info-level message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LevelInfo, format, args...)
}

// Warn logs a warn-level message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(LevelWarn, format, args...)
}

// Error logs an error-level message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(LevelError, format, args...)
}

// IsDebug returns true if debug-level logging is enabled
func (l *Logger) IsDebug() bool {
	return l.getLevel() <= LevelDebug
}
