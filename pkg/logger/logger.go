package logger

import (
	"fmt"
	"os"
	"strings"
	"sync"
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
	globalLevel Level = LevelInfo
	globalMu    sync.RWMutex
	colorize    bool = true
)

// SetGlobalLevel sets the minimum log level for all loggers
func SetGlobalLevel(level Level) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLevel = level
}

// SetColorize enables or disables ANSI color output
func SetColorize(enabled bool) {
	globalMu.Lock()
	defer globalMu.Unlock()
	colorize = enabled
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
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalLevel
}

func (l *Logger) getColorize() bool {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return colorize
}

// LogEntry represents a structured log line for WebUI live streaming
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Module    string `json:"module"`
	Message   string `json:"message"`
}

var (
	ringBufferMax = 150
	ringBuffer    = make([]LogEntry, 0, 150)
	ringBufferMu  sync.RWMutex
)

func pushLogEntry(entry LogEntry) {
	ringBufferMu.Lock()
	defer ringBufferMu.Unlock()
	if len(ringBuffer) >= ringBufferMax {
		ringBuffer = ringBuffer[1:]
	}
	ringBuffer = append(ringBuffer, entry)
}

// GetRecentLogs retrieves up to limit recent log entries
func GetRecentLogs(limit int) []LogEntry {
	ringBufferMu.RLock()
	defer ringBufferMu.RUnlock()
	n := len(ringBuffer)
	if limit <= 0 || limit > n {
		limit = n
	}
	res := make([]LogEntry, limit)
	copy(res, ringBuffer[n-limit:])
	return res
}

// ClearLogs clears all entries in the log ring buffer
func ClearLogs() {
	ringBufferMu.Lock()
	defer ringBufferMu.Unlock()
	ringBuffer = make([]LogEntry, 0, ringBufferMax)
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	now := time.Now().Format("2006-01-02 15:04:05.000")
	msg := fmt.Sprintf(format, args...)
	levelName := levelNames[level]

	pushLogEntry(LogEntry{
		Timestamp: now,
		Level:     levelName,
		Module:    l.module,
		Message:   msg,
	})

	if level < l.getLevel() {
		return
	}

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
