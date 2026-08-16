package logger

import (
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want Level
	}{
		{"DEBUG", LevelDebug},
		{"debug", LevelDebug},
		{"INFO", LevelInfo},
		{"info", LevelInfo},
		{"WARNING", LevelWarn},
		{"warn", LevelWarn},
		{"warning", LevelWarn},
		{"ERROR", LevelError},
		{"error", LevelError},
		{"err", LevelError},
		// Unknown / unrecognized levels fall back to LevelInfo.
		{"TRACE", LevelInfo},
		{"FATAL", LevelInfo},
		{"unknown-garbage", LevelInfo},
		{"", LevelInfo},
		{"   ", LevelInfo},
	}
	for _, c := range cases {
		if got := ParseLevel(c.in); got != c.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", c.in, got, c.want)
		} else {
			t.Logf("[logger] ParseLevel(%q) = %v", c.in, got)
		}
	}
}

func TestRingBufferCapacity(t *testing.T) {
	t.Log("[logger] ring buffer capacity: push 200 (cap 150) and check cap holds")
	ClearLogs()
	const n = 200 // exceeds default cap 150
	for i := 0; i < n; i++ {
		pushLogEntry(LogEntry{Level: "INFO", Module: "test", Message: "msg"})
	}
	logs := GetRecentLogs(1000)
	if len(logs) > 150 {
		t.Errorf("log buffer grew beyond capacity: len=%d", len(logs))
	}
	if len(logs) == 0 {
		t.Errorf("expected some logs, got 0")
	}
	t.Logf("[logger] ✓ retained %d entries (<=150 cap)", len(logs))
}

func TestRingBufferFIFOEviction(t *testing.T) {
	t.Log("[logger] FIFO eviction: oldest dropped, newest at tail")
	ClearLogs()
	const n = 150
	for i := 0; i < n; i++ {
		pushLogEntry(LogEntry{Level: "INFO", Module: "test", Message: "msg"})
	}
	logs := GetRecentLogs(1000)
	if len(logs) != 150 {
		t.Fatalf("expected exactly 150 logs, got %d", len(logs))
	}
	// After pushing one more, the oldest must be evicted and newest at the end (tail).
	pushLogEntry(LogEntry{Level: "INFO", Module: "test", Message: "newest"})
	logs = GetRecentLogs(1000)
	if len(logs) != 150 {
		t.Fatalf("expected 150 after eviction, got %d", len(logs))
	}
	if logs[len(logs)-1].Message != "newest" {
		t.Errorf("expected newest entry at end after eviction, got %q", logs[len(logs)-1].Message)
	}
	t.Logf("[logger] ✓ after eviction len=%d tail=%q", len(logs), logs[len(logs)-1].Message)
}

func TestGetRecentLogsLimit(t *testing.T) {
	t.Log("[logger] GetRecentLogs limit honored")
	ClearLogs()
	for i := 0; i < 50; i++ {
		pushLogEntry(LogEntry{Level: "INFO", Module: "test", Message: "msg"})
	}
	logs := GetRecentLogs(10)
	if len(logs) != 10 {
		t.Errorf("GetRecentLogs(10) returned %d, want 10", len(logs))
	} else {
		t.Logf("[logger] ✓ GetRecentLogs(10) returned %d", len(logs))
	}
}

func TestClearLogs(t *testing.T) {
	t.Log("[logger] ClearLogs empties the buffer")
	pushLogEntry(LogEntry{Level: "INFO", Module: "test", Message: "msg"})
	if len(GetRecentLogs(100)) == 0 {
		t.Fatalf("expected logs before clear")
	}
	ClearLogs()
	if len(GetRecentLogs(100)) != 0 {
		t.Errorf("expected 0 logs after ClearLogs")
	}
	t.Log("[logger] ✓ buffer cleared")
}

func TestParseLevelRejectsCasingConsistently(t *testing.T) {
	// Both lowercase and uppercase must map identically.
	if ParseLevel("DEBUG") != ParseLevel("debug") {
		t.Errorf("DEBUG and debug should parse to the same level")
	}
	if ParseLevel("ERROR") != ParseLevel("error") {
		t.Errorf("ERROR and error should parse to the same level")
	}
}
