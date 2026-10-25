//go:build !windows && !linux

package main

import (
	"bufio"
	"os"
	"strings"
)

// checkDebugger detects the presence of a debugger on macOS and other Unix-like systems.
// Returns true if a debugger is detected; the caller should exit silently.
//
// Only checks /proc/self/status for TracerPid (Linux compat, some BSDs).
// We deliberately do NOT call PTRACE_TRACEME: doing so from a standalone
// process marks it as a tracee of its parent (the shell), which causes the
// shell's job-control to report the process as "Stopped".
func checkDebugger() bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "TracerPid:") {
			pid := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
			if pid != "0" {
				return true
			}
		}
	}
	return false
}
