//go:build linux

package main

import (
	"bufio"
	"os"
	"strings"
)

// checkDebugger detects the presence of a debugger on Linux.
// Returns true if a debugger is detected; the caller should exit silently.
//
// We check /proc/self/status for TracerPid — the kernel sets this field
// whenever a process is being traced (PTRACE_ATTACH or PTRACE_TRACEME).
// This is the reliable, side-effect-free way to detect a tracer.
//
// We deliberately do NOT call PTRACE_TRACEME ourselves: doing so from a
// standalone (non-child, non-exec) process marks it as a tracee of its
// parent (the shell), which causes the shell's job-control to report the
// process as "Stopped" and prevents it from running in the foreground.
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
