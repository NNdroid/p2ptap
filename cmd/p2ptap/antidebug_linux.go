//go:build linux

package main

import (
	"bufio"
	"os"
	"strings"
	"syscall"
)

// checkDebugger detects the presence of a debugger on Linux.
// Returns true if a debugger is detected; the caller should exit silently.
func checkDebugger() bool {
	// 1. Check /proc/self/status for TracerPid — if non-zero, a debugger
	//    (or strace, gdb, etc.) is attached to our process.
	f, err := os.Open("/proc/self/status")
	if err == nil {
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
	}

	// 2. ptrace(PTRACE_TRACEME) — if we're already being traced, this fails
	//    with EPERM. A fresh process that isn't being debugged succeeds.
	_, _, errno := syscall.RawSyscall(syscall.SYS_PTRACE, 0, 0, 0) // PTRACE_TRACEME = 0
	if errno != 0 {
		return true
	}
	// Detach immediately so we don't interfere with normal operation.
	syscall.RawSyscall(syscall.SYS_PTRACE, 1, 0, 0) // PTRACE_DETACH = 17 on x86_64

	return false
}
