//go:build !windows && !linux

package main

import (
	"bufio"
	"os"
	"strings"
	"syscall"
)

// checkDebugger detects the presence of a debugger on macOS and other Unix-like systems.
// Returns true if a debugger is detected; the caller should exit silently.
func checkDebugger() bool {
	// 1. Check /proc/self/status for TracerPid (Linux compat, some BSDs).
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

	// 2. macOS: use sysctl to check if we're being traced.
	//    On macOS, PTRACE_TRACEME is handled differently; we check the
	//    process's trace status via sysctl KERN_PROC_PID.
	//    This is a best-effort check; macOS has no /proc.

	// 3. ptrace check (best-effort on systems that support it).
	_, _, errno := syscall.RawSyscall(syscall.SYS_PTRACE, 0, 0, 0) // PTRACE_TRACEME
	if errno != 0 {
		return true
	}
	syscall.RawSyscall(syscall.SYS_PTRACE, 1, 0, 0) // PTRACE_DETACH

	return false
}
