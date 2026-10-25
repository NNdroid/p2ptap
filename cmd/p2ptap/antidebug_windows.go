//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	antidebugKernel32 = syscall.NewLazyDLL("kernel32.dll")
	antidebugNtdll    = syscall.NewLazyDLL("ntdll.dll")

	procIsDebuggerPresent          = antidebugKernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebuggerPresent = antidebugKernel32.NewProc("CheckRemoteDebuggerPresent")
	procGetSystemInfo              = antidebugKernel32.NewProc("GetSystemInfo")
	procNtQueryInformationProcess  = antidebugNtdll.NewProc("NtQueryInformationProcess")
)

const (
	ntProcessDebugPort = 7
)

func checkDebugger() bool {
	ret, _, _ := procIsDebuggerPresent.Call()
	if ret != 0 {
		return true
	}

	// 2. CheckRemoteDebuggerPresent via the current-process pseudo-handle.
	{
		procHandle, _ := syscall.GetCurrentProcess()
		var isRemote int32 // BOOL
		ret, _, _ = procCheckRemoteDebuggerPresent.Call(
			uintptr(procHandle),
			uintptr(unsafe.Pointer(&isRemote)),
		)
		if ret != 0 && isRemote != 0 {
			return true
		}
	}

	// 3. NtQueryInformationProcess — catches HideFromDebugger bypasses.
	{
		procHandle, _ := syscall.GetCurrentProcess()
		var debugPort uintptr
		ret, _, _ = procNtQueryInformationProcess.Call(
			uintptr(procHandle),
			uintptr(ntProcessDebugPort),
			uintptr(unsafe.Pointer(&debugPort)),
			uintptr(unsafe.Sizeof(debugPort)),
			0,
		)
		if ret == 0 && debugPort != 0 {
			return true
		}
	}

	{
		var sysInfo struct {
			AllocationGranularity uintptr
			BasePriority          uintptr
			ActiveProcessorMask   uint16
		}
		procGetSystemInfo.Call(uintptr(unsafe.Pointer(&sysInfo)))
		if sysInfo.AllocationGranularity != 0x100000 && sysInfo.AllocationGranularity != 0x1000 {
			return true
		}
	}

	return false
}
