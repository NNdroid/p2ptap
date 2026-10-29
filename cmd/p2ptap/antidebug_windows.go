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
		// SYSTEM_INFO is a kernel-written struct; the field order and sizes
		// below MUST match the C ABI exactly.  On x64 dwAllocationGranularity
		// lives at byte offset 40 (after dwProcessorType), on x86 at offset 28.
		// A previous version laid this out as {AllocationGranularity uintptr;
		// BasePriority uintptr; ActiveProcessorMask uint16}, which read the
		// dwOemId field (9 on x64) as the granularity and made the check below
		// always fire, silently exiting every command with status 1.
		var sysInfo struct {
			ProcessorArchitecture     uint16
			Reserved                  uint16
			PageSize                  uint32
			MinimumApplicationAddress uintptr
			MaximumApplicationAddress uintptr
			ActiveProcessorMask       uintptr
			NumberOfProcessors        uint32
			ProcessorType             uint32
			AllocationGranularity     uint32
			ProcessorLevel            uint16
			ProcessorRevision         uint16
		}
		procGetSystemInfo.Call(uintptr(unsafe.Pointer(&sysInfo)))
		if sysInfo.AllocationGranularity != 0x10000 && sysInfo.AllocationGranularity != 0x1000 {
			return true
		}
	}

	return false
}
