//go:build windows

package node

import (
	"context"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// errorIoPending is the Windows ERROR_IO_PENDING code (997). It is the normal
// return for an overlapped NotifyAddrChange: the call succeeds and the
// operation completes (signalling the overlapped event) later.
const errorIoPending = 997

// modIphlpapi / procNotifyAddrChange let us subscribe to address changes via
// the OS iphlpapi.dll. NotifyAddrChange is not exported by
// golang.org/x/sys/windows, so we bind it lazily.
var (
	modIphlpapi          = syscall.NewLazyDLL("iphlpapi.dll")
	procNotifyAddrChange = modIphlpapi.NewProc("NotifyAddrChange")
)

// notifyAddrChange subscribes to IPv4/IPv6 address changes. With a non-nil
// overlapped it returns immediately and signals overlapped.HEvent when a change
// occurs; the Win32 error code is ERROR_IO_PENDING (errorIoPending) in that
// case, which we treat as success.
func notifyAddrChange(handle *windows.Handle, overlapped *windows.Overlapped) error {
	r1, _, _ := procNotifyAddrChange.Call(uintptr(unsafe.Pointer(handle)), uintptr(unsafe.Pointer(overlapped)))
	if r1 == 0 || r1 == errorIoPending {
		return nil
	}
	return syscall.Errno(r1)
}

// windowsNetMon uses the OS address-change notification (iphlpapi
// NotifyAddrChange) instead of the portable 2s poller, so a NIC up/down or
// address add/remove is reacted to immediately. This both lowers latency and
// removes the steady poll tick on Windows.
type windowsNetMon struct {
	tapName string

	cancelMu sync.Mutex
	cancelEv windows.Handle
}

func newWindowsNetMonOrNil(tapName string) NetMon {
	return &windowsNetMon{tapName: tapName}
}

func (m *windowsNetMon) Watch(ctx context.Context, onEvent func()) error {
	// Fire once so the initial NIC set is authoritative.
	onEvent()

	handled := windows.Handle(0)
	overlapped := windows.Overlapped{}

	changeEv, err := windows.CreateEvent(nil, 1 /* manual-reset */, 0, nil)
	if err != nil {
		return newPollNetMon(m.tapName).Watch(ctx, onEvent)
	}
	overlapped.HEvent = changeEv

	cancelEv, err := windows.CreateEvent(nil, 0 /* auto-reset */, 0, nil)
	if err != nil {
		windows.CloseHandle(changeEv)
		return newPollNetMon(m.tapName).Watch(ctx, onEvent)
	}
	m.cancelMu.Lock()
	m.cancelEv = cancelEv
	m.cancelMu.Unlock()

	if err := notifyAddrChange(&handled, &overlapped); err != nil {
		windows.CloseHandle(changeEv)
		windows.CloseHandle(cancelEv)
		m.cancelMu.Lock()
		m.cancelEv = 0
		m.cancelMu.Unlock()
		return newPollNetMon(m.tapName).Watch(ctx, onEvent)
	}

	go func() {
		defer windows.CloseHandle(changeEv)
		defer windows.CloseHandle(cancelEv)
		for {
			// Wait on either the address-change event or our cancel event.
			evs := []windows.Handle{cancelEv, changeEv}
			rc, err := windows.WaitForMultipleObjects(evs, false, windows.INFINITE)
			if err != nil {
				return
			}
			switch rc {
			case windows.WAIT_OBJECT_0 + 1:
				// Address change fired.
				windows.ResetEvent(changeEv)
				onEvent()
				// Re-arm for the next change.
				if err := notifyAddrChange(&handled, &overlapped); err != nil {
					return
				}
			default:
				// Cancel event (index 0) or an unexpected result — stop.
				return
			}
		}
	}()
	return nil
}

func (m *windowsNetMon) Close() error {
	m.cancelMu.Lock()
	ev := m.cancelEv
	m.cancelEv = 0
	m.cancelMu.Unlock()
	if ev != 0 {
		windows.SetEvent(ev)
	}
	return nil
}
