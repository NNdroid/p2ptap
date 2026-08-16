//go:build windows

package node

import (
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modfwpuclnt                   = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0           = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0          = modfwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmGetAppIdFromFileName0 = modfwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0           = modfwpuclnt.NewProc("FwpmFreeMemory0")
	procFwpmSubLayerAdd0          = modfwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0            = modfwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteById0     = modfwpuclnt.NewProc("FwpmFilterDeleteById0")
)

// WFP GUIDs
var (
	// Layers
	FWPM_LAYER_ALE_AUTH_CONNECT_V4 = windows.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xfe, 0xe2, 0x7e, 0x07}}
	FWPM_LAYER_ALE_AUTH_CONNECT_V6 = windows.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0x63, 0x33, 0xbb, 0xf5, 0x82, 0xe6}}

	// Conditions
	FWPM_CONDITION_ALE_APP_ID = windows.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4970, Data4: [8]byte{0x8b, 0x5d, 0x68, 0x5b, 0x8c, 0x9d, 0x2f, 0x2d}}

	// p2ptap Sublayer GUID: {670f5e1a-1d54-4f27-8a9d-12b9c3f4e5a6}
	P2PTAP_WFP_SUBLAYER_GUID = windows.GUID{Data1: 0x670f5e1a, Data2: 0x1d54, Data3: 0x4f27, Data4: [8]byte{0x8a, 0x9d, 0x12, 0xb9, 0xc3, 0xf4, 0xe5, 0xa6}}
)

const (
	FWP_MATCH_EQUAL             = 0
	FWP_ACTION_FLAG_TERMINATING = 0x00001000
	FWP_ACTION_BLOCK            = 0x00000001 | FWP_ACTION_FLAG_TERMINATING // 0x00001001
	FWP_ACTION_PERMIT           = 0x00000002 | FWP_ACTION_FLAG_TERMINATING // 0x00001002
	FWP_BYTE_BLOB_TYPE          = 11
	FWP_UINT64_TYPE             = 5
	FWPM_SESSION_FLAG_DYNAMIC   = 0x00000001
)

// RPC authentication services accepted by FwpmEngineOpen0.
//
// The docs are explicit that only these two values are supported for the
// authnService parameter: passing RPC_C_AUTHN_NONE (0) — which is what a naive
// "all zeros" call does — makes the call fail immediately with
// ERROR_NOT_SUPPORTED (0x32) on every Windows build. That single wrong argument
// was the reason process bypass never came up (see EnableProcessBypass).
const (
	RPC_C_AUTHN_WINNT   = 10
	RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF
)

// Well-known Win32/FWP status codes we special-case for diagnostics.
const (
	errorNotSupported         = 0x32       // ERROR_NOT_SUPPORTED
	errorAccessDenied         = 0x5        // ERROR_ACCESS_DENIED
	fwpAlreadyExists          = 0x80320019 // FWP_E_ALREADY_EXISTS
	fwpActionTypeNotSupported = 0x80320024 // FWP_E_ACTION_TYPE_NOT_SUPPORTED
)

type FWP_BYTE_BLOB struct {
	Size uint32
	Data *byte
}

type FWPM_DISPLAY_DATA0 struct {
	Name        *uint16
	Description *uint16
}

type FWPM_SUBLAYER0 struct {
	SubLayerKey  windows.GUID
	DisplayData  FWPM_DISPLAY_DATA0
	Flags        uint32
	ProviderKey  *windows.GUID
	ProviderData FWP_BYTE_BLOB
	Weight       uint16
}

type FWP_VALUE0 struct {
	Type  uint32
	Value uintptr
}

type FWP_CONDITION_VALUE0 struct {
	Type  uint32
	Value uintptr
}

type FWPM_FILTER_CONDITION0 struct {
	FieldKey       windows.GUID
	Match          uint32
	ConditionValue FWP_CONDITION_VALUE0
}

type FWPM_ACTION0 struct {
	Type       uint32
	CalloutKey windows.GUID
}

type FWPM_FILTER0 struct {
	FilterKey           windows.GUID
	DisplayData         FWPM_DISPLAY_DATA0
	Flags               uint32
	ProviderKey         *windows.GUID
	ProviderData        FWP_BYTE_BLOB
	LayerKey            windows.GUID
	SubLayerKey         windows.GUID
	Weight              FWP_VALUE0
	NumFilterConditions uint32
	FilterCondition     *FWPM_FILTER_CONDITION0
	Action              FWPM_ACTION0
	Context             uint64 // union { UINT64 rawContext; GUID *providerContextKey; }
	Reserved            uintptr
	FilterID            uint64
	// EffectiveWeight is written back by the WFP engine. It MUST be present:
	// without it the struct we hand to FwpmFilterAdd0 is 16 bytes shorter than
	// the FWPM_FILTER0 the kernel expects, so the engine writes the computed
	// weight past the end of our allocation and corrupts adjacent stack memory.
	EffectiveWeight FWP_VALUE0
}

type FWPM_SESSION0 struct {
	SessionKey         windows.GUID
	DisplayData        FWPM_DISPLAY_DATA0
	Flags              uint32
	TxnWaitTimeoutInMs uint32
	ProcessId          uint32
	Sid                uintptr
	Username           *uint16
	KernelMode         int32 // C BOOL (4 bytes), not a 1-byte Go bool
}

type WFPManager struct {
	mu           sync.Mutex
	engineHandle uintptr
	filterIDV4   uint64
	filterIDV6   uint64
	enabled      bool
}

var globalWFPManager = &WFPManager{}

// GetWFPManager returns the global WFP manager instance.
func GetWFPManager() *WFPManager {
	return globalWFPManager
}

// wfpStatusString renders a WFP/Win32 status code with a human-readable hint so
// the logs say *why* the call failed instead of only printing a bare hex value.
func wfpStatusString(ret uintptr) string {
	switch ret {
	case errorNotSupported:
		return "0x32 (ERROR_NOT_SUPPORTED - unsupported authentication service)"
	case errorAccessDenied:
		return "0x5 (ERROR_ACCESS_DENIED - administrator privileges required)"
	case fwpActionTypeNotSupported:
		return "0x80320024 (FWP_E_ACTION_TYPE_NOT_SUPPORTED - invalid action type for filter layer)"
	default:
		return fmt.Sprintf("0x%x (%v)", ret, windows.Errno(ret))
	}
}

// openWFPEngine opens a WFP engine session against the local filter engine.
//
// The authnService argument is the part that actually matters: FwpmEngineOpen0
// only accepts RPC_C_AUTHN_WINNT or RPC_C_AUTHN_DEFAULT. p2ptap previously
// passed the whole argument list as zeros, which meant authnService ==
// RPC_C_AUTHN_NONE, and the call failed with ERROR_NOT_SUPPORTED (0x32) on
// every machine — process bypass silently never existed. We try WINNT first
// (what tailscale/wf and the WFP samples use) and fall back to DEFAULT so a
// host with an unusual RPC configuration still gets a session.
func openWFPEngine(session *FWPM_SESSION0) (uintptr, error) {
	var lastRet uintptr
	for _, authnService := range []uintptr{RPC_C_AUTHN_WINNT, RPC_C_AUTHN_DEFAULT} {
		var handle uintptr
		ret, _, _ := procFwpmEngineOpen0.Call(
			0,            // serverName: NULL == local filter engine
			authnService, // authnService: RPC_C_AUTHN_NONE (0) is NOT supported
			0,            // authIdentity: NULL == use the calling process token
			uintptr(unsafe.Pointer(session)),
			uintptr(unsafe.Pointer(&handle)),
		)
		if ret == 0 {
			return handle, nil
		}
		lastRet = ret
		protectLog.Debug("FwpmEngineOpen0(authnService=%d) failed with status %s", authnService, wfpStatusString(ret))
	}
	return 0, fmt.Errorf("FwpmEngineOpen0 failed with status %s", wfpStatusString(lastRet))
}

// EnableProcessBypass registers WFP ALE permit filters for the current executable
// so that all outbound sockets created by p2ptap bypass TUN/TAP filtering.
func (w *WFPManager) EnableProcessBypass() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.enabled {
		return nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	pathPtr, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return err
	}

	var appIdPtr uintptr
	ret, _, _ := procFwpmGetAppIdFromFileName0.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&appIdPtr)),
	)
	if ret != 0 {
		return fmt.Errorf("FwpmGetAppIdFromFileName0 failed with status %s", wfpStatusString(ret))
	}
	defer procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&appIdPtr)))

	var session FWPM_SESSION0
	session.Flags = FWPM_SESSION_FLAG_DYNAMIC
	sessionName, _ := windows.UTF16PtrFromString("p2ptap Dynamic WFP Session")
	session.DisplayData.Name = sessionName

	handle, err := openWFPEngine(&session)
	if err != nil {
		return err
	}

	// Register p2ptap Sublayer
	sublayerName, _ := windows.UTF16PtrFromString("p2ptap Process Bypass Sublayer")
	sublayerDesc, _ := windows.UTF16PtrFromString("Bypasses p2ptap P2P control traffic from VPN hijacking")
	sublayer := FWPM_SUBLAYER0{
		SubLayerKey: P2PTAP_WFP_SUBLAYER_GUID,
		DisplayData: FWPM_DISPLAY_DATA0{
			Name:        sublayerName,
			Description: sublayerDesc,
		},
		Weight: 0xFFFF, // Maximum priority sublayer
	}
	ret, _, _ = procFwpmSubLayerAdd0.Call(handle, uintptr(unsafe.Pointer(&sublayer)), 0)
	if ret != 0 && ret != fwpAlreadyExists {
		procFwpmEngineClose0.Call(handle)
		return fmt.Errorf("FwpmSubLayerAdd0 failed with status %s", wfpStatusString(ret))
	}

	cond := FWPM_FILTER_CONDITION0{
		FieldKey: FWPM_CONDITION_ALE_APP_ID,
		Match:    FWP_MATCH_EQUAL,
		ConditionValue: FWP_CONDITION_VALUE0{
			Type:  FWP_BYTE_BLOB_TYPE,
			Value: appIdPtr,
		},
	}

	filterName, _ := windows.UTF16PtrFromString("p2ptap IPv4 Process Bypass Filter")
	filterV4 := FWPM_FILTER0{
		DisplayData: FWPM_DISPLAY_DATA0{
			Name: filterName,
		},
		LayerKey:            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
		SubLayerKey:         P2PTAP_WFP_SUBLAYER_GUID,
		NumFilterConditions: 1,
		FilterCondition:     &cond,
		Action: FWPM_ACTION0{
			Type: FWP_ACTION_PERMIT,
		},
	}

	var idV4 uint64
	ret, _, _ = procFwpmFilterAdd0.Call(
		handle,
		uintptr(unsafe.Pointer(&filterV4)),
		0,
		uintptr(unsafe.Pointer(&idV4)),
	)
	if ret != 0 {
		procFwpmEngineClose0.Call(handle)
		return fmt.Errorf("FwpmFilterAdd0 (V4) failed with status %s", wfpStatusString(ret))
	}

	filterNameV6, _ := windows.UTF16PtrFromString("p2ptap IPv6 Process Bypass Filter")
	filterV6 := FWPM_FILTER0{
		DisplayData: FWPM_DISPLAY_DATA0{
			Name: filterNameV6,
		},
		LayerKey:            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
		SubLayerKey:         P2PTAP_WFP_SUBLAYER_GUID,
		NumFilterConditions: 1,
		FilterCondition:     &cond,
		Action: FWPM_ACTION0{
			Type: FWP_ACTION_PERMIT,
		},
	}

	var idV6 uint64
	ret, _, _ = procFwpmFilterAdd0.Call(
		handle,
		uintptr(unsafe.Pointer(&filterV6)),
		0,
		uintptr(unsafe.Pointer(&idV6)),
	)
	if ret != 0 {
		_, _, _ = procFwpmFilterDeleteById0.Call(handle, uintptr(idV4))
		procFwpmEngineClose0.Call(handle)
		return fmt.Errorf("FwpmFilterAdd0 (V6) failed with status %s", wfpStatusString(ret))
	}

	w.engineHandle = handle
	w.filterIDV4 = idV4
	w.filterIDV6 = idV6
	w.enabled = true
	protectLog.Info("Successfully registered WFP process-level bypass filters (V4 filterID=%d, V6 filterID=%d) for %s", idV4, idV6, exePath)
	return nil
}

// DisableProcessBypass removes WFP process-level bypass filters and closes WFP engine session.
// Following tailscale/wf architecture, closing the FWPM_SESSION_FLAG_DYNAMIC session handle
// atomically and instantly purges all sublayers and filters in Windows kernel.
func (w *WFPManager) DisableProcessBypass() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.enabled || w.engineHandle == 0 {
		return nil
	}

	// Tailscale-style atomic session closure:
	// Closing the handle of a dynamic session causes WFP kernel engine to
	// instantly and atomically destroy all associated filters and sublayers.
	ret, _, _ := procFwpmEngineClose0.Call(w.engineHandle)
	if ret != 0 {
		protectLog.Warn("FwpmEngineClose0 returned status %s during WFP disable", wfpStatusString(ret))
	}

	w.engineHandle = 0
	w.filterIDV4 = 0
	w.filterIDV6 = 0
	w.enabled = false
	protectLog.Info("Successfully disabled WFP process-level bypass filters (atomic session close)")
	return nil
}
