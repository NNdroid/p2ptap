//go:build windows

package main

import "golang.org/x/sys/windows"

// hideConsoleIfAny releases a console window if one is attached to this
// process. When the GUI binary is built as a console subsystem (or launched via
// a mechanism that allocates one), Windows would otherwise pop a black console
// box on startup — most visibly during logon auto-start. The binary is built
// with -H windowsgui (no console), so GetConsoleWindow normally returns NULL
// and this is a no-op; it is a belt-and-suspenders guard for any code path or
// legacy build that still ends up with a console.
func hideConsoleIfAny() {
	k := windows.NewLazySystemDLL("kernel32.dll")
	getCW := k.NewProc("GetConsoleWindow")
	free := k.NewProc("FreeConsole")
	hwnd, _, _ := getCW.Call()
	if hwnd != 0 {
		_, _, _ = free.Call()
	}
}
