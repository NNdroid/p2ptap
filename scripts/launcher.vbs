' P2P TAP VPN launcher — no black console window, self-elevating.
' Double-click this to start p2ptap-tray cleanly. Administrator rights are
' obtained on first run so the TAP/Wintun driver and config.json can be written.
Option Explicit

Dim WshShell, FSO, scriptDir, trayExe, cliExe, vbsPath, cfgPath
Set WshShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")
scriptDir = FSO.GetParentFolderName(WScript.ScriptFullName)
trayExe  = FSO.BuildPath(scriptDir, "p2ptap-tray.exe")
cliExe   = FSO.BuildPath(scriptDir, "p2ptap.exe")
cfgPath  = FSO.BuildPath(scriptDir, "config.json")
vbsPath  = WScript.ScriptFullName

' Reliable admin check: capture the EXIT CODE of "net session" (NOT the COM
' error, which is always 0 because cmd.exe itself launched fine). Non-admins get
' ACCESS DENIED -> non-zero exit -> not admin.
Function IsAdmin()
    Dim rc
    On Error Resume Next
    rc = WshShell.Run("cmd /c net session >nul 2>&1", 0, True)
    On Error GoTo 0
    IsAdmin = (rc = 0)
End Function

If Not IsAdmin() Then
    ' Re-launch self elevated & hidden; quit this non-elevated copy.
    Dim sa
    Set sa = CreateObject("Shell.Application")
    sa.ShellExecute "wscript.exe", Chr(34) & vbsPath & Chr(34), scriptDir, "runas", 0
    WScript.Quit 0
End If

' From here we are elevated.

' Generate config.json on first run (needs admin to write into e.g. Program Files).
If Not FSO.FileExists(cfgPath) Then
    On Error Resume Next
    WshShell.Run Chr(34) & cliExe & Chr(34) & " genconf -o " & Chr(34) & cfgPath & Chr(34), 0, True
    On Error GoTo 0
End If

' Desktop shortcut (p2ptap.lnk -> this vbs) created once, with zero black window.
CreateDesktopShortcut

' Silently install the bundled TAP-Windows driver once (app falls back to Wintun).
EnsureTAPDriver

If FSO.FileExists(trayExe) Then
    WshShell.Run Chr(34) & trayExe & Chr(34) & " -c " & Chr(34) & cfgPath & Chr(34), 0, False
Else
    ' Fallback: run the CLI node (may show a window in CLI mode).
    WshShell.Run Chr(34) & cliExe & Chr(34) & " run -c " & Chr(34) & cfgPath & Chr(34), 1, False
End If

Set WshShell = Nothing
Set FSO = Nothing

Sub CreateDesktopShortcut()
    Dim desktop, lnkPath, sh, lnk
    desktop = WshShell.SpecialFolders("Desktop")
    If desktop = "" Then Exit Sub
    lnkPath = FSO.BuildPath(desktop, "p2ptap.lnk")
    If FSO.FileExists(lnkPath) Then Exit Sub
    Set sh = CreateObject("WScript.Shell")
    Set lnk = sh.CreateShortcut(lnkPath)
    lnk.TargetPath = vbsPath
    lnk.WorkingDirectory = scriptDir
    lnk.Description = "p2ptap"
    If FSO.FileExists(trayExe) Then lnk.IconLocation = trayExe
    lnk.Save
End Sub

Sub EnsureTAPDriver()
    Dim tapInstaller, marker
    tapInstaller = FSO.BuildPath(scriptDir, "tap-windows-9.21.2.exe")
    If Not FSO.FileExists(tapInstaller) Then Exit Sub
    marker = FSO.BuildPath(scriptDir, ".tap_installed")
    If FSO.FileExists(marker) Then Exit Sub
    On Error Resume Next
    WshShell.Run Chr(34) & tapInstaller & Chr(34) & " /S", 0, True
    On Error GoTo 0
    On Error Resume Next
    Dim f
    Set f = FSO.CreateTextFile(marker, True)
    f.Close
    On Error GoTo 0
End Sub
