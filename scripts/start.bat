@echo off
title P2P TAP VPN (Windows Tray & Service)
cd /d "%~dp0"

:: Auto-elevate to Administrator privileges via PowerShell UAC prompt
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Requesting Administrator privileges for TAP network driver access...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo =========================================================
echo              Starting P2P TAP VPN (Windows)
echo =========================================================

if not exist config.json (
    echo [*] config.json missing, generating default config with random PSK and MAC...
    p2ptap.exe genconf -o config.json
)

if exist p2ptap-tray.exe (
    echo [*] Launching p2ptap Windows System Tray GUI...
    start "" p2ptap-tray.exe -c config.json
) else (
    echo [*] Launching p2ptap CLI node...
    p2ptap.exe run -c config.json
)

exit /b
