@echo off
title P2P TAP VPN (Windows)
cd /d "%~dp0"

:: Self-elevate to Administrator if required (one-shot UAC). The elevated copy
:: re-runs this script. The tray also self-elevates on its own, but elevating
:: here first means the driver install + config.json write + node all run
:: privileged with a SINGLE prompt instead of two.
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: First run: generate config.json (needs admin to write into protected dirs
:: like Program Files). Best-effort; if it fails the tray falls back to defaults.
if not exist config.json (
    p2ptap.exe genconf -o config.json
)

:: GUI tray is preferred (windowsgui subsystem, no black window). It decides
:: standalone vs service mode internally. Falls back to the headless CLI node.
if exist p2ptap-tray.exe (
    start "" p2ptap-tray.exe -c config.json
) else (
    p2ptap.exe run -c config.json
)

exit /b
