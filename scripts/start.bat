@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM ============================================================
REM P2P TAP VPN Windows Launcher
REM ============================================================

cd /d "%~dp0"

set "BASE_DIR=%~dp0"
set "EXE=%BASE_DIR%p2ptap.exe"
set "TRAY_EXE=%BASE_DIR%p2ptap-tray.exe"
set "CONFIG=%BASE_DIR%config.json"

title P2P TAP VPN Launcher

echo ===================================================
echo             P2P TAP VPN Windows Launcher
echo ===================================================
echo.

REM ============================================================
REM 1. Administrator check
REM ============================================================

net session >nul 2>&1

if not errorlevel 1 goto ADMIN_OK

echo [*] Requesting Administrator permission...

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
"Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"

if errorlevel 1 (
    echo [ERROR] Failed to request Administrator permission.
    pause
    exit /b 1
)

exit /b 0


:ADMIN_OK

echo [+] Administrator permission confirmed.
echo.

REM ============================================================
REM 2. Check main executable
REM ============================================================

if exist "%EXE%" goto EXE_OK

echo [ERROR] p2ptap.exe was not found:
echo %EXE%
echo.
pause
exit /b 1


:EXE_OK

REM ============================================================
REM 3. Detect update
REM ============================================================

set "HAS_UPDATE=0"

if exist "%BASE_DIR%p2ptap.exe.new" set "HAS_UPDATE=1"
if exist "%BASE_DIR%p2ptap-tray.exe.new" set "HAS_UPDATE=1"
if exist "%BASE_DIR%update\p2ptap.exe" set "HAS_UPDATE=1"
if exist "%BASE_DIR%update\p2ptap-tray.exe" set "HAS_UPDATE=1"

if "!HAS_UPDATE!"=="0" goto NO_UPDATE

echo ===================================================
echo [*] Update files detected
echo ===================================================
echo.

REM ============================================================
REM 4. Stop tray
REM ============================================================

echo [*] Stopping tray process...

taskkill /F /IM p2ptap-tray.exe >nul 2>&1

timeout /t 1 /nobreak >nul

REM ============================================================
REM 5. Stop service
REM ============================================================

echo [*] Stopping p2ptap service...

"%EXE%" service stop >nul 2>&1

sc stop p2ptap >nul 2>&1
net stop p2ptap >nul 2>&1

timeout /t 2 /nobreak >nul

REM ============================================================
REM 6. Update p2ptap.exe from .new
REM ============================================================

if not exist "%BASE_DIR%p2ptap.exe.new" goto UPDATE_TRAY_NEW

echo [*] Updating p2ptap.exe...

move /Y "%BASE_DIR%p2ptap.exe.new" "%EXE%" >nul 2>&1

if not errorlevel 1 goto UPDATE_EXE_NEW_OK

echo [ERROR] Failed to update p2ptap.exe.
echo.
pause
exit /b 1


:UPDATE_EXE_NEW_OK

if exist "%EXE%" goto UPDATE_TRAY_NEW

echo [ERROR] p2ptap.exe is missing after update.
echo.
pause
exit /b 1


:UPDATE_TRAY_NEW

REM ============================================================
REM 7. Update tray from .new
REM ============================================================

if not exist "%BASE_DIR%p2ptap-tray.exe.new" goto UPDATE_DIR_EXE

echo [*] Updating p2ptap-tray.exe...

move /Y "%BASE_DIR%p2ptap-tray.exe.new" "%TRAY_EXE%" >nul 2>&1

if not errorlevel 1 goto UPDATE_TRAY_NEW_OK

echo [ERROR] Failed to update p2ptap-tray.exe.
echo.
pause
exit /b 1


:UPDATE_TRAY_NEW_OK

if exist "%TRAY_EXE%" goto UPDATE_DIR_EXE

echo [ERROR] p2ptap-tray.exe is missing after update.
echo.
pause
exit /b 1


:UPDATE_DIR_EXE

REM ============================================================
REM 8. Update p2ptap.exe from update directory
REM ============================================================

if not exist "%BASE_DIR%update\p2ptap.exe" goto UPDATE_DIR_TRAY

echo [*] Updating p2ptap.exe from update directory...

copy /Y "%BASE_DIR%update\p2ptap.exe" "%EXE%" >nul 2>&1

if not errorlevel 1 goto UPDATE_DIR_EXE_OK

echo [ERROR] Failed to copy p2ptap.exe.
echo.
pause
exit /b 1


:UPDATE_DIR_EXE_OK

if exist "%EXE%" goto DELETE_UPDATE_EXE

echo [ERROR] p2ptap.exe is missing after update.
echo.
pause
exit /b 1


:DELETE_UPDATE_EXE

del /F /Q "%BASE_DIR%update\p2ptap.exe" >nul 2>&1


:UPDATE_DIR_TRAY

REM ============================================================
REM 9. Update tray from update directory
REM ============================================================

if not exist "%BASE_DIR%update\p2ptap-tray.exe" goto UPDATE_DONE

echo [*] Updating p2ptap-tray.exe from update directory...

copy /Y "%BASE_DIR%update\p2ptap-tray.exe" "%TRAY_EXE%" >nul 2>&1

if not errorlevel 1 goto UPDATE_DIR_TRAY_OK

echo [ERROR] Failed to copy p2ptap-tray.exe.
echo.
pause
exit /b 1


:UPDATE_DIR_TRAY_OK

if exist "%TRAY_EXE%" goto DELETE_UPDATE_TRAY

echo [ERROR] p2ptap-tray.exe is missing after update.
echo.
pause
exit /b 1


:DELETE_UPDATE_TRAY

del /F /Q "%BASE_DIR%update\p2ptap-tray.exe" >nul 2>&1


:UPDATE_DONE

echo.
echo [+] Update completed successfully.
echo ---------------------------------------------------
echo.


:NO_UPDATE

REM ============================================================
REM 10. Generate config.json
REM ============================================================

if exist "%CONFIG%" goto CONFIG_OK

echo [*] config.json was not found.
echo [*] Generating default configuration...

"%EXE%" genconf -o "%CONFIG%"

if not errorlevel 1 goto CONFIG_GENERATED

echo [ERROR] Failed to generate config.json.
echo.
pause
exit /b 1


:CONFIG_GENERATED

if exist "%CONFIG%" goto CONFIG_OK

echo [ERROR] config.json was not created.
echo.
pause
exit /b 1


:CONFIG_OK

echo [+] Configuration file is ready.
echo.

REM ============================================================
REM 11. Check Windows service
REM ============================================================

echo [*] Checking p2ptap Windows service...

sc query p2ptap >nul 2>&1

if not errorlevel 1 goto SERVICE_EXISTS

echo [*] p2ptap service is not installed.
echo [*] Tray/CLI mode will be used.
echo.

goto START_TRAY


:SERVICE_EXISTS

echo [+] p2ptap Windows service is installed.
echo [*] Starting service...

REM First try application command
"%EXE%" service start >nul 2>&1

timeout /t 1 /nobreak >nul

REM Check actual service state
sc query p2ptap | findstr /I "RUNNING" >nul 2>&1

if not errorlevel 1 goto SERVICE_RUNNING

REM Application command did not result in RUNNING.
REM Try Windows Service Manager.

echo [*] Service is not running yet.
echo [*] Trying Windows Service Manager...

net start p2ptap >nul 2>&1

timeout /t 2 /nobreak >nul

REM Check actual state again
sc query p2ptap | findstr /I "RUNNING" >nul 2>&1

if not errorlevel 1 goto SERVICE_RUNNING

echo.
echo [ERROR] p2ptap service is not running.
echo.
echo Current service state:
echo ---------------------------------------------------
sc query p2ptap
echo ---------------------------------------------------
echo.
pause
exit /b 1


:SERVICE_RUNNING

echo [+] p2ptap Windows service is RUNNING.
echo.

REM ============================================================
REM 12. Start tray
REM ============================================================

:START_TRAY

echo [*] Checking old tray process...

taskkill /F /IM p2ptap-tray.exe >nul 2>&1

timeout /t 1 /nobreak >nul

if not exist "%TRAY_EXE%" goto START_CLI

echo [*] Starting p2ptap tray...

start "" "%TRAY_EXE%" -c "%CONFIG%"

if errorlevel 1 (
    echo [ERROR] Failed to start p2ptap-tray.exe.
    echo.
    pause
    exit /b 1
)

timeout /t 1 /nobreak >nul

tasklist /FI "IMAGENAME eq p2ptap-tray.exe" 2>nul | findstr /I "p2ptap-tray.exe" >nul 2>&1

if not errorlevel 1 goto START_OK

echo [ERROR] p2ptap-tray.exe exited immediately.
echo.
echo Try running this command manually:
echo.
echo p2ptap-tray.exe -c config.json
echo.
pause
exit /b 1


:START_CLI

echo [*] p2ptap-tray.exe was not found.
echo [*] Starting CLI mode...

start "" "%EXE%" run -c "%CONFIG%"

if errorlevel 1 (
    echo [ERROR] Failed to start p2ptap CLI.
    echo.
    pause
    exit /b 1
)

echo [+] p2ptap CLI started.
goto START_OK


:START_OK

echo.
echo ===================================================
echo P2P TAP VPN started successfully.
echo ===================================================
echo.

timeout /t 2 /nobreak >nul

exit /b 0