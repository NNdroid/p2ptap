# =============================================================================
# Build p2ptap Android AAR and APK (Windows PowerShell)
# =============================================================================
$ErrorActionPreference = "Stop"

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$ROOT_DIR = Split-Path -Parent $SCRIPT_DIR
$ANDROID_PROJ = "E:\AndroidStudioProjects\p2ptap"

# 1. Setup SDK & NDK environments
if (-not $env:ANDROID_HOME) {
    $env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
}
if (-not $env:ANDROID_NDK_HOME) {
    $ndkDir = Get-ChildItem "$env:ANDROID_HOME\ndk" -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if ($ndkDir) {
        $env:ANDROID_NDK_HOME = $ndkDir.FullName
    } else {
        Write-Error "Android NDK not found in $env:ANDROID_HOME\ndk"
    }
}

Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "  Building p2ptap Android AAR & APK" -ForegroundColor Cyan
Write-Host "  SDK : $env:ANDROID_HOME" -ForegroundColor Gray
Write-Host "  NDK : $env:ANDROID_NDK_HOME" -ForegroundColor Gray
Write-Host "=========================================================" -ForegroundColor Cyan

# 2. Build AAR using gomobile with 16 KB page size alignment (Android 15+ / Google Play compliant)
$env:GOFLAGS = "-ldflags=-checklinkname=0"
$env:CGO_LDFLAGS = "-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"
$AAR_DIR = "$ANDROID_PROJ\app\libs"
if (-not (Test-Path $AAR_DIR)) {
    New-Item -ItemType Directory -Force -Path $AAR_DIR | Out-Null
}
$AAR_OUT = "$AAR_DIR\p2ptap.aar"

Write-Host "Step 1: Compiling Go native engine into AAR for all architectures (arm64, arm, x86_64, x86)..." -ForegroundColor Yellow
gomobile bind -target="android" -androidapi 21 -javapkg com.p2ptap -ldflags="-checklinkname=0 -extldflags '-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384'" -o $AAR_OUT "$ROOT_DIR\pkg\android"

Write-Host "AAR generated: $AAR_OUT ($( (Get-Item $AAR_OUT).Length / 1MB ) MB)" -ForegroundColor Green

# 3. Assemble Debug APK
Write-Host "Step 2: Building Android APK with Gradle..." -ForegroundColor Yellow
Set-Location $ANDROID_PROJ
.\gradlew.bat assembleDebug

$APK_PATH = "$ANDROID_PROJ\app\build\outputs\apk\debug\app-debug.apk"
if (Test-Path $APK_PATH) {
    Write-Host "=========================================================" -ForegroundColor Green
    Write-Host "  APK Build Complete!" -ForegroundColor Green
    Write-Host "  Path: $APK_PATH" -ForegroundColor White
    Write-Host "  Size: $( [math]::Round((Get-Item $APK_PATH).Length / 1MB, 2) ) MB" -ForegroundColor White
    Write-Host "=========================================================" -ForegroundColor Green
}
