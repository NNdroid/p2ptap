# P2P TAP VPN Multi-Architecture Cross-Compilation Script (PowerShell)
# Usage:
#   .\scripts\build.ps1                      # Build all targets
#   .\scripts\build.ps1 -Target current       # Build for current host OS/Arch (fast)
#   .\scripts\build.ps1 -Target openwrt       # Build all OpenWrt targets (mipsle, mips, arm, arm64, amd64)
#   .\scripts\build.ps1 -OS linux -Arch arm64 # Build specific OS/Arch
#   .\scripts\build.ps1 -Target linux-amd64   # Build specific target alias

param(
    [string]$OS = "",
    [string]$Arch = "",
    [string]$Target = "all"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
Set-Location $RootDir

$origGOOS = $env:GOOS
$origGOARCH = $env:GOARCH

$BinDir = Join-Path $RootDir "bin"
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir | Out-Null
}

function Ensure-WintunDll {
    param([string]$arch)
    $wintunDir = Join-Path $ScriptDir "wintun\$arch"
    $wintunDll = Join-Path $wintunDir "wintun.dll"
    if (-not (Test-Path $wintunDll)) {
        Write-Host "[+] Auto-downloading latest WireGuard Wintun release from wintun.net..." -ForegroundColor Cyan
        $tempZip = Join-Path $env:TEMP "wintun_latest.zip"
        $tempExt = Join-Path $env:TEMP "wintun_latest_extracted"
        Invoke-WebRequest -Uri "https://www.wintun.net/builds/wintun-0.14.1.zip" -OutFile $tempZip -UseBasicParsing
        Expand-Archive -Path $tempZip -DestinationPath $tempExt -Force

        New-Item -ItemType Directory -Path (Join-Path $ScriptDir "wintun\amd64") -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $ScriptDir "wintun\386") -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $ScriptDir "wintun\arm64") -Force | Out-Null

        Copy-Item "$tempExt\wintun\bin\amd64\wintun.dll" (Join-Path $ScriptDir "wintun\amd64\") -Force
        Copy-Item "$tempExt\wintun\bin\x86\wintun.dll" (Join-Path $ScriptDir "wintun\386\") -Force
        Copy-Item "$tempExt\wintun\bin\arm64\wintun.dll" (Join-Path $ScriptDir "wintun\arm64\") -Force
        Remove-Item -Recurse -Force $tempZip, $tempExt
    }
    return $wintunDll
}

$AllTargets = @(
    @{ OS = "linux";   Arch = "amd64" },
    @{ OS = "linux";   Arch = "386" },
    @{ OS = "linux";   Arch = "arm64" },
    @{ OS = "linux";   Arch = "arm" },
    @{ OS = "linux";   Arch = "mips64le" },
    @{ OS = "linux";   Arch = "mipsle" },
    @{ OS = "linux";   Arch = "mips" },
    @{ OS = "linux";   Arch = "riscv64" },
    @{ OS = "linux";   Arch = "loong64" },
    @{ OS = "windows"; Arch = "amd64" },
    @{ OS = "windows"; Arch = "386" },
    @{ OS = "windows"; Arch = "arm64" },
    @{ OS = "darwin";  Arch = "amd64" },
    @{ OS = "darwin";  Arch = "arm64" }
)

# Determine targets to build
$SelectedTargets = @()

if ($OS -ne "" -and $Arch -ne "") {
    $SelectedTargets += @{ OS = $OS; Arch = $Arch }
} elseif ($OS -ne "") {
    $SelectedTargets = $AllTargets | Where-Object { $_.OS -eq $OS }
} elseif ($Arch -ne "") {
    $SelectedTargets = $AllTargets | Where-Object { $_.Arch -eq $Arch }
} elseif ($Target -eq "current" -or $Target -eq "native") {
    $nativeOS = "windows"
    if ($IsLinux) { $nativeOS = "linux" }
    elseif ($IsMacOS) { $nativeOS = "darwin" }
    
    $nativeArch = "amd64"
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $env:PROCESSOR_ARCHITEW6432 -eq "ARM64") { $nativeArch = "arm64" }
    
    $SelectedTargets += @{ OS = $nativeOS; Arch = $nativeArch }
} elseif ($Target -eq "openwrt") {
    $openwrtArchs = @("mipsle", "mips", "arm", "arm64", "amd64", "386", "mips64le", "riscv64")
    $SelectedTargets = $AllTargets | Where-Object { $_.OS -eq "linux" -and $openwrtArchs -contains $_.Arch }
} elseif ($Target -ne "all" -and $Target -ne "") {
    # Parse target string like "linux-amd64" or "windows-arm64"
    $parts = $Target.Split("-")
    if ($parts.Length -eq 2) {
        $SelectedTargets += @{ OS = $parts[0]; Arch = $parts[1] }
    } else {
        Write-Error "Unknown target specifier '$Target'. Use 'all', 'current', 'openwrt', or 'os-arch' format (e.g. linux-amd64)."
    }
} else {
    $SelectedTargets = $AllTargets
}

Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "       Building P2P TAP VPN Releases ($($SelectedTargets.Count) target(s)) " -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan

try {
    foreach ($t in $SelectedTargets) {
        $os = $t.OS
        $arch = $t.Arch
        $pkgName = "p2ptap-$os-$arch"
        $stageDir = Join-Path $BinDir $pkgName
        if (Test-Path $stageDir) { Remove-Item -Recurse -Force $stageDir }
        New-Item -ItemType Directory -Path $stageDir | Out-Null

        $ext = ""
        if ($os -eq "windows") { $ext = ".exe" }

        $binOut = Join-Path $stageDir "p2ptap$ext"
        $bootOut = Join-Path $stageDir "p2ptap-boot$ext"

        Write-Host "[+] Compiling for $os/$arch..." -ForegroundColor Green
        $env:CGO_ENABLED = "0"
        $env:GOOS = $os
        $env:GOARCH = $arch

        $ver = if ($env:P2PTAP_VERSION) { $env:P2PTAP_VERSION } else { "v1.0." + (Get-Date -Format "yyyyMMdd") }
        $buildTime = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        $gitCommit = (git rev-parse HEAD 2>$null) -replace "`n",""
        if (-not $gitCommit) { $gitCommit = "unknown" }
        $ldflags = "-s -w -X p2ptap/pkg/version.Version=$ver -X p2ptap/pkg/version.BuildTime=$buildTime -X p2ptap/pkg/version.GitCommit=$gitCommit"

        go build -ldflags="$ldflags" -o $binOut ./cmd/p2ptap
        go build -ldflags="$ldflags" -o $bootOut ./cmd/p2ptap-boot

        if ($os -eq "windows") {
            $trayOut = Join-Path $stageDir "p2ptap-tray.exe"
            $guiLdflags = "$ldflags -H windowsgui"
            go build -ldflags="$guiLdflags" -o $trayOut ./cmd/p2ptap-tray
            if (Test-Path (Join-Path $ScriptDir "start.bat")) {
                Copy-Item (Join-Path $ScriptDir "start.bat") $stageDir
            }
            $wintunDllFile = Ensure-WintunDll -arch $arch
            if (Test-Path $wintunDllFile) {
                Copy-Item $wintunDllFile $stageDir
            }
        } else {
            if (Test-Path (Join-Path $ScriptDir "start.sh")) {
                Copy-Item (Join-Path $ScriptDir "start.sh") $stageDir
            }
        }

        $zipPath = Join-Path $BinDir "$pkgName.zip"
        if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
        Compress-Archive -Path "$stageDir\*" -DestinationPath $zipPath
        Remove-Item -Recurse -Force $stageDir
    }
} finally {
    # Reset GOOS/GOARCH back to native environment
    if ($origGOOS) { $env:GOOS = $origGOOS } else { Remove-Item Env:\GOOS -ErrorAction SilentlyContinue }
    if ($origGOARCH) { $env:GOARCH = $origGOARCH } else { Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue }
}

Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "  Build Complete! Generated release artifacts in bin/ :" -ForegroundColor Cyan
Get-ChildItem $BinDir | Select-Object Name, Length
Write-Host "=========================================================" -ForegroundColor Cyan
