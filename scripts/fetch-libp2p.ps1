<#
.SYNOPSIS
    Materialise pkg/go-libp2p from pinned upstream + the local patch.

.DESCRIPTION
    pkg/go-libp2p is not versioned (see patches/go-libp2p/README.md). go.mod wires
    it in with:
        replace github.com/libp2p/go-libp2p v0.50.0 => ./pkg/go-libp2p
    so `go build` fails until this script has run in a fresh clone.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\fetch-libp2p.ps1

.EXAMPLE
    .\scripts\fetch-libp2p.ps1 -Force
#>
[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# git writes progress/advice to stderr; with ErrorActionPreference=Stop that is
# promoted to a terminating error even though the command succeeded. Native calls
# therefore run with 'Continue' and are judged by $LASTEXITCODE only.
function Invoke-Git {
    param([Parameter(Mandatory = $true)][scriptblock]$Call)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Call 2>&1 | ForEach-Object { Write-Verbose $_ }
    }
    finally {
        $ErrorActionPreference = $prev
    }
    return $LASTEXITCODE
}

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$PatchDir = Join-Path $Root 'patches\go-libp2p'
$Dest = Join-Path $Root 'pkg\go-libp2p'
$PinFile = Join-Path $PatchDir 'UPSTREAM'

if (-not (Test-Path $PinFile)) { throw "missing $PinFile" }

# Last non-comment line: "<module> <version> <commit>"
$pinLine = Get-Content $PinFile |
    Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' } |
    Select-Object -Last 1
$parts = $pinLine -split '\s+'
if ($parts.Count -lt 3) { throw "cannot parse ${PinFile}: '$pinLine'" }
$Module = $parts[0]
$Version = $parts[1]
$Commit = $parts[2]

$Patch = Join-Path $PatchDir ("p2ptap-$Version.patch")
if (-not (Test-Path $Patch)) { throw "missing patch $Patch (regenerate it after bumping the pin)" }

if ((Test-Path $Dest) -and -not $Force) {
    Write-Host "pkg/go-libp2p already present ($Module $Version); use -Force to rebuild"
    exit 0
}

$Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("p2ptap-libp2p-" + [guid]::NewGuid().ToString('N'))
$Src = Join-Path $Tmp 'src'
New-Item -ItemType Directory -Path $Tmp -Force | Out-Null

try {
    Write-Host "==> fetching $Module $Version ($($Commit.Substring(0,12)))"
    $cloneExit = Invoke-Git { git clone --quiet --depth 1 --branch $Version "https://$Module" $Src }
    if ($cloneExit -eq 0 -and (Test-Path $Src)) {
        $got = (& git -C $Src rev-parse HEAD).Trim()
        if ($got -ne $Commit) {
            Write-Warning "tag $Version resolves to $got, pin says $Commit"
            Write-Warning "the patch was generated against $Commit; update UPSTREAM if the tag moved"
        }
        Remove-Item -Recurse -Force (Join-Path $Src '.git')
    }
    else {
        # No git/network: fall back to the module cache, which a previous
        # `go mod download` will have populated. Say WHY — a silent fallback
        # turns a proxy problem into an unexplained "module not found" later.
        Write-Warning "git clone of $Module $Version failed (exit $cloneExit); trying the module cache"
        $goModCache = (& go env GOMODCACHE).Trim()
        $cached = Join-Path $goModCache "$Module@$Version"
        if (-not (Test-Path $cached)) {
            throw "cannot fetch $Module ${Version}: git clone failed and $cached is absent. Seed it with: go mod download $Module@$Version"
        }
        Write-Host "==> using module cache $cached"
        Copy-Item -Recurse -Force $cached $Src
        # Module cache files are read-only; make them writable before patching.
        Get-ChildItem -Recurse -Force $Src | ForEach-Object {
            $_.Attributes = $_.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
        }
    }

    Write-Host "==> applying $(Split-Path -Leaf $Patch)"
    Push-Location $Src
    try {
        $applyExit = Invoke-Git { git apply -p1 --whitespace=nowarn "$Patch" }
    }
    finally {
        Pop-Location
    }
    if ($applyExit -ne 0) { throw "git apply failed (exit $applyExit) for $Patch" }

    if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
    New-Item -ItemType Directory -Path (Split-Path -Parent $Dest) -Force | Out-Null
    Move-Item $Src $Dest

    # Fail loudly if the tree lost the local hooks the project calls, rather than
    # producing a build that silently dropped socket binding / WebRTC tuning.
    $swarmDial = Join-Path $Dest 'p2p\net\swarm\swarm_dial.go'
    if (-not (Test-Path $swarmDial)) { throw "materialised tree is missing p2p/net/swarm/swarm_dial.go" }
    if (-not (Select-String -Path $swarmDial -Pattern 'DialPeerToAddr' -SimpleMatch -Quiet)) {
        throw "patch did not apply: swarm_dial.go has no DialPeerToAddr hook"
    }
    if (-not (Test-Path (Join-Path $Dest 'p2p\transport\tcp\tcp.go'))) {
        throw "materialised tree is missing p2p/transport/tcp/tcp.go"
    }

    Write-Host "==> pkg/go-libp2p ready ($Module $Version + $(Split-Path -Leaf $Patch))"
}
finally {
    if (Test-Path $Tmp) { Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue }
}
