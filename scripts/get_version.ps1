param(
    [string]$Version = $env:P2PTAP_VERSION,
    [string]$SourceRef = 'HEAD'
)
$ErrorActionPreference = 'Stop'
if (-not $Version) { $Version = $env:P2PTAP_VERSION }
if ($Version) {
    if ($Version -cnotmatch '\Av?[0-9]+(\.[0-9]+)*(-[0-9a-f]{7})?\z') {
        throw 'Invalid version: expected v1.2.3 or v1.0.YYYYMMDD.COUNT-HASH7'
    }
    return 'v' + $Version.TrimStart('v')
}
$repoDir = Split-Path -Parent $PSScriptRoot
$shallow = & git -C $repoDir rev-parse --is-shallow-repository
if ($LASTEXITCODE -ne 0 -or $shallow -ne 'false') {
    throw 'Full Git history is required for automatic versioning; fetch with depth 0'
}
$commit = & git -C $repoDir rev-parse --verify "${SourceRef}^{commit}"
if ($LASTEXITCODE -ne 0) { throw "Cannot resolve source commit: $SourceRef" }
$count = & git -C $repoDir rev-list --count $commit
if ($LASTEXITCODE -ne 0 -or $count -cnotmatch '\A[1-9][0-9]*\z') { throw 'Cannot count source history' }
'v1.0.{0}.{1}-{2}' -f [DateTime]::UtcNow.ToString('yyyyMMdd', [Globalization.CultureInfo]::InvariantCulture), $count, $commit.Substring(0, 7)
