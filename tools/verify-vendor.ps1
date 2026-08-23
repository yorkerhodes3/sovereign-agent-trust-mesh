<#
.SYNOPSIS
    Windows equivalent of tools/verify-vendor.sh.

    Verifies the vendored ERC-8004 sources are byte-identical to the pinned
    upstream commit. vendor/ must mirror upstream exactly; SATM changes belong
    in contracts/src/.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$root         = Split-Path -Parent $PSScriptRoot
$vendor       = Join-Path $root "contracts\vendor\erc8004"
$upstreamFile = Join-Path $vendor "UPSTREAM"

if (-not (Test-Path $upstreamFile)) {
    Write-Error "UPSTREAM file not found at $upstreamFile"
    exit 1
}

$sha = (Select-String -Path $upstreamFile -Pattern '^commit:\s*(\S+)').Matches[0].Groups[1].Value
if (-not $sha) {
    Write-Error "No 'commit:' line in $upstreamFile"
    exit 1
}
Write-Host "pinned upstream commit: $sha"

$files = @(
    "IdentityRegistryUpgradeable",
    "ReputationRegistryUpgradeable",
    "ValidationRegistryUpgradeable",
    "ERC1967Proxy",
    "MinimalUUPS"
)

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("satm-vendor-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$failed = 0
try {
    foreach ($f in $files) {
        $url   = "https://raw.githubusercontent.com/erc-8004/erc-8004-contracts/$sha/contracts/$f.sol"
        $local = Join-Path $vendor "$f.sol"
        $fetch = Join-Path $tmp "$f.sol"

        try {
            Invoke-WebRequest -Uri $url -OutFile $fetch -UseBasicParsing
        } catch {
            Write-Host ("  FETCH-FAIL  {0}.sol" -f $f) -ForegroundColor Red
            $failed++
            continue
        }

        # Compare normalized content so a checkout line-ending policy does not
        # masquerade as tampering.
        $a = (Get-Content $fetch -Raw) -replace "`r`n", "`n"
        $b = (Get-Content $local -Raw) -replace "`r`n", "`n"

        if ($a -eq $b) {
            Write-Host ("  ok          {0}.sol" -f $f) -ForegroundColor Green
        } else {
            Write-Host ("  MODIFIED    {0}.sol" -f $f) -ForegroundColor Red
            $failed++
        }
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

if ($failed -gt 0) {
    Write-Host ""
    Write-Error "vendor/erc8004 has diverged from the pinned commit ($failed file(s)). Put SATM-specific changes in contracts/src/, not in vendor/."
    exit 1
}

Write-Host "all vendored sources match upstream" -ForegroundColor Green
