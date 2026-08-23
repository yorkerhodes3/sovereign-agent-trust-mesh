<#
.SYNOPSIS
    Windows equivalent of the Makefile. `make` is rarely present on Windows, and
    the Phase 0 toolchain (Foundry) is fully usable there, so the entry points
    are mirrored rather than making Windows a second-class environment.

.EXAMPLE
    .\make.ps1 test
    .\make.ps1 devnet-up
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Target = "help"
)

$ErrorActionPreference = "Stop"

$Contracts   = Join-Path $PSScriptRoot "contracts"
$AnvilL2Port = if ($env:ANVIL_L2_PORT) { $env:ANVIL_L2_PORT } else { 8545 }
$AnvilL1Port = if ($env:ANVIL_L1_PORT) { $env:ANVIL_L1_PORT } else { 8546 }
# anvil account #0 — a well-known devnet key. NEVER use outside a local chain.
$DevnetPk    = if ($env:DEVNET_PK) { $env:DEVNET_PK } else { "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" }

function Invoke-InContracts([string[]]$CmdArgs) {
    Push-Location $Contracts
    try {
        & forge @CmdArgs
        if ($LASTEXITCODE -ne 0) { throw "forge $($CmdArgs -join ' ') failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

function Start-Chain([int]$Port, [int]$ChainId, [string]$Role) {
    $existing = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  $Role already listening on :$Port" -ForegroundColor Yellow
        return
    }
    Start-Process -FilePath "anvil" `
        -ArgumentList "--port", $Port, "--chain-id", $ChainId, "--silent" `
        -WindowStyle Hidden
    Write-Host "  $Role  anvil :$Port  chainId $ChainId" -ForegroundColor Green
}

switch ($Target) {
    "help" {
        Write-Host "SATM targets (mirrors the Makefile):`n"
        @(
            @{ n = "deps";           d = "Install locked contract dependencies" }
            @{ n = "build";          d = "Compile contracts" }
            @{ n = "test";           d = "Run the contract test suite" }
            @{ n = "test-gas";       d = "Run tests with a gas report" }
            @{ n = "fmt";            d = "Format Solidity sources" }
            @{ n = "lint";           d = "Check formatting without writing" }
            @{ n = "coverage";       d = "Contract coverage report" }
            @{ n = "devnet-chains";  d = "Start both anvil chains (L2 + L1 roles)" }
            @{ n = "devnet-up";      d = "Chains + deployed registries (Phase 0 subset)" }
            @{ n = "devnet-down";    d = "Stop the local chains" }
            @{ n = "deploy-local";   d = "Deploy ERC-8004 registries to the local L2" }
            @{ n = "verify-vendor";  d = "Confirm vendored sources match the pinned commit" }
            @{ n = "ci";             d = "Everything CI runs" }
            @{ n = "clean";          d = "Remove build artifacts" }
        ) | ForEach-Object { "  {0,-16} {1}" -f $_.n, $_.d }
    }

    "deps"     { Invoke-InContracts @("soldeer", "install") }
    "build"    { Invoke-InContracts @("build") }
    "test"     { Invoke-InContracts @("test", "-vv") }
    "test-gas" { Invoke-InContracts @("test", "--gas-report") }
    "fmt"      { Invoke-InContracts @("fmt") }
    "lint"     { Invoke-InContracts @("fmt", "--check") }
    "coverage" { Invoke-InContracts @("coverage", "--report", "summary") }

    "devnet-chains" {
        Write-Host "starting local chains..."
        Start-Chain -Port $AnvilL2Port -ChainId 31337 -Role "L2"
        Start-Chain -Port $AnvilL1Port -ChainId 31338 -Role "L1"
        Start-Sleep -Seconds 3
        Write-Host "both chains up" -ForegroundColor Green
    }

    "devnet-down" {
        $stopped = 0
        Get-Process anvil -ErrorAction SilentlyContinue | ForEach-Object {
            Stop-Process -Id $_.Id -Force
            $stopped++
        }
        Write-Host "stopped $stopped anvil process(es)"
    }

    "deploy-local" {
        $env:PRIVATE_KEY = $DevnetPk
        Invoke-InContracts @(
            "script", "script/DeployRegistries.s.sol",
            "--rpc-url", "http://127.0.0.1:$AnvilL2Port",
            "--broadcast"
        )
    }

    "devnet-up" {
        & $PSCommandPath "devnet-chains"
        & $PSCommandPath "deploy-local"
        Write-Host "`ndevnet ready - see contracts/deployments/31337.json" -ForegroundColor Green
    }

    "verify-vendor" {
        & (Join-Path $PSScriptRoot "tools\verify-vendor.ps1")
    }

    "ci" {
        & $PSCommandPath "lint"
        & $PSCommandPath "build"
        & $PSCommandPath "test"
        & $PSCommandPath "verify-vendor"
    }

    "clean" {
        foreach ($d in @("out", "cache", "broadcast")) {
            $p = Join-Path $Contracts $d
            if (Test-Path $p) { Remove-Item -Recurse -Force $p }
        }
        Write-Host "cleaned"
    }

    default {
        Write-Error "Unknown target '$Target'. Run '.\make.ps1 help' for the list."
        exit 1
    }
}
