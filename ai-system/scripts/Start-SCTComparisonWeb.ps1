<#
.SYNOPSIS
    Starts the SCT comparison web application.

.EXAMPLE
    .\ai-system\scripts\Start-SCTComparisonWeb.ps1

.EXAMPLE
    .\ai-system\scripts\Start-SCTComparisonWeb.ps1 `
        -Shared -ListenAddress 0.0.0.0 -Port 8000
#>

[CmdletBinding()]
param(
    [switch]$Shared,
    [string]$ListenAddress = '127.0.0.1',
    [ValidateRange(1, 65535)] [int]$Port = 8000,
    [ValidateRange(1, 8)] [int]$JobWorkers = 1,
    [string]$ProviderConfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'SCT-ComparisonHelpers.ps1')

$systemRoot = Split-Path $PSScriptRoot -Parent
if (-not $Shared -and $ListenAddress -notin @('127.0.0.1', '::1', 'localhost')) {
    throw "A non-loopback ListenAddress requires -Shared."
}
if ($Shared) {
    Write-Warning (
        "Shared proof-of-concept mode has no authentication or built-in TLS. " +
        "Use only on a trusted isolated network."
    )
}

$arguments = @(
    '-m', 'sct_ai', 'web',
    '--host', $ListenAddress,
    '--port', [string]$Port,
    '--workers', [string]$JobWorkers
)
if ($Shared) { $arguments += '--shared' }
if (-not $ProviderConfigPath) {
    $candidate = Join-Path $systemRoot 'config\config.local.ai.json'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        $ProviderConfigPath = $candidate
    }
}
if ($ProviderConfigPath) {
    $arguments += @(
        '--provider-config',
        (Resolve-Path -LiteralPath $ProviderConfigPath -ErrorAction Stop).Path
    )
}

Write-Host "SCT comparison web application:" -ForegroundColor Green
Write-Host "  http://${ListenAddress}:$Port" -ForegroundColor White
$exitCode = Invoke-SCTComparisonPython -SystemRoot $systemRoot -Arguments $arguments
if ($exitCode -ne 0) {
    throw "SCT comparison web application exited with code $exitCode."
}
