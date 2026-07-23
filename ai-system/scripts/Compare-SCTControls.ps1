<#
.SYNOPSIS
    Compares two or more validated SCT result packages.

.EXAMPLE
    .\ai-system\scripts\Compare-SCTControls.ps1 `
        -PackagePath .\submissions\control-a.zip,.\submissions\control-b.zip `
        -PolicyPath .\ai-system\config\config.local.comparison.json

.EXAMPLE
    .\ai-system\scripts\Compare-SCTControls.ps1 `
        -PackagePath .\submissions\control-a.zip,.\submissions\control-b.zip `
        -PolicyPath .\ai-system\config\config.local.comparison.json `
        -Provider local-ollama -Model approved-model `
        -ProviderConfigPath .\ai-system\config\config.local.ai.json
#>

[CmdletBinding()]
param(
    [string[]]$PackagePath,
    [string]$PolicyPath,
    [string]$Provider = 'none',
    [string]$Model,
    [string]$ProviderConfigPath,
    [string]$ComparisonId,
    [string]$OutputRoot,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'SCT-ComparisonHelpers.ps1')

$systemRoot = Split-Path $PSScriptRoot -Parent
$repoRoot = Split-Path $systemRoot -Parent
if (-not $PackagePath -or $PackagePath.Count -eq 0) {
    $PackagePath = @(
        Select-SCTComparisonPackages -SubmissionsRoot (Join-Path $repoRoot 'submissions')
    )
}
if ($PackagePath.Count -lt 2) {
    throw "At least two comparison ZIPs are required."
}

$resolvedPackages = @(
    $PackagePath | ForEach-Object {
        (Resolve-Path -LiteralPath $_ -ErrorAction Stop).Path
    }
)
$arguments = @('-m', 'sct_ai', 'compare')
foreach ($package in $resolvedPackages) {
    $arguments += @('--package', $package)
}

if ($PolicyPath) {
    $arguments += @(
        '--policy',
        (Resolve-Path -LiteralPath $PolicyPath -ErrorAction Stop).Path
    )
}
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $systemRoot 'comparisons'
}
$arguments += @('--output-root', $OutputRoot, '--provider', $Provider)

if ($Provider -ne 'none') {
    if (-not $Model) { throw "-Model is required when AI analysis is enabled." }
    if (-not $ProviderConfigPath) {
        $candidate = Join-Path $systemRoot 'config\config.local.ai.json'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $ProviderConfigPath = $candidate
        } else {
            throw "-ProviderConfigPath is required when AI analysis is enabled."
        }
    }
    $arguments += @(
        '--model', $Model,
        '--provider-config',
        (Resolve-Path -LiteralPath $ProviderConfigPath -ErrorAction Stop).Path
    )
}
if ($ComparisonId) { $arguments += @('--comparison-id', $ComparisonId) }
if ($Force) { $arguments += '--force' }

$exitCode = Invoke-SCTComparisonPython -SystemRoot $systemRoot -Arguments $arguments
if ($exitCode -ne 0) {
    throw "SCT comparison exited with code $exitCode."
}
