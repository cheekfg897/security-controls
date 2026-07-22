<#
.SYNOPSIS
    Builds one validated SCT comparison ZIP for a control workspace.

.EXAMPLE
    .\scripts\review\Build-SCTComparisonPackage.ps1 `
        -ControlProfilePath .\results\sentinelone\control-profile.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ControlProfilePath,
    [string]$OutputPath,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\common\SCT-ReviewHelpers.ps1')

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$profilePath = (Resolve-Path -LiteralPath $ControlProfilePath -ErrorAction Stop).Path
$workspaceRoot = Split-Path $profilePath -Parent
$resultsPath = Join-Path $workspaceRoot 'results.csv'
$catalogPath = Join-Path $workspaceRoot 'test-catalog.csv'

$profile = Get-Content -LiteralPath $profilePath -Raw -Encoding UTF8 | ConvertFrom-Json
$profileErrors = @(Get-SCTControlProfileErrors -Profile $profile)
if ($profileErrors.Count -gt 0) {
    throw "Invalid control profile:`n$($profileErrors -join "`n")"
}
foreach ($requiredPath in @($resultsPath, $catalogPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Comparison package input is missing: $requiredPath"
    }
}

& (Join-Path $PSScriptRoot '..\validation\Check-SCTResults.ps1') -Path $resultsPath

$controlId = [string]$profile.control.id
if (-not $OutputPath) {
    $OutputPath = Join-Path (Join-Path $repoRoot 'submissions') "$controlId.zip"
}
$resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if ((Test-Path -LiteralPath $resolvedOutputPath) -and -not $Force) {
    throw "Submission already exists: $resolvedOutputPath. Use -Force to replace it."
}
$outputDirectory = Split-Path $resolvedOutputPath -Parent
if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

Compress-Archive -LiteralPath @($profilePath, $resultsPath, $catalogPath) `
    -DestinationPath $resolvedOutputPath -CompressionLevel Optimal -Force:$Force

Write-Host "Built comparison package:" -ForegroundColor Green
Write-Host "  $resolvedOutputPath" -ForegroundColor White
Write-Host "  control-profile.json, results.csv, test-catalog.csv" -ForegroundColor DarkGray
