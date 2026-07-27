<#
.SYNOPSIS
    Checks every module's test descriptions and prints the combined row count.
#>

[CmdletBinding()]
param([string]$ScenariosPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\common\SCT-ReviewHelpers.ps1')

if (-not $ScenariosPath) {
    $scriptsRoot = Split-Path $PSScriptRoot -Parent
    $repoRoot = Split-Path $scriptsRoot -Parent
    $ScenariosPath = Join-Path $repoRoot 'scenarios'
}

$catalog = Get-SCTCatalogData -ScenariosPath $ScenariosPath
if ($catalog.Errors.Count -gt 0) {
    Write-Host '[FAIL] SCT test catalog' -ForegroundColor Red
    foreach ($message in $catalog.Errors) { Write-Host "       $message" -ForegroundColor Red }
    exit 1
}

Write-Host "[OK]   Validated $($catalog.Rows.Count) catalog rows." -ForegroundColor Green
