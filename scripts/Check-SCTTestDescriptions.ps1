<#
.SYNOPSIS
    Checks every module's test descriptions and prints the combined row count.
#>

[CmdletBinding()]
param([string]$ScenariosPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_SCT-ReviewHelpers.ps1')

if (-not $ScenariosPath) {
    $ScenariosPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'scenarios'
}

$catalog = Get-SCTCatalogData -ScenariosPath $ScenariosPath
if ($catalog.Errors.Count -gt 0) {
    Write-Host '[FAIL] SCT test catalog' -ForegroundColor Red
    foreach ($message in $catalog.Errors) { Write-Host "       $message" -ForegroundColor Red }
    exit 1
}

Write-Host "[OK]   Validated $($catalog.Rows.Count) catalog rows." -ForegroundColor Green
