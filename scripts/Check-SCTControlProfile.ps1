<#
.SYNOPSIS
    Checks an SCT control-profile JSON file.

.EXAMPLE
    .\scripts\Check-SCTControlProfile.ps1 -Path .\config\control-profile.local.json
#>

[CmdletBinding()]
param([Parameter(Mandatory)] [string]$Path)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_SCT-ReviewHelpers.ps1')

try {
    $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $profile = Get-Content -LiteralPath $resolvedPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $errors = @(Get-SCTControlProfileErrors -Profile $profile)
} catch {
    Write-Host "[FAIL] $Path" -ForegroundColor Red
    Write-Host "       $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

if ($errors.Count -gt 0) {
    Write-Host "[FAIL] $resolvedPath" -ForegroundColor Red
    foreach ($message in $errors) { Write-Host "       $message" -ForegroundColor Red }
    exit 1
}

Write-Host "[OK]   $resolvedPath" -ForegroundColor Green
Write-Host "       Control: $($profile.control.display_name) ($($profile.control.id))" -ForegroundColor DarkGray
Write-Host "       Mode   : $($profile.policy.default_mode)" -ForegroundColor DarkGray
