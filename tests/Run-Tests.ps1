<#
.SYNOPSIS
    Runs every dependency-free SCT regression test.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$testFiles = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter 'Test-*.ps1' -File -Recurse | Sort-Object FullName)
if ($testFiles.Count -eq 0) {
    throw "No Test-*.ps1 files found under $PSScriptRoot."
}

foreach ($testFile in $testFiles) {
    Write-Host "`n==> $($testFile.FullName)" -ForegroundColor Cyan
    & $testFile.FullName
}

Write-Host "`nPassed $($testFiles.Count) test files." -ForegroundColor Green
