<#
.SYNOPSIS
    Runs the complete AI comparison system regression suite.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$systemRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $systemRoot 'scripts\SCT-ComparisonHelpers.ps1')

& (Join-Path $PSScriptRoot 'Test-AISystemSurface.ps1')

$arguments = @(
    '-m', 'unittest', 'discover',
    '-s', (Join-Path $PSScriptRoot 'python'),
    '-t', $systemRoot,
    '-v'
)
$exitCode = Invoke-SCTComparisonPython -SystemRoot $systemRoot -Arguments $arguments
if ($exitCode -ne 0) {
    throw "Python regression tests exited with code $exitCode."
}
