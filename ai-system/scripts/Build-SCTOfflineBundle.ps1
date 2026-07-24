<#
.SYNOPSIS
    Downloads the approved Python wheel set and creates a checksummed transfer bundle.

.DESCRIPTION
    Run this on an approved internet-connected Windows staging machine with
    the same supported Python 3.x minor version as the destination machine.
    Model files are optional and are copied only when explicitly supplied.
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$ModelPath,
    [ValidatePattern('^3\.\d+$')] [string]$PythonVersion,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'SCT-ComparisonHelpers.ps1')

$systemRoot = Split-Path $PSScriptRoot -Parent
$pythonArguments = @{ SystemRoot = $systemRoot }
if ($PythonVersion) {
    $pythonArguments.PythonVersion = $PythonVersion
}
$python = Get-SCTComparisonPython @pythonArguments
$PythonVersion = $python.Version
if (-not $OutputPath) {
    $versionTag = $PythonVersion.Replace('.', '')
    $OutputPath = Join-Path $systemRoot "offline-bundles\sct-comparison-python$versionTag"
}
$resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$driveRoot = [IO.Path]::GetPathRoot($resolvedOutput).TrimEnd('\')
if ($resolvedOutput.TrimEnd('\') -eq $driveRoot -or
    $resolvedOutput.TrimEnd('\') -eq $systemRoot.TrimEnd('\')) {
    throw "Offline bundle output must be a dedicated child directory, not a drive or AI system root."
}
if (Test-Path -LiteralPath $resolvedOutput) {
    if (-not $Force) {
        throw "Offline bundle already exists: $resolvedOutput. Use -Force to replace it."
    }
    Remove-Item -LiteralPath $resolvedOutput -Recurse -Force
}
New-Item -ItemType Directory -Path $resolvedOutput | Out-Null
$wheelhouse = New-Item -ItemType Directory -Path (Join-Path $resolvedOutput 'wheelhouse')
$requirementsTarget = New-Item -ItemType Directory -Path (Join-Path $resolvedOutput 'requirements')
$requirementsSource = Join-Path $systemRoot 'requirements\all.txt'
$buildRequirementsSource = Join-Path $systemRoot 'requirements\build.txt'
Copy-Item -LiteralPath $requirementsSource -Destination $requirementsTarget.FullName
Copy-Item -LiteralPath $buildRequirementsSource -Destination $requirementsTarget.FullName

$downloadArguments = @(
    '-m', 'pip', 'download',
    '--only-binary=:all:',
    '--dest', $wheelhouse.FullName,
    '-r', $requirementsSource,
    '-r', $buildRequirementsSource
)
$exitCode = Invoke-SCTComparisonPython `
    -SystemRoot $systemRoot `
    -Arguments $downloadArguments `
    -PythonVersion $PythonVersion
if ($exitCode -ne 0) {
    throw "Python dependency download exited with code $exitCode."
}

if ($ModelPath) {
    $resolvedModel = (Resolve-Path -LiteralPath $ModelPath -ErrorAction Stop).Path
    $modelTarget = New-Item -ItemType Directory -Path (Join-Path $resolvedOutput 'models')
    Copy-Item -LiteralPath $resolvedModel -Destination $modelTarget.FullName -Recurse
}

$files = @(
    Get-ChildItem -LiteralPath $resolvedOutput -Recurse -File |
        Sort-Object FullName |
        ForEach-Object {
            [pscustomobject][ordered]@{
                path   = [IO.Path]::GetRelativePath($resolvedOutput, $_.FullName).Replace('\', '/')
                bytes  = $_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            }
        }
)
$manifest = [pscustomobject][ordered]@{
    schema_version = '1.0'
    python_version = $PythonVersion
    created_at     = (Get-Date).ToUniversalTime().ToString('o')
    files          = $files
}
$manifest | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath (Join-Path $resolvedOutput 'bundle-manifest.json') -Encoding UTF8

Write-Host "Built offline transfer bundle:" -ForegroundColor Green
Write-Host "  $resolvedOutput"
Write-Host "  $($files.Count) checksummed file(s)"
