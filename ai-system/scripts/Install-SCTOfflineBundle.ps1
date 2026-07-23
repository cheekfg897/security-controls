<#
.SYNOPSIS
    Verifies and installs the SCT comparison wheelhouse without using a package index.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$BundlePath,
    [string]$VirtualEnvironmentPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'SCT-ComparisonHelpers.ps1')

$systemRoot = Split-Path $PSScriptRoot -Parent
$bundleRoot = (Resolve-Path -LiteralPath $BundlePath -ErrorAction Stop).Path
$manifestPath = Join-Path $bundleRoot 'bundle-manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Offline bundle is missing bundle-manifest.json."
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($manifest.schema_version -ne '1.0' -or $manifest.python_version -ne '3.11') {
    throw "Offline bundle manifest is unsupported."
}
foreach ($file in @($manifest.files)) {
    $candidate = Join-Path $bundleRoot ([string]$file.path)
    $resolvedCandidate = (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).Path
    $relativeCandidate = [IO.Path]::GetRelativePath($bundleRoot, $resolvedCandidate)
    if ([IO.Path]::IsPathRooted($relativeCandidate) -or
        $relativeCandidate -eq '..' -or
        $relativeCandidate.StartsWith("..$([IO.Path]::DirectorySeparatorChar)")) {
        throw "Offline bundle manifest contains an unsafe path: $($file.path)"
    }
    $actual = (Get-FileHash -LiteralPath $resolvedCandidate -Algorithm SHA256).Hash
    if ($actual -ne [string]$file.sha256) {
        throw "Offline bundle checksum failed: $($file.path)"
    }
}

if (-not $VirtualEnvironmentPath) {
    $VirtualEnvironmentPath = Join-Path $systemRoot '.venv'
}
$resolvedVenv = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
    $VirtualEnvironmentPath
)
if (Test-Path -LiteralPath $resolvedVenv) {
    throw "Virtual environment already exists: $resolvedVenv"
}
$python = Get-SCTComparisonPython -SystemRoot $systemRoot
& $python.FilePath @($python.Prefix) -m venv $resolvedVenv
if ($LASTEXITCODE -ne 0) { throw "Could not create the Python virtual environment." }

$venvPython = Join-Path $resolvedVenv 'Scripts\python.exe'
$wheelhouse = Join-Path $bundleRoot 'wheelhouse'
$requirements = Join-Path $bundleRoot 'requirements\all.txt'
& $venvPython -m pip install --no-index --find-links $wheelhouse -r $requirements
if ($LASTEXITCODE -ne 0) {
    throw "Offline dependency installation failed."
}

Write-Host "Installed SCT comparison dependencies:" -ForegroundColor Green
Write-Host "  $resolvedVenv"
Write-Host "Run comparison commands from this repository; the wrappers add ai-system\src to PYTHONPATH."
