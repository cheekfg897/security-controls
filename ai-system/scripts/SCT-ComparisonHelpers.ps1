# Shared Python discovery and invocation helpers for SCT comparison commands.

Set-StrictMode -Version Latest

function Get-SCTComparisonPython {
    [CmdletBinding()]
    param([string]$SystemRoot)

    $candidates = @()
    if ($SystemRoot) {
        $venvPython = Join-Path $SystemRoot '.venv\Scripts\python.exe'
        if (Test-Path -LiteralPath $venvPython -PathType Leaf) {
            $candidates += [pscustomobject]@{
                FilePath = $venvPython
                Prefix   = @()
            }
        }
    }
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        $candidates += [pscustomobject]@{
            FilePath = $py.Source
            Prefix   = @('-3.11')
        }
    }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        $candidates += [pscustomobject]@{
            FilePath = $python.Source
            Prefix   = @()
        }
    }

    foreach ($candidate in $candidates) {
        try {
            $version = & $candidate.FilePath @($candidate.Prefix) -c `
                'import sys; print(sys.version_info[0], sys.version_info[1], sep=chr(46))' 2>$null
            if ($LASTEXITCODE -eq 0 -and $version -eq '3.11') {
                return $candidate
            }
        } catch {
            continue
        }
    }

    throw @"
Python 3.11 is required for SCT comparison but was not found.

On an air-gapped machine, install Python 3.11 x64 and the verified SCT
wheelhouse, then run:
  .\ai-system\scripts\Install-SCTOfflineBundle.ps1 -BundlePath <bundle>
"@
}

function Invoke-SCTComparisonPython {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$SystemRoot,
        [Parameter(Mandatory)] [string[]]$Arguments
    )

    $python = Get-SCTComparisonPython -SystemRoot $SystemRoot
    $previousPythonPath = $env:PYTHONPATH
    $packageRoot = Join-Path $SystemRoot 'src'
    $env:PYTHONPATH = if ($previousPythonPath) {
        "$packageRoot$([IO.Path]::PathSeparator)$previousPythonPath"
    } else {
        $packageRoot
    }
    try {
        & $python.FilePath @($python.Prefix) @Arguments | Out-Host
        $exitCode = $LASTEXITCODE
        return $exitCode
    } finally {
        $env:PYTHONPATH = $previousPythonPath
    }
}

function Select-SCTComparisonPackages {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$SubmissionsRoot)

    $packages = @(
        Get-ChildItem -LiteralPath $SubmissionsRoot -Filter '*.zip' -File |
            Sort-Object Name
    )
    if ($packages.Count -lt 2) {
        throw "At least two ZIPs are required under: $SubmissionsRoot"
    }

    Write-Host ""
    Write-Host "Available comparison packages" -ForegroundColor Cyan
    for ($index = 0; $index -lt $packages.Count; $index++) {
        Write-Host ("  [{0}] {1}" -f ($index + 1), $packages[$index].Name)
    }
    $selection = (Read-Host "Select at least two package numbers, separated by commas").Trim()
    $indexes = @(
        $selection -split ',' |
            ForEach-Object { $_.Trim() -as [int] } |
            Where-Object { $null -ne $_ } |
            Select-Object -Unique
    )
    if ($indexes.Count -lt 2 -or
        @($indexes | Where-Object { $_ -lt 1 -or $_ -gt $packages.Count }).Count -gt 0) {
        throw "Select at least two valid package numbers."
    }
    return @($indexes | ForEach-Object { $packages[$_ - 1].FullName })
}
