# Shared Python discovery and invocation helpers for SCT comparison commands.

Set-StrictMode -Version Latest

function Test-SCTSupportedPythonVersion {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Version)

    try {
        $parsed = [version]$Version
    } catch {
        return $false
    }
    return $parsed.Major -eq 3 -and $parsed.Minor -ge 11
}

function Get-SCTComparisonPython {
    [CmdletBinding()]
    param(
        [string]$SystemRoot,
        [ValidatePattern('^3\.\d+$')] [string]$PythonVersion
    )

    if ($PythonVersion -and -not (Test-SCTSupportedPythonVersion -Version $PythonVersion)) {
        throw "Python $PythonVersion is unsupported. Use Python 3.11 or newer (Python 3.x)."
    }

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
        $launcherVersions = @()
        if ($PythonVersion) {
            $launcherVersions = @($PythonVersion)
        } else {
            try {
                $launcherVersions = @(
                    & $py.Source -0p 2>$null |
                        ForEach-Object {
                            if ([string]$_ -match '(?:-V:|-)(3\.\d+)') {
                                $Matches[1]
                            }
                        } |
                        Where-Object { Test-SCTSupportedPythonVersion -Version $_ } |
                        Sort-Object { [version]$_ } -Descending -Unique
                )
            } catch {
                $launcherVersions = @()
            }
        }
        foreach ($version in $launcherVersions) {
            $candidates += [pscustomobject]@{
                FilePath = $py.Source
                Prefix   = @("-$version")
            }
        }
        $candidates += [pscustomobject]@{
            FilePath = $py.Source
            Prefix   = @()
        }
    }
    $commandNames = @()
    if ($PythonVersion) {
        $commandNames += "python$PythonVersion"
    }
    $commandNames += @('python', 'python3')
    foreach ($commandName in $commandNames) {
        $python = Get-Command $commandName -ErrorAction SilentlyContinue
        if ($python) {
            $candidates += [pscustomobject]@{
                FilePath = $python.Source
                Prefix   = @()
            }
        }
    }

    $seen = @{}
    foreach ($candidate in $candidates) {
        $candidateKey = "$($candidate.FilePath)|$($candidate.Prefix -join ',')"
        if ($seen.ContainsKey($candidateKey)) {
            continue
        }
        $seen[$candidateKey] = $true
        try {
            $version = & $candidate.FilePath @($candidate.Prefix) -c `
                'import sys; print(sys.version_info[0], sys.version_info[1], sep=chr(46))' 2>$null
            $version = ([string]$version).Trim()
            if ($LASTEXITCODE -eq 0 -and
                (Test-SCTSupportedPythonVersion -Version $version) -and
                (-not $PythonVersion -or $version -eq $PythonVersion)) {
                return [pscustomobject]@{
                    FilePath = $candidate.FilePath
                    Prefix   = @($candidate.Prefix)
                    Version  = $version
                }
            }
        } catch {
            continue
        }
    }

    if ($PythonVersion) {
        throw "Python $PythonVersion was requested but was not found."
    }
    throw @"
Python 3.11 or newer (Python 3.x) is required for SCT comparison but was not found.

On an air-gapped machine, install a supported 64-bit Python runtime matching
the verified SCT wheelhouse, then run:
  .\ai-system\scripts\Install-SCTOfflineBundle.ps1 -BundlePath <bundle>
"@
}

function Invoke-SCTComparisonPython {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$SystemRoot,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [string]$PythonVersion
    )

    $pythonArguments = @{ SystemRoot = $SystemRoot }
    if ($PythonVersion) {
        $pythonArguments.PythonVersion = $PythonVersion
    }
    $python = Get-SCTComparisonPython @pythonArguments
    Write-Host "Using Python $($python.Version): $($python.FilePath)" -ForegroundColor DarkGray
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
