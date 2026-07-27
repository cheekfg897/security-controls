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
. (Join-Path $repoRoot 'core\SCT-Results.ps1')
$profilePath = (Resolve-Path -LiteralPath $ControlProfilePath -ErrorAction Stop).Path
$workspaceRoot = Split-Path $profilePath -Parent
Assert-SCTWorkspaceUsesModuleFiles -WorkspaceRoot $workspaceRoot -ControlProfilePath $profilePath

$profile = Get-Content -LiteralPath $profilePath -Raw -Encoding UTF8 | ConvertFrom-Json
$profileErrors = @(Get-SCTControlProfileErrors -Profile $profile)
if ($profileErrors.Count -gt 0) {
    throw "Invalid control profile:`n$($profileErrors -join "`n")"
}
$resultPaths = @(Get-SCTWorkspaceResultPaths -WorkspaceRoot $workspaceRoot)
if ($resultPaths.Count -eq 0) {
    throw "Comparison package input contains no module result files: $workspaceRoot"
}

$packagePaths = @($profilePath)
foreach ($resultsPath in $resultPaths) {
    $match = [regex]::Match((Split-Path $resultsPath -Leaf), '^results-module-(\d{2})\.csv$')
    if (-not $match.Success) { throw "Unexpected module results filename: $resultsPath" }
    $catalogPath = Get-SCTModuleCatalogPath -WorkspaceRoot $workspaceRoot -ModuleId $match.Groups[1].Value
    if (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) {
        throw "Comparison package input is missing the matching catalogue: $catalogPath"
    }
    $catalogRows = @(Import-Csv -LiteralPath $catalogPath -Encoding UTF8)
    if ($catalogRows.Count -eq 0) {
        throw "Comparison package catalogue contains no rows: $catalogPath"
    }
    foreach ($catalogRow in $catalogRows) {
        if ([string]$catalogRow.module_id -ne $match.Groups[1].Value -or
            [string]::IsNullOrWhiteSpace([string]$catalogRow.module_name)) {
            throw "Comparison package catalogue has invalid module identity: $catalogPath"
        }
    }
    $packagePaths += @($resultsPath, $catalogPath)
}

& (Join-Path $PSScriptRoot '..\validation\Check-SCTResults.ps1') -ControlProfilePath $profilePath

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

$stagingRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('sct-package-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stagingRoot | Out-Null
try {
    $stagedPaths = @()
    foreach ($sourcePath in $packagePaths) {
        $targetPath = Join-Path $stagingRoot (Split-Path $sourcePath -Leaf)
        if ((Split-Path $sourcePath -Leaf) -match '^results-module-\d{2}\.csv$') {
            $rows = @(Import-Csv -LiteralPath $sourcePath -Encoding UTF8)
            foreach ($row in $rows) {
                $canonical = ConvertTo-SCTCanonicalActionStatus `
                    -Status ([string]$row.action_status)
                if ($null -eq $canonical -or -not $canonical) {
                    throw "Cannot normalize action_status in: $sourcePath"
                }
                $row.action_status = $canonical
            }
            $rows | Export-Csv -LiteralPath $targetPath `
                -NoTypeInformation -Encoding UTF8
        } else {
            Copy-Item -LiteralPath $sourcePath -Destination $targetPath
        }
        $stagedPaths += $targetPath
    }

    Compress-Archive -LiteralPath $stagedPaths `
        -DestinationPath $resolvedOutputPath -CompressionLevel Optimal -Force:$Force
} finally {
    if (Test-Path -LiteralPath $stagingRoot) {
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force
    }
}

Write-Host "Built comparison package:" -ForegroundColor Green
Write-Host "  $resolvedOutputPath" -ForegroundColor White
Write-Host "  control-profile.json and $($resultPaths.Count) module result/catalog pair(s)" -ForegroundColor DarkGray
