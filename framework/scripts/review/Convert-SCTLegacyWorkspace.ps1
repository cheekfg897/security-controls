<#
.SYNOPSIS
    Converts one legacy combined SCT workspace to authoritative module files.

.DESCRIPTION
    Splits results.csv and test-catalog.csv by module, verifies that every row
    was written exactly once, then preserves the combined files under legacy/.

.EXAMPLE
    .\scripts\review\Convert-SCTLegacyWorkspace.ps1 `
        -ControlProfilePath .\results\sentinelone\control-profile.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ControlProfilePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repoRoot 'core\SCT-Results.ps1')
. (Join-Path $repoRoot 'scripts\common\SCT-ReviewHelpers.ps1')

$profilePath = (Resolve-Path -LiteralPath $ControlProfilePath -ErrorAction Stop).Path
$workspaceRoot = Split-Path $profilePath -Parent
$legacyResultsPath = Join-Path $workspaceRoot 'results.csv'
$legacyCatalogPath = Join-Path $workspaceRoot 'test-catalog.csv'

foreach ($requiredPath in @($legacyResultsPath, $legacyCatalogPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Legacy workspace input is missing: $requiredPath"
    }
}

$existingModuleFiles = @(
    Get-ChildItem -LiteralPath $workspaceRoot -File |
        Where-Object { $_.Name -match '^(results|test-catalog)-module-\d{2}\.csv$' }
)
if ($existingModuleFiles.Count -gt 0) {
    throw "Module-specific files already exist in '$workspaceRoot'; refusing to mix or overwrite workspace formats."
}
$legacyRoot = Join-Path $workspaceRoot 'legacy'
foreach ($legacyName in @('results.csv', 'test-catalog.csv')) {
    $archivePath = Join-Path $legacyRoot $legacyName
    if (Test-Path -LiteralPath $archivePath) {
        throw "Legacy archive destination already exists: $archivePath"
    }
}

Assert-SCTResultFileSchema -Path $legacyResultsPath
$resultRows = @(Import-Csv -LiteralPath $legacyResultsPath -Encoding UTF8)
$catalogRows = @(Import-Csv -LiteralPath $legacyCatalogPath -Encoding UTF8)
if ($resultRows.Count -eq 0) { throw "Legacy results contain no rows: $legacyResultsPath" }
if ($catalogRows.Count -eq 0) { throw "Legacy catalogue contains no rows: $legacyCatalogPath" }

$moduleByTechnique = @{}
foreach ($catalogRow in $catalogRows) {
    $techniqueId = [string]$catalogRow.technique_id
    $moduleId = [string]$catalogRow.module_id
    Assert-SCTModuleId -ModuleId $moduleId
    if (-not $techniqueId) { throw "Legacy catalogue contains a row without technique_id." }
    if ($moduleByTechnique.ContainsKey($techniqueId) -and $moduleByTechnique[$techniqueId] -ne $moduleId) {
        throw "Technique '$techniqueId' maps to more than one module in the legacy catalogue."
    }
    $moduleByTechnique[$techniqueId] = $moduleId
}

$resultsByModule = @{}
foreach ($resultRow in $resultRows) {
    $canonicalAction = ConvertTo-SCTCanonicalActionStatus `
        -Status ([string]$resultRow.action_status)
    if ($null -eq $canonicalAction) {
        throw "Legacy result has invalid action_status '$($resultRow.action_status)'."
    }
    $resultRow.action_status = $canonicalAction
    $techniqueId = [string]$resultRow.technique_id
    if (-not $moduleByTechnique.ContainsKey($techniqueId)) {
        throw "Legacy result Technique '$techniqueId' has no module mapping in test-catalog.csv."
    }
    $moduleId = $moduleByTechnique[$techniqueId]
    if (-not $resultsByModule.ContainsKey($moduleId)) { $resultsByModule[$moduleId] = @() }
    $resultsByModule[$moduleId] += $resultRow
}

$migrationRoot = Join-Path $workspaceRoot ('.module-migration-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $migrationRoot | Out-Null
try {
    $stagedPaths = @()
    foreach ($moduleId in @($resultsByModule.Keys | Sort-Object)) {
        $moduleResultsPath = Get-SCTModuleResultsPath -WorkspaceRoot $migrationRoot -ModuleId $moduleId
        $moduleCatalogPath = Get-SCTModuleCatalogPath -WorkspaceRoot $migrationRoot -ModuleId $moduleId

        $resultsByModule[$moduleId] | Export-Csv -LiteralPath $moduleResultsPath -NoTypeInformation -Encoding UTF8
        @($catalogRows | Where-Object { [string]$_.module_id -eq $moduleId }) |
            Export-Csv -LiteralPath $moduleCatalogPath -NoTypeInformation -Encoding UTF8

        Assert-SCTResultFileSchema -Path $moduleResultsPath
        $stagedPaths += @($moduleResultsPath, $moduleCatalogPath)
    }

    $writtenRows = 0
    foreach ($stagedResultsPath in @($stagedPaths | Where-Object { (Split-Path $_ -Leaf) -like 'results-module-*.csv' })) {
        $writtenRows += @(Import-Csv -LiteralPath $stagedResultsPath -Encoding UTF8).Count
    }
    if ($writtenRows -ne $resultRows.Count) {
        throw "Migration verification failed: read $($resultRows.Count) result rows but wrote $writtenRows."
    }

    foreach ($stagedPath in $stagedPaths) {
        Move-Item -LiteralPath $stagedPath -Destination (Join-Path $workspaceRoot (Split-Path $stagedPath -Leaf))
    }

    if (-not (Test-Path -LiteralPath $legacyRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $legacyRoot | Out-Null
    }
    foreach ($legacyPath in @($legacyResultsPath, $legacyCatalogPath)) {
        $destination = Join-Path $legacyRoot (Split-Path $legacyPath -Leaf)
        if (Test-Path -LiteralPath $destination) {
            throw "Legacy archive destination already exists: $destination"
        }
        Move-Item -LiteralPath $legacyPath -Destination $destination
    }
} finally {
    if (Test-Path -LiteralPath $migrationRoot -PathType Container) {
        Remove-Item -LiteralPath $migrationRoot -Recurse -Force
    }
}

Write-Host "Converted $($resultRows.Count) result rows into $($resultsByModule.Count) module file(s)." -ForegroundColor Green
Write-Host "Preserved the combined files under: $(Join-Path $workspaceRoot 'legacy')" -ForegroundColor DarkGray
