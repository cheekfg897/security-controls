<#
.SYNOPSIS
    Prepares the VM's raw SCT results for review in Excel.

.DESCRIPTION
    Reads the existing SCT subtest and sample result CSVs without modifying
    them. It joins each row to module.json and test-catalog.csv metadata, adds
    the exact technique script and sample identity, derives only the observed
    execution status, and leaves detection_status and action_status blank for
    a person to complete in Excel.

.EXAMPLE
    .\scripts\Prepare-SCTResultsForReview.ps1 `
        -ControlProfilePath .\config\control-profile.local.json

.EXAMPLE
    .\scripts\Prepare-SCTResultsForReview.ps1 `
        -ControlProfilePath .\config\control-profile.local.json `
        -OutputPath .\results\analysis\results-for-review.csv `
        -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ControlProfilePath,
    [string]$TestResultsPath,
    [string]$SampleResultsPath,
    [string]$ScenariosPath,
    [string]$OutputPath,
    [string]$CatalogOutputPath,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_SCT-ReviewHelpers.ps1')

function Get-ExecutionStatusFromSubtestOutcome {
    param([string]$Outcome)
    switch ($Outcome.ToUpperInvariant()) {
        'EXECUTED' { return 'executed' }
        'BLOCKED'  { return 'not_executed' }
        default    { return '' }
    }
}

function Get-ExecutionStatusFromSampleRow {
    param([string]$Stage, [string]$DeliverySuccess)
    if ($Stage -ne 'execution') { return '' }
    if ($DeliverySuccess -eq 'True') { return 'executed' }
    if ($DeliverySuccess -eq 'False') { return 'not_executed' }
    return ''
}

function Get-SourceResultFromSampleRow {
    param([string]$DeliverySuccess)
    if ($DeliverySuccess -in @('True', 'False')) { return "delivery_success=$DeliverySuccess" }
    return ''
}

$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $TestResultsPath) { $TestResultsPath = Join-Path $repoRoot 'results\raw\test-results.csv' }
if (-not $SampleResultsPath) { $SampleResultsPath = Join-Path $repoRoot 'results\raw\results.csv' }
if (-not $ScenariosPath) { $ScenariosPath = Join-Path $repoRoot 'scenarios' }
if (-not $OutputPath) { $OutputPath = Join-Path $repoRoot 'results\analysis\results-for-review.csv' }
if (-not $CatalogOutputPath) { $CatalogOutputPath = Join-Path $repoRoot 'results\analysis\test-catalog.csv' }

$resolvedProfilePath = (Resolve-Path -LiteralPath $ControlProfilePath -ErrorAction Stop).Path
$profile = Get-Content -LiteralPath $resolvedProfilePath -Raw -Encoding UTF8 | ConvertFrom-Json
$profileErrors = @(Get-SCTControlProfileErrors -Profile $profile)
if ($profileErrors.Count -gt 0) {
    throw "Invalid control profile:`n$($profileErrors -join "`n")"
}

$catalog = Get-SCTCatalogData -ScenariosPath $ScenariosPath
if ($catalog.Errors.Count -gt 0) {
    throw "Invalid SCT test catalog:`n$($catalog.Errors -join "`n")"
}

$catalogByKey = @{}
$techniqueDefaults = @{}
foreach ($catalogRow in @($catalog.Rows)) {
    $key = "$($catalogRow.technique_id)|$($catalogRow.subtest)"
    $catalogByKey[$key] = $catalogRow
    if (-not $techniqueDefaults.ContainsKey([string]$catalogRow.technique_id)) {
        $techniqueDefaults[[string]$catalogRow.technique_id] = $catalogRow
    }
}

$subtestRows = @()
$sampleRows = @()
if (Test-Path -LiteralPath $TestResultsPath -PathType Leaf) {
    $subtestRows = @(Import-Csv -LiteralPath $TestResultsPath -Encoding UTF8)
}
if (Test-Path -LiteralPath $SampleResultsPath -PathType Leaf) {
    $sampleRows = @(Import-Csv -LiteralPath $SampleResultsPath -Encoding UTF8)
}
if ($subtestRows.Count -eq 0 -and $sampleRows.Count -eq 0) {
    throw "No result rows were found. Checked '$TestResultsPath' and '$SampleResultsPath'."
}

# A write-stage row normally contains the sample hash. Carry it forward to the
# execution-stage row for the same sample so each tested input remains exact.
$sampleHashes = @{}
foreach ($row in $sampleRows) {
    $techniqueId = Get-SCTCsvRowValue -Row $row -Names @('technique_id', 'vector')
    $deliveryMethod = Get-SCTCsvRowValue -Row $row -Names @('delivery_method')
    $sampleId = Get-SCTCsvRowValue -Row $row -Names @('sample_id')
    $hash = Get-SCTSha256FromNotes -Notes (Get-SCTCsvRowValue -Row $row -Names @('notes'))
    if ($hash) { $sampleHashes["$techniqueId|$deliveryMethod|$sampleId"] = $hash }
}

$preparedRows = @()
$sequence = 0
foreach ($row in $subtestRows) {
    $sequence++
    $techniqueId = Get-SCTCsvRowValue -Row $row -Names @('technique_id', 'vector_id')
    $subtest = Get-SCTCsvRowValue -Row $row -Names @('subtest', 'technique')
    $catalogKey = "$techniqueId|$subtest"
    if (-not $catalogByKey.ContainsKey($catalogKey)) {
        throw "No catalog row matches subtest result '$techniqueId/$subtest'."
    }
    $metadata = $catalogByKey[$catalogKey]
    $outcome = Get-SCTCsvRowValue -Row $row -Names @('outcome')
    $preparedRows += [pscustomobject][ordered]@{
        timestamp         = Get-SCTCsvRowValue -Row $row -Names @('timestamp')
        run_id            = Get-SCTCsvRowValue -Row $row -Names @('run_id')
        control_id        = [string]$profile.control.id
        control_name      = [string]$profile.control.display_name
        technique_id      = $techniqueId
        technique_name    = [string]$metadata.technique_name
        subtest           = $subtest
        test_script       = [string]$metadata.test_script
        test_input        = ''
        test_input_sha256 = ''
        delivery_method   = ''
        test_stage        = 'execution'
        source_result     = $outcome
        execution_status  = Get-ExecutionStatusFromSubtestOutcome -Outcome $outcome
        detection_status  = ''
        action_status     = ''
        notes             = Get-SCTCsvRowValue -Row $row -Names @('notes')
        _sequence         = $sequence
    }
}

foreach ($row in $sampleRows) {
    $sequence++
    $techniqueId = Get-SCTCsvRowValue -Row $row -Names @('technique_id', 'vector')
    if (-not $techniqueDefaults.ContainsKey($techniqueId)) {
        throw "No catalog technique matches sample result '$techniqueId'."
    }
    $metadata = $techniqueDefaults[$techniqueId]
    $deliveryMethod = Get-SCTCsvRowValue -Row $row -Names @('delivery_method')
    $sampleId = Get-SCTCsvRowValue -Row $row -Names @('sample_id')
    $stage = Get-SCTCsvRowValue -Row $row -Names @('stage')
    $deliverySuccess = Get-SCTCsvRowValue -Row $row -Names @('delivery_success')
    $hash = Get-SCTSha256FromNotes -Notes (Get-SCTCsvRowValue -Row $row -Names @('notes'))
    if (-not $hash) {
        $hashKey = "$techniqueId|$deliveryMethod|$sampleId"
        if ($sampleHashes.ContainsKey($hashKey)) { $hash = $sampleHashes[$hashKey] }
    }
    $preparedRows += [pscustomobject][ordered]@{
        timestamp         = Get-SCTCsvRowValue -Row $row -Names @('timestamp')
        run_id            = Get-SCTCsvRowValue -Row $row -Names @('run_id')
        control_id        = [string]$profile.control.id
        control_name      = [string]$profile.control.display_name
        technique_id      = $techniqueId
        technique_name    = [string]$metadata.technique_name
        subtest           = ''
        test_script       = [string]$metadata.test_script
        test_input        = $sampleId
        test_input_sha256 = $hash
        delivery_method   = $deliveryMethod
        test_stage        = $stage
        source_result     = Get-SourceResultFromSampleRow -DeliverySuccess $deliverySuccess
        execution_status  = Get-ExecutionStatusFromSampleRow -Stage $stage -DeliverySuccess $deliverySuccess
        detection_status  = ''
        action_status     = ''
        notes             = Get-SCTCsvRowValue -Row $row -Names @('notes')
        _sequence         = $sequence
    }
}

$resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$resolvedCatalogPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CatalogOutputPath)
foreach ($path in @($resolvedOutputPath, $resolvedCatalogPath)) {
    if ((Test-Path -LiteralPath $path) -and -not $Force) {
        throw "Output file already exists: $path. Use -Force to replace generated output."
    }
    $directory = Split-Path $path -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
}

$preparedRows |
    Sort-Object _sequence |
    Select-Object timestamp, run_id, control_id, control_name, technique_id, technique_name, subtest, `
        test_script, test_input, test_input_sha256, delivery_method, test_stage, source_result, `
        execution_status, detection_status, action_status, notes |
    Export-Csv -LiteralPath $resolvedOutputPath -NoTypeInformation -Encoding UTF8

$catalog.Rows |
    Select-Object module_id, module_name, technique_id, technique_name, subtest, attack_id, test_script, `
        objective, what_it_does, success_indicator, status |
    Export-Csv -LiteralPath $resolvedCatalogPath -NoTypeInformation -Encoding UTF8

Write-Host "Wrote $($preparedRows.Count) result rows for review:" -ForegroundColor Green
Write-Host "  $resolvedOutputPath" -ForegroundColor White
Write-Host "Wrote $($catalog.Rows.Count) combined catalog rows:" -ForegroundColor Green
Write-Host "  $resolvedCatalogPath" -ForegroundColor White
Write-Host ''
Write-Host 'Open results-for-review.csv in Excel, fill detection_status and action_status, then save a copy as:' -ForegroundColor Cyan
Write-Host '  reviewed-results.csv' -ForegroundColor White
