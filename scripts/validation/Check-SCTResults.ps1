<#
.SYNOPSIS
    Checks a completed canonical SCT results CSV.

.DESCRIPTION
    Use this after filling detection_status, action_status, and optional
    reviewer_notes directly in results.csv. Generated observation fields must
    remain present and valid.

.EXAMPLE
    .\scripts\validation\Check-SCTResults.ps1 `
        -Path .\results\sentinelone\results.csv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repoRoot 'core\SCT-Results.ps1')

$resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
Assert-SCTResultFileSchema -Path $resolvedPath
$rows = @(Import-Csv -LiteralPath $resolvedPath -Encoding UTF8)
if ($rows.Count -eq 0) { throw "The results CSV contains no result rows: $resolvedPath" }

$requiredColumns = @(
    'timestamp', 'run_id', 'technique_id', 'technique_name', 'test_script',
    'test_stage', 'source_result', 'execution_status', 'detection_status',
    'action_status', 'reviewer_notes'
)
$columns = @($rows[0].PSObject.Properties.Name)
$errors = @()
foreach ($column in $requiredColumns) {
    if ($columns -notcontains $column) {
        $errors += "Missing required column '$column'."
    }
}
if ($errors.Count -gt 0) { throw ($errors -join [Environment]::NewLine) }

$allowedExecution = @('', 'executed', 'not_executed')
$allowedDetection = @('detected', 'not_detected')
$allowedAction = @('blocked_before_execution', 'blocked_after_execution', 'not_blocked')

for ($index = 0; $index -lt $rows.Count; $index++) {
    $row = $rows[$index]
    $csvLine = $index + 2
    $execution = [string]$row.execution_status
    $detection = [string]$row.detection_status
    $action = [string]$row.action_status

    foreach ($generatedField in @('timestamp', 'run_id', 'technique_id', 'technique_name', 'test_script', 'test_stage')) {
        if ([string]::IsNullOrWhiteSpace([string]$row.$generatedField)) {
            $errors += "CSV line $csvLine is missing generated field '$generatedField'."
        }
    }

    if ($execution -notin $allowedExecution) {
        $errors += "CSV line $csvLine has invalid execution_status '$execution'."
    }
    if ($detection -notin $allowedDetection) {
        $errors += "CSV line $csvLine must set detection_status to detected or not_detected."
    }
    if ($action -notin $allowedAction) {
        $errors += "CSV line $csvLine must set action_status to blocked_before_execution, blocked_after_execution, or not_blocked."
    }
    if ($execution -eq 'executed' -and $action -eq 'blocked_before_execution') {
        $errors += "CSV line $csvLine cannot be executed and blocked_before_execution."
    }
    if ($execution -eq 'not_executed' -and $action -eq 'blocked_after_execution') {
        $errors += "CSV line $csvLine cannot be not_executed and blocked_after_execution."
    }
    if ($action -eq 'blocked_after_execution' -and $execution -ne 'executed') {
        $errors += "CSV line $csvLine can use blocked_after_execution only when execution_status is executed."
    }
}

if ($errors.Count -gt 0) {
    throw "Invalid results CSV:`n$($errors -join "`n")"
}

Write-Host "Checked $($rows.Count) completed result rows." -ForegroundColor Green
