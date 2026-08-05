<#
.SYNOPSIS
    Checks one completed module result CSV or every result CSV in a workspace.

.DESCRIPTION
    Use this after filling detection_status, binary action_status (blocked or
    not_blocked), and optional reviewer_notes directly in
    results-module-<id>.csv. Generated observation fields must remain present
    and valid.

.EXAMPLE
    .\scripts\validation\Check-SCTResults.ps1 `
        -Path .\results\sentinelone\results-module-01.csv

.EXAMPLE
    .\scripts\validation\Check-SCTResults.ps1 `
        -ControlProfilePath .\results\sentinelone\sentinelone-control-profile.json
#>

[CmdletBinding(DefaultParameterSetName = 'Path')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Path')] [string]$Path,
    [Parameter(Mandatory, ParameterSetName = 'Workspace')] [string]$ControlProfilePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repoRoot 'core\SCT-Results.ps1')
. (Join-Path $repoRoot 'scripts\common\SCT-ReviewHelpers.ps1')

if ($PSCmdlet.ParameterSetName -eq 'Workspace') {
    $resolvedProfilePath = (Resolve-Path -LiteralPath $ControlProfilePath -ErrorAction Stop).Path
    $workspaceRoot = Split-Path $resolvedProfilePath -Parent
    Assert-SCTWorkspaceUsesModuleFiles -WorkspaceRoot $workspaceRoot -ControlProfilePath $resolvedProfilePath
    $resultPaths = @(Get-SCTWorkspaceResultPaths -WorkspaceRoot $workspaceRoot)
    if ($resultPaths.Count -eq 0) {
        throw "The workspace contains no module result files: $workspaceRoot"
    }
} else {
    $resultPaths = @((Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path)
}

$requiredColumns = @(
    'timestamp', 'run_id', 'technique_id', 'technique_name', 'test_script',
    'test_stage', 'source_result', 'execution_status', 'detection_status',
    'action_status', 'reviewer_notes'
)
$errors = @()
$allowedExecution = @('', 'executed', 'not_executed')
$checkedRows = 0
$legacyActionRows = 0

foreach ($resolvedPath in $resultPaths) {
    try {
        Assert-SCTResultFileSchema -Path $resolvedPath
    } catch {
        $errors += $_.Exception.Message
        continue
    }
    $rows = @(Import-Csv -LiteralPath $resolvedPath -Encoding UTF8)
    if ($rows.Count -eq 0) {
        $errors += "The results CSV contains no result rows: $resolvedPath"
        continue
    }
    $checkedRows += $rows.Count

    $columns = @($rows[0].PSObject.Properties.Name)
    foreach ($column in $requiredColumns) {
        if ($columns -notcontains $column) {
            $errors += "$resolvedPath is missing required column '$column'."
        }
    }

    $moduleMatch = [regex]::Match((Split-Path $resolvedPath -Leaf), '^results-module-(\d{2})\.csv$')
    $expectedModuleNumber = if ($moduleMatch.Success) { [int]$moduleMatch.Groups[1].Value } else { $null }

    $logicalAttempts = @{}
    for ($index = 0; $index -lt $rows.Count; $index++) {
        $row = $rows[$index]
        $csvLine = $index + 2
        $context = "$(Split-Path $resolvedPath -Leaf) line $csvLine"
        $execution = [string]$row.execution_status
        $rawDetection = [string]$row.detection_status
        $rawAction = [string]$row.action_status
        $detection = ConvertTo-SCTCanonicalDetectionStatus -Status $rawDetection
        $action = ConvertTo-SCTCanonicalActionStatus -Status $rawAction

        foreach ($generatedField in @('timestamp', 'run_id', 'technique_id', 'technique_name', 'test_script', 'test_stage')) {
            if ([string]::IsNullOrWhiteSpace([string]$row.$generatedField)) {
                $errors += "$context is missing generated field '$generatedField'."
            }
        }

        if ($null -ne $expectedModuleNumber) {
            $techniqueModule = ([string]$row.technique_id -split '\.')[0] -as [int]
            if ($techniqueModule -ne $expectedModuleNumber) {
                $errors += "$context contains Technique '$($row.technique_id)', which does not belong to Module $($moduleMatch.Groups[1].Value)."
            }
        }
        if ($execution -notin $allowedExecution) {
            $errors += "$context has invalid execution_status '$execution'."
        }
        $inputIdentity = if (
            [string]$row.technique_id -eq '1.1' -and
            [string]$row.test_input -match ' \[[0-9A-Fa-f]{8}\]$'
        ) {
            ([string]$row.test_input).Trim().ToLowerInvariant()
        } elseif (-not [string]::IsNullOrWhiteSpace([string]$row.test_input_sha256)) {
            ([string]$row.test_input_sha256).Trim().ToUpperInvariant()
        } else {
            ([string]$row.test_input).Trim().ToLowerInvariant()
        }
        $logicalKey = @(
            ([string]$row.run_id).Trim().ToLowerInvariant(),
            ([string]$row.technique_id).Trim().ToLowerInvariant(),
            ([string]$row.subtest).Trim().ToLowerInvariant(),
            ([string]$row.delivery_method).Trim().ToLowerInvariant(),
            $inputIdentity
        ) -join '|'
        if ($logicalAttempts.ContainsKey($logicalKey)) {
            $errors += (
                "$context duplicates the logical payload attempt already recorded at " +
                "$($logicalAttempts[$logicalKey]). Each payload attempt must use " +
                'one result row with its outcome in execution_status.'
            )
        } else {
            $logicalAttempts[$logicalKey] = $context
        }
        if (-not $detection) {
            $errors += (
                "$context must complete detection= with detected or not_detected."
            )
        }
        if (-not $action) {
            $errors += "$context must complete action= with blocked or not_blocked."
        } elseif (
            (Remove-SCTReviewPrompt -Value $rawAction -Prompt action) -in
                @('blocked_before_execution', 'blocked_after_execution')
        ) {
            $legacyActionRows++
        }
    }
}

if ($errors.Count -gt 0) {
    throw "Invalid results CSV:`n$($errors -join "`n")"
}

Write-Host "Checked $checkedRows completed result rows across $($resultPaths.Count) module file(s)." -ForegroundColor Green
if ($legacyActionRows -gt 0) {
    Write-Warning (
        "$legacyActionRows row(s) use legacy blocked-before/blocked-after values. " +
        "They are treated identically as blocked and normalized in new packages."
    )
}
