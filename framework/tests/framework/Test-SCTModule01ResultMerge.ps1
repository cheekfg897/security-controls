<#
.SYNOPSIS
    Verifies that legacy Module 01 stage rows become one write row per payload.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repoRoot 'core\SCT-Results.ps1')
$merger = Join-Path $repoRoot 'scripts\review\Merge-SCTModule01Results.ps1'
$validator = Join-Path $repoRoot 'scripts\validation\Check-SCTResults.ps1'
$tempRoot = Join-Path $PSScriptRoot (
    '.tmp-module01-merge-' + [guid]::NewGuid().ToString('N')
)
$script:Assertions = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function New-LegacyRow {
    param(
        [string]$SampleInput,
        [string]$Hash,
        [string]$Stage,
        [string]$SourceResult,
        [string]$ExecutionStatus = ''
    )

    [pscustomobject][ordered]@{
        technique_name    = 'Malware Payload Delivery'
        subtest           = ''
        test_input        = $SampleInput
        test_stage        = $Stage
        execution_status  = $ExecutionStatus
        detection_status  = 'detection=not_detected'
        action_status     = 'action=not_blocked'
        reviewer_notes    = 'notes=Fixture review'
        source_result     = $SourceResult
        delivery_method   = 'MalwarePayloadDelivery'
        timestamp         = (Get-Date).ToString('o')
        run_id            = 'merge-fixture'
        technique_id      = '1.1'
        test_script       = 'v1.1-known-malware/v1.1-known-malware.ps1'
        test_input_sha256 = $Hash
    }
}

try {
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    $resultsPath = Join-Path $tempRoot 'results-module-01.csv'
    @(
        New-LegacyRow -SampleInput 'delivered.exe [A1B2C3D4]' -Hash ('A' * 64) `
            -Stage 'write' -SourceResult 'delivery_success=True'
        New-LegacyRow -SampleInput 'delivered.exe [A1B2C3D4]' -Hash ('A' * 64) `
            -Stage 'execution' -ExecutionStatus 'executed' `
            -SourceResult 'execution_success=True'
        New-LegacyRow -SampleInput 'removed.exe [E5F6A7B8]' -Hash ('B' * 64) `
            -Stage 'write' -SourceResult 'delivery_success=False' `
            -ExecutionStatus 'not_executed'
    ) | Export-Csv -LiteralPath $resultsPath -NoTypeInformation -Encoding UTF8

    & $merger -Path $resultsPath
    $rows = @(Import-Csv -LiteralPath $resultsPath -Encoding UTF8)
    Assert-True ($rows.Count -eq 2) `
        'Three stage rows for two payloads must become two result rows.'
    Assert-True (@($rows | Where-Object { $_.test_stage -ne 'write' }).Count -eq 0) `
        'Every converted Module 01 row must use the write stage.'
    Assert-True (@($rows | Where-Object {
        $_.test_input -like 'delivered.exe*' -and $_.execution_status -eq 'executed'
    }).Count -eq 1) 'The executed payload must retain its execution outcome.'
    Assert-True (@($rows | Where-Object {
        $_.test_input -like 'removed.exe*' -and $_.execution_status -eq 'not_executed'
    }).Count -eq 1) 'A payload removed on sight must remain as one non-executed row.'
    $backupExists = Test-Path -LiteralPath "$resultsPath.before-row-merge.bak" -PathType Leaf
    Assert-True $backupExists 'The merge must retain an untouched backup.'
    $actualColumns = @($rows[0].PSObject.Properties.Name) -join '|'
    $expectedColumns = @(Get-SCTResultColumns) -join '|'
    Assert-True ($actualColumns -eq $expectedColumns) `
        'Merged rows must use the canonical result schema.'

    & $validator -Path $resultsPath
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        $resolvedTemp = (Resolve-Path -LiteralPath $tempRoot).Path
        $resolvedTests = (Resolve-Path -LiteralPath $PSScriptRoot).Path
        if (-not $resolvedTemp.StartsWith($resolvedTests, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove test fixture outside the test directory: $resolvedTemp"
        }
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }
}

Write-Host "Passed $script:Assertions Module 01 merge assertions." -ForegroundColor Green
