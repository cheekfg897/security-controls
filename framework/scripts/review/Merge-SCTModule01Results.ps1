<#
.SYNOPSIS
    Merges legacy Module 01 write/execution entries into one payload result row.

.DESCRIPTION
    Keeps one `test_stage=write` row per payload attempt. The execution outcome
    is stored in `execution_status` as `executed` or `not_executed`. A payload
    removed before execution remains present as a non-executed row.
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
if ((Split-Path $resolvedPath -Leaf) -ne 'results-module-01.csv') {
    throw "Module 01 merge accepts only results-module-01.csv: $resolvedPath"
}

$rows = @(Import-Csv -LiteralPath $resolvedPath -Encoding UTF8)
if ($rows.Count -eq 0) {
    throw "The Module 01 results file is empty: $resolvedPath"
}

function Get-RowField {
    param([object]$Row, [string]$Name)

    $property = $Row.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return '' }
    return ([string]$property.Value).Trim()
}

function Get-PayloadIdentity {
    param([object]$Row)

    $testInput = Get-RowField $Row 'test_input'
    if ((Get-RowField $Row 'technique_id') -eq '1.1' -and
        $testInput -match ' \[[0-9A-Fa-f]{8}\]$') {
        return $testInput.ToLowerInvariant()
    }
    $hash = Get-RowField $Row 'test_input_sha256'
    if ($hash) { return $hash.ToUpperInvariant() }
    return $testInput.ToLowerInvariant()
}

function Get-LogicalAttemptKey {
    param([object]$Row)

    return @(
        (Get-RowField $Row 'run_id').ToLowerInvariant()
        (Get-RowField $Row 'technique_id').ToLowerInvariant()
        (Get-RowField $Row 'subtest').ToLowerInvariant()
        (Get-RowField $Row 'delivery_method').ToLowerInvariant()
        (Get-PayloadIdentity $Row)
    ) -join '|'
}

function Get-FirstValue {
    param([object[]]$Rows, [string]$Name)

    foreach ($row in $Rows) {
        $value = Get-RowField $row $Name
        if ($value) { return $value }
    }
    return ''
}

function Get-ReviewValue {
    param(
        [object[]]$Rows,
        [string]$Name,
        [string]$Placeholder
    )

    $values = @(
        $Rows |
            ForEach-Object { Get-RowField $_ $Name } |
            Where-Object { $_ -and $_ -ne $Placeholder } |
            Select-Object -Unique
    )
    if ($values.Count -gt 1) {
        throw "Conflicting $Name values prevent automatic row merging."
    }
    if ($values.Count -eq 1) { return $values[0] }
    return $Placeholder
}

$groupedRows = @($rows | Group-Object -Property { Get-LogicalAttemptKey $_ })
$mergedRows = foreach ($group in $groupedRows) {
    $groupRows = @($group.Group)
    $writeRows = @($groupRows | Where-Object { (Get-RowField $_ 'test_stage') -eq 'write' })
    $executionRows = @($groupRows | Where-Object { (Get-RowField $_ 'test_stage') -eq 'execution' })

    if ($groupRows.Count -gt 1 -and
        ($writeRows.Count -ne 1 -or $executionRows.Count -ne 1)) {
        throw "Logical payload '$($group.Name)' cannot be merged unambiguously."
    }

    $baseRow = if ($writeRows.Count -eq 1) { $writeRows[0] } else { $groupRows[0] }
    $sourceValues = @(
        $groupRows |
            ForEach-Object { Get-RowField $_ 'source_result' } |
            Where-Object { $_ } |
            Select-Object -Unique
    )
    $executionStatus = if (@(
        $groupRows | Where-Object { (Get-RowField $_ 'execution_status') -eq 'executed' }
    ).Count -gt 0) { 'executed' } else { 'not_executed' }

    [pscustomobject][ordered]@{
        technique_name    = Get-RowField $baseRow 'technique_name'
        subtest           = Get-RowField $baseRow 'subtest'
        test_input        = Get-RowField $baseRow 'test_input'
        test_stage        = 'write'
        execution_status  = $executionStatus
        detection_status  = Get-ReviewValue $groupRows 'detection_status' 'detection='
        action_status     = Get-ReviewValue $groupRows 'action_status' 'action='
        reviewer_notes    = Get-ReviewValue $groupRows 'reviewer_notes' 'notes='
        source_result     = $sourceValues -join '; '
        delivery_method   = Get-RowField $baseRow 'delivery_method'
        timestamp         = Get-RowField $baseRow 'timestamp'
        run_id            = Get-RowField $baseRow 'run_id'
        technique_id      = Get-RowField $baseRow 'technique_id'
        test_script       = Get-RowField $baseRow 'test_script'
        test_input_sha256 = Get-FirstValue $groupRows 'test_input_sha256'
    }
}

$directory = Split-Path $resolvedPath -Parent
$fileName = Split-Path $resolvedPath -Leaf
$temporaryPath = Join-Path $directory (
    ".$fileName.row-merge-$([guid]::NewGuid().ToString('N')).tmp"
)
$backupPath = "$resolvedPath.before-row-merge.bak"
if (Test-Path -LiteralPath $backupPath) {
    $backupPath = "$resolvedPath.before-row-merge-$([guid]::NewGuid().ToString('N')).bak"
}

try {
    $mergedRows |
        Select-Object -Property (Get-SCTResultColumns) |
        Export-Csv -LiteralPath $temporaryPath -NoTypeInformation -Encoding UTF8
    Assert-SCTResultFileSchema -Path $temporaryPath

    Copy-Item -LiteralPath $resolvedPath -Destination $backupPath
    Move-Item -LiteralPath $temporaryPath -Destination $resolvedPath -Force
} finally {
    if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
        Remove-Item -LiteralPath $temporaryPath -Force
    }
}

Write-Host (
    "Merged $($rows.Count) Module 01 stage row(s) into " +
    "$(@($mergedRows).Count) payload result row(s)."
) -ForegroundColor Green
