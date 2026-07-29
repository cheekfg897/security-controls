# Canonical SCT result schema and append-only writer.

function Get-SCTResultColumns {
    [CmdletBinding()]
    param()

    return @(
        # Keep the reviewer context and editable fields visible without
        # horizontal scrolling. Machine-facing provenance remains available
        # at the end of the same authoritative row.
        'technique_name', 'subtest', 'test_input', 'test_stage',
        'execution_status', 'detection_status', 'action_status',
        'reviewer_notes', 'source_result', 'delivery_method', 'timestamp',
        'run_id', 'technique_id', 'test_script', 'test_input_sha256'
    )
}

function Get-SCTPreviousResultColumns {
    [CmdletBinding()]
    param()

    return @(
        'timestamp', 'run_id', 'technique_id', 'technique_name', 'subtest',
        'test_script', 'test_input', 'test_input_sha256', 'delivery_method',
        'test_stage', 'source_result', 'execution_status', 'detection_status',
        'action_status', 'reviewer_notes'
    )
}

function Get-SCTAllowedActionStatuses {
    [CmdletBinding()]
    param()

    return @(
        'blocked',
        'not_blocked',
        # Legacy values remain readable and are normalized when packaging.
        'blocked_before_execution',
        'blocked_after_execution'
    )
}

function Remove-SCTReviewPrompt {
    [CmdletBinding()]
    param(
        [AllowEmptyString()] [string]$Value,
        [Parameter(Mandatory)]
        [ValidateSet('detection', 'action', 'notes')]
        [string]$Prompt
    )

    $trimmed = if ($null -eq $Value) { '' } else { $Value.Trim() }
    $pattern = switch ($Prompt) {
        'detection' { '^(?i:detection)\s*=\s*(.*)$' }
        'action'    { '^(?i:action)\s*=\s*(.*)$' }
        'notes'     { '^(?i:(?:reviewer_)?notes)\s*=\s*(.*)$' }
    }
    if ($trimmed -match $pattern) {
        return ([string]$matches[1]).Trim()
    }
    return $trimmed
}

function ConvertTo-SCTCanonicalDetectionStatus {
    [CmdletBinding()]
    param([AllowEmptyString()] [string]$Status)

    switch ((Remove-SCTReviewPrompt -Value $Status -Prompt detection).ToLowerInvariant()) {
        'detected' { return 'detected' }
        'not_detected' { return 'not_detected' }
        '' { return '' }
        default { return $null }
    }
}

function ConvertTo-SCTCanonicalActionStatus {
    [CmdletBinding()]
    param([AllowEmptyString()] [string]$Status)

    switch ((Remove-SCTReviewPrompt -Value $Status -Prompt action).ToLowerInvariant()) {
        'blocked' { return 'blocked' }
        'blocked_before_execution' { return 'blocked' }
        'blocked_after_execution' { return 'blocked' }
        'not_blocked' { return 'not_blocked' }
        '' { return '' }
        default { return $null }
    }
}

function Assert-SCTResultFileSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [switch]$AllowLegacyNotesColumn
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $header = Get-Content -LiteralPath $Path -TotalCount 1 -Encoding UTF8
    $actualColumns = @($header -split ',' | ForEach-Object { $_.Trim().Trim('"') })
    $expectedColumns = @(Get-SCTResultColumns)
    $previousColumns = @(Get-SCTPreviousResultColumns)
    $actualKey = $actualColumns -join '|'
    $expectedKey = $expectedColumns -join '|'
    $previousKey = $previousColumns -join '|'

    if ($actualKey -eq $expectedKey -or $actualKey -eq $previousKey) {
        return
    }
    if ($AllowLegacyNotesColumn) {
        $expectedWithNotesKey = (@($expectedColumns) + 'notes') -join '|'
        $previousWithNotesKey = (@($previousColumns) + 'notes') -join '|'
        if ($actualKey -eq $expectedWithNotesKey -or
            $actualKey -eq $previousWithNotesKey) {
            return
        }
    }
    throw "Results CSV has an unexpected schema: $Path. Expected columns: $($expectedColumns -join ', ')."
}

function Convert-SCTLegacyResultFileSchema {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }

    $header = Get-Content -LiteralPath $Path -TotalCount 1 -Encoding UTF8
    $actualColumns = @($header -split ',' | ForEach-Object { $_.Trim().Trim('"') })
    $expectedColumns = @(Get-SCTResultColumns)
    $previousColumns = @(Get-SCTPreviousResultColumns)
    $actualKey = $actualColumns -join '|'
    $expectedKey = $expectedColumns -join '|'
    $previousKey = $previousColumns -join '|'
    $expectedWithNotesKey = (@($expectedColumns) + 'notes') -join '|'
    $previousWithNotesKey = (@($previousColumns) + 'notes') -join '|'

    if ($actualKey -eq $expectedKey) {
        return $null
    }
    $hasLegacyNotes = $actualKey -eq $expectedWithNotesKey -or
        $actualKey -eq $previousWithNotesKey
    $usesPreviousLayout = $actualKey -eq $previousKey -or
        $actualKey -eq $previousWithNotesKey
    if (-not $hasLegacyNotes -and -not $usesPreviousLayout) {
        Assert-SCTResultFileSchema -Path $Path
        return $null
    }

    $rows = @(Import-Csv -LiteralPath $Path -Encoding UTF8)
    $directory = Split-Path $Path -Parent
    $fileName = Split-Path $Path -Leaf
    $temporaryPath = Join-Path $directory (
        ".$fileName.result-layout-migration-$([guid]::NewGuid().ToString('N')).tmp"
    )
    $backupLabel = if ($usesPreviousLayout) {
        'before-review-first-layout'
    } else {
        'before-notes-removal'
    }
    $backupPath = "$Path.$backupLabel.bak"
    if (Test-Path -LiteralPath $backupPath) {
        $backupPath = "$Path.$backupLabel-$([guid]::NewGuid().ToString('N')).bak"
    }

    try {
        if ($rows.Count -gt 0) {
            $rows |
                Select-Object -Property $expectedColumns |
                Export-Csv -LiteralPath $temporaryPath -NoTypeInformation -Encoding UTF8
        }
        else {
            ('"' + ($expectedColumns -join '","') + '"') |
                Set-Content -LiteralPath $temporaryPath -Encoding UTF8
        }

        Assert-SCTResultFileSchema -Path $temporaryPath
        $migratedRows = @(Import-Csv -LiteralPath $temporaryPath)
        if ($migratedRows.Count -ne $rows.Count) {
            throw "Results CSV migration changed the row count for: $Path"
        }

        Copy-Item -LiteralPath $Path -Destination $backupPath
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
        Write-Verbose "Migrated the results CSV to the review-first layout: '$Path'. Backup: '$backupPath'."
        return $backupPath
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function Write-SCTResultRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [datetime]$Timestamp,
        [string]$RunId = '',
        [Parameter(Mandatory)] [string]$TechniqueId,
        [Parameter(Mandatory)] [string]$TechniqueName,
        [string]$Subtest = '',
        [string]$TestScript = '',
        [string]$TestInput = '',
        [string]$TestInputSha256 = '',
        [string]$DeliveryMethod = '',
        [Parameter(Mandatory)] [string]$TestStage,
        [string]$SourceResult = '',
        [ValidateSet('', 'executed', 'not_executed')] [string]$ExecutionStatus = ''
    )

    $directory = Split-Path $Path -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    Convert-SCTLegacyResultFileSchema -Path $Path | Out-Null
    Assert-SCTResultFileSchema -Path $Path

    [pscustomobject][ordered]@{
        technique_name    = $TechniqueName
        subtest           = $Subtest
        test_input        = $TestInput
        test_stage        = $TestStage
        execution_status  = $ExecutionStatus
        detection_status  = 'detection='
        action_status     = 'action='
        reviewer_notes    = 'notes='
        source_result     = $SourceResult
        delivery_method   = $DeliveryMethod
        timestamp         = $Timestamp.ToString('o')
        run_id            = $RunId
        technique_id      = $TechniqueId
        test_script       = $TestScript
        test_input_sha256 = $TestInputSha256
    } | Export-Csv -LiteralPath $Path -Append -NoTypeInformation -Encoding UTF8
}
