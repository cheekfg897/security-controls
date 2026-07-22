# Canonical SCT result schema and append-only writer.

function Get-SCTResultColumns {
    [CmdletBinding()]
    param()

    return @(
        'timestamp', 'run_id', 'technique_id', 'technique_name', 'subtest',
        'test_script', 'test_input', 'test_input_sha256', 'delivery_method',
        'test_stage', 'source_result', 'execution_status', 'detection_status',
        'action_status', 'reviewer_notes', 'notes'
    )
}

function Assert-SCTResultFileSchema {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $header = Get-Content -LiteralPath $Path -TotalCount 1 -Encoding UTF8
    $actualColumns = @($header -split ',' | ForEach-Object { $_.Trim().Trim('"') })
    $expectedColumns = @(Get-SCTResultColumns)
    if (($actualColumns -join '|') -ne ($expectedColumns -join '|')) {
        throw "Results CSV has an unexpected schema: $Path. Expected columns: $($expectedColumns -join ', ')."
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
        [ValidateSet('', 'executed', 'not_executed')] [string]$ExecutionStatus = '',
        [string]$Notes = ''
    )

    $directory = Split-Path $Path -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    Assert-SCTResultFileSchema -Path $Path

    [pscustomobject][ordered]@{
        timestamp         = $Timestamp.ToString('o')
        run_id            = $RunId
        technique_id      = $TechniqueId
        technique_name    = $TechniqueName
        subtest           = $Subtest
        test_script       = $TestScript
        test_input        = $TestInput
        test_input_sha256 = $TestInputSha256
        delivery_method   = $DeliveryMethod
        test_stage        = $TestStage
        source_result     = $SourceResult
        execution_status  = $ExecutionStatus
        detection_status  = ''
        action_status     = ''
        reviewer_notes    = ''
        notes             = $Notes
    } | Export-Csv -LiteralPath $Path -Append -NoTypeInformation -Encoding UTF8
}
