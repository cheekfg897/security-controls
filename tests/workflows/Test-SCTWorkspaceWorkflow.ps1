<#
.SYNOPSIS
    Dependency-free regression tests for the single-file product workflow.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repoRoot 'scripts\common\SCT-ReviewHelpers.ps1')
. (Join-Path $repoRoot 'core\SCT-Results.ps1')

$script:Assertions = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

$tempRoot = Join-Path $PSScriptRoot ('.tmp-workspace-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null

try {
    $resultsRoot = Join-Path $tempRoot 'results'
    $workspaceRoot = Join-Path $resultsRoot 'control-a'
    $profilePath = Join-Path $workspaceRoot 'control-profile.json'
    $resultsPath = Join-Path $workspaceRoot 'results.csv'
    $catalogPath = Join-Path $workspaceRoot 'test-catalog.csv'

    & (Join-Path $repoRoot 'scripts\review\Setup-SCTControl.ps1') `
        -NonInteractive -Force -ResultsRoot $resultsRoot `
        -ControlId 'control-a' -DisplayName 'Control A' -Vendor 'Fixture Vendor' `
        -Product 'Fixture XDR' -ProductVersion '1.0' -AgentVersion '2.0' `
        -PolicyName 'Detect-only fixture' -DefaultMode 'detect_only'

    Assert-True (Test-Path -LiteralPath $profilePath -PathType Leaf) `
        'Workspace setup must write control-profile.json.'
    Assert-True (Test-Path -LiteralPath $catalogPath -PathType Leaf) `
        'Workspace setup must write test-catalog.csv.'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $workspaceRoot 'raw'))) `
        'Workspace setup must not create a raw directory.'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $workspaceRoot 'analysis'))) `
        'Workspace setup must not create an analysis directory.'

    $catalogRows = @(Import-Csv -LiteralPath $catalogPath -Encoding UTF8)
    Assert-True ($catalogRows.Count -eq 44) 'The workspace catalogue must contain all current test descriptions.'

    Write-SCTResultRow -Path $resultsPath -Timestamp (Get-Date) -RunId 'run-a' `
        -TechniqueId '4.1' -TechniqueName 'Registry Run Keys' -Subtest 'HKCURunKey' `
        -TestScript 'v4.1-registry-run-key/v4.1-registry-run-key.ps1' `
        -TestStage 'execution' -SourceResult 'EXECUTED' -ExecutionStatus 'executed' `
        -Notes 'marker created'
    Write-SCTResultRow -Path $resultsPath -Timestamp (Get-Date) -RunId 'run-a' `
        -TechniqueId '1.1' -TechniqueName 'Disk Drop' `
        -TestScript 'v1.1-known-malware/v1.1-known-malware.ps1' `
        -TestInput 'malware-a.exe' -TestInputSha256 ('A' * 64) -DeliveryMethod 'DiskDrop' `
        -TestStage 'write' -SourceResult 'delivery_success=True; sysmon_event_found=True' `
        -Notes 'sample written'
    Write-SCTResultRow -Path $resultsPath -Timestamp (Get-Date) -RunId 'run-a' `
        -TechniqueId '1.1' -TechniqueName 'Disk Drop' `
        -TestScript 'v1.1-known-malware/v1.1-known-malware.ps1' `
        -TestInput 'malware-a.exe' -TestInputSha256 ('A' * 64) -DeliveryMethod 'DiskDrop' `
        -TestStage 'execution' -SourceResult 'delivery_success=True; sysmon_event_found=True' `
        -ExecutionStatus 'executed' -Notes 'sample executed'

    $rows = @(Import-Csv -LiteralPath $resultsPath -Encoding UTF8)
    Assert-True ($rows.Count -eq 3) 'Subtest and sample observations must append to the same results.csv.'
    Assert-True (@($rows | Where-Object { $_.detection_status -or $_.action_status }).Count -eq 0) `
        'New observations must leave human review fields blank.'

    $pendingValidationFailed = $false
    try {
        & (Join-Path $repoRoot 'scripts\validation\Check-SCTResults.ps1') -Path $resultsPath
    } catch {
        $pendingValidationFailed = $true
    }
    Assert-True $pendingValidationFailed 'Unreviewed results.csv must not pass final validation.'

    foreach ($row in $rows) {
        $row.detection_status = 'detected'
        $row.action_status = 'not_blocked'
        $row.reviewer_notes = 'Reviewed in fixture.'
    }
    $rows | Export-Csv -LiteralPath $resultsPath -NoTypeInformation -Encoding UTF8
    & (Join-Path $repoRoot 'scripts\validation\Check-SCTResults.ps1') -Path $resultsPath
    Assert-True (Test-Path -LiteralPath $resultsPath -PathType Leaf) `
        'The same results.csv must remain valid after in-place human review.'

    $packagePath = Join-Path $tempRoot 'control-a.zip'
    & (Join-Path $repoRoot 'scripts\review\Build-SCTComparisonPackage.ps1') `
        -ControlProfilePath $profilePath -OutputPath $packagePath -Force
    Assert-True (Test-Path -LiteralPath $packagePath -PathType Leaf) `
        'The comparison package builder must create one ZIP.'

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($packagePath)
    try {
        $entryNames = @($archive.Entries | ForEach-Object { $_.FullName } | Sort-Object)
    } finally {
        $archive.Dispose()
    }
    Assert-True (($entryNames -join '|') -eq 'control-profile.json|results.csv|test-catalog.csv') `
        'The comparison ZIP must contain exactly the profile, canonical results, and catalogue.'

    Write-Host "Passed $script:Assertions workspace-workflow assertions." -ForegroundColor Green
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
