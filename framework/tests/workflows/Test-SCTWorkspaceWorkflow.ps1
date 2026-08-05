<#
.SYNOPSIS
    Dependency-free regression tests for module-specific product workspaces.
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
    $profilePath = Join-Path $workspaceRoot 'control-a-control-profile.json'
    $results01 = Join-Path $workspaceRoot 'results-module-01.csv'
    $results04 = Join-Path $workspaceRoot 'results-module-04.csv'
    $catalog01 = Join-Path $workspaceRoot 'test-catalog-module-01.csv'
    $catalog04 = Join-Path $workspaceRoot 'test-catalog-module-04.csv'

    & (Join-Path $repoRoot 'scripts\review\Setup-SCTControl.ps1') `
        -NonInteractive -Force -ResultsRoot $resultsRoot `
        -ControlId 'control-a' -DisplayName 'Control A' -Vendor 'Fixture Vendor' `
        -Product 'Fixture XDR' -ProductVersion '1.0' -AgentVersion '2.0' `
        -PolicyName 'Detect-only fixture' -DefaultMode 'detect_only'

    Assert-True (Test-Path -LiteralPath $profilePath -PathType Leaf) `
        'Workspace setup must include the control id in the profile filename.'
    $catalogPaths = @(Get-ChildItem -LiteralPath $workspaceRoot -Filter 'test-catalog-module-*.csv' -File)
    Assert-True ($catalogPaths.Count -eq 4) 'Workspace setup must write one catalogue per current module.'
    Assert-True (-not (Test-Path -LiteralPath $results01)) `
        'Workspace setup must not create a module result file before its first observation.'
    $catalogRows = @($catalogPaths | ForEach-Object { Import-Csv -LiteralPath $_.FullName -Encoding UTF8 })
    Assert-True ($catalogRows.Count -eq 45) 'Module catalogues must contain all current test descriptions.'
    Assert-True (@($catalogRows | Where-Object { -not $_.module_id -or -not $_.module_name }).Count -eq 0) `
        'Every workspace catalogue row must identify its module.'

    $quickResultsRoot = Join-Path $tempRoot 'quick-results'
    $quickProfilePath = Join-Path (Join-Path $quickResultsRoot 'quick-control') `
        'quick-control-control-profile.json'
    $global:SCTTestReadResponses = New-Object 'System.Collections.Generic.Queue[string]'
    foreach ($response in @(
        'Quick Control',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        ''
    )) {
        $global:SCTTestReadResponses.Enqueue($response)
    }
    $global:SCTTestReadPrompts = @()
    function global:Read-Host {
        param([string]$Prompt)
        $global:SCTTestReadPrompts += $Prompt
        if ($global:SCTTestReadResponses.Count -gt 0) { return $global:SCTTestReadResponses.Dequeue() }
        throw "Unexpected Read-Host prompt: $Prompt"
    }
    try {
        & (Join-Path $repoRoot 'scripts\review\Setup-SCTControl.ps1') `
            -ResultsRoot $quickResultsRoot -ScenariosPath (Join-Path $repoRoot 'scenarios')
    } finally {
        $quickRemainingResponses = $global:SCTTestReadResponses.Count
        $quickReadPrompts = @($global:SCTTestReadPrompts)
        Remove-Item -LiteralPath 'Function:\global:Read-Host' -ErrorAction SilentlyContinue
        Remove-Variable -Name SCTTestReadResponses -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name SCTTestReadPrompts -Scope Global -ErrorAction SilentlyContinue
    }
    Assert-True ($quickRemainingResponses -eq 0) `
        'Quick configuration setup must allow Enter for every optional field.'
    Assert-True (@($quickReadPrompts | Where-Object { $_ -like '*Enter to skip*' }).Count -ge 6) `
        'Optional configuration prompts must explicitly advertise Enter-to-skip.'
    Assert-True (Test-Path -LiteralPath $quickProfilePath -PathType Leaf) `
        'Quick setup must derive a control id from the required display name.'
    $quickProfile = Get-Content -LiteralPath $quickProfilePath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($quickProfile.control.display_name -eq 'Quick Control') `
        'Quick setup must preserve the required display name.'
    Assert-True ($quickProfile.control.vendor -eq 'Not recorded' -and `
        $quickProfile.control.product -eq 'Not recorded' -and `
        $quickProfile.control.product_version -eq 'Not recorded' -and `
        $quickProfile.control.agent_version -eq 'Not recorded') `
        'Skipped optional control details must use valid Not recorded placeholders.'
    Assert-True ($quickProfile.policy.name -eq 'Not recorded' -and $quickProfile.policy.default_mode -eq 'custom') `
        'Skipped optional policy details must use valid placeholder values.'

    $draftResultsRoot = Join-Path $tempRoot 'draft-finalization-results'
    $draftWorkspaceRoot = Join-Path $draftResultsRoot 'framework-only-session'
    $draftResultPath = Join-Path $draftWorkspaceRoot 'results-module-04.csv'
    $draftProfilePath = Join-Path $draftWorkspaceRoot 'framework-only-session-control-profile.json'
    New-Item -ItemType Directory -Path $draftWorkspaceRoot -Force | Out-Null
    Write-SCTResultRow -Path $draftResultPath -Timestamp (Get-Date) -RunId 'draft-run' `
        -TechniqueId '4.1' -TechniqueName 'Registry Run Keys' -Subtest 'HKCURunKey' `
        -TestScript 'v4.1-registry-run-key/v4.1-registry-run-key.ps1' `
        -TestStage 'execution' -SourceResult 'EXECUTED' -ExecutionStatus 'executed'
    $draftRowsBeforeProfile = @(Import-Csv -LiteralPath $draftResultPath -Encoding UTF8)

    $global:SCTTestReadResponses = New-Object 'System.Collections.Generic.Queue[string]'
    foreach ($response in @('', '', '')) {
        $global:SCTTestReadResponses.Enqueue($response)
    }
    $global:SCTTestReadPrompts = @()
    function global:Read-Host {
        param([string]$Prompt)
        $global:SCTTestReadPrompts += $Prompt
        if ($global:SCTTestReadResponses.Count -gt 0) { return $global:SCTTestReadResponses.Dequeue() }
        throw "Unexpected Read-Host prompt: $Prompt"
    }
    try {
        & (Join-Path $repoRoot 'scripts\review\Setup-SCTControl.ps1') `
            -ResultsRoot $draftResultsRoot -ScenariosPath (Join-Path $repoRoot 'scenarios') `
            -ControlId 'framework-only-session' -DisplayName 'Framework Only Session' `
            -Vendor 'Fixture Vendor' -Product 'Fixture XDR' -ProductVersion '1.0' `
            -AgentVersion '2.0' -PolicyName 'Fixture policy' -DefaultMode 'detect_only' `
            -Notes 'Profile added after the run.' -PreserveExistingResults
    } finally {
        $draftRemainingResponses = $global:SCTTestReadResponses.Count
        $draftReadPrompts = @($global:SCTTestReadPrompts)
        Remove-Item -LiteralPath 'Function:\global:Read-Host' -ErrorAction SilentlyContinue
        Remove-Variable -Name SCTTestReadResponses -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name SCTTestReadPrompts -Scope Global -ErrorAction SilentlyContinue
    }

    Assert-True ($draftRemainingResponses -eq 0) `
        'Finalizing a draft must consume only the normal optional profile prompts.'
    Assert-True (@($draftReadPrompts | Where-Object { $_ -like '*Delete them*' }).Count -eq 0) `
        'Finalizing a draft must not ask to delete its existing results.'
    Assert-True (Test-Path -LiteralPath $draftProfilePath -PathType Leaf) `
        'Finalizing a draft must create its control profile in the existing session workspace.'
    $draftRowsAfterProfile = @(Import-Csv -LiteralPath $draftResultPath -Encoding UTF8)
    Assert-True ($draftRowsAfterProfile.Count -eq $draftRowsBeforeProfile.Count) `
        'Finalizing a draft must preserve every existing result row.'
    Assert-True ($draftRowsAfterProfile[0].run_id -eq 'draft-run') `
        'Finalizing a draft must preserve the content of existing result rows.'

    Write-SCTResultRow -Path $results04 -Timestamp (Get-Date) -RunId 'run-a' `
        -TechniqueId '4.1' -TechniqueName 'Registry Run Keys' -Subtest 'HKCURunKey' `
        -TestScript 'v4.1-registry-run-key/v4.1-registry-run-key.ps1' `
        -TestStage 'execution' -SourceResult 'EXECUTED' -ExecutionStatus 'executed'
    Write-SCTResultRow -Path $results01 -Timestamp (Get-Date) -RunId 'run-a' `
        -TechniqueId '1.1' -TechniqueName 'Malware Payload Delivery' `
        -TestScript 'v1.1-known-malware/v1.1-known-malware.ps1' `
        -TestInput 'malware-a.exe' -TestInputSha256 ('A' * 64) -DeliveryMethod 'MalwarePayloadDelivery' `
        -TestStage 'write' `
        -SourceResult 'delivery_success=True; write_sysmon_event_found=True' `
        -ExecutionStatus 'executed'

    Assert-True (@(Import-Csv -LiteralPath $results01).Count -eq 1) `
        'One Module 01 payload attempt must produce one result row.'
    Assert-True (@(Import-Csv -LiteralPath $results04).Count -eq 1) `
        'Module 04 observations must stay in results-module-04.csv.'

    $pendingValidationFailed = $false
    try {
        & (Join-Path $repoRoot 'scripts\validation\Check-SCTResults.ps1') -ControlProfilePath $profilePath
    } catch {
        $pendingValidationFailed = $true
    }
    Assert-True $pendingValidationFailed 'Unreviewed module results must not pass workspace validation.'

    $reviewedRowIndex = 0
    foreach ($resultPath in @($results01, $results04)) {
        $rows = @(Import-Csv -LiteralPath $resultPath -Encoding UTF8)
        foreach ($row in $rows) {
            $row.detection_status = 'detection=detected'
            $row.action_status = 'action=' + $(switch ($reviewedRowIndex) {
                0 { 'blocked' }
                1 { 'blocked_after_execution' }
                default { 'not_blocked' }
            })
            $row.reviewer_notes = 'notes=Reviewed in fixture.'
            if ($reviewedRowIndex -eq 1) {
                # Replacing the prompt entirely remains supported too.
                $row.detection_status = 'detected'
                $row.reviewer_notes = 'Reviewed in fixture.'
            }
            $reviewedRowIndex++
        }
        $rows | Export-Csv -LiteralPath $resultPath -NoTypeInformation -Encoding UTF8
    }
    & (Join-Path $repoRoot 'scripts\validation\Check-SCTResults.ps1') -ControlProfilePath $profilePath

    $packagePath = Join-Path $tempRoot 'control-a.zip'
    & (Join-Path $repoRoot 'scripts\review\Build-SCTComparisonPackage.ps1') `
        -ControlProfilePath $profilePath -OutputPath $packagePath -Force
    Assert-True (Test-Path -LiteralPath $packagePath -PathType Leaf) `
        'The comparison package builder must create one ZIP.'

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($packagePath)
    try {
        $entryNames = @($archive.Entries | ForEach-Object { $_.FullName } | Sort-Object)
        $packagedActionStatuses = @(
            $archive.Entries |
                Where-Object { $_.FullName -match '^results-module-\d{2}\.csv$' } |
                ForEach-Object {
                    $reader = [IO.StreamReader]::new($_.Open())
                    try {
                        @($reader.ReadToEnd() | ConvertFrom-Csv) |
                            ForEach-Object { [string]$_.action_status }
                    } finally {
                        $reader.Dispose()
                    }
                }
        )
        $packagedReviewRows = @(
            $archive.Entries |
                Where-Object { $_.FullName -match '^results-module-\d{2}\.csv$' } |
                ForEach-Object {
                    $reader = [IO.StreamReader]::new($_.Open())
                    try {
                        @($reader.ReadToEnd() | ConvertFrom-Csv)
                    } finally {
                        $reader.Dispose()
                    }
                }
        )
    } finally {
        $archive.Dispose()
    }
    $expectedEntries = @(
        'control-profile.json',
        'results-module-01.csv',
        'results-module-04.csv',
        'test-catalog-module-01.csv',
        'test-catalog-module-04.csv'
    )
    Assert-True (($entryNames -join '|') -eq ($expectedEntries -join '|')) `
        'The comparison ZIP must contain only the profile and tested module pairs.'
    Assert-True ($packagedActionStatuses -contains 'blocked') `
        'The comparison ZIP must retain canonical blocked outcomes.'
    Assert-True (@(
        $packagedActionStatuses |
            Where-Object { $_ -in @('blocked_before_execution', 'blocked_after_execution') }
    ).Count -eq 0) `
        'The comparison ZIP must normalize legacy blocked timing values to blocked.'
    Assert-True (@(
        $packagedReviewRows | Where-Object {
            $_.detection_status -ne 'detected' -or
            $_.reviewer_notes -ne 'Reviewed in fixture.'
        }
    ).Count -eq 0) `
        'The comparison ZIP must remove review prompts and retain entered values.'

    # A newly authored module automatically receives stable ID-based workspace files.
    $fixtureScenarios = Join-Path $tempRoot 'fixture-scenarios'
    $module05Root = Join-Path $fixtureScenarios '05-lateral-movement'
    New-Item -ItemType Directory -Path $module05Root -Force | Out-Null
    @'
{
  "id": "05",
  "name": "Lateral Movement",
  "techniques": [
    { "id": "5.1", "name": "Fixture Technique", "attack_id": "T0001", "script": "v5.1-fixture.ps1", "status": "planned" }
  ]
}
'@ | Set-Content -LiteralPath (Join-Path $module05Root 'module.json') -Encoding UTF8
    @'
"technique_id","subtest","objective","what_it_does","success_indicator"
"5.1","","Fixture objective","Fixture behavior","Fixture success"
'@ | Set-Content -LiteralPath (Join-Path $module05Root 'test-catalog.csv') -Encoding UTF8

    $fixtureResultsRoot = Join-Path $tempRoot 'fixture-results'
    & (Join-Path $repoRoot 'scripts\review\Setup-SCTControl.ps1') `
        -NonInteractive -Force -ResultsRoot $fixtureResultsRoot -ScenariosPath $fixtureScenarios `
        -ControlId 'control-b' -DisplayName 'Control B' -Vendor 'Fixture Vendor' `
        -Product 'Fixture XDR' -ProductVersion '1.0' -AgentVersion '2.0' `
        -PolicyName 'Fixture policy' -DefaultMode 'detect_only'
    $catalog05 = Join-Path $fixtureResultsRoot 'control-b\test-catalog-module-05.csv'
    Assert-True (Test-Path -LiteralPath $catalog05 -PathType Leaf) `
        'Adding Module 05 must automatically create test-catalog-module-05.csv.'

    $module05 = Get-Content -LiteralPath (Join-Path $module05Root 'module.json') -Raw | ConvertFrom-Json
    $module05.name = 'East-West Movement'
    $module05 | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $module05Root 'module.json') -Encoding UTF8
    [void](Sync-SCTWorkspaceCatalogs -ScenariosPath $fixtureScenarios -WorkspaceRoot (Split-Path $catalog05 -Parent))
    $renamedCatalogRows = @(Import-Csv -LiteralPath $catalog05)
    Assert-True ($renamedCatalogRows[0].module_name -eq 'East-West Movement') `
        'Changing a module display name must update catalogue content without changing its filename.'

    # Legacy conversion writes every row once and preserves the original combined files.
    $legacyWorkspace = Join-Path $tempRoot 'legacy-workspace'
    New-Item -ItemType Directory -Path $legacyWorkspace | Out-Null
    Copy-Item -LiteralPath $profilePath -Destination (Join-Path $legacyWorkspace 'control-profile.json')
    @(
        Import-Csv -LiteralPath $results01 -Encoding UTF8
        Import-Csv -LiteralPath $results04 -Encoding UTF8
    ) |
        Select-Object *, @{ Name = 'notes'; Expression = { 'legacy generated note' } } |
        Export-Csv -LiteralPath (Join-Path $legacyWorkspace 'results.csv') -NoTypeInformation -Encoding UTF8
    @(
        Import-Csv -LiteralPath $catalog01 -Encoding UTF8
        Import-Csv -LiteralPath $catalog04 -Encoding UTF8
    ) | Export-Csv -LiteralPath (Join-Path $legacyWorkspace 'test-catalog.csv') -NoTypeInformation -Encoding UTF8

    $legacyRejected = $false
    try {
        Assert-SCTWorkspaceUsesModuleFiles -WorkspaceRoot $legacyWorkspace `
            -ControlProfilePath (Join-Path $legacyWorkspace 'control-profile.json')
    } catch {
        $legacyRejected = $_.Exception.Message -like '*Convert-SCTLegacyWorkspace.ps1*'
    }
    Assert-True $legacyRejected 'Selecting a legacy workspace must stop with the exact conversion command.'

    & (Join-Path $repoRoot 'scripts\review\Convert-SCTLegacyWorkspace.ps1') `
        -ControlProfilePath (Join-Path $legacyWorkspace 'control-profile.json')
    $convertedRows = @(
        Import-Csv -LiteralPath (Join-Path $legacyWorkspace 'results-module-01.csv')
        Import-Csv -LiteralPath (Join-Path $legacyWorkspace 'results-module-04.csv')
    )
    Assert-True ($convertedRows.Count -eq 2) 'Legacy conversion must preserve every result exactly once.'
    Assert-True ($convertedRows[0].PSObject.Properties.Name -notcontains 'notes') `
        'Legacy conversion must remove the retired generated notes column.'
    Assert-True (@(
        $convertedRows |
            Where-Object { $_.action_status -in @('blocked_before_execution', 'blocked_after_execution') }
    ).Count -eq 0) `
        'Legacy conversion must normalize timing-specific blocked values.'
    Assert-True (Test-Path -LiteralPath (Join-Path $legacyWorkspace 'legacy\results.csv')) `
        'Legacy conversion must preserve the original combined results.'
    Assert-True (Test-Path -LiteralPath (Join-Path $legacyWorkspace 'legacy\test-catalog.csv')) `
        'Legacy conversion must preserve the original combined catalogue.'

    Write-Host "Passed $script:Assertions workspace-workflow assertions." -ForegroundColor Green
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
