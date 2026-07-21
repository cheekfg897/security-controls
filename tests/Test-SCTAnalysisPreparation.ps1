<#
.SYNOPSIS
    Dependency-free regression tests for control profiles, catalogues, and the
    CSV preparation workflow.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path $PSScriptRoot -Parent
. (Join-Path $repoRoot 'scripts\_SCT-ReviewHelpers.ps1')

$script:Assertions = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Assert-ErrorLike {
    param([string[]]$Errors, [string]$Pattern, [string]$Message)
    $script:Assertions++
    if (-not ($Errors | Where-Object { $_ -like $Pattern })) {
        throw "Assertion failed: $Message`nErrors: $($Errors -join ' | ')"
    }
}

$tempRoot = Join-Path $PSScriptRoot ('.tmp-analysis-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null

try {
    $profilePath = Join-Path $tempRoot 'control-a.json'
    & (Join-Path $repoRoot 'scripts\Setup-SCTControl.ps1') `
        -NonInteractive -Force -OutputPath $profilePath `
        -ControlId 'control-a' -DisplayName 'Control A' -Vendor 'Fixture Vendor' `
        -Product 'Fixture XDR' -ProductVersion '1.0' -AgentVersion '2.0' `
        -PolicyName 'Detect-only fixture' -DefaultMode 'detect_only'

    Assert-True (Test-Path -LiteralPath $profilePath -PathType Leaf) 'The profile generator must write JSON.'
    $profile = Get-Content -LiteralPath $profilePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $profileErrors = @(Get-SCTControlProfileErrors -Profile $profile)
    Assert-True ($profileErrors.Count -eq 0) "The generated profile must validate: $($profileErrors -join ' | ')"
    Assert-True ($profile.policy.default_mode -eq 'detect_only') 'The selected policy mode must be preserved.'

    $profile.policy.default_mode = 'automatic'
    $invalidProfileErrors = @(Get-SCTControlProfileErrors -Profile $profile)
    Assert-ErrorLike $invalidProfileErrors "*default_mode 'automatic'*" 'An unsupported policy mode must be rejected.'

    $catalogFixture = Join-Path $tempRoot 'catalog-fixture'
    New-Item -ItemType Directory -Path $catalogFixture | Out-Null
    @'
{
  "id": "05",
  "name": "Fixture Module",
  "techniques": [
    { "id": "5.1", "name": "Fixture Technique", "attack_id": "T0001", "script": "fixture.ps1" }
  ]
}
'@ | Set-Content -LiteralPath (Join-Path $catalogFixture 'module.json') -Encoding UTF8
    @'
"technique_id","subtest","objective","what_it_does","success_indicator"
"5.1","","Fixture objective","Performs the fixture action","The fixture marker exists"
'@ | Set-Content -LiteralPath (Join-Path $catalogFixture 'test-catalog.csv') -Encoding UTF8
    & (Join-Path $repoRoot 'scripts\Describe-SCTModuleTests.ps1') `
        -ModulePath (Join-Path $catalogFixture 'module.json') -Force
    $regeneratedCatalog = @(Import-Csv -LiteralPath (Join-Path $catalogFixture 'test-catalog.csv') -Encoding UTF8)
    Assert-True ($regeneratedCatalog.Count -eq 1) 'The catalogue generator must retain one row per manifest case.'
    Assert-True ($regeneratedCatalog[0].objective -eq 'Fixture objective') 'The catalogue generator must preserve existing descriptions.'

    $scenariosPath = Join-Path $repoRoot 'scenarios'
    $catalog = Get-SCTCatalogData -ScenariosPath $scenariosPath
    Assert-True ($catalog.Errors.Count -eq 0) "The repository catalogues must validate: $($catalog.Errors -join ' | ')"
    Assert-True ($catalog.Rows.Count -eq 44) 'Every current technique/subtest must have one catalogue row.'
    $hiddenXml = @($catalog.Rows | Where-Object { $_.technique_id -eq '4.2' -and $_.subtest -eq 'HiddenXML' })
    Assert-True ($hiddenXml.Count -eq 1) 'Scheduled-task HiddenXML metadata must be unique.'
    Assert-True ($hiddenXml[0].test_script -like '*/v4.2-scheduled-task.ps1') 'The catalogue must identify the exact test script.'
    Assert-True (-not [string]::IsNullOrWhiteSpace($hiddenXml[0].what_it_does)) 'The catalogue must explain what the test does.'

    $testResultsPath = Join-Path $tempRoot 'test-results.csv'
    @'
"timestamp","run_id","control","technique_id","technique_name","subtest","outcome","notes"
"2026-07-21T10:00:00.0000000+08:00","run-a","Control A","4.1","Registry Run Keys","HKCURunKey","EXECUTED","marker created"
"2026-07-21T10:01:00.0000000+08:00","run-a","Control A","4.2","Scheduled Task / Job","HiddenXML","BLOCKED","marker absent"
'@ | Set-Content -LiteralPath $testResultsPath -Encoding UTF8

    $sampleResultsPath = Join-Path $tempRoot 'results.csv'
    @'
"timestamp","run_id","control","technique_id","delivery_method","sample_id","stage","delivery_success","sysmon_event_found","notes"
"2026-07-21T10:02:00.0000000+08:00","run-a","Control A","1.1","disk-drop","malware-a.exe","write","True","","sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"2026-07-21T10:03:00.0000000+08:00","run-a","Control A","1.1","disk-drop","malware-a.exe","execution","True","","process started"
"2026-07-21T10:04:00.0000000+08:00","run-a","Control A","1.1","disk-drop","malware-b.exe","execution","False","","process did not start"
'@ | Set-Content -LiteralPath $sampleResultsPath -Encoding UTF8

    $pendingPath = Join-Path $tempRoot 'results-for-review.csv'
    $combinedCatalogPath = Join-Path $tempRoot 'test-catalog.csv'
    & (Join-Path $repoRoot 'scripts\Prepare-SCTResultsForReview.ps1') `
        -ControlProfilePath $profilePath -TestResultsPath $testResultsPath `
        -SampleResultsPath $sampleResultsPath -ScenariosPath $scenariosPath `
        -OutputPath $pendingPath -CatalogOutputPath $combinedCatalogPath -Force

    $pending = @(Import-Csv -LiteralPath $pendingPath -Encoding UTF8)
    Assert-True ($pending.Count -eq 5) 'All raw result rows must be preserved in the review CSV.'
    Assert-True (@($pending | Where-Object { $_.detection_status -or $_.action_status }).Count -eq 0) `
        'Human review fields must initially be blank.'

    $registry = @($pending | Where-Object { $_.technique_id -eq '4.1' })[0]
    Assert-True ($registry.execution_status -eq 'executed') 'EXECUTED must map only to the observed execution status.'
    Assert-True ($registry.test_script -like '*/v4.1-registry-run-key.ps1') 'Prepared subtests must identify their script.'

    $scheduledTask = @($pending | Where-Object { $_.technique_id -eq '4.2' })[0]
    Assert-True ($scheduledTask.execution_status -eq 'not_executed') 'A missing-marker BLOCKED result must map to not_executed.'

    $malwareAExecution = @($pending | Where-Object { $_.test_input -eq 'malware-a.exe' -and $_.test_stage -eq 'execution' })[0]
    Assert-True ($malwareAExecution.execution_status -eq 'executed') 'A successful execution-stage result must map to executed.'
    Assert-True ($malwareAExecution.test_input_sha256 -eq ('A' * 64)) 'The write-stage sample hash must carry to its execution row.'
    $writeRow = @($pending | Where-Object { $_.test_input -eq 'malware-a.exe' -and $_.test_stage -eq 'write' })[0]
    Assert-True ([string]::IsNullOrWhiteSpace($writeRow.execution_status)) 'A write-stage row must not claim execution.'

    $combinedCatalog = @(Import-Csv -LiteralPath $combinedCatalogPath -Encoding UTF8)
    Assert-True ($combinedCatalog.Count -eq 44) 'The generated combined catalogue must contain all metadata rows.'

    $pendingValidationFailed = $false
    try {
        & (Join-Path $repoRoot 'scripts\Check-SCTReviewedResults.ps1') -Path $pendingPath
    } catch {
        $pendingValidationFailed = $true
    }
    Assert-True $pendingValidationFailed 'A review CSV with blank human fields must not pass final validation.'

    foreach ($row in $pending) {
        $row.detection_status = 'detected'
        $row.action_status = if ($row.execution_status -eq 'not_executed') { 'blocked_before_execution' } else { 'not_blocked' }
    }
    $completedPath = Join-Path $tempRoot 'reviewed-results.csv'
    $pending | Export-Csv -LiteralPath $completedPath -NoTypeInformation -Encoding UTF8
    & (Join-Path $repoRoot 'scripts\Check-SCTReviewedResults.ps1') -Path $completedPath
    Assert-True (Test-Path -LiteralPath $completedPath -PathType Leaf) 'A completed review CSV must validate.'

    Write-Host "Passed $script:Assertions analysis-preparation assertions." -ForegroundColor Green
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
