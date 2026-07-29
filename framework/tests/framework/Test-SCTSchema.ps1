<#
.SYNOPSIS
    Dependency-free regression tests for the simplified SCT manifest contract.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repoRoot 'core\SCT-Core.ps1')

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

function Write-FixtureScript {
    param([string]$Directory, [string]$Name, [string]$Content)
    $path = Join-Path $Directory $Name
    Set-Content -LiteralPath $path -Value $Content -Encoding UTF8
    return $path
}

function ConvertTo-TestModule {
    param([string]$Json)
    return ($Json | ConvertFrom-Json)
}

$tempRoot = Join-Path $PSScriptRoot ('.tmp-schema-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null

try {
    Write-FixtureScript -Directory $tempRoot -Name 'direct.ps1' -Content 'param()' | Out-Null
    Write-FixtureScript -Directory $tempRoot -Name 'source.ps1' -Content 'param([string]$SourcePath)' | Out-Null
    Write-FixtureScript -Directory $tempRoot -Name 'drive.ps1' -Content 'param([string]$DriveLetter)' | Out-Null
    Write-FixtureScript -Directory $tempRoot -Name 'server.ps1' -Content 'param([string]$ServerIP, [int]$Port = 8080)' | Out-Null
    Write-FixtureScript -Directory $tempRoot -Name 'subtests.ps1' -Content @'
param(
    [ValidateSet('One','Two','All')]
    [string]$Subtest
)
'@ | Out-Null
    Write-FixtureScript -Directory $tempRoot -Name 'mixed.ps1' -Content @'
param(
    [ValidateSet('Local','Remote','AllLocal','AllRemote','All')]
    [string]$Subtest,
    [string]$ServerIP,
    [int]$Port = 8080
)
'@ | Out-Null

    $minimal = ConvertTo-TestModule @'
{
  "id": "05",
  "name": "Test Module",
  "techniques": [
    { "id": "5.1", "name": "Direct", "attack_id": "T0001", "script": "direct.ps1" }
  ]
}
'@
    $errors = @(Get-SCTModuleErrors -Module $minimal -ModuleDir $tempRoot)
    Assert-True ($errors.Count -eq 0) "A four-field technique must be valid. Errors: $($errors -join ' | ')"

    $withSubtests = ConvertTo-TestModule @'
{
  "id": "05",
  "name": "Test Module",
  "techniques": [
    {
      "id": "5.1",
      "name": "Selectable",
      "attack_id": "T0001.001",
      "script": "subtests.ps1",
      "subtests": ["One", "Two"]
    }
  ]
}
'@
    $errors = @(Get-SCTModuleErrors -Module $withSubtests -ModuleDir $tempRoot)
    Assert-True ($errors.Count -eq 0) 'A valid subtest technique must pass.'

    $mixed = ConvertTo-TestModule @'
{
  "id": "05",
  "name": "Test Module",
  "techniques": [
    {
      "id": "5.1",
      "name": "Mixed",
      "attack_id": "T0001",
      "script": "mixed.ps1",
      "subtests": ["Local", "Remote"],
      "server_subtests": ["Remote"]
    }
  ]
}
'@
    $errors = @(Get-SCTModuleErrors -Module $mixed -ModuleDir $tempRoot)
    Assert-True ($errors.Count -eq 0) 'Valid mixed local/server subtests must pass.'

    $legacy = ConvertTo-TestModule @'
{
  "id": "05",
  "name": "Test Module",
  "vectors": [],
  "techniques": [
    {
      "id": "5.1",
      "name": "Legacy",
      "attack_id": "T0001",
      "script": "direct.ps1",
      "type": "simple",
      "marker_file": "legacy"
    }
  ]
}
'@
    $errors = @(Get-SCTModuleErrors -Module $legacy -ModuleDir $tempRoot)
    Assert-ErrorLike $errors "*Unknown module field 'vectors'*" 'Legacy vectors must be rejected.'
    Assert-ErrorLike $errors "*unknown field 'type'*" 'Legacy type must be rejected.'
    Assert-ErrorLike $errors "*unknown field 'marker_file'*" 'Legacy marker_file must be rejected.'

    $reserved = ConvertTo-TestModule @'
{
  "id": "05",
  "name": "Test Module",
  "techniques": [
    {
      "id": "5.1",
      "name": "Reserved",
      "attack_id": "T0001",
      "script": "subtests.ps1",
      "subtests": ["One", "All"]
    }
  ]
}
'@
    $errors = @(Get-SCTModuleErrors -Module $reserved -ModuleDir $tempRoot)
    Assert-ErrorLike $errors "*must not list 'All'*" 'Run-all entries must be derived, not authored.'

    $mismatch = ConvertTo-TestModule @'
{
  "id": "05",
  "name": "Test Module",
  "techniques": [
    {
      "id": "5.1",
      "name": "Mismatch",
      "attack_id": "T0001",
      "script": "subtests.ps1",
      "subtests": ["Missing"]
    }
  ]
}
'@
    $errors = @(Get-SCTModuleErrors -Module $mismatch -ModuleDir $tempRoot)
    Assert-ErrorLike $errors "*ValidateSet is missing subtest 'Missing'*" 'Manifest/script subtest drift must be rejected.'

    $badServer = ConvertTo-TestModule @'
{
  "id": "05",
  "name": "Test Module",
  "techniques": [
    {
      "id": "5.1",
      "name": "Bad server subtest",
      "attack_id": "T0001",
      "script": "subtests.ps1",
      "subtests": ["One", "Two"],
      "server_subtests": ["Remote"]
    }
  ]
}
'@
    $errors = @(Get-SCTModuleErrors -Module $badServer -ModuleDir $tempRoot)
    Assert-ErrorLike $errors "*server_subtest 'Remote' is not listed in subtests*" 'Server subtests must be a subset.'
    Assert-ErrorLike $errors "*does not accept -ServerIP*" 'Server-aware scripts must accept ServerIP.'

    $escapedPath = ConvertTo-TestModule @'
{
  "id": "05",
  "name": "Test Module",
  "techniques": [
    { "id": "5.1", "name": "Escape", "attack_id": "T0001", "script": "../escape.ps1" }
  ]
}
'@
    $errors = @(Get-SCTModuleErrors -Module $escapedPath -ModuleDir $tempRoot)
    Assert-ErrorLike $errors '*script path escapes the module folder*' 'Script traversal must be rejected.'

    $wrongModule = ConvertTo-TestModule @'
{
  "id": "05",
  "name": "Test Module",
  "techniques": [
    { "id": "6.1", "name": "Wrong module", "attack_id": "T0001", "script": "direct.ps1" }
  ]
}
'@
    $errors = @(Get-SCTModuleErrors -Module $wrongModule -ModuleDir $tempRoot)
    Assert-ErrorLike $errors "*does not belong to Module '05'*" 'Technique IDs must match their module.'

    $planned = ConvertTo-TestModule @'
{
  "id": "05",
  "name": "Test Module",
  "techniques": [
    {
      "id": "5.1",
      "name": "Planned",
      "attack_id": "T0001",
      "script": "future.ps1",
      "status": "planned"
    }
  ]
}
'@
    $errors = @(Get-SCTModuleErrors -Module $planned -ModuleDir $tempRoot)
    Assert-True ($errors.Count -eq 0) 'Planned techniques may reserve a future script path.'

    $runtimeScenarios = Join-Path $tempRoot 'runtime-scenarios'
    $runtimeModuleDir = Join-Path $runtimeScenarios '05-runtime-resilience'
    New-Item -ItemType Directory -Path $runtimeModuleDir -Force | Out-Null
    Write-FixtureScript -Directory $runtimeModuleDir -Name 'available.ps1' -Content 'param()' | Out-Null
    Set-Content -LiteralPath (Join-Path $runtimeModuleDir 'module.json') -Encoding UTF8 -Value @'
{
  "id": "05",
  "name": "Runtime Resilience",
  "techniques": [
    { "id": "5.1", "name": "Quarantined", "attack_id": "T0001", "script": "missing.ps1" },
    { "id": "5.2", "name": "Available", "attack_id": "T0002", "script": "available.ps1" }
  ]
}
'@
    $runtimeManifest = Get-Content -LiteralPath (Join-Path $runtimeModuleDir 'module.json') -Raw |
        ConvertFrom-Json
    $strictRuntimeErrors = @(
        Get-SCTModuleErrors -Module $runtimeManifest -ModuleDir $runtimeModuleDir
    )
    Assert-ErrorLike $strictRuntimeErrors "*Technique '5.1' script was not found*" `
        'Strict module validation must continue reporting missing scripts.'
    $runtimeModules = @(Get-SCTModules -ScenariosPath $runtimeScenarios -WarningAction SilentlyContinue)
    Assert-True ($runtimeModules.Count -eq 1) `
        'Runtime discovery must keep a module loaded when one technique script is missing.'
    Assert-True (@($runtimeModules[0].techniques).Count -eq 2) `
        'Runtime discovery must retain both unavailable and runnable techniques for stable menu numbering.'

    $workflowCases = @(
        @{ Script = 'direct.ps1'; Technique = $minimal.techniques[0]; Expected = 'direct' },
        @{ Script = 'source.ps1'; Technique = $minimal.techniques[0]; Expected = 'sample-batch' },
        @{ Script = 'drive.ps1'; Technique = $minimal.techniques[0]; Expected = 'removable-media' },
        @{ Script = 'server.ps1'; Technique = $minimal.techniques[0]; Expected = 'client-server' },
        @{ Script = 'subtests.ps1'; Technique = $withSubtests.techniques[0]; Expected = 'subtests' }
    )
    foreach ($case in $workflowCases) {
        $actual = Get-SCTTechniqueWorkflow -Technique $case.Technique -ScriptPath (Join-Path $tempRoot $case.Script)
        Assert-True ($actual -eq $case.Expected) "Expected workflow '$($case.Expected)', got '$actual'."
    }

    $marker = Get-SCTMarkerPath -TechniqueId '4.2' -Subtest 'HiddenXML'
    Assert-True ($marker -like '*\Temp\art-v4.2-HiddenXML.txt') 'Marker paths must follow the standard convention.'

    $canonicalCsv = Join-Path $tempRoot 'canonical-results.csv'
    Write-SCTResultRow -Path $canonicalCsv -Timestamp (Get-Date) -RunId 'fixture-run' `
        -TechniqueId '4.2' -TechniqueName 'Scheduled Task' -Subtest 'HiddenXML' `
        -TestScript 'v4.2-scheduled-task/v4.2-scheduled-task.ps1' -TestStage 'execution' `
        -SourceResult 'BLOCKED' -ExecutionStatus 'not_executed'
    $canonicalRows = @(Import-Csv -LiteralPath $canonicalCsv)
    Assert-True ($canonicalRows[0].technique_id -eq '4.2') 'Canonical results must identify the technique.'
    Assert-True ($canonicalRows[0].subtest -eq 'HiddenXML') 'Canonical results must identify the subtest.'
    Assert-True ($canonicalRows[0].PSObject.Properties.Name.Count -eq (Get-SCTResultColumns).Count) `
        'Canonical results must use the complete shared schema.'
    Assert-True (
        (@($canonicalRows[0].PSObject.Properties.Name)[0..7] -join '|') -eq
        'technique_name|subtest|test_input|test_stage|execution_status|detection_status|action_status|reviewer_notes'
    ) 'Canonical results must put reviewer-facing columns before technical provenance.'
    Assert-True ($canonicalRows[0].PSObject.Properties.Name -notcontains 'notes') `
        'Canonical results must not include the removed generated notes column.'
    Assert-True (
        $canonicalRows[0].detection_status -eq 'detection=' -and
        $canonicalRows[0].action_status -eq 'action=' -and
        $canonicalRows[0].reviewer_notes -eq 'notes='
    ) 'New result rows must provide compact prompts in all review fields.'
    Assert-True (
        (ConvertTo-SCTCanonicalDetectionStatus -Status 'detection=detected') -eq
            'detected'
    ) 'A reviewer must be able to type a detection value after the prompt.'
    Assert-True (
        (ConvertTo-SCTCanonicalActionStatus -Status 'action=blocked') -eq 'blocked'
    ) 'A reviewer must be able to type an action value after the prompt.'
    Assert-True (
        (Remove-SCTReviewPrompt -Value 'notes=Reviewed' -Prompt notes) -eq 'Reviewed'
    ) 'The package builder must be able to remove the notes prompt.'
    Assert-True (
        (ConvertTo-SCTCanonicalActionStatus -Status 'blocked') -eq 'blocked'
    ) 'The canonical blocked status must remain blocked.'
    Assert-True (
        (ConvertTo-SCTCanonicalActionStatus -Status 'blocked_before_execution') -eq 'blocked'
    ) 'Legacy blocked-before outcomes must normalize to blocked.'
    Assert-True (
        (ConvertTo-SCTCanonicalActionStatus -Status 'blocked_after_execution') -eq 'blocked'
    ) 'Legacy blocked-after outcomes must normalize to blocked.'

    $legacyNotesCsv = Join-Path $tempRoot 'legacy-notes-results.csv'
    $legacyNotesRow = $canonicalRows[0].PSObject.Copy()
    $legacyNotesRow | Add-Member -NotePropertyName 'notes' -NotePropertyValue 'legacy generated detail'
    $legacyNotesRow | Export-Csv -LiteralPath $legacyNotesCsv -NoTypeInformation -Encoding UTF8
    Assert-SCTResultFileSchema -Path $legacyNotesCsv -AllowLegacyNotesColumn

    Write-SCTResultRow -Path $legacyNotesCsv -Timestamp (Get-Date) -RunId 'fixture-run-2' `
        -TechniqueId '4.2' -TechniqueName 'Scheduled Task' -Subtest 'HiddenXML' `
        -TestScript 'v4.2-scheduled-task/v4.2-scheduled-task.ps1' -TestStage 'execution' `
        -SourceResult 'EXECUTED' -ExecutionStatus 'executed'

    $migratedLegacyRows = @(Import-Csv -LiteralPath $legacyNotesCsv)
    Assert-True ($migratedLegacyRows.Count -eq 2) `
        'Migrating an existing results file must retain its rows before appending.'
    Assert-True ($migratedLegacyRows[0].PSObject.Properties.Name -notcontains 'notes') `
        'The automatic results migration must remove the legacy notes column.'
    Assert-True ($migratedLegacyRows[0].technique_id -eq '4.2') `
        'The automatic results migration must preserve existing row values.'
    Assert-True (Test-Path -LiteralPath "$legacyNotesCsv.before-notes-removal.bak" -PathType Leaf) `
        'The automatic results migration must retain an untouched backup.'

    $previousLayoutCsv = Join-Path $tempRoot 'previous-layout-results.csv'
    $canonicalRows[0] |
        Select-Object -Property (Get-SCTPreviousResultColumns) |
        Export-Csv -LiteralPath $previousLayoutCsv -NoTypeInformation -Encoding UTF8
    Assert-SCTResultFileSchema -Path $previousLayoutCsv

    Write-SCTResultRow -Path $previousLayoutCsv -Timestamp (Get-Date) -RunId 'fixture-run-3' `
        -TechniqueId '4.2' -TechniqueName 'Scheduled Task' -Subtest 'HiddenXML' `
        -TestScript 'v4.2-scheduled-task/v4.2-scheduled-task.ps1' -TestStage 'execution' `
        -SourceResult 'EXECUTED' -ExecutionStatus 'executed'

    $migratedLayoutRows = @(Import-Csv -LiteralPath $previousLayoutCsv)
    Assert-True ($migratedLayoutRows.Count -eq 2) `
        'Migrating the previous results layout must retain its rows before appending.'
    Assert-True (
        ($migratedLayoutRows[0].PSObject.Properties.Name -join '|') -eq
        ((Get-SCTResultColumns) -join '|')
    ) 'The automatic migration must put existing results into the review-first layout.'
    Assert-True ($migratedLayoutRows[0].technique_id -eq '4.2') `
        'The review-first layout migration must preserve technical field values.'
    Assert-True (
        Test-Path -LiteralPath "$previousLayoutCsv.before-review-first-layout.bak" -PathType Leaf
    ) 'The review-first layout migration must retain an untouched backup.'

    $scenariosPath = Join-Path $repoRoot 'scenarios'
    $realModules = @(Get-SCTModules -ScenariosPath $scenariosPath)
    Assert-True ($realModules.Count -eq 4) 'All four repository modules must load.'
    Assert-True (@($realModules | ForEach-Object { $_.techniques }).Count -eq 15) 'All 15 repository techniques must load.'

    foreach ($toolName in @(
        'AddModule', 'DescribeModuleTests', 'SetupControl', 'BuildPackage',
        'ComparePackages', 'CheckControlProfile', 'CheckModules', 'CheckResults',
        'CheckTestDescriptions'
    )) {
        $toolPath = Get-SCTRepositoryToolPath -RepoRoot $repoRoot -Tool $toolName
        Assert-True (Test-Path -LiteralPath $toolPath -PathType Leaf) `
            "Manage SCT must resolve the $toolName utility."
    }

    $fixtureResultsRoot = Join-Path $tempRoot 'results'
    $fixtureWorkspaceRoot = Join-Path $fixtureResultsRoot 'example-control'
    New-Item -ItemType Directory -Path $fixtureWorkspaceRoot -Force | Out-Null
    $fixtureProfilePath = Join-Path $fixtureWorkspaceRoot 'example-control-control-profile.json'
    Copy-Item -LiteralPath (Join-Path $repoRoot 'config\control-profile.example.json') `
        -Destination $fixtureProfilePath
    $discoveredProfiles = @(Get-SCTControlProfilePaths -ResultsRoot $fixtureResultsRoot)
    Assert-True ($discoveredProfiles.Count -eq 1) 'Control workspace discovery must find one profile per product folder.'
    Assert-True ((Split-Path $discoveredProfiles[0] -Leaf) -eq 'example-control-control-profile.json') `
        'Control workspace discovery must use the control-specific profile filename.'
    $script:ReadResponses = New-Object 'System.Collections.Generic.Queue[string]'
    $script:ReadResponses.Enqueue('1')
    $script:ReadPrompts = @()
    function Read-Host {
        param([string]$Prompt)
        $script:ReadPrompts += $Prompt
        if ($script:ReadResponses.Count -gt 0) { return $script:ReadResponses.Dequeue() }
        throw "Unexpected Read-Host prompt: $Prompt"
    }
    try {
        $explicitlySelectedProfile = Select-SCTControlProfilePath -ResultsRoot $fixtureResultsRoot
    } finally {
        Remove-Item -LiteralPath 'Function:\Read-Host' -ErrorAction SilentlyContinue
    }
    Assert-True ($explicitlySelectedProfile -eq $fixtureProfilePath) `
        'Selecting existing configuration must work even when only one profile exists.'
    Assert-True ($script:ReadResponses.Count -eq 0 -and $script:ReadPrompts.Count -eq 1) `
        'The existing-configuration action must show a choice instead of silently returning one profile.'
    $fixtureWorkspace = Get-SCTControlWorkspace -RepoRoot $tempRoot -ProfilePath $fixtureProfilePath
    Assert-True ($fixtureWorkspace.ControlId -eq 'example-control') 'The workspace must use the profile control id.'
    Assert-True ((Get-SCTModuleResultsPath -WorkspaceRoot $fixtureWorkspaceRoot -ModuleId '01') -eq `
        (Join-Path $fixtureWorkspaceRoot 'results-module-01.csv')) `
        'Module 01 observations must use the stable module result filename.'
    foreach ($moduleId in @('02', '03', '04')) {
        Assert-True ((Get-SCTModuleResultsPath -WorkspaceRoot $fixtureWorkspaceRoot -ModuleId $moduleId) -eq `
            (Join-Path $fixtureWorkspaceRoot "results-module-$moduleId.csv")) `
            "Module $moduleId observations must use results-module-$moduleId.csv."
    }
    Assert-True ((Get-SCTModuleCatalogPath -WorkspaceRoot $fixtureWorkspaceRoot -ModuleId '02') -eq `
        (Join-Path $fixtureWorkspaceRoot 'test-catalog-module-02.csv')) `
        'Module 02 descriptions must use the stable module catalogue filename.'

    $module1 = @($realModules | Where-Object { $_.id -eq '01' })[0]
    $technique14 = @($module1.techniques | Where-Object { $_.id -eq '1.4' })[0]
    Assert-True (($technique14.subtests -join '|') -eq 'EICARWrite|HiddenPowerShell') `
        'Technique 1.4 must expose separate EICAR and hidden PowerShell observations.'
    $technique14Path = Join-Path $module1.ScriptDir $technique14.script
    Assert-True (Test-SCTScriptSupportsParameter -ScriptPath $technique14Path -ParameterName 'Subtest') `
        'Technique 1.4 must use the standard subtest runner contract.'

    $module2 = @($realModules | Where-Object { $_.id -eq '02' })[0]
    $technique21 = @($module2.techniques | Where-Object { $_.id -eq '2.1' })[0]
    $technique22 = @($module2.techniques | Where-Object { $_.id -eq '2.2' })[0]
    Assert-True (($technique21.subtests -join '|') -eq 'WordVBA') `
        'Technique 2.1 must expose its WordVBA marker observation.'
    Assert-True ($null -eq $technique22.PSObject.Properties['subtests']) `
        'Technique 2.2 must use the direct/manual result-attestation path.'
    foreach ($sampleTechniqueId in @('1.1', '1.2', '1.3')) {
        $sampleTechnique = @($module1.techniques | Where-Object { $_.id -eq $sampleTechniqueId })[0]
        $sampleScriptPath = Join-Path $module1.ScriptDir $sampleTechnique.script
        Assert-True (Test-SCTScriptSupportsParameter -ScriptPath $sampleScriptPath -ParameterName 'ResultsPath') `
            "Technique $sampleTechniqueId must accept the selected workspace result path."
        $sampleScriptText = Get-Content -LiteralPath $sampleScriptPath -Raw -Encoding UTF8
        Assert-True ($sampleScriptText -notmatch 'results\\raw') `
            "Technique $sampleTechniqueId must not fall back to the old shared results directory."
        $missingWorkspaceRejected = $false
        try {
            & $sampleScriptPath
        } catch {
            $missingWorkspaceRejected = $_.Exception.Message -like '*ResultsPath is required*'
        }
        Assert-True $missingWorkspaceRejected `
            "Technique $sampleTechniqueId must reject a direct run without a workspace result path."
    }

    $module4 = @($realModules | Where-Object { $_.id -eq '04' })[0]
    $technique41 = @($module4.techniques | Where-Object { $_.id -eq '4.1' })[0]
    foreach ($registrySubtest in @('HKCURunKey','HKCURunOnce','HKLMRunKey','HKLMRunOnce')) {
        Assert-True ($technique41.subtests -contains $registrySubtest) "Technique 4.1 must include $registrySubtest."
    }
    $technique41Path = Join-Path $module4.ScriptDir $technique41.script
    $technique44 = @($module4.techniques | Where-Object { $_.id -eq '4.4' })[0]
    foreach ($wmiSubtest in @('CommandLineConsumer','ActiveScriptConsumer')) {
        Assert-True ($technique44.subtests -contains $wmiSubtest) "Technique 4.4 must include $wmiSubtest."
    }
    $technique44Path = Join-Path $module4.ScriptDir $technique44.script
    foreach ($requiredParameter in @('Subtest','NoPause','NoReport','CleanupOnly','NoCleanupPrompt')) {
        Assert-True (Test-SCTScriptSupportsParameter -ScriptPath $technique44Path -ParameterName $requiredParameter) `
            "Technique 4.4 must accept -$requiredParameter."
    }
    $technique42 = @($module4.techniques | Where-Object { $_.id -eq '4.2' })[0]
    $technique42Path = Join-Path $module4.ScriptDir $technique42.script
    $technique42Text = Get-Content -LiteralPath $technique42Path -Raw
    Assert-True ($technique42Text -match 'TaskName\s*=\s*\$tn') `
        'Technique 4.2 HiddenXML registration must pass the task name to RegisterByXml.'
    Assert-True ($technique42Text -match "TaskPath\s*=\s*'\\'") `
        'Technique 4.2 HiddenXML registration must pass an explicit root task path.'
    Assert-True ($technique42Text -match 'Xml\s*=\s*\$xmlContent') `
        'Technique 4.2 HiddenXML registration must pass the task XML to RegisterByXml.'
    $technique41Text = Get-Content -LiteralPath $technique41Path -Raw
    Assert-True ($technique41Text -match 'Test-SCTOwnedRunValue') `
        'Technique 4.1 cleanup must identify SCT-owned Run values before removing them.'
    Assert-True ($technique41Text -match 'Refusing to overwrite existing registry value') `
        'Technique 4.1 must preserve pre-existing Run values.'
    $technique43 = @($module4.techniques | Where-Object { $_.id -eq '4.3' })[0]
    $technique43Path = Join-Path $module4.ScriptDir $technique43.script
    $technique43Text = Get-Content -LiteralPath $technique43Path -Raw
    Assert-True ($technique43Text -match 'SCT-Startup-Backup-v4\.3') `
        'Technique 4.3 must use a dedicated backup for the current Startup-folder value.'
    Assert-True ($technique43Text -match 'SCT-Userinit-Backup-v4\.3') `
        'Technique 4.3 must use a dedicated Winlogon Userinit backup.'
    Assert-True ($technique43Text -notmatch 'Remove-Item\s+\$redirectDir\s+-Recurse') `
        'Technique 4.3 cleanup must not recursively remove the redirect directory.'
    Assert-True (@($module4.techniques | ForEach-Object { $_.subtests }).Count -eq 19) 'Module 04 must expose all 19 persistence subtests.'

    $module3 = @($realModules | Where-Object { $_.id -eq '03' })[0]
    $technique31 = @($module3.techniques | Where-Object { $_.id -eq '3.1' })[0]
    Assert-True ($technique31.status -eq 'planned') `
        'Technique 3.1 must remain explicitly planned until it has executable result logic.'
    Assert-True (@($module3.techniques | ForEach-Object {
        if ($_.PSObject.Properties['subtests']) { $_.subtests }
    }).Count -eq 8) `
        'Module 03 must expose all 8 implemented subtest observations.'
    $technique32 = @($module3.techniques | Where-Object { $_.id -eq '3.2' })[0]
    $technique32Path = Join-Path $module3.ScriptDir $technique32.script
    $technique32Text = Get-Content -LiteralPath $technique32Path -Raw
    Assert-True ($technique32Text -match "\[EnvironmentVariableTarget\]::User") `
        'Technique 3.2 SilentCleanup must set the current-user windir value seen by Task Scheduler.'
    Assert-True ($technique32Text -notmatch '\$env:windir\s*=') `
        'Technique 3.2 must not rely on a process-local windir override.'
    Assert-True ($technique32Text -match 'IsInRole\(\[Security\.Principal\.WindowsBuiltInRole\]::Administrator\)') `
        'Technique 3.2 must reject an already elevated Administrator token.'
    Assert-True ($technique32Text -match 'Refusing to overwrite an existing per-user class override') `
        'Technique 3.2 must preserve pre-existing per-user class overrides.'
    Assert-True ($technique32Text -notmatch 'Remove-Item\s+["'']HKCU:\\Software\\Classes\\(?:ms-settings|mscfile)["'']') `
        'Technique 3.2 must not recursively delete an entire per-user class branch.'
    $technique33 = @($module3.techniques | Where-Object { $_.id -eq '3.3' })[0]
    $technique33Path = Join-Path $module3.ScriptDir $technique33.script
    foreach ($requiredParameter in @('Subtest','NoPause','NoReport','CleanupOnly','NoCleanupPrompt')) {
        Assert-True (Test-SCTScriptSupportsParameter -ScriptPath $technique33Path -ParameterName $requiredParameter) `
            "Technique 3.3 must accept -$requiredParameter for managed launch and cleanup."
    }

    # Exercise the interactive subtest-to-CSV path without launching a technique.
    $interactiveScript = Write-FixtureScript -Directory $tempRoot -Name 'interactive.ps1' -Content @'
param(
    [ValidateSet('One','All')]
    [string]$Subtest,
    [switch]$NoCleanupPrompt,
    [switch]$NoReport,
    [switch]$NoPause,
    [switch]$CleanupOnly
)
'@
    $interactiveCsv = Join-Path $tempRoot 'interactive-results.csv'
    $originalSystemRoot = $env:SystemRoot
    try {
        $env:SystemRoot = $tempRoot
        $script:ReadResponses = New-Object 'System.Collections.Generic.Queue[string]'
        $script:ReadResponses.Enqueue('1')
        $script:ReadResponses.Enqueue('')
        $script:ReadResponses.Enqueue('')

        function Read-Host {
            param([string]$Prompt)
            if ($script:ReadResponses.Count -gt 0) { return $script:ReadResponses.Dequeue() }
            return ''
        }

        function Start-Process {
            param(
                [string]$FilePath,
                [object[]]$ArgumentList,
                [switch]$Wait,
                [switch]$NoNewWindow,
                [switch]$PassThru,
                [System.Management.Automation.ActionPreference]$ErrorAction
            )
            if ($ArgumentList -contains '-CleanupOnly') {
                $script:MockCleanupCalls++
                return [pscustomobject]@{ ExitCode = 0 }
            }
            return [pscustomobject]@{ ExitCode = $script:MockProcessExitCode }
        }
        $script:MockProcessExitCode = 0
        $script:MockCleanupCalls = 0

        function Test-SCTMarkerFile {
            param([string]$Path)
            return $false
        }

        $interactiveTechnique = [pscustomobject]@{
            id = '4.99'
            name = 'Interactive CSV Fixture'
            script = 'interactive.ps1'
            subtests = @('One')
        }
        Invoke-SCTSubtests -Technique $interactiveTechnique -ScriptPath $interactiveScript `
            -Control 'FixtureControl' -ResultsPath $interactiveCsv

        Assert-True (Test-Path -LiteralPath $interactiveCsv -PathType Leaf) `
            'Interactive subtest execution must create its selected module result file.'
        $interactiveRows = @(Import-Csv -LiteralPath $interactiveCsv)
        Assert-True ($interactiveRows.Count -eq 1) 'Interactive subtest execution must write one row.'
        Assert-True ($interactiveRows[0].technique_id -eq '4.99') 'Interactive CSV must identify the technique.'
        Assert-True ($interactiveRows[0].subtest -eq 'One') 'Interactive CSV must identify the subtest.'
        Assert-True (-not [string]::IsNullOrWhiteSpace($interactiveRows[0].run_id)) `
            'Interactive CSV rows must have a run_id.'
        Assert-True ($interactiveRows[0].execution_status -eq 'not_executed') `
            'A missing marker must be captured as not_executed.'
        Assert-True ($interactiveRows[0].source_result -eq 'NOT_EXECUTED') `
            'A missing marker must not be mislabeled as a confirmed control block.'
        Assert-True ($script:MockCleanupCalls -eq 1) `
            'Interactive managed subtests must clean up only after their CSV result is recorded.'

        $errorCsv = Join-Path $tempRoot 'interactive-error-results.csv'
        $script:MockProcessExitCode = 2
        $script:ReadResponses = New-Object 'System.Collections.Generic.Queue[string]'
        foreach ($response in @('1', '', '')) { $script:ReadResponses.Enqueue($response) }
        Invoke-SCTSubtests -Technique $interactiveTechnique -ScriptPath $interactiveScript `
            -Control 'FixtureControl' -ResultsPath $errorCsv
        $errorRows = @(Import-Csv -LiteralPath $errorCsv)
        Assert-True ($errorRows.Count -eq 1 -and $errorRows[0].source_result -eq 'ERROR') `
            'A nonzero technique exit must append an ERROR row instead of claiming a block.'
        Assert-True ($script:MockCleanupCalls -eq 2) `
            'Managed cleanup must still run after a failed interactive technique.'
        $script:MockProcessExitCode = 0

        # Direct/manual techniques must also append an authoritative result row.
        $directCsv = Join-Path $tempRoot 'results-module-05.csv'
        $directTechnique = [pscustomobject]@{
            id = '5.1'
            name = 'Direct CSV Fixture'
            script = 'direct.ps1'
        }

        $script:ReadResponses = New-Object 'System.Collections.Generic.Queue[string]'
        foreach ($response in @('', 'E', '')) { $script:ReadResponses.Enqueue($response) }
        Invoke-DirectTechnique -Technique $directTechnique -ScriptPath (Join-Path $tempRoot 'direct.ps1') `
            -ResultsPath $directCsv

        $script:ReadResponses = New-Object 'System.Collections.Generic.Queue[string]'
        foreach ($response in @('', 'N', '')) { $script:ReadResponses.Enqueue($response) }
        Invoke-DirectTechnique -Technique $directTechnique -ScriptPath (Join-Path $tempRoot 'direct.ps1') `
            -ResultsPath $directCsv

        $script:MockProcessExitCode = 9
        $script:ReadResponses = New-Object 'System.Collections.Generic.Queue[string]'
        foreach ($response in @('', '')) { $script:ReadResponses.Enqueue($response) }
        Invoke-DirectTechnique -Technique $directTechnique -ScriptPath (Join-Path $tempRoot 'direct.ps1') `
            -ResultsPath $directCsv
        $script:MockProcessExitCode = 0

        $script:ReadResponses = New-Object 'System.Collections.Generic.Queue[string]'
        foreach ($response in @('', 'S', '')) { $script:ReadResponses.Enqueue($response) }
        Invoke-DirectTechnique -Technique $directTechnique -ScriptPath (Join-Path $tempRoot 'direct.ps1') `
            -ResultsPath $directCsv

        $directRows = @(Import-Csv -LiteralPath $directCsv)
        Assert-True ($directRows.Count -eq 3) 'Skipping a direct result must not append a row.'
        Assert-True ($directRows[0].execution_status -eq 'executed') `
            'An executed direct result must use execution_status executed.'
        Assert-True ($directRows[1].source_result -eq 'NOT_EXECUTED' -and
            $directRows[1].execution_status -eq 'not_executed') `
            'A not-executed direct result must not claim that the control blocked it.'
        Assert-True ($directRows[2].source_result -eq 'ERROR') `
            'A failed direct technique must append an ERROR row automatically.'
    } finally {
        $env:SystemRoot = $originalSystemRoot
    }

    Write-Host "Passed $script:Assertions schema assertions." -ForegroundColor Green
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
