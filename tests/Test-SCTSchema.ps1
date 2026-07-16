<#
.SYNOPSIS
    Dependency-free regression tests for the simplified SCT manifest contract.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path $PSScriptRoot -Parent
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

    $legacyCsv = Join-Path $tempRoot 'legacy-results.csv'
    @'
"timestamp","control","vector_id","vector_name","technique","outcome","notes"
"2026-01-01T00:00:00.0000000Z","Test","4.2","Scheduled Task","HiddenXML","BLOCKED","legacy"
'@ | Set-Content -LiteralPath $legacyCsv -Encoding UTF8
    Update-SCTTestResultsSchema -Path $legacyCsv
    $migrated = @(Import-Csv -LiteralPath $legacyCsv)
    Assert-True ($migrated[0].technique_id -eq '4.2') 'Legacy result technique ID must migrate.'
    Assert-True ($migrated[0].subtest -eq 'HiddenXML') 'Legacy result subtest must migrate.'
    Assert-True ($migrated[0].PSObject.Properties.Name -contains 'run_id') 'Migrated results must include run_id.'

    $scenariosPath = Join-Path $repoRoot 'scenarios'
    $realModules = @(Get-SCTModules -ScenariosPath $scenariosPath)
    Assert-True ($realModules.Count -eq 4) 'All four repository modules must load.'
    Assert-True (@($realModules | ForEach-Object { $_.techniques }).Count -eq 14) 'All 14 repository techniques must load.'

    Write-Host "Passed $script:Assertions schema assertions." -ForegroundColor Green
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
