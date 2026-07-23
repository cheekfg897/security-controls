<#
.SYNOPSIS
    Dependency-free checks for the repository-owned comparison surface.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$systemRoot = Split-Path $PSScriptRoot -Parent
$repoRoot = Split-Path $systemRoot -Parent
$script:Assertions = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

$requiredPaths = @(
    'pyproject.toml',
    'README.md',
    'src\sct_ai\cli.py',
    'src\sct_ai\web.py',
    'src\sct_ai\metrics.py',
    'scripts\Compare-SCTControls.ps1',
    'scripts\Start-SCTComparisonWeb.ps1',
    'config\comparison-policy.example.json',
    'config\ai-providers.example.json',
    'comparisons\README.md'
)
foreach ($relativePath in $requiredPaths) {
    Assert-True (Test-Path -LiteralPath (Join-Path $systemRoot $relativePath) -PathType Leaf) `
        "Comparison surface must include $relativePath."
}

$htmxPath = Join-Path $systemRoot 'src\sct_ai\static\htmx.min.js'
Assert-True (Test-Path -LiteralPath $htmxPath -PathType Leaf) `
    'HTMX must be vendored for air-gapped browser use.'
Assert-True ((Get-Content -LiteralPath $htmxPath -Raw) -match 'version:"2\.0\.10"') `
    'The vendored HTMX asset must stay pinned to 2.0.10.'

$skillRoot = Join-Path $systemRoot 'src\sct_ai\skills'
foreach ($skillName in @(
    'profile-context', 'module-analysis', 'cross-control-synthesis',
    'qualified-recommendation'
)) {
    $root = Join-Path $skillRoot $skillName
    foreach ($fileName in @(
        'skill.json', 'system.md', 'prompt.md', 'input.schema.json',
        'output.schema.json'
    )) {
        Assert-True (Test-Path -LiteralPath (Join-Path $root $fileName) -PathType Leaf) `
            "Runtime skill $skillName must include $fileName."
    }
}

. (Join-Path $repoRoot 'core\SCT-Core.ps1')
$comparisonTool = Get-SCTRepositoryToolPath -RepoRoot $repoRoot -Tool 'ComparePackages'
Assert-True ($comparisonTool -eq (Join-Path $repoRoot 'ai-system\scripts\Compare-SCTControls.ps1')) `
    'Manage SCT must resolve the comparison CLI wrapper.'

$parserErrors = @()
Get-ChildItem -LiteralPath (Join-Path $systemRoot 'scripts') -Filter '*.ps1' -File |
    ForEach-Object {
        [void][Management.Automation.Language.Parser]::ParseFile(
            $_.FullName,
            [ref]$null,
            [ref]$parserErrors
        )
    }
Assert-True ($parserErrors.Count -eq 0) `
    "Comparison PowerShell scripts must parse: $($parserErrors -join '; ')"

Write-Host "Passed $script:Assertions comparison-surface assertions." -ForegroundColor Green
