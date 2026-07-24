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

. (Join-Path $systemRoot 'scripts\SCT-ComparisonHelpers.ps1')
foreach ($version in @('3.11', '3.12', '3.13', '3.14', '3.20')) {
    Assert-True (Test-SCTSupportedPythonVersion -Version $version) `
        "Python $version must be accepted."
}
foreach ($version in @('2.7', '3.10', '4.0', 'invalid')) {
    Assert-True (-not (Test-SCTSupportedPythonVersion -Version $version)) `
        "Python $version must be rejected."
}
$pyproject = Get-Content -LiteralPath (Join-Path $systemRoot 'pyproject.toml') -Raw
Assert-True ($pyproject -match 'requires-python\s*=\s*">=3\.11,<4"') `
    'Package metadata must support Python 3.11 and newer within Python 3.x.'

$requiredPaths = @(
    'pyproject.toml',
    'README.md',
    'src\sct_ai\cli.py',
    'src\sct_ai\asgi.py',
    'src\sct_ai\web.py',
    'src\sct_ai\metrics.py',
    'scripts\Compare-SCTControls.ps1',
    'scripts\Start-SCTComparisonWeb.ps1',
    'requirements\build.txt',
    'config\comparison-policy.example.json',
    'config\ai-providers.example.json',
    'comparisons\README.md'
)
foreach ($relativePath in $requiredPaths) {
    Assert-True (Test-Path -LiteralPath (Join-Path $systemRoot $relativePath) -PathType Leaf) `
        "Comparison surface must include $relativePath."
}

Assert-True ($pyproject -match 'sct-web\s*=\s*"sct_ai\.cli:web_main"') `
    'The installable package must expose the Python-first sct-web command.'
$asgiSource = Get-Content -LiteralPath (Join-Path $systemRoot 'src\sct_ai\asgi.py') -Raw
Assert-True ($asgiSource -match 'app\s*=\s*create_app_from_env\(\)') `
    'The package must expose a conventional ASGI application object.'
$offlineInstaller = Get-Content -LiteralPath (
    Join-Path $systemRoot 'scripts\Install-SCTOfflineBundle.ps1'
) -Raw
Assert-True ($offlineInstaller -match '--editable\s+\$systemRoot') `
    'Offline installation must install the Python package for direct module startup.'

$htmxPath = Join-Path $systemRoot 'src\sct_ai\static\htmx.min.js'
Assert-True (Test-Path -LiteralPath $htmxPath -PathType Leaf) `
    'HTMX must be vendored for air-gapped browser use.'
Assert-True ((Get-Content -LiteralPath $htmxPath -Raw) -match 'version:"2\.0\.10"') `
    'The vendored HTMX asset must stay pinned to 2.0.10.'

$skillCatalogPath = Join-Path $systemRoot 'src\sct_ai\skills.json'
Assert-True (Test-Path -LiteralPath $skillCatalogPath -PathType Leaf) `
    'The consolidated runtime skill catalog must exist.'
$skillCatalog = Get-Content -LiteralPath $skillCatalogPath -Raw -Encoding UTF8 |
    ConvertFrom-Json
foreach ($skillName in @(
    'profile-context', 'module-analysis', 'cross-control-synthesis',
    'qualified-recommendation'
)) {
    Assert-True ($null -ne $skillCatalog.skills.$skillName) `
        "Runtime skill catalog must include $skillName."
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
