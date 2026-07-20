#Requires -Version 5.1
<#
.SYNOPSIS
    Security Controls Testing (SCT) Framework - Interactive Launcher

.DESCRIPTION
    Menu-driven launcher for structured endpoint security control evaluation.
    Discovers test modules automatically by scanning scenarios/ for module.json
    files - no code changes required to add new modules or techniques.

    Supports Windows 10 and Windows 11. Requires PowerShell 5.1 or later.
    No external modules or tools required beyond what ships with Windows.

    See README.md for full usage, and for how to extend the framework with
    new malware samples, techniques, or entirely new test modules.

.PARAMETER Control
    Name of the security product under test (e.g. SentinelOne, CarbonBlack,
    Morphisec, Baseline-NoAV). Passed automatically to every test script so
    results.csv rows are tagged consistently. If omitted, the launcher prompts
    at startup.

.PARAMETER SamplesPath
    Override the default samples/ folder used for malware ZIP archives.
    Defaults to <repo-root>\samples\.

.EXAMPLE
    .\Start-SCT.ps1

.EXAMPLE
    .\Start-SCT.ps1 -Control SentinelOne

.EXAMPLE
    .\Start-SCT.ps1 -Control CarbonBlack -SamplesPath D:\MalwareSamples

.NOTES
    Lab use only. Run inside an isolated VM - NEVER on production systems.
    PowerShell 5.1+. No external modules required.
#>

[CmdletBinding()]
param(
    [string]$Control,
    [string]$SamplesPath,
    [string]$RunModule,
    [switch]$NonInteractive,
    [ValidateRange(0, 300)] [int]$StartDelaySeconds = 10,
    [Alias('InterVectorDelaySeconds')]
    [ValidateRange(0, 300)] [int]$InterTechniqueDelaySeconds = 3
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Load the core library (all menu/dispatch functions live there)
# ---------------------------------------------------------------------------
$corePath = Join-Path $PSScriptRoot 'core\SCT-Core.ps1'
if (-not (Test-Path $corePath)) {
    Write-Host ""
    Write-Host "  [!] Core library missing: $corePath" -ForegroundColor Red
    Write-Host "  [!] Ensure the full repository is present and intact." -ForegroundColor Red
    Write-Host ""
    exit 1
}
. $corePath

# ---------------------------------------------------------------------------
# Resolve working paths
# ---------------------------------------------------------------------------
$scenariosPath    = Join-Path $PSScriptRoot 'scenarios'
$resultsPath      = Join-Path $PSScriptRoot 'results\raw\results.csv'
$testResultsPath  = Join-Path $PSScriptRoot 'results\raw\test-results.csv'
if (-not $SamplesPath) {
    $SamplesPath = Join-Path $PSScriptRoot 'samples'
}

# ---------------------------------------------------------------------------
# Welcome banner
# ---------------------------------------------------------------------------
Show-SCTBanner

# ---------------------------------------------------------------------------
# Prompt for security product name (once, reused for all tests)
# ---------------------------------------------------------------------------
if (-not $Control) {
    if ($NonInteractive) {
        throw "-Control is required with -NonInteractive so CSV rows identify the product under test."
    }
    Write-Host "  Before we start, identify the security product under test." -ForegroundColor White
    Write-Host "  This label tags every row in the sample and subtest result CSVs." -ForegroundColor DarkGray
    Write-Host "  Examples: SentinelOne, CarbonBlack, Morphisec, Baseline-NoAV" -ForegroundColor DarkGray
    $Control = (Read-Host "`n  Security product name").Trim()
    if (-not $Control) { $Control = 'Unnamed-Control' }
}

Write-Host ""
Write-Host "  Control       : $Control" -ForegroundColor Green
Write-Host "  Sample CSV    : $resultsPath" -ForegroundColor DarkGray
Write-Host "  Subtest CSV   : $testResultsPath" -ForegroundColor DarkGray
Write-Host "  Samples       : $SamplesPath" -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# Discover modules from scenarios/*/module.json
# ---------------------------------------------------------------------------
$modules = Get-SCTModules -ScenariosPath $scenariosPath

if ($modules.Count -eq 0) {
    Write-Host ""
    Write-Host "  [!] No modules found in: $scenariosPath" -ForegroundColor Red
    Write-Host "  [!] Each module folder needs a module.json file." -ForegroundColor Red
    Write-Host "  [!] See docs/project-structure.md -> 'Adding a module'." -ForegroundColor Red
    Write-Host ""
    exit 1
}

Write-Host "  Modules  : $($modules.Count) loaded" -ForegroundColor DarkGray

if ($NonInteractive) {
    if (-not $RunModule) {
        throw "-NonInteractive requires -RunModule. Module 04 is currently supported."
    }

    $targetModule = @($modules | Where-Object { $_.id -eq $RunModule })
    if ($targetModule.Count -ne 1) {
        throw "Module '$RunModule' was not found. Use -RunModule 04 for the Persistence module."
    }

    [void](Invoke-SCTModuleNonInteractive -Module $targetModule[0] -Control $Control `
        -TestResultsPath $testResultsPath -StartDelaySeconds $StartDelaySeconds `
        -InterTechniqueDelaySeconds $InterTechniqueDelaySeconds)
    exit 0
}

if ($RunModule) {
    throw "-RunModule requires -NonInteractive. Use: .\Start-SCT.ps1 -Control <product> -RunModule 04 -NonInteractive"
}

# ---------------------------------------------------------------------------
# Main menu loop
# ---------------------------------------------------------------------------
while ($true) {
    Show-SCTMainMenu -Modules $modules -Control $Control

    $choice = (Read-Host "  Selection").Trim()

    if (-not $choice) { continue }

    switch ($choice.ToUpper()) {
        'Q' {
            Write-Host ""
            Write-Host "  Exiting. Review your results at:" -ForegroundColor Gray
            Write-Host "  Samples : $resultsPath" -ForegroundColor DarkGray
            Write-Host "  Subtests: $testResultsPath" -ForegroundColor DarkGray
            Write-Host ""
            exit 0
        }
        'V' {
            Show-SCTSummary -ResultsPath $resultsPath -TestResultsPath $testResultsPath
        }
        default {
            $idx = $choice -as [int]
            if ($idx -ge 1 -and $idx -le $modules.Count) {
                Invoke-SCTModuleMenu -Module $modules[$idx - 1] `
                    -Control $Control `
                    -SamplesPath $SamplesPath `
                    -ScenarioRoot $scenariosPath `
                    -ResultsPath $resultsPath `
                    -TestResultsPath $testResultsPath
            } else {
                Write-Host "  Invalid selection. Enter 1-$($modules.Count), [V], or [Q]." -ForegroundColor Yellow
                Start-Sleep -Milliseconds 600
            }
        }
    }
}
