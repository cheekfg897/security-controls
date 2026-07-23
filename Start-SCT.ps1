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
    Deprecated compatibility parameter. The control name is now read from the
    selected control profile so identity and results cannot diverge.

.PARAMETER ControlProfilePath
    Selects a product workspace through its results\<control-id>\control-profile.json.
    Required with -NonInteractive. Interactive runs prompt when multiple
    workspaces exist and automatically select the only workspace when possible.

.PARAMETER SamplesPath
    Override the default samples/ folder used for malware ZIP archives.
    Defaults to <repo-root>\samples\.

.EXAMPLE
    .\Start-SCT.ps1

.EXAMPLE
    .\Start-SCT.ps1 -ControlProfilePath .\results\sentinelone\control-profile.json

.EXAMPLE
    .\Start-SCT.ps1 -ControlProfilePath .\results\sentinelone\control-profile.json `
        -SamplesPath D:\MalwareSamples

.NOTES
    Lab use only. Run inside an isolated VM - NEVER on production systems.
    PowerShell 5.1+. No external modules required.
#>

[CmdletBinding()]
param(
    [string]$Control,
    [string]$ControlProfilePath,
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
$resultsRoot      = Join-Path $PSScriptRoot 'results'
if (-not $SamplesPath) {
    $SamplesPath = Join-Path $PSScriptRoot 'samples'
}

$workspace = $null
if ($ControlProfilePath) {
    $workspace = Get-SCTControlWorkspace -RepoRoot $PSScriptRoot -ProfilePath $ControlProfilePath
} else {
    $availableProfiles = @(Get-SCTControlProfilePaths -ResultsRoot $resultsRoot)
    if ($availableProfiles.Count -eq 1) {
        $workspace = Get-SCTControlWorkspace -RepoRoot $PSScriptRoot -ProfilePath $availableProfiles[0]
    } elseif ($Control) {
        foreach ($profilePath in $availableProfiles) {
            $candidate = Get-SCTControlWorkspace -RepoRoot $PSScriptRoot -ProfilePath $profilePath
            if ($candidate.ControlId -eq $Control -or $candidate.ControlName -eq $Control) {
                $workspace = $candidate
                break
            }
        }
    }
}

if ($workspace) {
    if ($Control -and $Control -ne $workspace.ControlName -and $Control -ne $workspace.ControlId) {
        Write-Warning "Ignoring -Control '$Control'; the selected profile identifies '$($workspace.ControlName)'."
    }
    $Control = $workspace.ControlName
}

# ---------------------------------------------------------------------------
# Welcome banner
# ---------------------------------------------------------------------------
Show-SCTBanner

# ---------------------------------------------------------------------------
# Validate non-interactive identity requirements
# ---------------------------------------------------------------------------
if ($NonInteractive -and -not $ControlProfilePath) {
    throw "-ControlProfilePath is required with -NonInteractive so configuration and results stay together."
}

Write-Host ""
if ($workspace) {
    Write-Host "  Control       : $($workspace.ControlName) [$($workspace.ControlId)]" -ForegroundColor Green
    Write-Host "  Workspace     : $($workspace.WorkspaceRoot)" -ForegroundColor DarkGray
} else {
    Write-Host "  Control       : no workspace selected" -ForegroundColor Yellow
    Write-Host "  Setup         : [M] Manage SCT -> [3] Create a control workspace" -ForegroundColor DarkGray
}
Write-Host "  Samples       : $SamplesPath" -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# Discover modules from scenarios/*/module.json
# ---------------------------------------------------------------------------
$modules = Get-SCTModules -ScenariosPath $scenariosPath

if ($modules.Count -eq 0) {
    Write-Host ""
    Write-Host "  [!] No modules found in: $scenariosPath" -ForegroundColor Red
    Write-Host "  [!] Each module folder needs a module.json file." -ForegroundColor Red
    Write-Host "  [!] See docs/guides/project-structure.md -> 'Adding a module'." -ForegroundColor Red
    Write-Host ""
    exit 1
}

if ($workspace) {
    [void](Sync-SCTWorkspaceCatalogs -ScenariosPath $scenariosPath -WorkspaceRoot $workspace.WorkspaceRoot)
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
        -ResultsPath (Get-SCTModuleResultsPath -WorkspaceRoot $workspace.WorkspaceRoot -ModuleId $targetModule[0].id) `
        -StartDelaySeconds $StartDelaySeconds `
        -InterTechniqueDelaySeconds $InterTechniqueDelaySeconds)
    exit 0
}

if ($RunModule) {
    throw "-RunModule requires -NonInteractive. Use -ControlProfilePath <profile> -RunModule 04 -NonInteractive."
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
            if ($workspace) {
                Write-Host "  Exiting. Product workspace:" -ForegroundColor Gray
                Write-Host "  $($workspace.WorkspaceRoot)" -ForegroundColor DarkGray
            } else {
                Write-Host "  Exiting. No product workspace was selected." -ForegroundColor Gray
            }
            Write-Host ""
            exit 0
        }
        'V' {
            if (-not $workspace) {
                $selectedProfile = Select-SCTControlProfilePath -ResultsRoot $resultsRoot
                if ($selectedProfile) {
                    $workspace = Get-SCTControlWorkspace -RepoRoot $PSScriptRoot -ProfilePath $selectedProfile
                    [void](Sync-SCTWorkspaceCatalogs -ScenariosPath $scenariosPath -WorkspaceRoot $workspace.WorkspaceRoot)
                    $Control = $workspace.ControlName
                }
            }
            if ($workspace) {
                Show-SCTSummary -WorkspaceRoot $workspace.WorkspaceRoot
            }
        }
        'M' {
            $profilesBefore = @(Get-SCTControlProfilePaths -ResultsRoot $resultsRoot)
            Invoke-SCTManagementMenu -RepoRoot $PSScriptRoot
            $modules = Get-SCTModules -ScenariosPath $scenariosPath
            $profilesAfter = @(Get-SCTControlProfilePaths -ResultsRoot $resultsRoot)
            $newProfiles = @($profilesAfter | Where-Object { $profilesBefore -notcontains $_ })
            if ($newProfiles.Count -eq 1) {
                $workspace = Get-SCTControlWorkspace -RepoRoot $PSScriptRoot -ProfilePath $newProfiles[0]
                [void](Sync-SCTWorkspaceCatalogs -ScenariosPath $scenariosPath -WorkspaceRoot $workspace.WorkspaceRoot)
                $Control = $workspace.ControlName
                Write-Host "  Active workspace: $($workspace.ControlName) [$($workspace.ControlId)]" -ForegroundColor Green
            } elseif ($workspace -and (Test-Path -LiteralPath $workspace.ProfilePath)) {
                $workspace = Get-SCTControlWorkspace -RepoRoot $PSScriptRoot -ProfilePath $workspace.ProfilePath
                [void](Sync-SCTWorkspaceCatalogs -ScenariosPath $scenariosPath -WorkspaceRoot $workspace.WorkspaceRoot)
                $Control = $workspace.ControlName
            }
        }
        'C' {
            $selectedProfile = Select-SCTControlProfilePath -ResultsRoot $resultsRoot
            if ($selectedProfile) {
                $workspace = Get-SCTControlWorkspace -RepoRoot $PSScriptRoot -ProfilePath $selectedProfile
                [void](Sync-SCTWorkspaceCatalogs -ScenariosPath $scenariosPath -WorkspaceRoot $workspace.WorkspaceRoot)
                $Control = $workspace.ControlName
                Write-Host "  Active workspace: $($workspace.ControlName) [$($workspace.ControlId)]" -ForegroundColor Green
            }
        }
        default {
            $idx = $choice -as [int]
            if ($idx -ge 1 -and $idx -le $modules.Count) {
                if (-not $workspace) {
                    $selectedProfile = Select-SCTControlProfilePath -ResultsRoot $resultsRoot
                    if ($selectedProfile) {
                        $workspace = Get-SCTControlWorkspace -RepoRoot $PSScriptRoot -ProfilePath $selectedProfile
                        [void](Sync-SCTWorkspaceCatalogs -ScenariosPath $scenariosPath -WorkspaceRoot $workspace.WorkspaceRoot)
                        $Control = $workspace.ControlName
                    }
                }
                if (-not $workspace) {
                    continue
                }
                Invoke-SCTModuleMenu -Module $modules[$idx - 1] `
                    -Control $Control `
                    -SamplesPath $SamplesPath `
                    -ScenarioRoot $scenariosPath `
                    -ResultsPath (Get-SCTModuleResultsPath -WorkspaceRoot $workspace.WorkspaceRoot `
                        -ModuleId $modules[$idx - 1].id)
            } else {
                Write-Host "  Invalid selection. Enter 1-$($modules.Count), [C], [M], [V], or [Q]." -ForegroundColor Yellow
                Start-Sleep -Milliseconds 600
            }
        }
    }
}
