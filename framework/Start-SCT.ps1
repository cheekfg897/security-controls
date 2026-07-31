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
    Selects a product workspace through its
    results\<control-id>\<control-id>-control-profile.json.
    Required with -NonInteractive. Interactive runs without this parameter
    create a named draft session and let the operator decide whether to create
    a control profile before or after running tests.

.PARAMETER SamplesPath
    Override the default samples/ folder used for malware ZIP archives.
    Defaults to <framework-root>\samples\.

.EXAMPLE
    .\Start-SCT.ps1

.EXAMPLE
    .\Start-SCT.ps1 -ControlProfilePath .\results\sentinelone\sentinelone-control-profile.json

.EXAMPLE
    .\Start-SCT.ps1 -ControlProfilePath .\results\sentinelone\sentinelone-control-profile.json `
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

function Read-SCTSessionName {
    while ($true) {
        $value = (Read-Host '  Session name (required)').Trim()
        if ($value) { return $value }
        Write-Host "  Enter a name for this test session." -ForegroundColor Yellow
    }
}

function Read-SCTYesNo {
    param([Parameter(Mandatory)] [string]$Prompt)

    while ($true) {
        $value = (Read-Host "$Prompt [y/N]").Trim()
        if (-not $value -or $value -match '^(n|no)$') { return $false }
        if ($value -match '^(y|yes)$') { return $true }
        Write-Host '  Enter Y or N.' -ForegroundColor Yellow
    }
}

function Complete-SCTDraftProfile {
    param([Parameter(Mandatory)] $DraftWorkspace)

    if (-not $DraftWorkspace.IsDraft) { return $DraftWorkspace }

    Invoke-SCTRepositoryTool -RepoRoot $PSScriptRoot -Tool 'SetupControl' -Arguments @(
        '-ResultsRoot', $resultsRoot,
        '-ScenariosPath', $scenariosPath,
        '-ControlId', $DraftWorkspace.ControlId,
        '-DisplayName', $DraftWorkspace.ControlName,
        '-PreserveExistingResults'
    )

    $profilePath = Get-SCTControlProfilePath `
        -WorkspaceRoot $DraftWorkspace.WorkspaceRoot `
        -ControlId $DraftWorkspace.ControlId
    if (-not (Test-Path -LiteralPath $profilePath -PathType Leaf)) {
        throw "The control profile was not created: $profilePath"
    }
    return (Get-SCTControlWorkspace -RepoRoot $PSScriptRoot -ProfilePath $profilePath)
}

$workspace = $null
if ($ControlProfilePath) {
    $workspace = Get-SCTControlWorkspace -RepoRoot $PSScriptRoot -ProfilePath $ControlProfilePath
} else {
    $availableProfiles = @(Get-SCTControlProfilePaths -ResultsRoot $resultsRoot)
    if ($Control) {
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
} else {
    # A deprecated free-text -Control value is not a selected configuration.
    $Control = $null
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

if (-not $workspace) {
    Write-Host ""
    Write-Host "  Start a test session" -ForegroundColor Cyan
    Write-Host "  A control profile is optional while running tests." -ForegroundColor White
    Write-Host "  You can create it now, later from [N] on the Main Menu, or before exiting." -ForegroundColor White
    Write-Host ""

    $sessionName = Read-SCTSessionName
    $workspace = New-SCTDraftWorkspace -ResultsRoot $resultsRoot -SessionName $sessionName
    $Control = $workspace.ControlName

    Write-Host ""
    Write-Host "  Draft session created: $($workspace.ControlName) [$($workspace.ControlId)]" -ForegroundColor Green
    Write-Host "  Results will be saved under: $($workspace.WorkspaceRoot)" -ForegroundColor DarkGray
    if (Read-SCTYesNo -Prompt '  Create a new control profile for this session now?') {
        try {
            $workspace = Complete-SCTDraftProfile -DraftWorkspace $workspace
            $Control = $workspace.ControlName
            Write-Host "  Profile created for this session." -ForegroundColor Green
        } catch {
            Write-Host "  Profile was not created: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  Continuing with the draft session; existing results will still be saved." -ForegroundColor White
        }
    } else {
        Write-Host "  Continuing without a profile. Choose [N] whenever you are ready to create one." -ForegroundColor Yellow
    }
}

Write-Host ""
if ($workspace.IsDraft) {
    Write-Host "  Session       : $($workspace.SessionName) [$($workspace.ControlId)]" -ForegroundColor Green
    Write-Host "  Profile       : not created (draft session)" -ForegroundColor Yellow
    Write-Host "  Workspace     : $($workspace.WorkspaceRoot)" -ForegroundColor DarkGray
} elseif ($workspace) {
    Write-Host "  Session       : $($workspace.SessionName)" -ForegroundColor Green
    Write-Host "  Configuration : $($workspace.ControlName) [$($workspace.ControlId)]" -ForegroundColor Green
    Write-Host "  Workspace     : $($workspace.WorkspaceRoot)" -ForegroundColor DarkGray
} else {
    $startupConfigurationCount = @(Get-SCTControlProfilePaths -ResultsRoot $resultsRoot).Count
    Write-Host "  Configuration : none selected - required before a module can run" -ForegroundColor Yellow
    if ($startupConfigurationCount -gt 0) {
        Write-Host "  Next step     : choose [C] to select one of $startupConfigurationCount existing configuration(s)" -ForegroundColor White
    } else {
        Write-Host "  Next step     : choose [N] to create a configuration" -ForegroundColor White
    }
    Write-Host "                  Only display name is required; press Enter to skip optional fields." -ForegroundColor White
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
    $configurationCount = @(Get-SCTControlProfilePaths -ResultsRoot $resultsRoot).Count
    Show-SCTMainMenu -Modules $modules -SessionName $workspace.SessionName -Control $Control `
        -DraftSession:$workspace.IsDraft -ConfigurationCount $configurationCount

    $choice = (Read-Host "  Selection").Trim()

    if (-not $choice) { continue }

    switch ($choice.ToUpper()) {
        'Q' {
            Write-Host ""
            if ($workspace.IsDraft -and
                @(Get-SCTWorkspaceResultPaths -WorkspaceRoot $workspace.WorkspaceRoot).Count -gt 0 -and
                (Read-SCTYesNo -Prompt '  This draft has results. Create its control profile before exiting?')) {
                try {
                    $workspace = Complete-SCTDraftProfile -DraftWorkspace $workspace
                    $Control = $workspace.ControlName
                    Write-Host "  Profile created for this session." -ForegroundColor Green
                } catch {
                    Write-Host "  Profile was not created: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
            if ($workspace.IsDraft) {
                Write-Host "  Exiting. Draft session results:" -ForegroundColor Gray
                Write-Host "  $($workspace.WorkspaceRoot)" -ForegroundColor DarkGray
                Write-Host "  This draft has no control profile and cannot be packaged yet." -ForegroundColor Yellow
            } elseif ($workspace) {
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
            } elseif (-not $workspace.IsDraft -and (Test-Path -LiteralPath $workspace.ProfilePath)) {
                $workspace = Get-SCTControlWorkspace -RepoRoot $PSScriptRoot -ProfilePath $workspace.ProfilePath
                [void](Sync-SCTWorkspaceCatalogs -ScenariosPath $scenariosPath -WorkspaceRoot $workspace.WorkspaceRoot)
                $Control = $workspace.ControlName
            }
        }
        'N' {
            try {
                if ($workspace.IsDraft) {
                    $workspace = Complete-SCTDraftProfile -DraftWorkspace $workspace
                    $selectedProfile = $workspace.ProfilePath
                } else {
                    $profilesBefore = @(Get-SCTControlProfilePaths -ResultsRoot $resultsRoot)
                    Invoke-SCTRepositoryTool -RepoRoot $PSScriptRoot -Tool 'SetupControl'
                    $profilesAfter = @(Get-SCTControlProfilePaths -ResultsRoot $resultsRoot)
                    $newProfiles = @($profilesAfter | Where-Object { $profilesBefore -notcontains $_ })
                    $selectedProfile = if ($newProfiles.Count -eq 1) {
                        $newProfiles[0]
                    } elseif ($profilesAfter.Count -gt 0) {
                        Select-SCTControlProfilePath -ResultsRoot $resultsRoot
                    } else {
                        $null
                    }
                }
                if ($selectedProfile) {
                    $workspace = Get-SCTControlWorkspace -RepoRoot $PSScriptRoot -ProfilePath $selectedProfile
                    [void](Sync-SCTWorkspaceCatalogs -ScenariosPath $scenariosPath -WorkspaceRoot $workspace.WorkspaceRoot)
                    $Control = $workspace.ControlName
                    Write-Host "  Active configuration: $($workspace.ControlName) [$($workspace.ControlId)]" -ForegroundColor Green
                }
            } catch {
                Write-Host "  Configuration was not created: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        'C' {
            $selectedProfile = Select-SCTControlProfilePath -ResultsRoot $resultsRoot
            if ($selectedProfile) {
                $workspace = Get-SCTControlWorkspace -RepoRoot $PSScriptRoot -ProfilePath $selectedProfile
                [void](Sync-SCTWorkspaceCatalogs -ScenariosPath $scenariosPath -WorkspaceRoot $workspace.WorkspaceRoot)
                $Control = $workspace.ControlName
                Write-Host "  Active configuration: $($workspace.ControlName) [$($workspace.ControlId)]" -ForegroundColor Green
            }
        }
        default {
            $idx = $choice -as [int]
            if ($idx -ge 1 -and $idx -le $modules.Count) {
                if (-not $workspace) {
                    Write-Host ""
                    Write-Host "  A configuration is required before this module can run." -ForegroundColor Yellow
                    Write-Host "  Select an existing configuration below, or cancel and choose [N] to create one." -ForegroundColor White
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
                Write-Host "  Invalid selection. Enter 1-$($modules.Count), [C], [N], [M], [V], or [Q]." -ForegroundColor Yellow
                Start-Sleep -Milliseconds 600
            }
        }
    }
}
