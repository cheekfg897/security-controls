# core/SCT-Core.ps1
# Shared helper functions for Start-SCT.ps1
# Do not run this file directly - it is dot-sourced by Start-SCT.ps1

Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'SCT-Results.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\common\SCT-ReviewHelpers.ps1')

# =============================================================================
# BANNER
# =============================================================================

function Show-SCTBanner {
    Clear-Host
    Write-Host ""
    Write-Host "  +============================================================================+" -ForegroundColor Cyan
    Write-Host "  |                                                                            |" -ForegroundColor Cyan
    Write-Host "  |   SECURITY CONTROLS TESTING FRAMEWORK  (SCT)                              |" -ForegroundColor Cyan
    Write-Host "  |   Endpoint Detection & Prevention Evaluation  |  MITRE ATT&CK Mapped      |" -ForegroundColor Cyan
    Write-Host "  |   Platform: Windows 10 / 11  |  PowerShell 5.1+  |  Isolated VM Only     |" -ForegroundColor Cyan
    Write-Host "  |                                                                            |" -ForegroundColor Cyan
    Write-Host "  +============================================================================+" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  !! WARNING: Run inside an isolated lab VM only. Never run on production systems. !!" -ForegroundColor Red
    Write-Host ""
}

# =============================================================================
# MODULE DISCOVERY
# =============================================================================

function Get-SCTPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $InputObject,
        [Parameter(Mandatory)] [string]$Name,
        $Default = $null
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $Default
}

function Get-SCTModuleErrors {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Module,
        [Parameter(Mandatory)] [string]$ModuleDir
    )

    $errors = @()
    $moduleFields = @('id', 'name', 'description', 'techniques')
    $techniqueFields = @('id', 'name', 'description', 'attack_id', 'script', 'subtests', 'server_subtests', 'status')

    foreach ($property in $Module.PSObject.Properties.Name) {
        if ($moduleFields -notcontains $property) {
            $errors += "Unknown module field '$property'."
        }
    }

    foreach ($required in @('id', 'name', 'techniques')) {
        $value = Get-SCTPropertyValue -InputObject $Module -Name $required
        if ($null -eq $value -or ($value -is [string] -and [string]::IsNullOrWhiteSpace($value))) {
            $errors += "Missing required module field '$required'."
        }
    }

    $moduleId = [string](Get-SCTPropertyValue -InputObject $Module -Name 'id' -Default '')
    if ($moduleId -and $moduleId -notmatch '^\d{2}$') {
        $errors += "Module id '$moduleId' must contain two digits, for example '04'."
    }

    # Windows PowerShell 5.1 collapses single-element JSON arrays, so values
    # are normalized with @() instead of validating the deserialized CLR type.
    $techniquesValue = Get-SCTPropertyValue -InputObject $Module -Name 'techniques' -Default @()
    $techniques = @($techniquesValue)
    if ($techniques.Count -eq 0) {
        $errors += "Module '$moduleId' must define at least one technique."
    }

    $seenIds = @{}
    foreach ($technique in $techniques) {
        if ($null -eq $technique) {
            $errors += "Module '$moduleId' contains a null technique entry."
            continue
        }

        $techniqueId = [string](Get-SCTPropertyValue -InputObject $technique -Name 'id' -Default '')
        foreach ($property in $technique.PSObject.Properties.Name) {
            if ($techniqueFields -notcontains $property) {
                $errors += "Technique '$techniqueId' has unknown field '$property'."
            }
        }

        foreach ($required in @('id', 'name', 'attack_id', 'script')) {
            $value = Get-SCTPropertyValue -InputObject $technique -Name $required
            if ($null -eq $value -or ($value -is [string] -and [string]::IsNullOrWhiteSpace($value))) {
                $errors += "A technique is missing required field '$required'."
            }
        }

        if ($techniqueId -and $techniqueId -notmatch '^\d+\.\d+$') {
            $errors += "Technique id '$techniqueId' must use module.technique notation, for example '4.1'."
        } elseif ($techniqueId -and $moduleId -match '^\d{2}$' -and ([int]($techniqueId -split '\.')[0]) -ne [int]$moduleId) {
            $errors += "Technique id '$techniqueId' does not belong to Module '$moduleId'."
        }
        if ($seenIds.ContainsKey($techniqueId)) {
            $errors += "Technique id '$techniqueId' is duplicated."
        } else {
            $seenIds[$techniqueId] = $true
        }

        $status = [string](Get-SCTPropertyValue -InputObject $technique -Name 'status' -Default '')
        if ($status -and $status -ne 'planned') {
            $errors += "Technique '$techniqueId' has invalid status '$status'. Omit status when ready, or use 'planned'."
        }

        $attackId = [string](Get-SCTPropertyValue -InputObject $technique -Name 'attack_id' -Default '')
        if ($attackId -and $attackId -notmatch '^T\d{4}(\.\d{3})?$') {
            $errors += "Technique '$techniqueId' has invalid ATT&CK id '$attackId'."
        }

        $subtestsValue = Get-SCTPropertyValue -InputObject $technique -Name 'subtests' -Default @()
        $serverSubtestsValue = Get-SCTPropertyValue -InputObject $technique -Name 'server_subtests' -Default @()
        $subtests = @($subtestsValue)
        $serverSubtests = @($serverSubtestsValue)
        $seenSubtests = @{}
        foreach ($subtest in $subtests) {
            if ([string]::IsNullOrWhiteSpace([string]$subtest)) {
                $errors += "Technique '$techniqueId' contains an empty subtest name."
                continue
            }
            if ([string]$subtest -in @('All', 'AllLocal', 'AllRemote')) {
                $errors += "Technique '$techniqueId' must not list '$subtest'; the launcher adds run-all choices automatically."
            }
            if ($seenSubtests.ContainsKey([string]$subtest)) {
                $errors += "Technique '$techniqueId' contains duplicate subtest '$subtest'."
            } else {
                $seenSubtests[[string]$subtest] = $true
            }
        }
        $seenServerSubtests = @{}
        foreach ($subtest in $serverSubtests) {
            if ($subtests -notcontains $subtest) {
                $errors += "Technique '$techniqueId' server_subtest '$subtest' is not listed in subtests."
            }
            if ($seenServerSubtests.ContainsKey([string]$subtest)) {
                $errors += "Technique '$techniqueId' contains duplicate server_subtest '$subtest'."
            } else {
                $seenServerSubtests[[string]$subtest] = $true
            }
        }

        $script = [string](Get-SCTPropertyValue -InputObject $technique -Name 'script' -Default '')
        $scriptPath = $null
        if ($script) {
            if ([IO.Path]::IsPathRooted($script)) {
                $errors += "Technique '$techniqueId' script path must be relative to the module folder: $script"
            } elseif ([IO.Path]::GetExtension($script) -ne '.ps1') {
                $errors += "Technique '$techniqueId' script path must end in .ps1: $script"
            } else {
                $moduleRoot = [IO.Path]::GetFullPath($ModuleDir).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
                $scriptPath = [IO.Path]::GetFullPath((Join-Path $ModuleDir $script))
                if (-not $scriptPath.StartsWith($moduleRoot, [StringComparison]::OrdinalIgnoreCase)) {
                    $errors += "Technique '$techniqueId' script path escapes the module folder: $script"
                    $scriptPath = $null
                }
            }
        }

        if ($status -ne 'planned') {
            if ($scriptPath -and -not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
                $errors += "Technique '$techniqueId' script was not found: $script"
            } elseif ($scriptPath -and $subtests.Count -gt 0) {
                if (-not (Test-SCTScriptSupportsParameter -ScriptPath $scriptPath -ParameterName 'Subtest')) {
                    $errors += "Technique '$techniqueId' defines subtests, but its script does not accept -Subtest."
                } else {
                    $allowedSubtests = @(Get-SCTScriptValidateSetValues -ScriptPath $scriptPath -ParameterName 'Subtest')
                    if ($allowedSubtests.Count -eq 0) {
                        $errors += "Technique '$techniqueId' script must apply ValidateSet to -Subtest."
                    } else {
                        foreach ($subtest in @($subtests) + @('All')) {
                            if ($allowedSubtests -notcontains $subtest) {
                                $errors += "Technique '$techniqueId' script ValidateSet is missing subtest '$subtest'."
                            }
                        }
                        if ($serverSubtests.Count -gt 0 -and $allowedSubtests -notcontains 'AllRemote') {
                            $errors += "Technique '$techniqueId' script ValidateSet is missing 'AllRemote'."
                        }
                        $localSubtests = @($subtests | Where-Object { $serverSubtests -notcontains $_ })
                        if ($serverSubtests.Count -gt 0 -and $localSubtests.Count -gt 0 -and $allowedSubtests -notcontains 'AllLocal') {
                            $errors += "Technique '$techniqueId' script ValidateSet is missing 'AllLocal'."
                        }
                    }
                }
                if ($serverSubtests.Count -gt 0) {
                    foreach ($parameter in @('ServerIP', 'Port')) {
                        if (-not (Test-SCTScriptSupportsParameter -ScriptPath $scriptPath -ParameterName $parameter)) {
                            $errors += "Technique '$techniqueId' has server_subtests, but its script does not accept -$parameter."
                        }
                    }
                }
            }
        }
    }

    return $errors
}

function Get-SCTModules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScenariosPath
    )

    $modules = @()

    if (-not (Test-Path $ScenariosPath)) {
        Write-Warning "Scenarios path not found: $ScenariosPath"
        return $modules
    }

    $dirs = Get-ChildItem -Path $ScenariosPath -Directory | Sort-Object Name

    foreach ($dir in $dirs) {
        $jsonFile = Join-Path $dir.FullName 'module.json'
        if (-not (Test-Path $jsonFile)) { continue }

        try {
            $raw    = Get-Content -Path $jsonFile -Raw -Encoding UTF8
            $module = $raw | ConvertFrom-Json

            $moduleErrors = @(Get-SCTModuleErrors -Module $module -ModuleDir $dir.FullName)
            if ($moduleErrors.Count -gt 0) {
                foreach ($message in $moduleErrors) {
                    Write-Warning "$($dir.Name)/module.json: $message"
                }
                continue
            }

            # Runtime-only path used to resolve technique scripts.
            $module | Add-Member -NotePropertyName 'ScriptDir' `
                -NotePropertyValue $dir.FullName -Force

            $modules += $module
        } catch {
            Write-Warning "Could not load module.json in '$($dir.Name)': $($_.Exception.Message)"
        }
    }

    return $modules
}

# =============================================================================
# MAIN MENU
# =============================================================================

function Show-SCTMainMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$Modules,
        [string]$Control,
        [ValidateRange(0, 2147483647)]
        [int]$ConfigurationCount = 0
    )

    Write-Host ""
    Write-Host "  +----------------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |  MAIN MENU                                                                 |" -ForegroundColor Cyan
    if ($Control) {
        $tag = "  |  Control : $Control"
        Write-Host ($tag.PadRight(77) + '|') -ForegroundColor Cyan
    }
    Write-Host "  +----------------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
    if (-not $Control) {
        Write-Host "  [!] CONFIGURATION REQUIRED BEFORE A MODULE CAN RUN" -ForegroundColor Yellow
        if ($ConfigurationCount -gt 0) {
            Write-Host "      Choose [C] to select one of $ConfigurationCount existing configuration(s)." -ForegroundColor White
        } else {
            Write-Host "      No existing configurations were found." -ForegroundColor White
        }
        Write-Host "      Choose [N] to create one; only a display name is required." -ForegroundColor White
        Write-Host "      During setup, press Enter to skip any optional field." -ForegroundColor White
        Write-Host ""
    }
    Write-Host "  What would you like to do?" -ForegroundColor White
    Write-Host ""

    for ($i = 0; $i -lt $Modules.Count; $i++) {
        $m              = $Modules[$i]
        $techniqueCount = @($m.techniques).Count
        $countLabel     = "($techniqueCount techniques)"
        $label          = "[$($i + 1)]"
        Write-Host ("  {0,-5} {1,-45} {2}" -f $label, $m.name, $countLabel) -ForegroundColor White
        $description = Get-SCTPropertyValue -InputObject $m -Name 'description' -Default ''
        if ($description) { Write-Host ("        $description") -ForegroundColor DarkGray }
        Write-Host ""
    }

    $configurationAction = if ($Control) { 'Select or switch configuration' } else { 'Select existing configuration' }
    Write-Host "  [C]   $configurationAction ($ConfigurationCount available)" -ForegroundColor Yellow
    Write-Host "  [N]   Create new configuration" -ForegroundColor Yellow
    Write-Host "        Only display name is required; press Enter to skip optional fields." -ForegroundColor Gray
    Write-Host "  [M]   Manage SCT" -ForegroundColor Yellow
    Write-Host "  [V]   View Results Summary" -ForegroundColor Yellow
    Write-Host "  [Q]   Quit" -ForegroundColor Yellow
    Write-Host ""
}

function Get-SCTControlProfilePaths {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$ResultsRoot)

    if (-not (Test-Path -LiteralPath $ResultsRoot -PathType Container)) { return @() }
    return @(
        Get-ChildItem -LiteralPath $ResultsRoot -Directory |
            ForEach-Object { Join-Path $_.FullName 'control-profile.json' } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Sort-Object
    )
}

function Get-SCTControlWorkspace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RepoRoot,
        [Parameter(Mandatory)] [string]$ProfilePath
    )

    $resolvedProfilePath = (Resolve-Path -LiteralPath $ProfilePath -ErrorAction Stop).Path
    try {
        $profile = Get-Content -LiteralPath $resolvedProfilePath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "Could not read control profile '$resolvedProfilePath': $($_.Exception.Message)"
    }

    $control = Get-SCTPropertyValue -InputObject $profile -Name 'control'
    if ($null -eq $control) {
        throw "Control profile '$resolvedProfilePath' is missing its control object."
    }
    $controlId = [string](Get-SCTPropertyValue -InputObject $control -Name 'id' -Default '')
    $controlName = [string](Get-SCTPropertyValue -InputObject $control -Name 'display_name' -Default '')
    if ($controlId -notmatch '^[a-z0-9][a-z0-9._-]*$' -or -not $controlName) {
        throw "Control profile '$resolvedProfilePath' is missing a valid control id or display name."
    }

    $resultsRoot = [IO.Path]::GetFullPath((Join-Path $RepoRoot 'results'))
    $expectedProfilePath = [IO.Path]::GetFullPath(
        (Join-Path (Join-Path $resultsRoot $controlId) 'control-profile.json')
    )
    if (-not $resolvedProfilePath.Equals($expectedProfilePath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Control profile '$resolvedProfilePath' must be stored at '$expectedProfilePath'."
    }

    $workspaceRoot = Split-Path $resolvedProfilePath -Parent
    Assert-SCTWorkspaceUsesModuleFiles -WorkspaceRoot $workspaceRoot -ControlProfilePath $resolvedProfilePath
    return [pscustomobject]@{
        ControlId       = $controlId
        ControlName     = $controlName
        ProfilePath     = $resolvedProfilePath
        WorkspaceRoot   = $workspaceRoot
    }
}

function Select-SCTControlProfilePath {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$ResultsRoot)

    $profilePaths = @(Get-SCTControlProfilePaths -ResultsRoot $ResultsRoot)
    if ($profilePaths.Count -eq 0) {
        Write-Host ""
        Write-Host "  No existing configurations were found." -ForegroundColor Yellow
        Write-Host "  Use [N] Create New Configuration on the Main Menu." -ForegroundColor White
        Write-Host "  Only a display name is required; press Enter to skip optional setup fields." -ForegroundColor White
        return $null
    }

    Write-Host ""
    Write-Host "  Select an existing configuration:" -ForegroundColor White
    for ($index = 0; $index -lt $profilePaths.Count; $index++) {
        $label = Split-Path (Split-Path $profilePaths[$index] -Parent) -Leaf
        try {
            $profile = Get-Content -LiteralPath $profilePaths[$index] -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($profile.control.display_name) { $label = "$($profile.control.display_name) [$label]" }
        } catch {
            $label = "$label (invalid profile)"
        }
        Write-Host ("  [{0}]  {1}" -f ($index + 1), $label) -ForegroundColor White
    }
    Write-Host "  [0]  Cancel" -ForegroundColor Yellow

    while ($true) {
        $choice = (Read-Host "`n  Existing configuration").Trim()
        if (-not $choice -or $choice -eq '0') { return $null }
        $selectedIndex = $choice -as [int]
        if ($selectedIndex -ge 1 -and $selectedIndex -le $profilePaths.Count) {
            return $profilePaths[$selectedIndex - 1]
        }
        Write-Host "  Invalid configuration selection. Enter 1-$($profilePaths.Count), or 0 to cancel." -ForegroundColor Yellow
    }
}

function Get-SCTRepositoryToolPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RepoRoot,
        [Parameter(Mandatory)]
        [ValidateSet(
            'AddModule', 'DescribeModuleTests', 'SetupControl', 'BuildPackage',
            'ComparePackages', 'CheckControlProfile', 'CheckModules', 'CheckResults',
            'CheckTestDescriptions'
        )]
        [string]$Tool
    )

    if ($Tool -eq 'ComparePackages') {
        $repositoryRoot = Split-Path -Path $RepoRoot -Parent
        return Join-Path $repositoryRoot 'ai-system\scripts\Compare-SCTControls.ps1'
    }

    $relativePath = switch ($Tool) {
        'AddModule'             { 'scripts\authoring\Add-SCTModule.ps1' }
        'DescribeModuleTests'   { 'scripts\authoring\Describe-SCTModuleTests.ps1' }
        'SetupControl'          { 'scripts\review\Setup-SCTControl.ps1' }
        'BuildPackage'          { 'scripts\review\Build-SCTComparisonPackage.ps1' }
        'CheckControlProfile'   { 'scripts\validation\Check-SCTControlProfile.ps1' }
        'CheckModules'          { 'scripts\validation\Check-SCTModules.ps1' }
        'CheckResults'          { 'scripts\validation\Check-SCTResults.ps1' }
        'CheckTestDescriptions' { 'scripts\validation\Check-SCTTestDescriptions.ps1' }
    }

    return Join-Path $RepoRoot $relativePath
}

function Invoke-SCTRepositoryTool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RepoRoot,
        [Parameter(Mandatory)] [string]$Tool,
        [object[]]$Arguments = @()
    )

    $scriptPath = Get-SCTRepositoryToolPath -RepoRoot $RepoRoot -Tool $Tool
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw "SCT tool is missing: $scriptPath"
    }

    $hostExecutable = (Get-Process -Id $PID).Path
    Push-Location -LiteralPath $RepoRoot
    try {
        & $hostExecutable -NoProfile -ExecutionPolicy Bypass -File $scriptPath @Arguments
        $exitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    if ($exitCode -ne 0) {
        throw "SCT tool '$Tool' exited with code $exitCode."
    }
}

function Select-SCTModulePath {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$ScenariosPath)

    $moduleFiles = @(Get-ChildItem -LiteralPath $ScenariosPath -Filter 'module.json' -File -Recurse | Sort-Object FullName)
    if ($moduleFiles.Count -eq 0) {
        Write-Host "  No module.json files found under $ScenariosPath." -ForegroundColor Yellow
        return $null
    }

    Write-Host ""
    for ($index = 0; $index -lt $moduleFiles.Count; $index++) {
        $moduleFile = $moduleFiles[$index]
        $label = $moduleFile.Directory.Name
        try {
            $metadata = Get-Content -LiteralPath $moduleFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($metadata.name) { $label = "$($metadata.id) $($metadata.name)" }
        } catch {
            $label = "$label (invalid JSON)"
        }
        Write-Host ("  [{0}]  {1}" -f ($index + 1), $label) -ForegroundColor White
    }
    Write-Host "  [0]  Cancel" -ForegroundColor Yellow

    $choice = (Read-Host "`n  Module").Trim()
    if (-not $choice -or $choice -eq '0') { return $null }
    $selectedIndex = $choice -as [int]
    if ($selectedIndex -ge 1 -and $selectedIndex -le $moduleFiles.Count) {
        return $moduleFiles[$selectedIndex - 1].FullName
    }

    Write-Host "  Invalid module selection." -ForegroundColor Yellow
    return $null
}

function Invoke-SCTManagementMenu {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$RepoRoot)

    $scenariosPath = Join-Path $RepoRoot 'scenarios'
    $resultsRoot = Join-Path $RepoRoot 'results'

    while ($true) {
        Write-Host ""
        Write-Host "  +----------------------------------------------------------------------------+" -ForegroundColor Magenta
        Write-Host "  |  MANAGE SCT                                                                |" -ForegroundColor Magenta
        Write-Host "  +----------------------------------------------------------------------------+" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "  Authoring" -ForegroundColor Cyan
        Write-Host "  [1]  Add a new SCT module" -ForegroundColor White
        Write-Host "  [2]  Add or repair a module's test descriptions" -ForegroundColor White
        Write-Host ""
        Write-Host "  Product workflow" -ForegroundColor Cyan
        Write-Host "  [3]  Create or update a control configuration/workspace" -ForegroundColor Yellow
        Write-Host "       Only display name is required; press Enter to skip optional fields." -ForegroundColor Gray
        Write-Host "  [4]  Check completed module results" -ForegroundColor White
        Write-Host "  [5]  Build comparison ZIP" -ForegroundColor White
        Write-Host "  [6]  Compare two or more result ZIPs" -ForegroundColor White
        Write-Host ""
        Write-Host "  Repository validation" -ForegroundColor Cyan
        Write-Host "  [7]  Check modules and test descriptions" -ForegroundColor White
        Write-Host "  [8]  Check a control profile" -ForegroundColor White
        Write-Host ""
        Write-Host "  [0]  Back to Main Menu" -ForegroundColor Yellow
        Write-Host ""

        $choice = (Read-Host "  Selection").Trim()
        if (-not $choice -or $choice -eq '0') { return }

        $ranTool = $false
        try {
            switch ($choice) {
                '1' {
                    Invoke-SCTRepositoryTool -RepoRoot $RepoRoot -Tool 'AddModule'
                    $ranTool = $true
                }
                '2' {
                    $modulePath = Select-SCTModulePath -ScenariosPath $scenariosPath
                    if ($modulePath) {
                        Invoke-SCTRepositoryTool -RepoRoot $RepoRoot -Tool 'DescribeModuleTests' `
                            -Arguments @('-ModulePath', $modulePath)
                        $ranTool = $true
                    }
                }
                '3' {
                    Invoke-SCTRepositoryTool -RepoRoot $RepoRoot -Tool 'SetupControl'
                    $ranTool = $true
                }
                '4' {
                    $profilePath = Select-SCTControlProfilePath -ResultsRoot $resultsRoot
                    if ($profilePath) {
                        Invoke-SCTRepositoryTool -RepoRoot $RepoRoot -Tool 'CheckResults' `
                            -Arguments @('-ControlProfilePath', $profilePath)
                        $ranTool = $true
                    }
                }
                '5' {
                    $profilePath = Select-SCTControlProfilePath -ResultsRoot $resultsRoot
                    if ($profilePath) {
                        Invoke-SCTRepositoryTool -RepoRoot $RepoRoot -Tool 'BuildPackage' `
                            -Arguments @('-ControlProfilePath', $profilePath, '-Force')
                        $ranTool = $true
                    }
                }
                '6' {
                    Invoke-SCTRepositoryTool -RepoRoot $RepoRoot -Tool 'ComparePackages'
                    $ranTool = $true
                }
                '7' {
                    Invoke-SCTRepositoryTool -RepoRoot $RepoRoot -Tool 'CheckModules'
                    Invoke-SCTRepositoryTool -RepoRoot $RepoRoot -Tool 'CheckTestDescriptions'
                    $ranTool = $true
                }
                '8' {
                    $profilePath = Select-SCTControlProfilePath -ResultsRoot $resultsRoot
                    if ($profilePath) {
                        Invoke-SCTRepositoryTool -RepoRoot $RepoRoot -Tool 'CheckControlProfile' `
                            -Arguments @('-Path', $profilePath)
                        $ranTool = $true
                    }
                }
                default {
                    Write-Host "  Invalid selection. Enter 0-8." -ForegroundColor Yellow
                }
            }
        } catch {
            Write-Host ""
            Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red
            $ranTool = $true
        }

        if ($ranTool) {
            [void](Read-Host "`n  Press Enter to return to Manage SCT")
        }
    }
}

# =============================================================================
# MODULE SUB-MENU + DISPATCH
# =============================================================================

function Invoke-SCTModuleMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Module,
        [Parameter(Mandatory)] [string]$Control,
        [Parameter(Mandatory)] [string]$SamplesPath,
        [Parameter(Mandatory)] [string]$ScenarioRoot,
        [Parameter(Mandatory)] [string]$ResultsPath
    )

    while ($true) {
        Write-Host ""
        Write-Host "  +----------------------------------------------------------------------------+" -ForegroundColor Magenta
        Write-Host ("  |  " + $Module.name.ToUpper()) -ForegroundColor Magenta
        Write-Host "  +----------------------------------------------------------------------------+" -ForegroundColor Magenta
        Write-Host ""

        $techniques = @($Module.techniques)

        for ($i = 0; $i -lt $techniques.Count; $i++) {
            $technique = $techniques[$i]
            $status = Get-SCTPropertyValue -InputObject $technique -Name 'status' -Default ''
            $stub   = if ($status -eq 'planned') { '  [PLANNED]' } else { '' }
            $color  = if ($status -eq 'planned') { 'DarkGray' } else { 'White' }
            Write-Host ("  [{0}]  {1}{2}" -f ($i + 1), $technique.name, $stub) -ForegroundColor $color
            $description = Get-SCTPropertyValue -InputObject $technique -Name 'description' -Default ''
            if ($description) { Write-Host ("        $description") -ForegroundColor DarkGray }
            Write-Host ("        ATT&CK: $($technique.attack_id)") -ForegroundColor DarkGray
            Write-Host ""
        }

        Write-Host "  [0]   Back to Main Menu" -ForegroundColor Yellow
        Write-Host ""

        $choice = (Read-Host "  Selection").Trim()

        if ($choice -eq '0' -or $choice -eq '') { return }

        $idx = $choice -as [int]
        if ($idx -ge 1 -and $idx -le $techniques.Count) {
            Invoke-SCTTechnique -Technique $techniques[$idx - 1] `
                -ModuleScriptDir $Module.ScriptDir `
                -Control $Control `
                -SamplesPath $SamplesPath `
                -ResultsPath $ResultsPath
        } else {
            Write-Host "  Invalid selection." -ForegroundColor Yellow
        }
    }
}

# =============================================================================
# TECHNIQUE EXECUTION DISPATCHER
# =============================================================================

function Invoke-SCTTechnique {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Technique,
        [Parameter(Mandatory)] [string]$ModuleScriptDir,
        [Parameter(Mandatory)] [string]$Control,
        [Parameter(Mandatory)] [string]$SamplesPath,
        [Parameter(Mandatory)] [string]$ResultsPath
    )

    $scriptPath = Join-Path $ModuleScriptDir $Technique.script

    Write-Host ""
    Write-Host "  ============================================================================" -ForegroundColor Cyan
    Write-Host "  TECHNIQUE $($Technique.id): $($Technique.name)" -ForegroundColor Cyan
    Write-Host "  ATT&CK: $($Technique.attack_id)" -ForegroundColor DarkGray
    Write-Host "  ============================================================================" -ForegroundColor Cyan

    $status = Get-SCTPropertyValue -InputObject $Technique -Name 'status' -Default ''
    if ($status -eq 'planned') {
        Write-Host ""
        Write-Host "  [i] This technique is planned but not yet implemented." -ForegroundColor Yellow
        Write-Host "  [i] Create the script at: $scriptPath" -ForegroundColor DarkGray
        Write-Host "  [i] Then remove 'status' from its module.json entry." -ForegroundColor DarkGray
        Read-Host "`n  Press Enter to return"
        return
    }

    if (-not (Test-Path $scriptPath)) {
        Write-Host ""
        Write-Host "  [!] Script not found: $scriptPath" -ForegroundColor Red
        Write-Host "  [!] Check the technique's 'script' path in module.json." -ForegroundColor Red
        Read-Host "`n  Press Enter to return"
        return
    }

    switch (Get-SCTTechniqueWorkflow -Technique $Technique -ScriptPath $scriptPath) {
        'subtests' {
            Invoke-SCTSubtests -Technique $Technique -ScriptPath $scriptPath -Control $Control -ResultsPath $ResultsPath
        }
        'sample-batch' {
            Invoke-SampleBatchTechnique -Technique $Technique -ScriptPath $scriptPath -Control $Control -SamplesPath $SamplesPath -ResultsPath $ResultsPath
        }
        'removable-media' {
            Invoke-RemovableMediaTechnique -Technique $Technique -ScriptPath $scriptPath -Control $Control -ResultsPath $ResultsPath
        }
        'client-server' {
            Invoke-ClientServerTechnique -Technique $Technique -ScriptPath $scriptPath -Control $Control -ResultsPath $ResultsPath
        }
        default {
            Invoke-DirectTechnique -Technique $Technique -ScriptPath $scriptPath -ResultsPath $ResultsPath
        }
    }
}

function Get-SCTTechniqueWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Technique,
        [Parameter(Mandatory)] [string]$ScriptPath
    )

    if (@(Get-SCTPropertyValue -InputObject $Technique -Name 'subtests' -Default @()).Count -gt 0) {
        return 'subtests'
    }
    if (Test-SCTScriptSupportsParameter -ScriptPath $ScriptPath -ParameterName 'SourcePath') {
        return 'sample-batch'
    }
    if (Test-SCTScriptSupportsParameter -ScriptPath $ScriptPath -ParameterName 'DriveLetter') {
        return 'removable-media'
    }
    if (Test-SCTScriptSupportsParameter -ScriptPath $ScriptPath -ParameterName 'ServerIP') {
        return 'client-server'
    }
    return 'direct'
}

# =============================================================================
# WORKFLOW: staged sample batch
# Extracts ZIPs from samples/ to C:\Temp\SCT-Staging\, including nested ZIPs
# when the operator opts in, then calls the script with -SourcePath and
# -Control. Supports -DryRun.
# =============================================================================

function Invoke-SampleBatchTechnique {
    [CmdletBinding()]
    param($Technique, [string]$ScriptPath, [string]$Control, [string]$SamplesPath, [string]$ResultsPath)

    Write-Host ""
    Write-Host "  Delivers and optionally executes malware/tool samples from the samples/ folder." -ForegroundColor White
    Write-Host "  Drop a ZIP of samples, or a ZIP containing sample ZIPs, into samples/." -ForegroundColor DarkGray
    Write-Host ""

    $stagingRoot = 'C:\Temp\SCT-Staging'
    $sourcePath  = $null

    # Discover ZIP files in samples/
    $zips = @()
    if (Test-Path $SamplesPath) {
        $zips = @(Get-ChildItem -Path $SamplesPath -Filter '*.zip' -File -ErrorAction SilentlyContinue)
    }

    if ($zips.Count -gt 0) {
        Write-Host "  ZIP archives in samples/:" -ForegroundColor White
        Write-Host ""
        for ($i = 0; $i -lt $zips.Count; $i++) {
            $sz = [math]::Round($zips[$i].Length / 1KB, 0)
            Write-Host ("  [{0}]  {1}  ({2:N0} KB)" -f ($i + 1), $zips[$i].Name, $sz) -ForegroundColor White
        }
        Write-Host ""
        if ($zips.Count -gt 1) {
            Write-Host "  [A]   Run ALL ZIPs together as one batch" -ForegroundColor Yellow
        }
        Write-Host "  [M]   Use an already-extracted folder" -ForegroundColor Yellow
        Write-Host "  [0]   Cancel" -ForegroundColor Yellow
        Write-Host ""

        $hint = if ($zips.Count -gt 1) { "(number), [A] all, [M] folder, [0] cancel" } `
                else                    { "(number), [M] folder, [0] cancel" }
        $zipChoice = (Read-Host "  Select $hint").Trim()

        if ($zipChoice -eq '0' -or $zipChoice -eq '') { return }

        if ($zipChoice -ieq 'A') {
            $zipPassword = (Read-Host "  ZIP password for all archives (press Enter if none)").Trim()
            Write-Host ""
            $sourcePath = Merge-StagingFromZips -Zips $zips -StagingRoot $stagingRoot `
                -Password $zipPassword -PromptForNestedArchives
        } elseif ($zipChoice -ieq 'M') {
            $sourcePath = (Read-Host "  Full path to already-extracted folder").Trim()
            if (-not $sourcePath) { return }
        } else {
            $zipIdx = $zipChoice -as [int]
            if ($zipIdx -ge 1 -and $zipIdx -le $zips.Count) {
                $chosenZip = $zips[$zipIdx - 1]
                $zipPassword = (Read-Host "  ZIP password (press Enter if none)").Trim()
                Write-Host ""
                try {
                    $sourcePath = Merge-StagingFromZips -Zips @($chosenZip) `
                        -StagingRoot $stagingRoot -Password $zipPassword -PromptForNestedArchives
                } catch {
                    Write-Host "  [!] Extraction failed: $($_.Exception.Message)" -ForegroundColor Red
                    Read-Host "`n  Press Enter to return"
                    return
                }
            } else {
                Write-Host "  Invalid selection." -ForegroundColor Yellow
                Read-Host "`n  Press Enter to return"
                return
            }
        }
    } else {
        Write-Host "  No ZIP files found in: $SamplesPath" -ForegroundColor Yellow
        Write-Host "  Drop ZIP files into samples/ and re-run, or enter a folder path below." -ForegroundColor DarkGray
        Write-Host ""
        $manual = (Read-Host "  Path to staging folder (or press Enter to cancel)").Trim()
        if (-not $manual) { return }
        $sourcePath = $manual
    }

    if (-not (Test-Path $sourcePath)) {
        Write-Host "  [!] Path does not exist: $sourcePath" -ForegroundColor Red
        Read-Host "`n  Press Enter to return"
        return
    }

    Write-Host ""
    $executeInput = (Read-Host "  Execute samples after delivery, not just copy them? [Y/N]").Trim()
    $doExecute    = $executeInput -ieq 'Y'

    Write-Host ""
    Write-Host "  [*] Open your EDR/AV console and start monitoring before proceeding." -ForegroundColor Yellow
    Read-Host "  Press Enter to start"

    $scriptArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"",
        '-SourcePath', "`"$sourcePath`"",
        '-Control', "`"$Control`"",
        '-ResultsPath', "`"$ResultsPath`""
    )
    if ($doExecute) { $scriptArgs += '-Execute' }

    Write-Host ""
    Write-Host "  [>] Launching: $ScriptPath" -ForegroundColor Cyan
    Write-Host ""

    Start-Process -FilePath 'powershell.exe' -ArgumentList $scriptArgs -Wait -NoNewWindow

    Write-Host ""
    Write-Host "  [*] Done. Results appended to: $ResultsPath" -ForegroundColor Cyan
    if ($sourcePath -like "$stagingRoot*") {
        Write-Host "  [!] Extracted files remain at: $sourcePath" -ForegroundColor Yellow
        Write-Host "      Delete when review is complete:" -ForegroundColor DarkGray
        Write-Host "      Remove-Item -Recurse -Force '$sourcePath'" -ForegroundColor DarkGray
    }
    Read-Host "`n  Press Enter to return"
}

# =============================================================================
# WORKFLOW: removable media
# Prompts for a drive letter, then calls the script with -DriveLetter -Control.
# =============================================================================

function Invoke-RemovableMediaTechnique {
    [CmdletBinding()]
    param($Technique, [string]$ScriptPath, [string]$Control, [string]$ResultsPath)

    Write-Host ""
    Write-Host "  Prerequisites:" -ForegroundColor White
    Write-Host "    1. Attach a USB drive to this VM" -ForegroundColor DarkGray
    Write-Host "    2. The drive must already contain the sample files - no manifest needed" -ForegroundColor DarkGray
    Write-Host "    3. Load the drive on a separate unprotected machine - NOT this VM" -ForegroundColor DarkGray
    Write-Host "       (Loading from this VM means the control has already scanned them)" -ForegroundColor DarkGray
    Write-Host ""

    $driveLetter = (Read-Host "  Drive letter of removable media (e.g. E:), or press Enter to auto-detect").Trim()

    $executeInput = (Read-Host "  Execute samples after delivery, not just copy them? [Y/N]").Trim()
    $doExecute    = $executeInput -ieq 'Y'

    $dryRunInput = (Read-Host "  Run as DRY RUN? (detects drive + lists files, no real delivery) [Y/N]").Trim()
    $isDryRun    = $dryRunInput -ieq 'Y'

    Write-Host ""
    Write-Host "  [*] Open your EDR/AV console and start monitoring before proceeding." -ForegroundColor Yellow
    Read-Host "  Press Enter to launch Technique $($Technique.id)"

    $scriptArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"",
        '-Control', "`"$Control`"",
        '-ResultsPath', "`"$ResultsPath`""
    )
    if ($driveLetter) { $scriptArgs += @('-DriveLetter', $driveLetter) }
    if ($doExecute)   { $scriptArgs += '-Execute' }
    if ($isDryRun)    { $scriptArgs += '-DryRun' }

    Write-Host ""
    Write-Host "  [>] Launching: $ScriptPath" -ForegroundColor Cyan
    Write-Host ""

    Start-Process -FilePath 'powershell.exe' -ArgumentList $scriptArgs -Wait -NoNewWindow
    Read-Host "`n  Press Enter to return"
}

# =============================================================================
# WORKFLOW: client/server
# Prompts for server IP/port, calls the victim script with -ServerIP -Control.
# The tester must start the companion server script on a second VM first.
# =============================================================================

function Invoke-ClientServerTechnique {
    [CmdletBinding()]
    param($Technique, [string]$ScriptPath, [string]$Control, [string]$ResultsPath)

    Write-Host ""
    Write-Host "  Prerequisites:" -ForegroundColor White
    Write-Host "    1. Start the companion server script on a second VM first" -ForegroundColor DarkGray
    Write-Host "    2. Both VMs must have network connectivity between them" -ForegroundColor DarkGray
    Write-Host "    3. Confirm the server is listening before continuing" -ForegroundColor DarkGray
    Write-Host ""

    $serverIP = (Read-Host "  IP address of the server VM (e.g. 192.168.1.100)").Trim()
    if (-not $serverIP) {
        Write-Host "  Server IP is required for this technique." -ForegroundColor Red
        Read-Host "`n  Press Enter to return"
        return
    }

    $portInput = (Read-Host "  Port number [default: 8080]").Trim()
    $port      = if ($portInput) { $portInput } else { '8080' }

    $executeInput = (Read-Host "  Execute samples after download, not just download them? [Y/N]").Trim()
    $doExecute    = $executeInput -ieq 'Y'

    $dryRunInput = (Read-Host "  Run as DRY RUN? (fetches file listing, no real downloads) [Y/N]").Trim()
    $isDryRun    = $dryRunInput -ieq 'Y'

    Write-Host ""
    Write-Host "  [*] Open your EDR/AV console and start monitoring before proceeding." -ForegroundColor Yellow
    Read-Host "  Press Enter to launch Technique $($Technique.id)"

    $scriptArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"",
        '-ServerIP', $serverIP,
        '-Port', $port,
        '-Control', "`"$Control`"",
        '-ResultsPath', "`"$ResultsPath`""
    )
    if ($doExecute) { $scriptArgs += '-Execute' }
    if ($isDryRun)  { $scriptArgs += '-DryRun' }

    Write-Host ""
    Write-Host "  [>] Launching: $ScriptPath" -ForegroundColor Cyan
    Write-Host ""

    Start-Process -FilePath 'powershell.exe' -ArgumentList $scriptArgs -Wait -NoNewWindow
    Read-Host "`n  Press Enter to return"
}

# =============================================================================
# SUBTEST RUNNER
# module.json lists real subtests only. The launcher supplies run-all choices,
# derives marker paths, and asks for a server only when the selection needs one.
# =============================================================================

function Get-SCTMarkerPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$TechniqueId,
        [Parameter(Mandatory)] [string]$Subtest
    )

    return (Join-Path $env:SystemRoot "Temp\art-v$TechniqueId-$Subtest.txt")
}

function Invoke-SCTSubtests {
    [CmdletBinding()]
    param(
        $Technique,
        [string]$ScriptPath,
        [string]$Control,
        [string]$ResultsPath,
        [switch]$NonInteractive,
        [string]$RunId
    )

    $subtests = @(Get-SCTPropertyValue -InputObject $Technique -Name 'subtests' -Default @())
    $serverSubtests = @(Get-SCTPropertyValue -InputObject $Technique -Name 'server_subtests' -Default @())
    if ($subtests.Count -eq 0) {
        Write-Host ""
        Write-Host "  [!] No subtests are defined for Technique $($Technique.id)." -ForegroundColor Red
        Read-Host "`n  Press Enter to return"
        return
    }

    if ($NonInteractive) {
        $selected = 'All'
    } else {
        $choices = @($subtests)
        if ($serverSubtests.Count -gt 0) {
            $localSubtests = @($subtests | Where-Object { $serverSubtests -notcontains $_ })
            if ($localSubtests.Count -gt 0) { $choices += 'AllLocal' }
            $choices += 'AllRemote'
        }
        $choices += 'All'

        Write-Host ""
        Write-Host "  Available subtests:" -ForegroundColor White
        Write-Host ""

        for ($i = 0; $i -lt $choices.Count; $i++) {
            $item = $choices[$i]
            $needsServer = $serverSubtests -contains $item
            $tag = if ($needsServer) { '  [needs server VM]' } else { '' }
            $color = if ($item -like 'All*') { 'Yellow' } elseif ($needsServer) { 'Cyan' } else { 'White' }
            Write-Host ("  [{0}]  {1}{2}" -f ($i + 1), $item, $tag) -ForegroundColor $color
        }

        Write-Host "  [0]   Cancel" -ForegroundColor DarkGray
        Write-Host ""

        $choice = (Read-Host "  Select subtest").Trim()
        if ($choice -eq '0' -or $choice -eq '') { return }

        $idx = $choice -as [int]
        if ($idx -lt 1 -or $idx -gt $choices.Count) {
            Write-Host "  Invalid selection." -ForegroundColor Yellow
            Read-Host "`n  Press Enter to return"
            return
        }

        $selected = $choices[$idx - 1]
    }

    $toCheck = @(switch ($selected) {
        'All'       { @($subtests) }
        'AllRemote' { @($serverSubtests) }
        'AllLocal'  { @($subtests | Where-Object { $serverSubtests -notcontains $_ }) }
        default     { @($selected) }
    })
    if (-not $RunId) {
        $techniqueToken = $Technique.id -replace '[^0-9A-Za-z]', ''
        $RunId = "I$techniqueToken-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + `
            ([guid]::NewGuid().ToString('N').Substring(0, 6))
    }
    $runResults = @()
    $needsServer = @($toCheck | Where-Object { $serverSubtests -contains $_ }).Count -gt 0

    $serverIP = $null
    $port = '8080'
    if ($needsServer) {
        if ($NonInteractive) {
            throw "Technique $($Technique.id) needs server details and cannot run non-interactively."
        }
        Write-Host ""
        Write-Host "  '$selected' needs the companion server VM." -ForegroundColor Cyan
        $serverIP = (Read-Host "  Server VM IP address").Trim()
        if (-not $serverIP) {
            Write-Host "  Server IP is required for '$selected'." -ForegroundColor Red
            Read-Host "`n  Press Enter to return"
            return
        }
        $portInput = (Read-Host "  Port number [default: 8080]").Trim()
        if ($portInput) { $port = $portInput }
    }

    foreach ($subtest in $toCheck) {
        $markerPath = Get-SCTMarkerPath -TechniqueId $Technique.id -Subtest $subtest
        Remove-Item -LiteralPath $markerPath -Force -ErrorAction SilentlyContinue
    }

    Write-Host ""
    if ($NonInteractive) {
        Write-Host "  [*] Running all subtests without prompts." -ForegroundColor Yellow
    } else {
        Write-Host "  [*] Open your EDR/AV console and start monitoring before proceeding." -ForegroundColor Yellow
        Read-Host "  Press Enter to run: $selected"
    }

    $scriptArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"",
        '-Subtest', $selected
    )
    if ($serverIP) { $scriptArgs += @('-ServerIP', $serverIP, '-Port', $port) }
    if (Test-SCTScriptSupportsParameter -ScriptPath $ScriptPath -ParameterName 'NoCleanupPrompt') {
        $scriptArgs += '-NoCleanupPrompt'
    }
    if (Test-SCTScriptSupportsParameter -ScriptPath $ScriptPath -ParameterName 'NoReport') {
        $scriptArgs += '-NoReport'
    }
    # SCT owns the interactive start/end prompts. A script that supports
    # -NoPause must not add its own nested prompts, which can strand the user
    # before the module menu regains control.
    if (Test-SCTScriptSupportsParameter -ScriptPath $ScriptPath -ParameterName 'NoPause') {
        $scriptArgs += '-NoPause'
    }

    Write-Host ""
    Write-Host "  [>] Launching: $ScriptPath -Subtest $selected" -ForegroundColor Cyan
    Write-Host ""

    $startTime = Get-Date
    $launchError = ''
    $processExitCode = $null
    try {
        $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $scriptArgs `
            -Wait -NoNewWindow -PassThru -ErrorAction Stop
        $processExitCode = $process.ExitCode
        if ($processExitCode -ne 0) {
            Write-Host "  [!] Technique script exited with code $processExitCode." -ForegroundColor Yellow
        }
    } catch {
        $launchError = $_.Exception.Message
        Write-Host "  [!] Technique script could not be launched: $launchError" -ForegroundColor Red
    }

    if ($ResultsPath) {
        Write-Host ""
        Write-Host "  [*] Checking results..." -ForegroundColor Cyan
        Write-Host ""

        # A launched technique can leave a short-lived child process that writes
        # its marker just after the parent script exits. Wait once for the batch,
        # not once per subtest.
        if (-not $launchError) {
            Start-Sleep -Milliseconds 800
        }

        $executedCount = 0
        foreach ($subtest in $toCheck) {
            $markerPath = Get-SCTMarkerPath -TechniqueId $Technique.id -Subtest $subtest
            $executed   = Test-SCTMarkerFile -Path $markerPath
            if ($executed) {
                $outcome = 'EXECUTED'
                $displayOutcome = 'EXECUTED'
                $notes = "marker found: $markerPath"
                $icon = '[!]'
                $color = 'Yellow'
            } elseif ($launchError) {
                $outcome = 'ERROR'
                $displayOutcome = 'ERROR'
                $notes = "technique launch error: $launchError; marker absent: $markerPath"
                $icon = '[X]'
                $color = 'Red'
            } elseif ($processExitCode -ne 0) {
                $outcome = 'ERROR'
                $displayOutcome = 'ERROR'
                $notes = "technique script exit code: $processExitCode; marker absent: $markerPath"
                $icon = '[X]'
                $color = 'Red'
            } else {
                $outcome = 'NOT_EXECUTED'
                $displayOutcome = 'NOT EXECUTED'
                $notes = "marker absent after test: $markerPath"
                $icon = '[?]'
                $color = 'Gray'
            }

            if ($executed) { $executedCount++ }
            Write-Host ("  {0}  {1,-28}  {2}" -f $icon, $subtest, $displayOutcome) -ForegroundColor $color

            Write-SCTResult -Path $ResultsPath -Timestamp $startTime `
                -TechniqueId $Technique.id -TechniqueName $Technique.name -Subtest $subtest `
                -TestScript ([string]$Technique.script) -Outcome $outcome -Notes $notes -RunId $RunId

            $runResults += [pscustomobject]@{
                run_id      = $RunId
                control     = $Control
                technique_id = $Technique.id
                subtest     = $subtest
                outcome     = $outcome
                notes       = $notes
            }
        }

        Write-Host ""
        Write-Host "  $executedCount of $($toCheck.Count) subtests executed this run" -ForegroundColor Cyan
        Write-Host "  Results appended to: $ResultsPath" -ForegroundColor DarkGray
        Write-Host "  [i] [!] Marker found: execution observed" -ForegroundColor DarkGray
        Write-Host "  [i] [?] Marker absent: execution not observed; this alone does not prove a control block" -ForegroundColor DarkGray
        Write-Host "  [i] [X] Script error: fix the test prerequisite or launch failure before comparison" -ForegroundColor DarkGray
        Write-Host "  [i] Set detection_status (detected/not_detected) and action_status (blocked/not_blocked) in this module result CSV" -ForegroundColor DarkGray
    }

    if ($NonInteractive) {
        return $runResults
    }

    $cleanupParameters = @('CleanupOnly', 'NoCleanupPrompt', 'NoPause', 'NoReport')
    $supportsManagedCleanup = @(
        $cleanupParameters |
            Where-Object { -not (Test-SCTScriptSupportsParameter -ScriptPath $ScriptPath -ParameterName $_) }
    ).Count -eq 0
    if ($supportsManagedCleanup) {
        Write-Host "  [*] Cleaning up after results were recorded..." -ForegroundColor DarkGray
        Invoke-SCTTechniqueCleanup -ScriptPath $ScriptPath
    }

    Read-Host "`n  Press Enter to return"
}

# =============================================================================
# NON-INTERACTIVE MODULE RUNNER
# Runs every subtest in Module 04 without menu, pause, or cleanup prompts.
# Results are recorded before each technique is cleaned up.
# =============================================================================

function Test-SCTAdministrator {
    [CmdletBinding()]
    param()

    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-SCTCountdown {
    [CmdletBinding()]
    param([ValidateRange(0, 300)] [int]$Seconds)

    for ($remaining = $Seconds; $remaining -gt 0; $remaining--) {
        Write-Host ("  Starting in {0} second{1}..." -f $remaining, $(if ($remaining -eq 1) { '' } else { 's' })) -ForegroundColor Yellow
        Start-Sleep -Seconds 1
    }
}

function Invoke-SCTTechniqueCleanup {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$ScriptPath)

    $cleanupArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"",
        '-CleanupOnly', '-NoCleanupPrompt', '-NoPause', '-NoReport'
    )
    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $cleanupArgs -Wait -NoNewWindow -PassThru
    if ($process.ExitCode -ne 0) {
        Write-Host "  [!] Cleanup script exited with code $($process.ExitCode): $ScriptPath" -ForegroundColor Red
    }
}

function Show-SCTModuleRunSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [array]$Results,
        [Parameter(Mandatory)] [string]$RunId,
        [Parameter(Mandatory)] [string]$ResultsPath
    )

    $total    = $Results.Count
    $executed = @($Results | Where-Object { $_.outcome -eq 'EXECUTED' }).Count
    $markerAbsent = @($Results | Where-Object { $_.outcome -in @('NOT_EXECUTED', 'BLOCKED') }).Count
    $errors = @($Results | Where-Object { $_.outcome -eq 'ERROR' }).Count

    Write-Host ""
    Write-Host "  ============================================================================" -ForegroundColor Cyan
    Write-Host "  MODULE 04 RUN COMPLETE" -ForegroundColor Cyan
    Write-Host "  ============================================================================" -ForegroundColor Cyan
    Write-Host "  Run ID   : $RunId" -ForegroundColor White
    Write-Host "  Results  : $total total | $executed marker found | $markerAbsent marker absent | $errors errors" -ForegroundColor White
    Write-Host "  CSV      : $ResultsPath" -ForegroundColor DarkGray

    foreach ($group in ($Results | Group-Object technique_id | Sort-Object Name)) {
        $groupExecuted = @($group.Group | Where-Object { $_.outcome -eq 'EXECUTED' }).Count
        $groupMarkerAbsent = @($group.Group | Where-Object { $_.outcome -in @('NOT_EXECUTED', 'BLOCKED') }).Count
        $groupErrors = @($group.Group | Where-Object { $_.outcome -eq 'ERROR' }).Count
        Write-Host ("  Technique {0}: {1} total | {2} marker found | {3} marker absent | {4} errors" -f $group.Name, $group.Count, $groupExecuted, $groupMarkerAbsent, $groupErrors) -ForegroundColor White
    }
}

function Invoke-SCTModuleNonInteractive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Module,
        [Parameter(Mandatory)] [string]$Control,
        [Parameter(Mandatory)] [string]$ResultsPath,
        [ValidateRange(0, 300)] [int]$StartDelaySeconds = 10,
        [ValidateRange(0, 300)] [int]$InterTechniqueDelaySeconds = 3
    )

    if ($Module.id -ne '04') {
        throw "Non-interactive module runs are currently supported only for Module 04."
    }
    if (-not (Test-SCTAdministrator)) {
        throw "Module 04 full runs require an elevated PowerShell session. Open PowerShell as Administrator and run the command again."
    }

    $techniques = @($Module.techniques)
    if ($techniques.Count -eq 0 -or @($techniques | Where-Object { @(Get-SCTPropertyValue -InputObject $_ -Name 'subtests' -Default @()).Count -eq 0 }).Count -gt 0) {
        throw "Module 04 must contain only techniques with subtests for a non-interactive run."
    }

    $subtestCount = 0
    foreach ($technique in $techniques) {
        $scriptPath = Join-Path $Module.ScriptDir $technique.script
        if (-not (Test-Path -LiteralPath $scriptPath)) {
            throw "Script not found: $scriptPath"
        }
        foreach ($parameter in @('NoPause', 'NoReport', 'CleanupOnly')) {
            if (-not (Test-SCTScriptSupportsParameter -ScriptPath $scriptPath -ParameterName $parameter)) {
                throw "Technique $($technique.id) must support -$parameter for a non-interactive Module 04 run."
            }
        }
        $subtestCount += @($technique.subtests).Count
    }

    $runId = "M04-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + ([guid]::NewGuid().ToString('N').Substring(0, 6))

    Write-Host ""
    Write-Host "  Module 04 non-interactive run" -ForegroundColor Cyan
    Write-Host "  Control  : $Control" -ForegroundColor White
    Write-Host "  Techniques: $($techniques.Count)" -ForegroundColor White
    Write-Host "  Subtests  : $subtestCount" -ForegroundColor White
    Write-Host "  Run ID   : $runId" -ForegroundColor White
    Write-Host "  Cleanup  : automatic after each technique is recorded" -ForegroundColor DarkGray
    Start-SCTCountdown -Seconds $StartDelaySeconds

    $runResults = @()
    for ($index = 0; $index -lt $techniques.Count; $index++) {
        $technique  = $techniques[$index]
        $scriptPath = Join-Path $Module.ScriptDir $technique.script

        Write-Host ""
        Write-Host "  [>] Technique $($technique.id): $($technique.name)" -ForegroundColor Cyan
        try {
            $techniqueResults = @(Invoke-SCTSubtests -Technique $technique -ScriptPath $scriptPath -Control $Control `
                -ResultsPath $ResultsPath -NonInteractive -RunId $runId)
            $runResults += $techniqueResults
        } finally {
            Write-Host "  [*] Cleaning up Technique $($technique.id)..." -ForegroundColor DarkGray
            Invoke-SCTTechniqueCleanup -ScriptPath $scriptPath
        }

        if ($index -lt ($techniques.Count - 1) -and $InterTechniqueDelaySeconds -gt 0) {
            Write-Host "  Waiting $InterTechniqueDelaySeconds seconds before the next technique..." -ForegroundColor DarkGray
            Start-Sleep -Seconds $InterTechniqueDelaySeconds
        }
    }

    Show-SCTModuleRunSummary -Results $runResults -RunId $runId -ResultsPath $ResultsPath
    return $runResults
}

# =============================================================================
# WORKFLOW: direct script
# Runs the script directly with no extra parameters. Used for self-contained
# techniques that handle their own prompting (for example DLL sideloading).
# =============================================================================

function Invoke-DirectTechnique {
    [CmdletBinding()]
    param($Technique, [string]$ScriptPath, [string]$ResultsPath)

    Write-Host ""
    Write-Host "  [*] Open your EDR/AV console and start monitoring before proceeding." -ForegroundColor Yellow
    Read-Host "  Press Enter to launch Technique $($Technique.id)"

    $scriptArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$ScriptPath`"")

    Write-Host ""
    Write-Host "  [>] Launching: $ScriptPath" -ForegroundColor Cyan
    Write-Host ""

    $startTime = Get-Date
    $launchError = ''
    $processExitCode = $null
    try {
        $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $scriptArgs `
            -Wait -NoNewWindow -PassThru -ErrorAction Stop
        $processExitCode = $process.ExitCode
    } catch {
        $launchError = $_.Exception.Message
    }

    if ($ResultsPath) {
        if ($launchError -or $processExitCode -ne 0) {
            $failure = if ($launchError) {
                "technique launch error: $launchError"
            } else {
                "technique script exit code: $processExitCode"
            }
            $runId = "I$($Technique.id -replace '[^0-9A-Za-z]', '')-" +
                (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' +
                ([guid]::NewGuid().ToString('N').Substring(0, 6))
            Write-SCTResult -Path $ResultsPath -Timestamp $startTime -RunId $runId `
                -TechniqueId $Technique.id -TechniqueName $Technique.name -Subtest '' `
                -TestScript ([string]$Technique.script) -Outcome 'ERROR' -Notes $failure
            Write-Host "  [!] $failure" -ForegroundColor Red
            Write-Host "  Error result appended to: $ResultsPath" -ForegroundColor DarkGray
        } else {
            Write-Host ""
            Write-Host "  Record the observed execution result:" -ForegroundColor White
            Write-Host "  [E] Executed    [N] Not executed    [S] Skip" -ForegroundColor DarkGray
            $answer = (Read-Host "  Result").Trim().ToUpperInvariant()
            if ($answer -in @('E', 'N')) {
                $notes = (Read-Host "  Notes (optional)").Trim()
                $outcome = if ($answer -eq 'E') { 'EXECUTED' } else { 'NOT_EXECUTED' }
                $runId = "I$($Technique.id -replace '[^0-9A-Za-z]', '')-" +
                    (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' +
                    ([guid]::NewGuid().ToString('N').Substring(0, 6))
                Write-SCTResult -Path $ResultsPath -Timestamp $startTime -RunId $runId `
                    -TechniqueId $Technique.id -TechniqueName $Technique.name -Subtest '' `
                    -TestScript ([string]$Technique.script) -Outcome $outcome -Notes $notes
                Write-Host "  Result appended to: $ResultsPath" -ForegroundColor DarkGray
            } else {
                Write-Host "  No result row was written." -ForegroundColor DarkGray
            }
        }
    }
    Read-Host "`n  Press Enter to return"
}

# =============================================================================
# ZIP EXTRACTION
# No-password ZIPs use .NET System.IO.Compression (no dependencies).
# Password-protected ZIPs require 7-Zip - auto-detected from common install
# paths or PATH. Falls back gracefully with a clear error if not found.
# =============================================================================

function Find-7Zip {
    $candidates = @(
        'C:\Program Files\7-Zip\7z.exe',
        'C:\Program Files (x86)\7-Zip\7z.exe'
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    $onPath = Get-Command '7z.exe' -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    return $null
}

function Invoke-ZipExtraction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$DestPath,
        [string]$Password = ''
    )

    if (Test-Path $DestPath) {
        $answer = (Read-Host "  Destination already exists: $DestPath`n  Overwrite? [Y/N]").Trim()
        if ($answer -ine 'Y') {
            Write-Host "  [*] Using existing extraction at: $DestPath" -ForegroundColor Green
            return
        }
        Remove-Item -Path $DestPath -Recurse -Force
    }

    New-Item -ItemType Directory -Path $DestPath -Force | Out-Null

    if ($Password) {
        $7zPath = Find-7Zip
        if (-not $7zPath) {
            Write-Host "  [!] 7-Zip is required for password-protected ZIPs but was not found." -ForegroundColor Red
            Write-Host "  [!] Install 7-Zip (7-zip.org), or extract the ZIP manually and use [M]." -ForegroundColor DarkGray
            throw "7-Zip not found. Cannot extract password-protected ZIP without it."
        }
        Write-Host "  [*] Using 7-Zip: $7zPath" -ForegroundColor DarkGray
        & $7zPath x "-p$Password" "-o$DestPath" $ZipPath '-y' | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "7-Zip extraction failed (exit $LASTEXITCODE). Verify the password and ZIP file integrity."
        }
    } else {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $DestPath)
    }

    Write-Host "  [+] Extracted to: $DestPath" -ForegroundColor Green
}

# =============================================================================
# ZIP SAMPLE STAGING
# Extracts every ZIP in $Zips to an isolated subfolder, optionally discovers
# and extracts ZIPs found inside those archives, and writes a bundle manifest
# for v1.1. Each archive keeps its original directory structure and supporting
# files. Nested extraction is bounded by archive count and depth.
# =============================================================================

function Merge-StagingFromZips {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$Zips,
        [Parameter(Mandatory)][string]$StagingRoot,
        [string]$Password = '',
        [switch]$PromptForNestedArchives,
        [switch]$ExpandNestedArchives,
        [AllowEmptyString()][string]$NestedPassword = '',
        [ValidateRange(1, 10)][int]$MaxArchiveDepth = 3,
        [ValidateRange(1, 1000)][int]$MaxArchiveCount = 100
    )

    if ($PromptForNestedArchives -and $ExpandNestedArchives) {
        throw 'Use either -PromptForNestedArchives or -ExpandNestedArchives, not both.'
    }

    $timestamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
    $runSuffix   = [guid]::NewGuid().ToString('N').Substring(0, 6)
    $combinedDir = Join-Path $StagingRoot "combined-$timestamp-$runSuffix"
    New-Item -ItemType Directory -Path $combinedDir -Force | Out-Null

    $recognisedExtensionPattern = '\.(exe|dll|com|bat|cmd|ps1|vbs|js|hta|jar|py)$'
    $bundleRecords      = @()
    $recognisedFiles    = 0
    $supportFiles       = 0
    $warnings           = @()
    $archiveCount       = 0
    $topLevelCount      = 0
    $nestedArchiveCount = 0
    $queue              = New-Object System.Collections.Queue
    $expandNested       = $ExpandNestedArchives.IsPresent
    $nestedDecision     = $ExpandNestedArchives.IsPresent
    $nestedPasswordValue = if ($PSBoundParameters.ContainsKey('NestedPassword')) {
        $NestedPassword
    } else {
        $Password
    }

    foreach ($zip in $Zips) {
        $queue.Enqueue([pscustomobject]@{
            File     = $zip
            Depth    = 0
            Password = $Password
        })
    }

    while ($queue.Count -gt 0) {
        if ($archiveCount -ge $MaxArchiveCount) {
            $warnings += "Stopped after $MaxArchiveCount archives (safety limit)."
            break
        }

        $item = $queue.Dequeue()
        $zip = $item.File
        if (-not (Test-Path -LiteralPath $zip.FullName -PathType Leaf)) {
            $msg = "Skipped missing archive: $($zip.FullName)"
            $warnings += $msg
            Write-Host "  [!] $msg" -ForegroundColor Red
            continue
        }

        $archiveCount++
        if ($item.Depth -eq 0) {
            $topLevelCount++
        } else {
            $nestedArchiveCount++
        }
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($zip.Name)
        $destName = '{0:D3}-{1}' -f $archiveCount, $baseName
        $destDir  = Join-Path $combinedDir $destName

        $depthLabel = if ($item.Depth -gt 0) { " (nested depth $($item.Depth))" } else { '' }
        Write-Host "  [*] Extracting $($zip.Name)$depthLabel..." -ForegroundColor Yellow
        try {
            Invoke-ZipExtraction -ZipPath $zip.FullName -DestPath $destDir -Password $item.Password
        } catch {
            $msg = "Skipped $($zip.Name): $($_.Exception.Message)"
            $warnings += $msg
            Write-Host "  [!] $msg" -ForegroundColor Red
            continue
        }

        $extractedFiles = @(Get-ChildItem -LiteralPath $destDir -File -Recurse -ErrorAction SilentlyContinue)
        $nestedZips = @($extractedFiles | Where-Object { $_.Extension -ieq '.zip' })
        $nonZipFiles = @($extractedFiles | Where-Object { $_.Extension -ine '.zip' })
        $sampleFiles = @($nonZipFiles | Where-Object { $_.Extension -match $recognisedExtensionPattern })
        $bundleSupportFiles = @($nonZipFiles | Where-Object { $_.Extension -notmatch $recognisedExtensionPattern })
        $recognisedFiles += $sampleFiles.Count
        $supportFiles += $bundleSupportFiles.Count
        Write-Host (
            "    $($sampleFiles.Count) recognised sample file(s), " +
            "$($bundleSupportFiles.Count) supporting/other file(s), " +
            "$($nestedZips.Count) nested ZIP(s)"
        ) -ForegroundColor DarkGray

        if ($sampleFiles.Count -gt 0) {
            $relativeCandidates = @(
                $sampleFiles | ForEach-Object {
                    $_.FullName.Substring($destDir.Length).TrimStart('\', '/')
                }
            )
            $archiveHash = ''
            try {
                $archiveHash = (Get-FileHash -LiteralPath $zip.FullName -Algorithm SHA256).Hash
            } catch {
                $warnings += "Could not hash archive $($zip.Name): $($_.Exception.Message)"
            }
            $bundleRecords += [pscustomobject]@{
                id                  = $destName
                name                = $baseName
                relative_path       = $destName
                archive_name        = $zip.Name
                archive_sha256      = $archiveHash
                depth               = $item.Depth
                recognised_files    = @($relativeCandidates)
                supporting_files    = $bundleSupportFiles.Count
            }
        }

        if ($nestedZips.Count -eq 0) {
            continue
        }

        if ($item.Depth -ge $MaxArchiveDepth) {
            $warnings += "Ignored $($nestedZips.Count) nested ZIP(s) in $($zip.Name): maximum depth $MaxArchiveDepth reached."
            continue
        }

        if (-not $nestedDecision) {
            Write-Host ""
            Write-Host "  [!] Found $($nestedZips.Count) ZIP archive(s) inside $($zip.Name):" -ForegroundColor Yellow
            foreach ($nestedZip in $nestedZips) {
                Write-Host "      $($nestedZip.Name)" -ForegroundColor DarkGray
            }
            Write-Host ""
            $nestedChoice = (Read-Host "  Extract nested ZIPs and include their samples? [Y/N]").Trim()
            $expandNested = $nestedChoice -ieq 'Y'
            $nestedDecision = $true

            if ($expandNested) {
                $enteredPassword = (Read-Host "  Password for nested ZIPs (Enter reuses the outer ZIP password)").Trim()
                $nestedPasswordValue = if ($enteredPassword) { $enteredPassword } else { $item.Password }
            }
            Write-Host ""
        }

        if ($expandNested) {
            foreach ($nestedZip in $nestedZips) {
                $queue.Enqueue([pscustomobject]@{
                    File     = $nestedZip
                    Depth    = $item.Depth + 1
                    Password = $nestedPasswordValue
                })
            }
        } else {
            $warnings += "Ignored $($nestedZips.Count) nested ZIP(s) found in $($zip.Name) at operator request."
        }
    }

    $manifestPath = Join-Path $combinedDir '.sct-bundles.json'
    [pscustomobject]@{
        schema_version = 1
        created_at     = (Get-Date).ToUniversalTime().ToString('o')
        bundles        = @($bundleRecords)
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    Write-Host ""
    Write-Host "  [+] Bundle staging   : $combinedDir" -ForegroundColor Green
    Write-Host "  [+] Malware bundles : $($bundleRecords.Count)" -ForegroundColor Green
    Write-Host "  [+] Recognised files: $recognisedFiles" -ForegroundColor Green
    Write-Host "  [+] Support/other    : $supportFiles (preserved inside bundles)" -ForegroundColor DarkGray
    Write-Host (
        "  [+] ZIPs processed   : $archiveCount " +
        "($topLevelCount selected/top-level, $nestedArchiveCount nested)"
    ) -ForegroundColor Green

    if ($warnings) {
        Write-Host ""
        foreach ($w in $warnings) { Write-Host "  [!] $w" -ForegroundColor Yellow }
    }

    return $combinedDir
}

# =============================================================================
# RESULT WRITER - writes one canonical row per subtest to the selected module CSV.
# =============================================================================

function Write-SCTResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [datetime]$Timestamp,
        [string]$RunId = '',
        [Parameter(Mandatory)] [string]$TechniqueId,
        [Parameter(Mandatory)] [string]$TechniqueName,
        [Parameter(Mandatory)] [AllowEmptyString()] [string]$Subtest,
        [string]$TestScript = '',
        [Parameter(Mandatory)] [ValidateSet('EXECUTED','NOT_EXECUTED','BLOCKED','NOT-EXPLOITABLE','ERROR')]
        [string]$Outcome,
        [string]$Notes = ''
    )

    $executionStatus = switch ($Outcome) {
        'EXECUTED' { 'executed' }
        'NOT_EXECUTED' { 'not_executed' }
        'BLOCKED'  { 'not_executed' }
        default    { '' }
    }
    Write-SCTResultRow -Path $Path -Timestamp $Timestamp -RunId $RunId `
        -TechniqueId $TechniqueId -TechniqueName $TechniqueName -Subtest $Subtest `
        -TestScript $TestScript -TestStage 'execution' -SourceResult $Outcome `
        -ExecutionStatus $executionStatus -Notes $Notes
}

# =============================================================================
# MARKER FILE CHECK  -  returns $true if the expected marker file exists.
# Invoke-SCTSubtests removes expected markers before launch and performs one
# batch-level grace wait, so presence proves that the current run wrote it.
# =============================================================================

function Test-SCTMarkerFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path
    )

    return (Test-Path -LiteralPath $Path)
}

# =============================================================================
# SCRIPT PARAMETER CHECK
# Used by the launcher to opt into newer script parameters without breaking
# older technique scripts that do not know about them.
# =============================================================================

function Test-SCTScriptSupportsParameter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ScriptPath,
        [Parameter(Mandatory)] [string]$ParameterName
    )

    try {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $ScriptPath,
            [ref]$tokens,
            [ref]$errors
        )
        if ($errors.Count -gt 0 -or -not $ast.ParamBlock) { return $false }

        $parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object {
            $_.Name.VariablePath.UserPath
        })
        return ($parameterNames -contains $ParameterName)
    } catch {
        return $false
    }
}

function Get-SCTScriptValidateSetValues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ScriptPath,
        [Parameter(Mandatory)] [string]$ParameterName
    )

    try {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $ScriptPath,
            [ref]$tokens,
            [ref]$errors
        )
        if ($errors.Count -gt 0 -or -not $ast.ParamBlock) { return @() }

        $parameter = $ast.ParamBlock.Parameters | Where-Object {
            $_.Name.VariablePath.UserPath -eq $ParameterName
        } | Select-Object -First 1
        if (-not $parameter) { return @() }

        $attribute = $parameter.Attributes | Where-Object {
            $_ -is [System.Management.Automation.Language.AttributeAst] -and
            $_.TypeName.Name -eq 'ValidateSet'
        } | Select-Object -First 1
        if (-not $attribute) { return @() }

        return @($attribute.PositionalArguments | ForEach-Object { [string]$_.Value })
    } catch {
        return @()
    }
}

# =============================================================================
# CALC.EXE SPAWN CHECK - proof of execution for in-memory subtests.
# Checks Sysmon EID 1 first. If Sysmon is not installed, falls back to a
# manual [E]xecuted / [B]locked / [S]kip prompt so nothing is lost.
# =============================================================================

function Test-SCTCalcSpawned {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [datetime]$After)

    Start-Sleep -Milliseconds 1000
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            Id        = 1
            StartTime = $After
        } -ErrorAction Stop

        if ($events | Where-Object { $_.Message -match 'calc\.exe' }) {
            return @{ Outcome = 'EXECUTED'; Notes = 'calc.exe process creation detected via Sysmon EID 1' }
        }
        return @{ Outcome = 'BLOCKED'; Notes = 'calc.exe not detected in Sysmon EID 1 within test window' }
    } catch {
        Write-Host ""
        Write-Host "  Sysmon unavailable for automated detection." -ForegroundColor Yellow
        Write-Host "  Did the subtest execute as expected? (e.g. did Calculator open?)" -ForegroundColor White
        Write-Host "  [E] Executed    [B] Blocked    [S] Skip (do not record)" -ForegroundColor DarkGray
        $answer = (Read-Host "  ").Trim().ToUpper()
        switch ($answer) {
            'E' { return @{ Outcome = 'EXECUTED'; Notes = 'manually confirmed by tester - no Sysmon' } }
            'B' { return @{ Outcome = 'BLOCKED';  Notes = 'manually confirmed by tester - no Sysmon' } }
            default { return $null }
        }
    }
}

# =============================================================================
# RESULTS SUMMARY
# Reads every authoritative module result file in the active control workspace.
# =============================================================================

function Show-SCTSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$WorkspaceRoot)

    Write-Host ""
    Write-Host "  ============================================================================" -ForegroundColor Cyan
    Write-Host "  AGGREGATED TEST RESULTS" -ForegroundColor Cyan
    Write-Host "  ============================================================================" -ForegroundColor Cyan

    $resultPaths = @(Get-SCTWorkspaceResultPaths -WorkspaceRoot $WorkspaceRoot)
    if ($resultPaths.Count -eq 0) {
        Write-Host ""
        Write-Host "  No results found yet. Run some tests first." -ForegroundColor Yellow
        Write-Host "  Results will appear under: $WorkspaceRoot" -ForegroundColor DarkGray
        Write-Host ""
        Read-Host "  Press Enter to return"
        return
    }

    try {
        $data = @()
        foreach ($resultsPath in $resultPaths) {
            Assert-SCTResultFileSchema -Path $resultsPath
            $data += @(Import-Csv -LiteralPath $resultsPath -Encoding UTF8 -ErrorAction Stop)
        }
        if ($data.Count -eq 0) { throw 'The module result files have no rows.' }

        Write-Host ""
        $header = "  {0,-12} {1,-8} {2,-10} {3,-12} {4}"
        Write-Host ($header -f 'Technique', 'Rows', 'Executed', 'Not executed', 'Reviewed') -ForegroundColor White
        foreach ($group in ($data | Group-Object technique_id | Sort-Object Name)) {
            $executed = @($group.Group | Where-Object { $_.execution_status -eq 'executed' }).Count
            $notExecuted = @($group.Group | Where-Object { $_.execution_status -eq 'not_executed' }).Count
            $reviewed = @($group.Group | Where-Object { $_.detection_status -and $_.action_status }).Count
            Write-Host ($header -f $group.Name, $group.Count, $executed, $notExecuted, $reviewed) -ForegroundColor White
        }
        Write-Host ("  " + ('-' * 64)) -ForegroundColor DarkGray
        $reviewedTotal = @($data | Where-Object { $_.detection_status -and $_.action_status }).Count
        Write-Host "  $($data.Count) rows total; $reviewedTotal reviewed." -ForegroundColor Cyan
        Write-Host "  Sources: $($resultPaths.Count) module result file(s) under $WorkspaceRoot" -ForegroundColor DarkGray
    } catch {
        Write-Host "  Could not read module results: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ""
    Read-Host "  Press Enter to return"
}
