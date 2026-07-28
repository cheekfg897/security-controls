<#
.SYNOPSIS
    Sets up the JSON profile for the security control tested in this VM.

.DESCRIPTION
    Prompts for a configuration display name and derives a control id, then
    optionally collects product, policy, exclusion, and local-log details.
    Press Enter to skip optional interactive fields. Skipped text fields are
    recorded as "Not recorded", and a skipped default mode uses "custom", so
    the saved profile remains valid. Use -NonInteractive with all named
    parameters for automation and tests. By default, creates
    results\<control-id>\control-profile.json together with one module-specific
    test catalogue for every discovered SCT module.

    If results-module-<id>.csv files already exist for this workspace (for
    example, left over from a previous control tested under the same
    control-id), an interactive run asks whether to delete them so the new
    run starts with a clean results set. Pass -DeleteExistingResults to
    delete them without prompting (including in -NonInteractive runs); omit
    it to leave existing result files untouched.

.EXAMPLE
    .\scripts\review\Setup-SCTControl.ps1

.EXAMPLE
    .\scripts\review\Setup-SCTControl.ps1 -NonInteractive -Force `
        -ControlId control-a -DisplayName 'Control A' -Vendor Vendor `
        -Product Product -ProductVersion 1.0 -AgentVersion 1.0 `
        -PolicyName 'Evaluation Policy' -DefaultMode detect_only

.EXAMPLE
    .\scripts\review\Setup-SCTControl.ps1 -NonInteractive -Force -DeleteExistingResults `
        -ControlId control-a -DisplayName 'Control A' -Vendor Vendor `
        -Product Product -ProductVersion 1.0 -AgentVersion 1.0 `
        -PolicyName 'Evaluation Policy' -DefaultMode detect_only
#>

[CmdletBinding()]
param(
    [string]$ResultsRoot,
    [string]$ScenariosPath,
    [string]$ControlId,
    [string]$DisplayName,
    [string]$Vendor,
    [string]$Product,
    [string]$ProductVersion,
    [string]$AgentVersion,
    [string]$PolicyName,
    [ValidateSet('detect_only', 'detect_and_block', 'custom')]
    [string]$DefaultMode,
    [string]$Notes = '',
    [switch]$NonInteractive,
    [switch]$Force,
    [switch]$DeleteExistingResults
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\common\SCT-ReviewHelpers.ps1')

function Read-RequiredValue {
    param([string]$Prompt, [string]$Current, [scriptblock]$Validate, [string]$Message)
    if ($Current -and (-not $Validate -or (& $Validate $Current))) { return $Current }
    if ($NonInteractive) { throw "$Prompt is required." }
    while ($true) {
        $value = (Read-Host $Prompt).Trim()
        if ($value -and (-not $Validate -or (& $Validate $value))) { return $value }
        Write-Host "  $Message" -ForegroundColor Yellow
    }
}

function Read-YesNoValue {
    param([string]$Prompt)
    while ($true) {
        $value = (Read-Host "$Prompt [y/N]").Trim()
        if (-not $value -or $value -match '^(n|no)$') { return $false }
        if ($value -match '^(y|yes)$') { return $true }
        Write-Host '  Enter Y or N.' -ForegroundColor Yellow
    }
}

function ConvertTo-SCTControlId {
    param([Parameter(Mandatory)] [string]$Value)

    $candidate = $Value.Trim().ToLowerInvariant()
    $candidate = [regex]::Replace($candidate, '[^a-z0-9._-]+', '-')
    $candidate = $candidate.Trim([char[]]'._-')
    if (-not $candidate) {
        $candidate = 'control-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
    }
    return $candidate
}

function Read-InteractiveControlId {
    param([string]$Current, [Parameter(Mandatory)] [string]$DisplayName)

    if ($Current -and $Current -match '^[a-z0-9][a-z0-9._-]*$') { return $Current }
    $suggested = ConvertTo-SCTControlId -Value $DisplayName
    while ($true) {
        $value = (Read-Host "Control id [$suggested] (Enter to accept)").Trim()
        if (-not $value) { $value = $suggested }
        if ($value -match '^[a-z0-9][a-z0-9._-]*$') { return $value }
        Write-Host '  Use lowercase letters, digits, dots, underscores, or hyphens.' -ForegroundColor Yellow
    }
}

function Read-OptionalTextValue {
    param(
        [Parameter(Mandatory)] [string]$Prompt,
        [string]$Current,
        [string]$SkippedValue = 'Not recorded'
    )

    if ($Current) { return $Current }
    $value = (Read-Host "$Prompt (optional; Enter to skip)").Trim()
    if ($value) { return $value }
    return $SkippedValue
}

function Read-InteractiveDefaultMode {
    param([string]$Current)

    if ($Current -in @('detect_only', 'detect_and_block', 'custom')) { return $Current }
    while ($true) {
        $value = (Read-Host 'Default mode: detect_only, detect_and_block, or custom [custom] (Enter to skip)').Trim()
        if (-not $value) { return 'custom' }
        if ($value -in @('detect_only', 'detect_and_block', 'custom')) { return $value }
        Write-Host '  Enter detect_only, detect_and_block, custom, or press Enter to skip.' -ForegroundColor Yellow
    }
}

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not $ResultsRoot) { $ResultsRoot = Join-Path $repoRoot 'results' }
if (-not $ScenariosPath) { $ScenariosPath = Join-Path $repoRoot 'scenarios' }

if ($NonInteractive) {
    $ControlId = Read-RequiredValue 'Control id' $ControlId `
        { param($value) $value -match '^[a-z0-9][a-z0-9._-]*$' } `
        'Use lowercase letters, digits, dots, underscores, or hyphens.'
    $DisplayName = Read-RequiredValue 'Control display name' $DisplayName $null 'Enter a display name.'
    $Vendor = Read-RequiredValue 'Vendor' $Vendor $null 'Enter a vendor.'
    $Product = Read-RequiredValue 'Product' $Product $null 'Enter a product.'
    $ProductVersion = Read-RequiredValue 'Product version' $ProductVersion $null 'Enter a product version.'
    $AgentVersion = Read-RequiredValue 'Agent version' $AgentVersion $null 'Enter an agent version.'
    $PolicyName = Read-RequiredValue 'Policy name' $PolicyName $null 'Enter a policy name.'
    $DefaultMode = Read-RequiredValue 'Default mode (detect_only, detect_and_block, or custom)' $DefaultMode `
        { param($value) $value -in @('detect_only', 'detect_and_block', 'custom') } `
        'Enter detect_only, detect_and_block, or custom.'
} else {
    Write-Host ""
    Write-Host "  Create or update a control configuration" -ForegroundColor Cyan
    Write-Host "  Only the display name is required." -ForegroundColor White
    Write-Host "  Press Enter to accept the suggested id or skip any optional field." -ForegroundColor White
    Write-Host "  Skipped details are saved as 'Not recorded'; skipped mode becomes 'custom'." -ForegroundColor Gray
    Write-Host ""

    $DisplayName = Read-RequiredValue 'Configuration display name (required)' $DisplayName $null 'Enter a display name.'
    $ControlId = Read-InteractiveControlId -Current $ControlId -DisplayName $DisplayName
    $Vendor = Read-OptionalTextValue -Prompt 'Vendor' -Current $Vendor
    $Product = Read-OptionalTextValue -Prompt 'Product' -Current $Product
    $ProductVersion = Read-OptionalTextValue -Prompt 'Product version' -Current $ProductVersion
    $AgentVersion = Read-OptionalTextValue -Prompt 'Agent version' -Current $AgentVersion
    $PolicyName = Read-OptionalTextValue -Prompt 'Policy name' -Current $PolicyName
    $DefaultMode = Read-InteractiveDefaultMode -Current $DefaultMode
}

$OutputPath = Join-Path (Join-Path $ResultsRoot $ControlId) 'control-profile.json'

$settings = @()
$exclusions = @()
$localLogs = @()
if (-not $NonInteractive) {
    while (Read-YesNoValue 'Add a product-specific policy setting?') {
        $name = Read-RequiredValue 'Setting name' '' $null 'Enter a setting name.'
        $value = Read-RequiredValue 'Setting value' '' $null 'Enter a setting value.'
        $scope = Read-RequiredValue 'Scope (for example global, module:01, or technique:4.2)' 'global' $null 'Enter a scope.'
        $settingNotes = (Read-Host 'Setting notes (optional)').Trim()
        $settings += [pscustomobject][ordered]@{ name = $name; value = $value; scope = $scope; notes = $settingNotes }
    }

    $rawExclusions = (Read-Host 'Exclusions, separated by semicolons (optional)').Trim()
    if ($rawExclusions) {
        $exclusions = @($rawExclusions -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    while (Read-YesNoValue 'Record a local product log path?') {
        $logName = Read-RequiredValue 'Log name' '' $null 'Enter a log name.'
        $logPath = Read-RequiredValue 'Log path' '' $null 'Enter a log path.'
        $logFormat = Read-RequiredValue 'Log format (text, csv, json, jsonl, xml, or evtx)' '' `
            { param($value) $value -in @('text', 'csv', 'json', 'jsonl', 'xml', 'evtx') } `
            'Enter text, csv, json, jsonl, xml, or evtx.'
        $localLogs += [pscustomobject][ordered]@{ name = $logName; path = $logPath; format = $logFormat }
    }

    if (-not $Notes) { $Notes = (Read-Host 'Profile notes (optional)').Trim() }
}

$profile = [pscustomobject][ordered]@{
    schema_version = '1.0'
    control = [pscustomobject][ordered]@{
        id              = $ControlId
        display_name    = $DisplayName
        vendor          = $Vendor
        product         = $Product
        product_version = $ProductVersion
        agent_version   = $AgentVersion
    }
    policy = [pscustomobject][ordered]@{
        name         = $PolicyName
        default_mode = $DefaultMode
        settings     = @($settings)
        exclusions   = @($exclusions)
    }
    local_logs = @($localLogs)
    notes = $Notes
}

$errors = @(Get-SCTControlProfileErrors -Profile $profile)
if ($errors.Count -gt 0) { throw ($errors -join [Environment]::NewLine) }

$resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if ((Test-Path -LiteralPath $resolvedPath) -and -not $Force) {
    if ($NonInteractive -or -not (Read-YesNoValue "Overwrite ${resolvedPath}?")) {
        throw "Output file already exists: $resolvedPath"
    }
}
$directory = Split-Path $resolvedPath -Parent
if (Test-Path -LiteralPath $directory -PathType Container) {
    Assert-SCTWorkspaceUsesModuleFiles -WorkspaceRoot $directory -ControlProfilePath $resolvedPath

    $existingResultPaths = @(Get-SCTWorkspaceResultPaths -WorkspaceRoot $directory)
    if ($existingResultPaths.Count -gt 0) {
        $shouldDelete = [bool]$DeleteExistingResults
        if (-not $shouldDelete -and -not $NonInteractive) {
            Write-Host ""
            Write-Host "  Existing result file(s) found in this workspace:" -ForegroundColor Yellow
            foreach ($existingPath in $existingResultPaths) {
                Write-Host "    $(Split-Path $existingPath -Leaf)" -ForegroundColor DarkGray
            }
            $shouldDelete = Read-YesNoValue "  Delete them so this control starts with a clean results set?"
        }
        if ($shouldDelete) {
            foreach ($existingPath in $existingResultPaths) {
                Remove-Item -LiteralPath $existingPath -Force
            }
            Write-Host "  Deleted $($existingResultPaths.Count) existing result file(s)." -ForegroundColor Yellow
        }
    }
}
if ($directory -and -not (Test-Path -LiteralPath $directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}

$profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resolvedPath -Encoding UTF8
Write-Host "Wrote $resolvedPath" -ForegroundColor Green
$catalogPaths = @(Sync-SCTWorkspaceCatalogs -ScenariosPath $ScenariosPath -WorkspaceRoot $directory)
foreach ($catalogPath in $catalogPaths) {
    Write-Host "Wrote $catalogPath" -ForegroundColor Green
}
Write-Host "Workspace: $directory" -ForegroundColor Green
Write-Host "Check with: .\scripts\validation\Check-SCTControlProfile.ps1 -Path `"$resolvedPath`"" -ForegroundColor DarkGray
