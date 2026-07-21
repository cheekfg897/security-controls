<#
.SYNOPSIS
    Sets up the JSON profile for the security control tested in this VM.

.DESCRIPTION
    Prompts for the common control and policy fields, then optionally collects
    vendor-specific settings, exclusions, and local log locations. Use
    -NonInteractive with the named parameters for automation and tests.

.EXAMPLE
    .\scripts\Setup-SCTControl.ps1

.EXAMPLE
    .\scripts\Setup-SCTControl.ps1 -NonInteractive -Force `
        -ControlId control-a -DisplayName 'Control A' -Vendor Vendor `
        -Product Product -ProductVersion 1.0 -AgentVersion 1.0 `
        -PolicyName 'Evaluation Policy' -DefaultMode detect_only
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
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
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_SCT-ReviewHelpers.ps1')

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

$repoRoot = Split-Path $PSScriptRoot -Parent
if (-not $OutputPath) {
    $OutputPath = Join-Path $repoRoot 'config\control-profile.local.json'
}

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
    if ($NonInteractive -or -not (Read-YesNoValue "Overwrite $resolvedPath?")) {
        throw "Output file already exists: $resolvedPath"
    }
}
$directory = Split-Path $resolvedPath -Parent
if ($directory -and -not (Test-Path -LiteralPath $directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}

$profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resolvedPath -Encoding UTF8
Write-Host "Wrote $resolvedPath" -ForegroundColor Green
Write-Host "Check with: .\scripts\Check-SCTControlProfile.ps1 -Path `"$resolvedPath`"" -ForegroundColor DarkGray
