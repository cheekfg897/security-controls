<#
.SYNOPSIS
    Adds the module.json definition for a new SCT module.

.DESCRIPTION
    Guides an author through the module -> techniques -> subtests hierarchy.
    Execution behavior, run-all entries, and marker paths are inferred by SCT
    and are intentionally not stored in module.json.

.EXAMPLE
    .\scripts\Add-SCTModule.ps1

.EXAMPLE
    .\scripts\Add-SCTModule.ps1 -OutputPath .\scenarios\05-lateral-movement\module.json

.EXAMPLE
    .\scripts\Add-SCTModule.ps1 -NoWrite
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$NoWrite,
    [switch]$SkipTestDescriptions
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-Required {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string]$Default,
        [scriptblock]$Validate,
        [string]$ValidationMessage = 'Invalid value.'
    )

    while ($true) {
        $label = if ($Default) { "$Prompt [$Default]" } else { $Prompt }
        $value = (Read-Host $label).Trim()
        if (-not $value -and $Default) { $value = $Default }
        if ($value -and (-not $Validate -or (& $Validate $value))) { return $value }
        Write-Host "  $ValidationMessage" -ForegroundColor Yellow
    }
}

function Read-Optional {
    param([Parameter(Mandatory)][string]$Prompt, [string]$Default)

    $label = if ($Default) { "$Prompt [$Default]" } else { $Prompt }
    $value = (Read-Host $label).Trim()
    if (-not $value) { return $Default }
    return $value
}

function Read-YesNo {
    param([Parameter(Mandatory)][string]$Prompt, [bool]$Default = $false)

    $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $value = (Read-Host "$Prompt $suffix").Trim()
        if (-not $value) { return $Default }
        if ($value -match '^(y|yes)$') { return $true }
        if ($value -match '^(n|no)$') { return $false }
        Write-Host '  Enter Y or N.' -ForegroundColor Yellow
    }
}

function Read-List {
    param([Parameter(Mandatory)][string]$Prompt)

    $raw = (Read-Host $Prompt).Trim()
    if (-not $raw) { return @() }
    return @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function ConvertTo-Slug {
    param([Parameter(Mandatory)][string]$Value)

    $slug = ($Value.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
    if ($slug) { return $slug }
    return 'new-technique'
}

function Add-IfPresent {
    param(
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Target,
        [Parameter(Mandatory)][string]$Name,
        $Value
    )

    if ($null -eq $Value) { return }
    if ($Value -is [string] -and -not $Value) { return }
    if ($Value -is [array] -and $Value.Count -eq 0) { return }
    $Target[$Name] = $Value
}

Write-Host ''
Write-Host 'SCT module.json generator' -ForegroundColor Cyan
Write-Host 'Hierarchy: module -> techniques -> optional subtests' -ForegroundColor DarkGray
Write-Host ''

$moduleId = Read-Required -Prompt 'Module id, two digits' -Default '05' `
    -Validate { param($value) $value -match '^\d{2}$' } `
    -ValidationMessage 'Use two digits, for example 05.'
$moduleName = Read-Required -Prompt 'Module name' -Default 'Lateral Movement'
$moduleDescription = Read-Optional -Prompt 'Module description (optional)'
$moduleNumber = [int]$moduleId

if (-not $OutputPath) {
    $folder = Join-Path 'scenarios' ("{0}-{1}" -f $moduleId, (ConvertTo-Slug $moduleName))
    $OutputPath = Read-Optional -Prompt 'Output path' -Default (Join-Path $folder 'module.json')
}

$techniques = @()
$usedTechniqueIds = @{}
$index = 1
do {
    Write-Host ''
    Write-Host "Technique $index" -ForegroundColor Cyan

    $techniqueId = Read-Required -Prompt 'Technique id' -Default "$moduleNumber.$index" `
        -Validate {
            param($value)
            $value -match ("^{0}\.\d+$" -f $moduleNumber) -and
            -not $usedTechniqueIds.ContainsKey($value)
        } `
        -ValidationMessage "Use a unique ID from Module $moduleId, for example $moduleNumber.$index."
    $usedTechniqueIds[$techniqueId] = $true
    $name = Read-Required -Prompt 'Technique name'
    $description = Read-Optional -Prompt 'Technique description (optional)'
    $attackId = Read-Required -Prompt 'MITRE ATT&CK id (for example T1547.001)' `
        -Validate { param($value) $value -match '^T\d{4}(\.\d{3})?$' } `
        -ValidationMessage 'Use an ATT&CK ID such as T1059 or T1059.001.'
    $slug = ConvertTo-Slug $name
    $script = Read-Required -Prompt 'Script path, relative to the module folder' `
        -Default ("{0}-{1}/{0}-{1}.ps1" -f $techniqueId, $slug) `
        -Validate {
            param($value)
            -not [IO.Path]::IsPathRooted($value) -and
            [IO.Path]::GetExtension($value) -eq '.ps1' -and
            $value -notmatch '(^|[\\/])\.\.([\\/]|$)'
        } `
        -ValidationMessage 'Use a relative .ps1 path that stays inside the module folder.'

    $technique = [ordered]@{
        id = $techniqueId
        name = $name
    }
    Add-IfPresent -Target $technique -Name 'description' -Value $description
    $technique['attack_id'] = $attackId
    $technique['script'] = $script

    if (Read-YesNo -Prompt 'Is this technique still planned?' -Default $false) {
        $technique['status'] = 'planned'
    } else {
        while ($true) {
            $subtests = @(Read-List -Prompt 'Subtests, comma-separated (leave blank for none)')
            $reserved = @($subtests | Where-Object { $_ -in @('All', 'AllLocal', 'AllRemote') })
            $duplicates = @($subtests | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
            if ($reserved.Count -eq 0 -and $duplicates.Count -eq 0) { break }
            if ($reserved.Count -gt 0) {
                Write-Host "  Do not enter run-all choices; SCT adds them: $($reserved -join ', ')" -ForegroundColor Yellow
            }
            if ($duplicates.Count -gt 0) {
                Write-Host "  Remove duplicate subtests: $($duplicates -join ', ')" -ForegroundColor Yellow
            }
        }
        if ($subtests.Count -gt 0) {
            $technique['subtests'] = $subtests
            while ($true) {
                $serverSubtests = @(Read-List -Prompt 'Subtests that need a server VM (leave blank for none)')
                $invalid = @($serverSubtests | Where-Object { $subtests -notcontains $_ })
                $duplicates = @($serverSubtests | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
                if ($invalid.Count -eq 0 -and $duplicates.Count -eq 0) { break }
                if ($invalid.Count -gt 0) {
                    Write-Host "  Server subtests must also appear in subtests: $($invalid -join ', ')" -ForegroundColor Yellow
                }
                if ($duplicates.Count -gt 0) {
                    Write-Host "  Remove duplicate server subtests: $($duplicates -join ', ')" -ForegroundColor Yellow
                }
            }
            Add-IfPresent -Target $technique -Name 'server_subtests' -Value $serverSubtests
        }
    }

    $techniques += [pscustomobject]$technique
    $index++
} while (Read-YesNo -Prompt 'Add another technique?' -Default $false)

$module = [ordered]@{
    id = $moduleId
    name = $moduleName
}
Add-IfPresent -Target $module -Name 'description' -Value $moduleDescription
$module['techniques'] = @($techniques)

$json = [pscustomobject]$module | ConvertTo-Json -Depth 8
$null = $json | ConvertFrom-Json

Write-Host ''
Write-Host 'Generated module.json:' -ForegroundColor Cyan
Write-Host $json

if ($NoWrite) {
    Write-Host ''
    Write-Host 'NoWrite set; file was not written.' -ForegroundColor Yellow
    return
}

$resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$outputDir = Split-Path -Path $resolvedPath -Parent
if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
    if (-not (Read-YesNo -Prompt "Create directory $outputDir?" -Default $true)) { return }
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}
if ((Test-Path -LiteralPath $resolvedPath) -and
    -not (Read-YesNo -Prompt "Overwrite $resolvedPath?" -Default $false)) { return }

Set-Content -LiteralPath $resolvedPath -Value $json -Encoding UTF8
Write-Host ''
Write-Host "Wrote $resolvedPath" -ForegroundColor Green
if ($SkipTestDescriptions) {
    Write-Host 'Test descriptions were skipped. Add them later with:' -ForegroundColor Yellow
    Write-Host ".\scripts\Describe-SCTModuleTests.ps1 -ModulePath `"$resolvedPath`"" -ForegroundColor White
} else {
    Write-Host ''
    Write-Host 'Now describe the tests in this module.' -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot 'Describe-SCTModuleTests.ps1') -ModulePath $resolvedPath
}
