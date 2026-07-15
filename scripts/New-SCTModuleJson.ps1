<#
.SYNOPSIS
    Creates a simplified SCT module.json file.

.DESCRIPTION
    Guides an author through the module -> techniques -> subtests hierarchy.
    Execution behavior, run-all entries, and marker paths are inferred by SCT
    and are intentionally not stored in module.json.

.EXAMPLE
    .\scripts\New-SCTModuleJson.ps1

.EXAMPLE
    .\scripts\New-SCTModuleJson.ps1 -OutputPath .\scenarios\05-lateral-movement\module.json

.EXAMPLE
    .\scripts\New-SCTModuleJson.ps1 -NoWrite
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$NoWrite
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
$index = 1
do {
    Write-Host ''
    Write-Host "Technique $index" -ForegroundColor Cyan

    $techniqueId = Read-Required -Prompt 'Technique id' -Default "$moduleNumber.$index" `
        -Validate { param($value) $value -match '^\d+\.\d+$' } `
        -ValidationMessage 'Use module.technique notation, for example 5.1.'
    $name = Read-Required -Prompt 'Technique name'
    $description = Read-Optional -Prompt 'Technique description (optional)'
    $attackId = Read-Required -Prompt 'MITRE ATT&CK id' -Default 'T0000'
    $slug = ConvertTo-Slug $name
    $script = Read-Required -Prompt 'Script path, relative to the module folder' `
        -Default ("{0}-{1}/{0}-{1}.ps1" -f $techniqueId, $slug)

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
        $subtests = @(Read-List -Prompt 'Subtests, comma-separated (leave blank for none)')
        if ($subtests.Count -gt 0) {
            $technique['subtests'] = $subtests
            $serverSubtests = @(Read-List -Prompt 'Subtests that need a server VM (leave blank for none)')
            $invalid = @($serverSubtests | Where-Object { $subtests -notcontains $_ })
            if ($invalid.Count -gt 0) {
                throw "Server subtests must also appear in subtests: $($invalid -join ', ')"
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
