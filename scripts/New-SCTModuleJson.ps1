<#
.SYNOPSIS
    Interactively creates a scenarios/<module>/module.json manifest for SCT.

.DESCRIPTION
    Prompts for module-level metadata and one or more vectors, then writes a
    formatted module.json file. By default, it omits legacy "supports" metadata
    because the launcher dispatches by "type" and does not read "supports".

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
    [switch]$NoWrite,
    [switch]$IncludeSupports
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ValidVectorTypes = @(
    'technique',
    'fileless',
    'malware-batch',
    'removable-media',
    'client-server',
    'simple',
    'not-implemented'
)

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

        if (-not [string]::IsNullOrWhiteSpace($value)) {
            if (-not $Validate -or (& $Validate $value)) {
                return $value
            }
            Write-Host "  $ValidationMessage" -ForegroundColor Yellow
        } else {
            Write-Host '  Value is required.' -ForegroundColor Yellow
        }
    }
}

function Read-Optional {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string]$Default
    )

    $label = if ($Default) { "$Prompt [$Default]" } else { $Prompt }
    $value = (Read-Host $label).Trim()
    if (-not $value -and $Default) { return $Default }
    return $value
}

function Read-YesNo {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [bool]$Default = $false
    )

    $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $value = (Read-Host "$Prompt $suffix").Trim()
        if (-not $value) { return $Default }
        if ($value -match '^(y|yes)$') { return $true }
        if ($value -match '^(n|no)$') { return $false }
        Write-Host '  Enter Y or N.' -ForegroundColor Yellow
    }
}

function Read-CsvList {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string[]]$Default = @(),
        [switch]$Required
    )

    $defaultText = if ($Default.Count -gt 0) { $Default -join ', ' } else { $null }
    while ($true) {
        $label = if ($defaultText) { "$Prompt [$defaultText]" } else { $Prompt }
        $raw = (Read-Host $label).Trim()
        if (-not $raw -and $Default.Count -gt 0) {
            return @($Default)
        }

        $items = @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($items.Count -gt 0 -or -not $Required) {
            return $items
        }

        Write-Host '  Enter at least one comma-separated value.' -ForegroundColor Yellow
    }
}

function ConvertTo-Slug {
    param([Parameter(Mandatory)][string]$Value)

    $slug = $Value.ToLowerInvariant()
    $slug = $slug -replace '[^a-z0-9]+', '-'
    $slug = $slug.Trim('-')
    if (-not $slug) { return 'new-module' }
    return $slug
}

function Get-SupportsForType {
    param([Parameter(Mandatory)][string]$Type)

    switch ($Type) {
        'malware-batch'   { return @('control', 'source_path', 'execute', 'dry_run', 'summarize') }
        'removable-media' { return @('control', 'drive_letter', 'execute', 'dry_run', 'summarize') }
        'client-server'   { return @('control', 'server_ip', 'port', 'execute', 'dry_run', 'summarize') }
        'technique'       { return @('technique') }
        'fileless'        { return @('technique', 'server_ip', 'port') }
        default           { return @() }
    }
}

function Add-OptionalProperty {
    param(
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Target,
        [Parameter(Mandatory)][string]$Name,
        $Value
    )

    if ($null -eq $Value) { return }
    if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) { return }
    if ($Value -is [array] -and $Value.Count -eq 0) { return }

    $Target[$Name] = $Value
}

Write-Host ''
Write-Host 'SCT module.json generator' -ForegroundColor Cyan
Write-Host 'Creates a module manifest from guided prompts.' -ForegroundColor DarkGray
Write-Host ''

$moduleId = Read-Required `
    -Prompt 'Module id, two digits' `
    -Default '05' `
    -Validate { param($v) $v -match '^\d{2}$' } `
    -ValidationMessage 'Use two digits, e.g. 05.'

$displayName = Read-Required -Prompt 'Display name' -Default 'Lateral Movement'
$description = Read-Required -Prompt 'Module description'
$mitreTactics = Read-CsvList -Prompt 'MITRE tactics, comma-separated' -Required
$moduleNumber = [int]$moduleId

if (-not $OutputPath) {
    $defaultFolder = Join-Path 'scenarios' ("{0}-{1}" -f $moduleId, (ConvertTo-Slug $displayName))
    $defaultOutputPath = Join-Path $defaultFolder 'module.json'
    $OutputPath = Read-Optional -Prompt 'Output path' -Default $defaultOutputPath
}

$vectors = @()
$vectorIndex = 1

do {
    Write-Host ''
    Write-Host "Vector $vectorIndex" -ForegroundColor Cyan

    $defaultVectorId = "$moduleNumber.$vectorIndex"
    $vectorId = Read-Required -Prompt 'Vector id' -Default $defaultVectorId
    $vectorName = Read-Required -Prompt 'Vector name'
    $vectorDescription = Read-Required -Prompt 'Vector description'
    $mitre = Read-Required -Prompt 'MITRE technique id' -Default 'T0000'
    $vectorSlug = ConvertTo-Slug $vectorName
    $defaultScriptPath = "v$vectorId-$vectorSlug/v$vectorId-$vectorSlug.ps1"
    $script = Read-Required -Prompt 'Script path, relative to module folder' -Default $defaultScriptPath

    Write-Host ''
    Write-Host 'Vector types:' -ForegroundColor White
    for ($i = 0; $i -lt $ValidVectorTypes.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i + 1), $ValidVectorTypes[$i]) -ForegroundColor DarkGray
    }

    $typeChoice = Read-Required `
        -Prompt 'Vector type, name or number' `
        -Default 'not-implemented' `
        -Validate {
            param($v)
            (($v -as [int]) -ge 1 -and ($v -as [int]) -le $ValidVectorTypes.Count) -or ($ValidVectorTypes -contains $v)
        } `
        -ValidationMessage 'Choose one of the listed types.'

    $typeNumber = $typeChoice -as [int]
    $type = if ($typeNumber -ge 1 -and $typeNumber -le $ValidVectorTypes.Count) {
        $ValidVectorTypes[$typeNumber - 1]
    } else {
        $typeChoice
    }

    $vector = [ordered]@{
        id = $vectorId
        name = $vectorName
        description = $vectorDescription
        mitre = $mitre
        script = $script
        type = $type
    }

    if ($type -eq 'technique' -or $type -eq 'fileless') {
        $techniques = Read-CsvList -Prompt 'Techniques, comma-separated' -Required
        if (($techniques -notcontains 'All') -and (Read-YesNo -Prompt 'Add All as the final technique?' -Default $true)) {
            $techniques += 'All'
        }
        Add-OptionalProperty -Target $vector -Name 'techniques' -Value $techniques
    }

    if ($type -eq 'technique') {
        $individual = @($vector['techniques'] | Where-Object { $_ -ne 'All' })
        Add-OptionalProperty -Target $vector -Name 'individual_techniques' -Value $individual

        $defaultMarker = "C:\Windows\Temp\art-v$vectorId-{technique}.txt"
        $marker = Read-Optional -Prompt 'Marker file template' -Default $defaultMarker
        Add-OptionalProperty -Target $vector -Name 'marker_file' -Value $marker

        $defaultTechnique = Read-Optional -Prompt 'Default technique (optional)'
        Add-OptionalProperty -Target $vector -Name 'default_technique' -Value $defaultTechnique
    }

    if ($type -eq 'fileless') {
        $remoteTechniques = Read-CsvList -Prompt 'Remote techniques that need server VM, comma-separated'
        Add-OptionalProperty -Target $vector -Name 'remote_techniques' -Value $remoteTechniques
    }

    if ($IncludeSupports) {
        $vector['supports'] = @(Get-SupportsForType -Type $type)
    }

    $vectors += [pscustomobject]$vector
    $vectorIndex++
} while (Read-YesNo -Prompt 'Add another vector?' -Default $false)

$manifest = [ordered]@{
    id = $moduleId
    display_name = $displayName
    description = $description
    mitre_tactics = @($mitreTactics)
    vectors = @($vectors)
}

$json = [pscustomobject]$manifest | ConvertTo-Json -Depth 12
$null = $json | ConvertFrom-Json

Write-Host ''
Write-Host 'Generated module.json:' -ForegroundColor Cyan
Write-Host $json

if ($NoWrite) {
    Write-Host ''
    Write-Host 'NoWrite set; file was not written.' -ForegroundColor Yellow
    return
}

$resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$outputDir = Split-Path -Path $resolvedOutputPath -Parent

if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
    if (Read-YesNo -Prompt "Create directory $outputDir?" -Default $true) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    } else {
        Write-Host 'Directory was not created; manifest was not written.' -ForegroundColor Yellow
        return
    }
}

if ((Test-Path -LiteralPath $resolvedOutputPath) -and -not (Read-YesNo -Prompt "Overwrite $resolvedOutputPath?" -Default $false)) {
    Write-Host 'Existing file left unchanged.' -ForegroundColor Yellow
    return
}

Set-Content -LiteralPath $resolvedOutputPath -Value $json -Encoding UTF8
Write-Host ''
Write-Host "Wrote $resolvedOutputPath" -ForegroundColor Green
