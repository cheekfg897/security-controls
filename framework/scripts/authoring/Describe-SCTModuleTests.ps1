<#
.SYNOPSIS
    Describes a module's tests in its human-readable test-catalog.csv.

.DESCRIPTION
    Reads the technique and subtest identities from module.json, preserves
    matching existing catalogue text, and prompts for the three descriptions
    needed by later result review.

.EXAMPLE
    .\scripts\authoring\Describe-SCTModuleTests.ps1 `
        -ModulePath .\scenarios\05-data-exfiltration\module.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ModulePath,
    [string]$OutputPath,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-SCTCatalogText {
    param([string]$Prompt, [string]$Default)

    while ($true) {
        $label = if ($Default) { "$Prompt [$Default]" } else { $Prompt }
        $value = (Read-Host $label).Trim()
        if (-not $value) { $value = $Default }
        if ($value) { return $value }
        Write-Host '  A description is required.' -ForegroundColor Yellow
    }
}

function Read-SCTYesNo {
    param([string]$Prompt)
    while ($true) {
        $value = (Read-Host "$Prompt [y/N]").Trim()
        if (-not $value -or $value -match '^(n|no)$') { return $false }
        if ($value -match '^(y|yes)$') { return $true }
        Write-Host '  Enter Y or N.' -ForegroundColor Yellow
    }
}

$resolvedModulePath = (Resolve-Path -LiteralPath $ModulePath -ErrorAction Stop).Path
$module = Get-Content -LiteralPath $resolvedModulePath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $module.techniques) { throw "The module has no techniques: $resolvedModulePath" }

if (-not $OutputPath) {
    $OutputPath = Join-Path (Split-Path $resolvedModulePath -Parent) 'test-catalog.csv'
}
$resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

$existingByKey = @{}
if (Test-Path -LiteralPath $resolvedOutputPath -PathType Leaf) {
    foreach ($row in @(Import-Csv -LiteralPath $resolvedOutputPath -Encoding UTF8)) {
        $existingByKey["$($row.technique_id)|$($row.subtest)"] = $row
    }
}

$rows = @()
foreach ($technique in @($module.techniques)) {
    $subtests = if ($technique.PSObject.Properties['subtests']) { @($technique.subtests) } else { @('') }
    foreach ($subtest in $subtests) {
        $key = "$($technique.id)|$subtest"
        $existing = if ($existingByKey.ContainsKey($key)) { $existingByKey[$key] } else { $null }
        $variation = if ($subtest) { " / $subtest" } else { '' }

        Write-Host ''
        Write-Host "$($technique.id) $($technique.name)$variation" -ForegroundColor Cyan
        if ($existing -and $existing.objective -and $existing.what_it_does -and $existing.success_indicator) {
            $rows += [pscustomobject][ordered]@{
                technique_id      = [string]$technique.id
                subtest           = [string]$subtest
                objective         = [string]$existing.objective
                what_it_does       = [string]$existing.what_it_does
                success_indicator = [string]$existing.success_indicator
            }
            Write-Host 'Preserved existing description.' -ForegroundColor DarkGray
            continue
        }

        $defaultObjective = if ($existing) { [string]$existing.objective } elseif ($technique.PSObject.Properties['description']) { [string]$technique.description } else { '' }
        $defaultWhat = if ($existing) { [string]$existing.what_it_does } else { '' }
        $defaultSuccess = if ($existing) { [string]$existing.success_indicator } else { '' }

        $rows += [pscustomobject][ordered]@{
            technique_id      = [string]$technique.id
            subtest           = [string]$subtest
            objective         = Read-SCTCatalogText 'Objective' $defaultObjective
            what_it_does       = Read-SCTCatalogText 'What it does' $defaultWhat
            success_indicator = Read-SCTCatalogText 'Success indicator' $defaultSuccess
        }
    }
}

if ((Test-Path -LiteralPath $resolvedOutputPath) -and -not $Force -and
    -not (Read-SCTYesNo "Overwrite ${resolvedOutputPath}?")) {
    Write-Host 'No file was changed.' -ForegroundColor Yellow
    return
}

$directory = Split-Path $resolvedOutputPath -Parent
if ($directory -and -not (Test-Path -LiteralPath $directory)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}
$rows | Export-Csv -LiteralPath $resolvedOutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Wrote $($rows.Count) catalogue rows to $resolvedOutputPath" -ForegroundColor Green
Write-Host 'Check with: .\scripts\validation\Check-SCTTestDescriptions.ps1' -ForegroundColor DarkGray
