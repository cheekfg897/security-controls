<#
.SYNOPSIS
    Checks every SCT module.json file and its script contract.

.EXAMPLE
    .\scripts\validation\Check-SCTModules.ps1
#>

[CmdletBinding()]
param(
    [string]$ScenariosPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptsRoot = Split-Path $PSScriptRoot -Parent
$repoRoot = Split-Path $scriptsRoot -Parent
if (-not $ScenariosPath) {
    $ScenariosPath = Join-Path $repoRoot 'scenarios'
}
. (Join-Path $repoRoot 'core\SCT-Core.ps1')

$failed = $false
$moduleFiles = @(Get-ChildItem -Path $ScenariosPath -Filter 'module.json' -File -Recurse | Sort-Object FullName)
if ($moduleFiles.Count -eq 0) {
    Write-Error "No module.json files found under: $ScenariosPath"
}

foreach ($file in $moduleFiles) {
    try {
        $module = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        $errors = @(Get-SCTModuleErrors -Module $module -ModuleDir $file.Directory.FullName)
        if ($errors.Count -gt 0) {
            $failed = $true
            Write-Host "[FAIL] $($file.FullName)" -ForegroundColor Red
            foreach ($message in $errors) {
                Write-Host "       $message" -ForegroundColor Red
            }
            continue
        }

        Write-Host "[OK]   Module $($module.id): $($module.name)" -ForegroundColor Green
        foreach ($technique in @($module.techniques)) {
            $status = Get-SCTPropertyValue -InputObject $technique -Name 'status' -Default ''
            if ($status -eq 'planned') {
                Write-Host "       $($technique.id) planned" -ForegroundColor DarkGray
                continue
            }
            $scriptPath = Join-Path $file.Directory.FullName $technique.script
            $workflow = Get-SCTTechniqueWorkflow -Technique $technique -ScriptPath $scriptPath
            $subtestCount = @(Get-SCTPropertyValue -InputObject $technique -Name 'subtests' -Default @()).Count
            $detail = if ($subtestCount -gt 0) { "$workflow, $subtestCount subtests" } else { $workflow }
            Write-Host "       $($technique.id) $detail" -ForegroundColor DarkGray
        }
    } catch {
        $failed = $true
        Write-Host "[FAIL] $($file.FullName)" -ForegroundColor Red
        Write-Host "       $($_.Exception.Message)" -ForegroundColor Red
    }
}

if ($failed) { exit 1 }
Write-Host "Validated $($moduleFiles.Count) module files." -ForegroundColor Cyan
