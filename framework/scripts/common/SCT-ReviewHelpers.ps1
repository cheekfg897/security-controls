# Internal shared helpers for the CSV-first SCT result-review workflow.
# Dot-source this file from review and validation scripts; do not run it directly.

Set-StrictMode -Version Latest

function Assert-SCTModuleId {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$ModuleId)

    if ($ModuleId -notmatch '^\d{2}$') {
        throw "Module id '$ModuleId' must contain two digits, for example '01'."
    }
}

function Get-SCTModuleResultsFileName {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$ModuleId)

    Assert-SCTModuleId -ModuleId $ModuleId
    return "results-module-$ModuleId.csv"
}

function Get-SCTModuleCatalogFileName {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$ModuleId)

    Assert-SCTModuleId -ModuleId $ModuleId
    return "test-catalog-module-$ModuleId.csv"
}

function Get-SCTModuleResultsPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$WorkspaceRoot,
        [Parameter(Mandatory)] [string]$ModuleId
    )

    return (Join-Path $WorkspaceRoot (Get-SCTModuleResultsFileName -ModuleId $ModuleId))
}

function Get-SCTModuleCatalogPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$WorkspaceRoot,
        [Parameter(Mandatory)] [string]$ModuleId
    )

    return (Join-Path $WorkspaceRoot (Get-SCTModuleCatalogFileName -ModuleId $ModuleId))
}

function Get-SCTWorkspaceResultPaths {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$WorkspaceRoot)

    if (-not (Test-Path -LiteralPath $WorkspaceRoot -PathType Container)) { return @() }
    return @(
        Get-ChildItem -LiteralPath $WorkspaceRoot -Filter 'results-module-*.csv' -File |
            Where-Object { $_.Name -match '^results-module-\d{2}\.csv$' } |
            Sort-Object Name |
            ForEach-Object FullName
    )
}

function Assert-SCTWorkspaceUsesModuleFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$WorkspaceRoot,
        [string]$ControlProfilePath = (Join-Path $WorkspaceRoot 'control-profile.json')
    )

    $legacyResults = Join-Path $WorkspaceRoot 'results.csv'
    $legacyCatalog = Join-Path $WorkspaceRoot 'test-catalog.csv'
    if ((Test-Path -LiteralPath $legacyResults -PathType Leaf) -or
        (Test-Path -LiteralPath $legacyCatalog -PathType Leaf)) {
        throw ("Legacy combined workspace files were found in '$WorkspaceRoot'. Convert them with: " +
            ".\scripts\review\Convert-SCTLegacyWorkspace.ps1 -ControlProfilePath `"$ControlProfilePath`"")
    }
}

function Get-SCTAnalysisPropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $InputObject,
        [Parameter(Mandatory)] [string]$Name,
        $Default = $null
    )

    if ($null -eq $InputObject) { return $Default }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $Default
}

function Test-SCTAnalysisValuePresent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $InputObject,
        [Parameter(Mandatory)] [string]$Name
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if (-not $property -or $null -eq $property.Value) { return $false }
    if ($property.Value -is [string]) {
        return -not [string]::IsNullOrWhiteSpace([string]$property.Value)
    }
    return $true
}

function Get-SCTUnknownFieldErrors {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $InputObject,
        [Parameter(Mandatory)] [string[]]$AllowedFields,
        [Parameter(Mandatory)] [string]$Context
    )

    $errors = @()
    if ($null -eq $InputObject) { return $errors }
    foreach ($name in $InputObject.PSObject.Properties.Name) {
        if ($AllowedFields -notcontains $name) {
            $errors += "$Context has unknown field '$name'."
        }
    }
    return $errors
}

function Get-SCTControlProfileErrors {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Profile)

    $errors = @()
    $errors += Get-SCTUnknownFieldErrors -InputObject $Profile `
        -AllowedFields @('schema_version', 'control', 'policy', 'local_logs', 'notes') `
        -Context 'Control profile'

    foreach ($required in @('schema_version', 'control', 'policy')) {
        if (-not (Test-SCTAnalysisValuePresent -InputObject $Profile -Name $required)) {
            $errors += "Control profile is missing required field '$required'."
        }
    }

    $schemaVersion = [string](Get-SCTAnalysisPropertyValue -InputObject $Profile -Name 'schema_version' -Default '')
    if ($schemaVersion -and $schemaVersion -ne '1.0') {
        $errors += "Unsupported control profile schema_version '$schemaVersion'; expected '1.0'."
    }

    $control = Get-SCTAnalysisPropertyValue -InputObject $Profile -Name 'control'
    if ($control) {
        $errors += Get-SCTUnknownFieldErrors -InputObject $control `
            -AllowedFields @('id', 'display_name', 'vendor', 'product', 'product_version', 'agent_version') `
            -Context 'Control profile control'
        foreach ($required in @('id', 'display_name', 'vendor', 'product', 'product_version', 'agent_version')) {
            if (-not (Test-SCTAnalysisValuePresent -InputObject $control -Name $required)) {
                $errors += "Control profile control is missing required field '$required'."
            }
        }
        $controlId = [string](Get-SCTAnalysisPropertyValue -InputObject $control -Name 'id' -Default '')
        if ($controlId -and $controlId -notmatch '^[a-z0-9][a-z0-9._-]*$') {
            $errors += "Control id '$controlId' must use lowercase letters, digits, dots, underscores, or hyphens."
        }
    }

    $policy = Get-SCTAnalysisPropertyValue -InputObject $Profile -Name 'policy'
    if ($policy) {
        $errors += Get-SCTUnknownFieldErrors -InputObject $policy `
            -AllowedFields @('name', 'default_mode', 'settings', 'exclusions') `
            -Context 'Control profile policy'
        foreach ($required in @('name', 'default_mode')) {
            if (-not (Test-SCTAnalysisValuePresent -InputObject $policy -Name $required)) {
                $errors += "Control profile policy is missing required field '$required'."
            }
        }
        $mode = [string](Get-SCTAnalysisPropertyValue -InputObject $policy -Name 'default_mode' -Default '')
        if ($mode -and $mode -notin @('detect_only', 'detect_and_block', 'custom')) {
            $errors += "Policy default_mode '$mode' must be detect_only, detect_and_block, or custom."
        }

        $settings = @(Get-SCTAnalysisPropertyValue -InputObject $policy -Name 'settings' -Default @())
        for ($index = 0; $index -lt $settings.Count; $index++) {
            $setting = $settings[$index]
            if ($null -eq $setting) {
                $errors += "Policy settings contains a null entry at index $index."
                continue
            }
            $errors += Get-SCTUnknownFieldErrors -InputObject $setting `
                -AllowedFields @('name', 'value', 'scope', 'notes') `
                -Context "Policy setting at index $index"
            foreach ($required in @('name', 'value', 'scope')) {
                if (-not (Test-SCTAnalysisValuePresent -InputObject $setting -Name $required)) {
                    $errors += "Policy setting at index $index is missing required field '$required'."
                }
            }
        }

        $exclusions = @(Get-SCTAnalysisPropertyValue -InputObject $policy -Name 'exclusions' -Default @())
        for ($index = 0; $index -lt $exclusions.Count; $index++) {
            if ([string]::IsNullOrWhiteSpace([string]$exclusions[$index])) {
                $errors += "Policy exclusions contains an empty entry at index $index."
            }
        }
    }

    $localLogs = @(Get-SCTAnalysisPropertyValue -InputObject $Profile -Name 'local_logs' -Default @())
    for ($index = 0; $index -lt $localLogs.Count; $index++) {
        $log = $localLogs[$index]
        if ($null -eq $log) {
            $errors += "local_logs contains a null entry at index $index."
            continue
        }
        $errors += Get-SCTUnknownFieldErrors -InputObject $log `
            -AllowedFields @('name', 'path', 'format') `
            -Context "Local log at index $index"
        foreach ($required in @('name', 'path', 'format')) {
            if (-not (Test-SCTAnalysisValuePresent -InputObject $log -Name $required)) {
                $errors += "Local log at index $index is missing required field '$required'."
            }
        }
        $format = [string](Get-SCTAnalysisPropertyValue -InputObject $log -Name 'format' -Default '')
        if ($format -and $format -notin @('text', 'csv', 'json', 'jsonl', 'xml', 'evtx')) {
            $errors += "Local log format '$format' at index $index is unsupported."
        }
    }

    return $errors
}

function Get-SCTCatalogData {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$ScenariosPath)

    $errors = @()
    $combinedRows = @()
    $moduleFiles = @(Get-ChildItem -LiteralPath $ScenariosPath -Filter 'module.json' -File -Recurse | Sort-Object FullName)
    if ($moduleFiles.Count -eq 0) {
        $errors += "No module.json files found under: $ScenariosPath"
        return [pscustomobject]@{ Rows = @(); Errors = @($errors) }
    }

    foreach ($moduleFile in $moduleFiles) {
        try {
            $module = Get-Content -LiteralPath $moduleFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
            $errors += "Could not read $($moduleFile.FullName): $($_.Exception.Message)"
            continue
        }

        $catalogPath = Join-Path $moduleFile.Directory.FullName 'test-catalog.csv'
        if (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) {
            $errors += "Module $($module.id) is missing test-catalog.csv."
            continue
        }

        try {
            $catalogRows = @(Import-Csv -LiteralPath $catalogPath -Encoding UTF8)
        } catch {
            $errors += "Could not read ${catalogPath}: $($_.Exception.Message)"
            continue
        }

        $requiredColumns = @('technique_id', 'subtest', 'objective', 'what_it_does', 'success_indicator')
        $header = Get-Content -LiteralPath $catalogPath -TotalCount 1 -Encoding UTF8
        foreach ($column in $requiredColumns) {
            if ($header -notmatch ('(^|,)"?' + [regex]::Escape($column) + '"?(,|$)')) {
                $errors += "$catalogPath is missing required column '$column'."
            }
        }

        $catalogByKey = @{}
        foreach ($row in $catalogRows) {
            $techniqueId = [string]$row.technique_id
            $subtest = [string]$row.subtest
            $key = "$techniqueId|$subtest"
            if ($catalogByKey.ContainsKey($key)) {
                $errors += "$catalogPath contains duplicate row '$techniqueId/$subtest'."
                continue
            }
            $catalogByKey[$key] = $row
            foreach ($column in @('technique_id', 'objective', 'what_it_does', 'success_indicator')) {
                if ([string]::IsNullOrWhiteSpace([string]$row.$column)) {
                    $errors += "$catalogPath row '$techniqueId/$subtest' has an empty '$column'."
                }
            }
        }

        $validKeys = @{}
        foreach ($technique in @($module.techniques)) {
            $subtests = @(Get-SCTAnalysisPropertyValue -InputObject $technique -Name 'subtests' -Default @())
            $expectedSubtests = if ($subtests.Count -gt 0) { @($subtests) } else { @('') }
            foreach ($subtest in $expectedSubtests) {
                $key = "$($technique.id)|$subtest"
                $validKeys[$key] = $true
                if (-not $catalogByKey.ContainsKey($key)) {
                    $errors += "$catalogPath is missing a row for '$($technique.id)/$subtest'."
                    continue
                }

                $row = $catalogByKey[$key]
                $status = [string](Get-SCTAnalysisPropertyValue -InputObject $technique -Name 'status' -Default '')
                $relativeScript = ('scenarios/{0}/{1}' -f $moduleFile.Directory.Name, [string]$technique.script) -replace '\\', '/'
                $combinedRows += [pscustomobject][ordered]@{
                    module_id         = [string]$module.id
                    module_name       = [string]$module.name
                    technique_id      = [string]$technique.id
                    technique_name    = [string]$technique.name
                    subtest           = [string]$subtest
                    attack_id         = [string]$technique.attack_id
                    test_script       = $relativeScript
                    objective         = [string]$row.objective
                    what_it_does       = [string]$row.what_it_does
                    success_indicator = [string]$row.success_indicator
                    status            = $status
                }
            }
        }

        foreach ($key in $catalogByKey.Keys) {
            if (-not $validKeys.ContainsKey($key)) {
                $errors += "$catalogPath contains unknown technique/subtest row '$key'."
            }
        }
    }

    return [pscustomobject]@{ Rows = @($combinedRows); Errors = @($errors) }
}

function Sync-SCTWorkspaceCatalogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ScenariosPath,
        [Parameter(Mandatory)] [string]$WorkspaceRoot
    )

    $catalog = Get-SCTCatalogData -ScenariosPath $ScenariosPath
    if ($catalog.Errors.Count -gt 0) {
        throw "Invalid SCT test catalog:`n$($catalog.Errors -join "`n")"
    }
    if (-not (Test-Path -LiteralPath $WorkspaceRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $WorkspaceRoot -Force | Out-Null
    }

    $writtenPaths = @()
    foreach ($moduleGroup in @($catalog.Rows | Group-Object module_id | Sort-Object Name)) {
        $catalogPath = Get-SCTModuleCatalogPath -WorkspaceRoot $WorkspaceRoot -ModuleId $moduleGroup.Name
        $moduleGroup.Group |
            Select-Object module_id, module_name, technique_id, technique_name, subtest, attack_id, test_script, `
                objective, what_it_does, success_indicator, status |
            Export-Csv -LiteralPath $catalogPath -NoTypeInformation -Encoding UTF8
        $writtenPaths += $catalogPath
    }
    return @($writtenPaths)
}

function Get-SCTCsvRowValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Row,
        [Parameter(Mandatory)] [string[]]$Names,
        [string]$Default = ''
    )

    foreach ($name in $Names) {
        $property = $Row.PSObject.Properties[$name]
        if ($property -and $null -ne $property.Value) {
            return [string]$property.Value
        }
    }
    return $Default
}
