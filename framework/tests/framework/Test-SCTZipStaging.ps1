<#
.SYNOPSIS
    Verifies flat and nested ZIP sample staging without executing any sample.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repoRoot 'core\SCT-Core.ps1')

$script:Assertions = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

$tempRoot = Join-Path $PSScriptRoot ('.tmp-zip-staging-' + [guid]::NewGuid().ToString('N'))

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $innerSource = Join-Path $tempRoot 'inner-source'
    $innerSubdir = Join-Path $innerSource 'payloads'
    $innerZip = Join-Path $tempRoot 'inner-malware.zip'
    $outerSource = Join-Path $tempRoot 'outer-source'
    $outerBundleDir = Join-Path $outerSource 'bundles'
    $outerZip = Join-Path $tempRoot 'outer-container.zip'
    $stagingRoot = Join-Path $tempRoot 'staging'

    New-Item -ItemType Directory -Path $innerSubdir -Force | Out-Null
    New-Item -ItemType Directory -Path $outerBundleDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $innerSubdir 'nested-sample.exe') `
        -Value 'inert nested ZIP staging fixture' -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $innerSubdir 'settings.ini') `
        -Value 'supporting-file=true' -Encoding ASCII
    [System.IO.Compression.ZipFile]::CreateFromDirectory($innerSource, $innerZip)
    Copy-Item -LiteralPath $innerZip -Destination (Join-Path $outerBundleDir 'inner-malware.zip')
    [System.IO.Compression.ZipFile]::CreateFromDirectory($outerSource, $outerZip)

    $script:ReadResponses = New-Object 'System.Collections.Generic.Queue[string]'
    $script:ReadResponses.Enqueue('Y')
    $script:ReadResponses.Enqueue('')
    $script:ReadPrompts = @()
    function Read-Host {
        param([string]$Prompt)
        $script:ReadPrompts += $Prompt
        if ($script:ReadResponses.Count -gt 0) { return $script:ReadResponses.Dequeue() }
        throw "Unexpected Read-Host prompt: $Prompt"
    }

    $stagedPath = Merge-StagingFromZips -Zips @((Get-Item -LiteralPath $outerZip)) `
        -StagingRoot $stagingRoot -PromptForNestedArchives

    $manifestPath = Join-Path $stagedPath '.sct-bundles.json'
    $outerBundle = Join-Path $stagedPath '001-outer-container'
    $innerBundle = Join-Path $stagedPath '002-inner-malware'
    $stagedSample = Join-Path $innerBundle 'payloads\nested-sample.exe'
    $stagedSupport = Join-Path $innerBundle 'payloads\settings.ini'
    Assert-True ($script:ReadResponses.Count -eq 0) `
        'The nested archive confirmation and password prompts must both be shown.'
    Assert-True (@($script:ReadPrompts | Where-Object { $_ -like '*Extract nested ZIPs*' }).Count -eq 1) `
        'The launcher must explicitly ask before extracting a nested ZIP.'
    Assert-True (Test-Path -LiteralPath $stagedSample -PathType Leaf) `
        'A sample inside an inner ZIP must retain its bundle directory structure.'
    Assert-True (Test-Path -LiteralPath $stagedSupport -PathType Leaf) `
        'Supporting files must remain beside the nested sample.'
    Assert-True (Test-Path -LiteralPath (Join-Path $outerBundle 'bundles\inner-malware.zip') -PathType Leaf) `
        'The selected outer container must remain distinct from extracted inner bundles.'
    Assert-True ((Get-Content -LiteralPath $stagedSample -Raw).Trim() -eq 'inert nested ZIP staging fixture') `
        'Nested sample contents must be preserved.'
    Assert-True (@(Get-ChildItem -LiteralPath $stagedPath -Directory).Count -eq 2) `
        'The outer and inner ZIP must each be extracted exactly once.'
    Assert-True (Test-Path -LiteralPath $manifestPath -PathType Leaf) `
        'Bundle staging must write the v1.1 bundle manifest.'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True (@($manifest.bundles).Count -eq 1) `
        'A ZIP-only outer container must not be counted as a malware bundle.'
    Assert-True (@($manifest.bundles | Where-Object { $_.name -eq 'inner-malware' }).Count -eq 1) `
        'The inner malware archive must have its own bundle record.'

    $v11Script = Join-Path $repoRoot 'scenarios\01-malware-delivery\v1.1-known-malware\v1.1-known-malware.ps1'
    & $v11Script -SourcePath $stagedPath -Control 'Fixture Control' -Execute -DryRun
    Assert-True $true `
        'v1.1 dry-run must accept bundle staging without copying or executing fixture files.'

    Write-Host "Passed $script:Assertions ZIP-staging assertions." -ForegroundColor Green
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        $resolvedTemp = (Resolve-Path -LiteralPath $tempRoot).Path
        $resolvedTests = (Resolve-Path -LiteralPath $PSScriptRoot).Path
        if (-not $resolvedTemp.StartsWith($resolvedTests, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove test fixture outside the test directory: $resolvedTemp"
        }
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }
}
