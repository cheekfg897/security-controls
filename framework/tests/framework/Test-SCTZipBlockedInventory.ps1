<#
.SYNOPSIS
    Verifies that pre-extraction inventory retains a sample removed before
    selection without using a real malware fixture.
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

$tempRoot = Join-Path $PSScriptRoot (
    '.tmp-zip-blocked-inventory-' + [guid]::NewGuid().ToString('N')
)

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $sourceDir = Join-Path $tempRoot 'source'
    $zipPath = Join-Path $tempRoot 'samples.zip'
    $stagingRoot = Join-Path $tempRoot 'staging'
    New-Item -ItemType Directory -Path $sourceDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $sourceDir 'available.exe') `
        -Value 'inert available executable fixture' -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $sourceDir 'removed.exe') `
        -Value 'inert removed executable fixture' -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $sourceDir 'settings.ini') `
        -Value 'fixture=true' -Encoding ASCII
    [System.IO.Compression.ZipFile]::CreateFromDirectory($sourceDir, $zipPath)

    # Simulate a control interrupting extraction after one harmless fixture.
    function Invoke-ZipExtraction {
        param(
            [Parameter(Mandatory)][string]$ZipPath,
            [Parameter(Mandatory)][string]$DestPath,
            [string]$Password = ''
        )

        New-Item -ItemType Directory -Path $DestPath -Force | Out-Null
        $archive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
        try {
            $entry = $archive.Entries | Where-Object { $_.FullName -eq 'available.exe' }
            $inputStream = $entry.Open()
            $outputStream = [System.IO.File]::Create((Join-Path $DestPath 'available.exe'))
            try {
                $inputStream.CopyTo($outputStream)
            } finally {
                $outputStream.Dispose()
                $inputStream.Dispose()
            }
        } finally {
            $archive.Dispose()
        }
        throw 'simulated antivirus interruption'
    }

    $stagedPath = Merge-StagingFromZips `
        -Zips @((Get-Item -LiteralPath $zipPath)) -StagingRoot $stagingRoot
    $manifestPath = Join-Path $stagedPath '.sct-bundles.json'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $bundle = @($manifest.bundles)[0]
    $expected = @($bundle.expected_files)
    $available = $expected | Where-Object { $_.name -eq 'available.exe' }
    $removed = $expected | Where-Object { $_.name -eq 'removed.exe' }

    Assert-True ([int]$manifest.schema_version -eq 2) `
        'Staging must write the pre-extraction inventory schema.'
    Assert-True ($expected.Count -eq 2) `
        'Both recognized archive members must remain in the manifest.'
    Assert-True ([bool]$available.present_after_extraction) `
        'The extracted fixture must be marked present.'
    Assert-True (-not [bool]$removed.present_after_extraction) `
        'The interrupted fixture must remain recorded as missing.'
    Assert-True (-not [string]::IsNullOrWhiteSpace([string]$removed.sha256)) `
        'A password-free member must retain its pre-extraction SHA-256.'
    Assert-True ([string]$bundle.extraction_error -like '*simulated antivirus*') `
        'The manifest must retain the extraction interruption.'

    $scenarioPath = Join-Path $repoRoot `
        'scenarios\01-malware-delivery\v1.1-known-malware\v1.1-known-malware.ps1'
    & $scenarioPath -SourcePath $stagedPath -Control 'Fixture Control' -Execute -DryRun |
        Out-Null
    Assert-True $true `
        'Technique 1.1 must accept a bundle with a missing expected member.'

    Write-Host "Passed $script:Assertions blocked-inventory assertions." -ForegroundColor Green
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        $resolvedTemp = (Resolve-Path -LiteralPath $tempRoot).Path
        $resolvedTests = (Resolve-Path -LiteralPath $PSScriptRoot).Path
        if (-not $resolvedTemp.StartsWith($resolvedTests, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove fixture outside the test directory: $resolvedTemp"
        }
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }
}
