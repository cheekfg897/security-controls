<#
.SYNOPSIS
    Verifies interactive handling of an existing module results CSV.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $repoRoot 'core\SCT-Core.ps1')

$script:Assertions = 0
$script:ReadResponses = [System.Collections.Generic.Queue[string]]::new()
$script:ReadPrompts = @()

function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "Assertion failed: $Message" }
}

function Read-Host {
    param([string]$Prompt)

    $script:ReadPrompts += $Prompt
    if ($script:ReadResponses.Count -eq 0) {
        throw "No mocked response remains for prompt: $Prompt"
    }
    return $script:ReadResponses.Dequeue()
}

$tempRoot = Join-Path $PSScriptRoot (
    '.tmp-existing-results-prompt-' + [guid]::NewGuid().ToString('N')
)
New-Item -ItemType Directory -Path $tempRoot | Out-Null

try {
    $resultsPath = Join-Path $tempRoot 'results-module-01.csv'

    $script:ReadResponses.Enqueue('N')
    Set-Content -LiteralPath $resultsPath -Value 'existing-results' -Encoding UTF8
    $deleted = Confirm-SCTExistingResultsFile -ResultsPath $resultsPath
    Assert-True (-not $deleted) 'Answering N must report that the existing file was kept.'
    Assert-True (Test-Path -LiteralPath $resultsPath -PathType Leaf) `
        'Answering N must preserve the existing results CSV.'
    Assert-True (
        (Get-Content -LiteralPath $resultsPath -Raw).Trim() -eq 'existing-results'
    ) 'Answering N must not modify the existing results CSV.'

    $script:ReadResponses.Enqueue('')
    $deleted = Confirm-SCTExistingResultsFile -ResultsPath $resultsPath
    Assert-True (-not $deleted) 'Pressing Enter must use the safe keep-and-append default.'
    Assert-True (Test-Path -LiteralPath $resultsPath -PathType Leaf) `
        'Pressing Enter must preserve the existing results CSV.'

    $script:ReadResponses.Enqueue('invalid')
    $script:ReadResponses.Enqueue('Y')
    $promptCountBeforeDelete = $script:ReadPrompts.Count
    $deleted = Confirm-SCTExistingResultsFile -ResultsPath $resultsPath
    Assert-True $deleted 'Answering Y must report that the existing file was deleted.'
    Assert-True (-not (Test-Path -LiteralPath $resultsPath)) `
        'Answering Y must delete the existing results CSV.'
    Assert-True (
        ($script:ReadPrompts.Count - $promptCountBeforeDelete) -eq 2
    ) 'An invalid response must prompt again before accepting Y.'

    $promptCountBeforeMissingFile = $script:ReadPrompts.Count
    $deleted = Confirm-SCTExistingResultsFile -ResultsPath $resultsPath
    Assert-True (-not $deleted) 'A missing results CSV must not report a deletion.'
    Assert-True (
        $script:ReadPrompts.Count -eq $promptCountBeforeMissingFile
    ) 'A missing results CSV must not prompt the operator.'

    Write-Host "Passed $script:Assertions existing-results prompt assertions." -ForegroundColor Green
}
finally {
    if (Test-Path -LiteralPath $tempRoot -PathType Container) {
        $resolvedTempRoot = (Resolve-Path -LiteralPath $tempRoot).Path
        $resolvedTestRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
        $expectedPrefix = $resolvedTestRoot.TrimEnd('\') + '\.tmp-existing-results-prompt-'
        if (-not $resolvedTempRoot.StartsWith(
            $expectedPrefix,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Refusing to remove unexpected test directory: $resolvedTempRoot"
        }
        Remove-Item -LiteralPath $resolvedTempRoot -Recurse -Force
    }
}
