<#
.SYNOPSIS
    Verifies safe handling of stale SCT marker files before a subtest rerun.
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
    '.tmp-existing-marker-prompt-' + [guid]::NewGuid().ToString('N')
)
New-Item -ItemType Directory -Path $tempRoot | Out-Null

try {
    $markerPath = Join-Path $tempRoot 'art-v4.3-ShellFolderRedirect.txt'

    $promptCountBeforeMissingMarker = $script:ReadPrompts.Count
    $cleared = Clear-SCTExistingMarker -Path $markerPath
    Assert-True $cleared 'A missing marker must already be ready for a run.'
    Assert-True (
        $script:ReadPrompts.Count -eq $promptCountBeforeMissingMarker
    ) 'A missing marker must not prompt the operator.'

    Set-Content -LiteralPath $markerPath -Value 'stale-marker' -Encoding UTF8
    $script:ReadResponses.Enqueue('N')
    $cleared = Clear-SCTExistingMarker -Path $markerPath
    Assert-True (-not $cleared) 'Answering N must cancel marker removal.'
    Assert-True (Test-Path -LiteralPath $markerPath -PathType Leaf) `
        'Answering N must preserve the stale marker.'

    $script:ReadResponses.Enqueue('invalid')
    $script:ReadResponses.Enqueue('Y')
    $promptCountBeforeDelete = $script:ReadPrompts.Count
    $cleared = Clear-SCTExistingMarker -Path $markerPath
    Assert-True $cleared 'Answering Y must prepare the marker path.'
    Assert-True (-not (Test-Path -LiteralPath $markerPath)) `
        'Answering Y must delete the stale marker.'
    Assert-True (
        ($script:ReadPrompts.Count - $promptCountBeforeDelete) -eq 2
    ) 'An invalid response must prompt again before accepting Y.'

    Set-Content -LiteralPath $markerPath -Value 'stale-marker' -Encoding UTF8
    $promptCountBeforeNonInteractive = $script:ReadPrompts.Count
    $cleared = Clear-SCTExistingMarker -Path $markerPath -NonInteractive
    Assert-True $cleared 'A non-interactive run must clear its deterministic stale marker.'
    Assert-True (-not (Test-Path -LiteralPath $markerPath)) `
        'A non-interactive run must delete the stale marker.'
    Assert-True (
        $script:ReadPrompts.Count -eq $promptCountBeforeNonInteractive
    ) 'A non-interactive run must not prompt.'

    Write-Host "Passed $script:Assertions existing-marker prompt assertions." -ForegroundColor Green
}
finally {
    if (Test-Path -LiteralPath $tempRoot -PathType Container) {
        $resolvedTempRoot = (Resolve-Path -LiteralPath $tempRoot).Path
        $resolvedTestRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
        $expectedPrefix = $resolvedTestRoot.TrimEnd('\') + '\.tmp-existing-marker-prompt-'
        if (-not $resolvedTempRoot.StartsWith(
            $expectedPrefix,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Refusing to remove unexpected test directory: $resolvedTempRoot"
        }
        Remove-Item -LiteralPath $resolvedTempRoot -Recurse -Force
    }
}
