<#
.SYNOPSIS
    Imports an approved local GGUF or supported Safetensors model into Ollama.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ModelPath,
    [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9._:-]+$')] [string]$ModelName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ollama = Get-Command ollama -ErrorAction Stop
$resolvedModel = (Resolve-Path -LiteralPath $ModelPath -ErrorAction Stop).Path
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('sct-ollama-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
try {
    $modelFile = Join-Path $tempRoot 'Modelfile'
    "FROM `"$resolvedModel`"" | Set-Content -LiteralPath $modelFile -Encoding UTF8
    & $ollama.Source create $ModelName -f $modelFile
    if ($LASTEXITCODE -ne 0) { throw "Ollama model import failed." }
    & $ollama.Source show $ModelName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Ollama could not verify the imported model." }
    Write-Host "Imported Ollama model '$ModelName'." -ForegroundColor Green
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
