<#
.SYNOPSIS
    Vector 4.1: Registry Run Keys / Startup Folder Persistence (T1547.001)

.DESCRIPTION
    Five sub-tests covering the most common autostart persistence locations.

    Sub-test 1 (HKCURunKey)  - reg.exe writes a Base64-encoded PowerShell command to the
                                HKCU Run key. Most common persistence method; no elevation needed.

    Sub-test 2 (HKCURunOnce) - Set-ItemProperty writes a command to HKCU RunOnce.
                                Executes once after next login; uses native PS cmdlet instead
                                of reg.exe, producing different telemetry.

    Sub-test 3 (StartupVBS)  - VBS file dropped to the user startup folder and executed
                                immediately via cscript.exe. Simulates a script dropper.

    Sub-test 4 (StartupBAT)  - BAT file dropped to the user startup folder and executed
                                immediately via cmd.exe. Simulates batch-based persistence.

    Sub-test 5 (SystemBC)    - Mirrors the SystemBC malware-as-a-service pattern:
                                a hidden-window PowerShell -File command written to HKCU Run.

    All sub-tests write a marker file to C:\Windows\Temp\ as proof-of-execution.
    Nothing malicious runs - benign file writes only.

.PARAMETER Technique
    Which sub-test to run. Use 'All' to run all five sequentially.
    Default: HKCURunKey.

.EXAMPLE
    .\v4.1-registry-run-key.ps1 -Technique HKCURunKey
    .\v4.1-registry-run-key.ps1 -Technique All
#>

param(
    [ValidateSet('HKCURunKey','HKCURunOnce','StartupVBS','StartupBAT','SystemBC','All')]
    [string]$Technique = 'HKCURunKey',
    [switch]$NoCleanupPrompt,
    [switch]$NoReport,
    [switch]$NoPause,
    [switch]$CleanupOnly
)

$tempDir    = "C:\Windows\Temp"
$valueName  = "SecurityControlsTest"
$startupDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"

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

function Test-ExecutionResult {
    param([string]$Name)
    Start-Sleep -Milliseconds 1500
    $marker = "$tempDir\art-v4.1-$Name.txt"
    if (Test-Path $marker) {
        Write-Host "[+] SUCCESS: Payload executed - $marker" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[-] FAILED: Payload did not execute (or was blocked)" -ForegroundColor Red
        return $false
    }
}

function Invoke-Cleanup {
    param([string[]]$Names)
    foreach ($n in $Names) {
        Remove-Item "$tempDir\art-v4.1-$n.txt" -Force -ErrorAction Ignore
    }
    Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"     -Name $valueName         -Force -ErrorAction Ignore
    Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name $valueName         -Force -ErrorAction Ignore
    Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"     -Name "socks5_powershell" -Force -ErrorAction Ignore
    Remove-Item "$startupDir\sct-vbs-test.vbs"        -Force -ErrorAction Ignore
    Remove-Item "$startupDir\sct-bat-test.bat"        -Force -ErrorAction Ignore
    Remove-Item "$tempDir\sct-systembc-payload.ps1"   -Force -ErrorAction Ignore
    Write-Host "[+] Cleanup complete" -ForegroundColor Green
}

# ==============================================================================
# SUB-TEST 1: HKCU Run Key via reg.exe
# Atomic Red Team: T1547.001 Test #1
# ==============================================================================

function Test-HKCURunKey {
    Write-Header "HKCU Run Key via reg.exe (Atomic Test #1)" "HIGH"
    Write-Host "`nPath   : HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    Write-Host "Method : reg.exe adds a named value; data is a Base64-encoded PS command"
    Write-Host "         executed at each user login. No elevation required."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 13  - RegistryEvent (Value Set) on the Run key path"
    Write-Host "  Sysmon 1   - reg.exe process created with Run key path in arguments"
    Write-Host "  EDR alert  - most products watch HKCU\...\Run continuously"
    Write-Host "  SIEM rule  - Run key modification followed by a new process within short window"

    $marker  = "$tempDir\art-v4.1-HKCURunKey.txt"
    $command = "Set-Content -Path '$marker' -Value '[' + (Get-Date) + '] HKCURunKey executed'"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $runVal  = "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encoded"

    Write-Host "`n[*] Writing Run key value via reg.exe..." -ForegroundColor Yellow
    Write-Host "    Key  : HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ForegroundColor DarkGray
    Write-Host "    Value: $valueName" -ForegroundColor DarkGray
    Write-Host "    Data : powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand [base64]" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 13 - RegistryEvent (Value Set)]" -ForegroundColor DarkGray

    $regOut = reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V $valueName /t REG_SZ /F /D "$runVal" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  RESULT: Registry write blocked or failed - $regOut" -ForegroundColor Green
        return $false
    }
    Write-Host "    Write succeeded." -ForegroundColor Green

    Write-Host "`n[*] Verifying key was written..." -ForegroundColor Yellow
    reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V $valueName | Out-Host

    Write-Host "`n[*] Executing payload now (simulates next-login trigger)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - powershell.exe with -EncodedCommand and -WindowStyle Hidden]" -ForegroundColor DarkGray
    try {
        Start-Process powershell.exe -ArgumentList @(
            "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", $encoded
        ) -Wait -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "HKCURunKey")
}

# ==============================================================================
# SUB-TEST 2: HKCU RunOnce via PowerShell Set-ItemProperty
# Atomic Red Team: T1547.001 Test #3 (HKCU variant, no elevation)
# ==============================================================================

function Test-HKCURunOnce {
    Write-Header "HKCU RunOnce via Set-ItemProperty (Atomic Test #3 variant)" "HIGH"
    Write-Host "`nPath   : HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    Write-Host "Method : Set-ItemProperty - avoids reg.exe, uses native PS cmdlet."
    Write-Host "         RunOnce fires once after next login, then auto-deletes the value."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 13     - RegistryEvent (Value Set) on RunOnce key path"
    Write-Host "  Event 4104    - Script Block Logging: Set-ItemProperty on a persistence path"
    Write-Host "  EDR alert     - RunOnce modification is less common than Run; may be higher-confidence"
    Write-Host "  Process chain - powershell.exe (parent) -> powershell.exe -WindowStyle Hidden"

    $marker       = "$tempDir\art-v4.1-HKCURunOnce.txt"
    $runOncePath  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    $command      = "Set-Content -Path '$marker' -Value '[' + (Get-Date) + '] HKCURunOnce executed'"
    $encoded      = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $runVal       = "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encoded"

    Write-Host "`n[*] Writing RunOnce value via Set-ItemProperty..." -ForegroundColor Yellow
    Write-Host "    Path : $runOncePath" -ForegroundColor DarkGray
    Write-Host "    Name : $valueName" -ForegroundColor DarkGray
    Write-Host "    Value: powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand [base64]" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 13 - RegistryEvent (Value Set)]" -ForegroundColor DarkGray

    try {
        Set-ItemProperty -Path $runOncePath -Name $valueName -Value $runVal -ErrorAction Stop
        Write-Host "    Write succeeded." -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: Registry write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Verifying key was written..." -ForegroundColor Yellow
    Get-ItemProperty -Path $runOncePath -Name $valueName -ErrorAction Ignore | Select-Object $valueName

    Write-Host "`n[*] Executing payload now (simulates next-login RunOnce trigger)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - powershell.exe with -EncodedCommand and -WindowStyle Hidden]" -ForegroundColor DarkGray
    try {
        Start-Process powershell.exe -ArgumentList @(
            "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", $encoded
        ) -Wait -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "HKCURunOnce")
}

# ==============================================================================
# SUB-TEST 3: Startup Folder - VBS file
# Atomic Red Team: T1547.001 Test #4
# ==============================================================================

function Test-StartupVBS {
    Write-Header "VBS File in User Startup Folder (Atomic Test #4)" "MEDIUM"
    Write-Host "`nPath   : $startupDir"
    Write-Host "Method : VBScript dropped to startup folder and executed immediately via cscript.exe."
    Write-Host "         Fires automatically at every user login without any registry modification."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 11  - FileCreate: .vbs file written to a startup folder path"
    Write-Host "  Sysmon 1   - cscript.exe spawned with a startup-folder path as argument"
    Write-Host "  EDR alert  - script interpreter (cscript.exe/wscript.exe) launched from startup location"

    $vbsPath = "$startupDir\sct-vbs-test.vbs"
    $marker  = "$tempDir\art-v4.1-StartupVBS.txt"

    $vbsContent = @"
Set fso = CreateObject("Scripting.FileSystemObject")
Set f = fso.CreateTextFile("$marker", True)
f.Write "[" & Now() & "] StartupVBS executed"
f.Close
"@

    Write-Host "`n[*] Dropping VBS to startup folder: $vbsPath" -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 11 - FileCreate in startup folder]" -ForegroundColor DarkGray
    try {
        Set-Content -Path $vbsPath -Value $vbsContent -Encoding UTF8 -ErrorAction Stop
        Write-Host "    File written: $vbsPath" -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: File write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Executing VBS via cscript.exe (simulates login trigger)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - cscript.exe launched from startup-folder path]" -ForegroundColor DarkGray
    try {
        Start-Process cscript.exe -ArgumentList @("//nologo", $vbsPath) -Wait -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "StartupVBS")
}

# ==============================================================================
# SUB-TEST 4: Startup Folder - BAT file
# Atomic Red Team: T1547.001 Test #6
# ==============================================================================

function Test-StartupBAT {
    Write-Header "BAT File in User Startup Folder (Atomic Test #6)" "MEDIUM"
    Write-Host "`nPath   : $startupDir"
    Write-Host "Method : Batch file dropped to startup folder and executed immediately via cmd.exe."
    Write-Host "         Fires automatically at every user login without any registry modification."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 11  - FileCreate: .bat file written to a startup folder path"
    Write-Host "  Sysmon 1   - cmd.exe spawned from a startup-folder path"
    Write-Host "  EDR alert  - cmd.exe execution from startup location is unusual"

    $batPath = "$startupDir\sct-bat-test.bat"
    $marker  = "$tempDir\art-v4.1-StartupBAT.txt"

    $batContent = "@echo off`r`necho [%DATE% %TIME%] StartupBAT executed > `"$marker`""

    Write-Host "`n[*] Dropping BAT to startup folder: $batPath" -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 11 - FileCreate in startup folder]" -ForegroundColor DarkGray
    try {
        Set-Content -Path $batPath -Value $batContent -Encoding ASCII -ErrorAction Stop
        Write-Host "    File written: $batPath" -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: File write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Executing BAT via cmd.exe (simulates login trigger)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - cmd.exe spawned from startup-folder path]" -ForegroundColor DarkGray
    try {
        Start-Process cmd.exe -ArgumentList @("/c", $batPath) -Wait -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "StartupBAT")
}

# ==============================================================================
# SUB-TEST 5: SystemBC-pattern - hidden PowerShell in HKCU Run Key
# Atomic Red Team: T1547.001 Test #9
# ==============================================================================

function Test-SystemBC {
    Write-Header "SystemBC Pattern: Hidden PowerShell in HKCU Run Key (Atomic Test #9)" "HIGH"
    Write-Host "`nPath   : HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    Write-Host "Method : Mirrors the SystemBC malware-as-a-service IOC pattern. A -windowstyle"
    Write-Host "         hidden, -ExecutionPolicy Bypass PowerShell -File command is written to the"
    Write-Host "         Run key under the value name 'socks5_powershell'."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 13  - RegistryEvent (Value Set): Run key value contains hidden PS pattern"
    Write-Host "  EDR alert  - Run key data with '-windowstyle hidden' and '-ExecutionPolicy Bypass'"
    Write-Host "  IOC match  - value name 'socks5_powershell' is a known SystemBC indicator"
    Write-Host "  SIEM rule  - Run key write + hidden PS child process within short window"

    $payloadScript = "$tempDir\sct-systembc-payload.ps1"
    $marker        = "$tempDir\art-v4.1-SystemBC.txt"
    $runKeyPath    = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $runKeyName    = "socks5_powershell"

    $ps1Content = "Set-Content -Path '$marker' -Value `"[`$(Get-Date)] SystemBC payload executed`""

    Write-Host "`n[*] Writing payload script to disk: $payloadScript" -ForegroundColor Yellow
    try {
        Set-Content -Path $payloadScript -Value $ps1Content -Encoding UTF8 -ErrorAction Stop
        Write-Host "    Script written." -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: Script write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    $runVal = "powershell.exe -windowstyle hidden -ExecutionPolicy Bypass -File `"$payloadScript`""

    Write-Host "`n[*] Writing Run key value '$runKeyName' via Set-ItemProperty..." -ForegroundColor Yellow
    Write-Host "    Path : $runKeyPath" -ForegroundColor DarkGray
    Write-Host "    Name : $runKeyName" -ForegroundColor DarkGray
    Write-Host "    Value: $runVal" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 13 - RegistryEvent (Value Set) with SystemBC IOC pattern]" -ForegroundColor DarkGray

    try {
        Set-ItemProperty -Path $runKeyPath -Name $runKeyName -Value $runVal -ErrorAction Stop
        Write-Host "    Write succeeded." -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: Registry write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Verifying key was written..." -ForegroundColor Yellow
    Get-ItemProperty -Path $runKeyPath -Name $runKeyName -ErrorAction Ignore | Select-Object $runKeyName

    Write-Host "`n[*] Executing hidden PowerShell payload (simulates next login)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - powershell.exe -windowstyle hidden spawned from Run key]" -ForegroundColor DarkGray
    try {
        Start-Process powershell.exe -ArgumentList @(
            "-windowstyle", "hidden", "-ExecutionPolicy", "Bypass", "-File", $payloadScript
        ) -Wait -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "SystemBC")
}

# ==============================================================================
# RUN ALL
# ==============================================================================

function Test-All {
    Write-Host "`n+==============================================================================+" -ForegroundColor Cyan
    Write-Host "|   REGISTRY RUN KEYS / STARTUP FOLDER - ALL TECHNIQUES                       |" -ForegroundColor Cyan
    Write-Host "+==============================================================================+" -ForegroundColor Cyan

    $tests = @(
        @{ Name = 'HKCURunKey';  Fn = ${function:Test-HKCURunKey}  },
        @{ Name = 'HKCURunOnce'; Fn = ${function:Test-HKCURunOnce} },
        @{ Name = 'StartupVBS';  Fn = ${function:Test-StartupVBS}  },
        @{ Name = 'StartupBAT';  Fn = ${function:Test-StartupBAT}  },
        @{ Name = 'SystemBC';    Fn = ${function:Test-SystemBC}     }
    )

    $results = @()
    foreach ($t in $tests) {
        $results += @{ Name = $t.Name; Success = (& $t.Fn) }
        if (-not $NoPause) {
            Write-Host "`n[!] Check EDR/AV console before continuing." -ForegroundColor Yellow
            [void](Read-Host "    Press Enter for next sub-test")
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
        $label = if ($r.Success) { "EXECUTED" } else { "BLOCKED " }
        $color = if ($r.Success) { 'Green' }   else { 'Red' }
        Write-Host "  [$label] $($r.Name)" -ForegroundColor $color
    }
    $ok    = ($Results | Where-Object { $_.Success }).Count
    $total = $Results.Count
    Write-Host "`n  $ok of $total techniques executed successfully" -ForegroundColor Cyan
}

# ==============================================================================
# MAIN
# ==============================================================================

if ($CleanupOnly) {
    Invoke-Cleanup -Names @('HKCURunKey','HKCURunOnce','StartupVBS','StartupBAT','SystemBC')
    exit 0
}

Write-Host "`n[TEST] Registry Run Keys / Startup Folder Persistence (Vector 4.1)" -ForegroundColor Cyan
Write-Host "  MITRE: T1547.001  |  Phase 4  |  Persistence`n"

switch ($Technique) {
    'All' {
        $results = Test-All
        if (-not $NoReport) {
            Write-Report -Results $results
        }
        Write-Host "`n[*] Marker files in $tempDir (art-v4.1-*.txt) left for review." -ForegroundColor Yellow
        if (-not $NoCleanupPrompt) {
            $c = Read-Host "Clean up now? (Y/N)"
            if ($c -eq 'Y' -or $c -eq 'y') {
                Invoke-Cleanup -Names @('HKCURunKey','HKCURunOnce','StartupVBS','StartupBAT','SystemBC')
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
            'HKCURunKey'  { Test-HKCURunKey  }
            'HKCURunOnce' { Test-HKCURunOnce }
            'StartupVBS'  { Test-StartupVBS  }
            'StartupBAT'  { Test-StartupBAT  }
            'SystemBC'    { Test-SystemBC     }
        }

        $color = if ($success) { 'Green' } else { 'Red' }
        Write-Host "`n[RESULT] Technique '$Technique': $(if ($success) { 'EXECUTED' } else { 'BLOCKED' })" -ForegroundColor $color
        if (-not $NoCleanupPrompt) {
            $c = Read-Host "Clean up now? (Y/N)"
            if ($c -eq 'Y' -or $c -eq 'y') { Invoke-Cleanup -Names @($Technique) }
        }
    }
}
