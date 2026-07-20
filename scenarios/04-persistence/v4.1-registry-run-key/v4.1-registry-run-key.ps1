<#
.SYNOPSIS
    Technique 4.1: Registry Run Keys / Startup Folder Persistence (T1547.001)

.DESCRIPTION
    Seven subtests covering the most common user- and machine-wide autostart
    persistence locations.

    Subtest 1 (HKCURunKey)  - reg.exe writes a Base64-encoded PowerShell command to the
                                HKCU Run key. Most common persistence method; no elevation needed.

    Subtest 2 (HKCURunOnce) - Set-ItemProperty writes a command to HKCU RunOnce.
                                Executes once after next login; uses native PS cmdlet instead
                                of reg.exe, producing different telemetry.

    Subtest 3 (HKLMRunKey)  - reg.exe writes the same benign command to the machine-wide
                                HKLM Run key. Requires an elevated PowerShell session.

    Subtest 4 (HKLMRunOnce) - Set-ItemProperty writes a command to machine-wide HKLM
                                RunOnce. Requires an elevated PowerShell session.

    Subtest 5 (StartupVBS)  - VBS file dropped to the user startup folder and executed
                                immediately via cscript.exe. Simulates a script dropper.

    Subtest 6 (StartupBAT)  - BAT file dropped to the user startup folder and executed
                                immediately via cmd.exe. Simulates batch-based persistence.

    Subtest 7 (SystemBC)    - Mirrors the SystemBC malware-as-a-service pattern:
                                a hidden-window PowerShell -File command written to HKCU Run.

    All subtests write a marker file to C:\Windows\Temp\ as proof-of-execution.
    Nothing malicious runs - benign file writes only.

.PARAMETER Subtest
    Which subtest to run. Use 'All' to run all seven sequentially. HKLM subtests
    require an elevated PowerShell session.
    Default: HKCURunKey.

.PARAMETER CheckHKLMWriteAccess
    Probe write access to the machine-wide HKLM Run key, remove the temporary
    value immediately, and exit. Run from an elevated PowerShell to test HKLM.

.EXAMPLE
    .\v4.1-registry-run-key.ps1 -Subtest HKCURunKey
    .\v4.1-registry-run-key.ps1 -Subtest All
#>

param(
    [ValidateSet('HKCURunKey','HKCURunOnce','HKLMRunKey','HKLMRunOnce','StartupVBS','StartupBAT','SystemBC','All')]
    [Alias('Technique')]
    [string]$Subtest = 'HKCURunKey',
    [switch]$NoCleanupPrompt,
    [switch]$NoReport,
    [switch]$NoPause,
    [switch]$CleanupOnly,
    [switch]$CheckHKLMWriteAccess
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
    Write-Host "  SUBTEST: $Title" -ForegroundColor Magenta
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
        switch ($n) {
            'HKCURunKey'  { Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"     -Name $valueName         -Force -ErrorAction Ignore }
            'HKCURunOnce' { Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name $valueName         -Force -ErrorAction Ignore }
            'HKLMRunKey'  { Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"     -Name $valueName         -Force -ErrorAction Ignore }
            'HKLMRunOnce' { Remove-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name $valueName         -Force -ErrorAction Ignore }
            'StartupVBS'  { Remove-Item "$startupDir\sct-vbs-test.vbs"      -Force -ErrorAction Ignore }
            'StartupBAT'  { Remove-Item "$startupDir\sct-bat-test.bat"      -Force -ErrorAction Ignore }
            'SystemBC' {
                Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "socks5_powershell" -Force -ErrorAction Ignore
                Remove-Item "$tempDir\sct-systembc-payload.ps1" -Force -ErrorAction Ignore
            }
        }
    }
    Write-Host "[+] Cleanup complete" -ForegroundColor Green
}

function Test-HKLMRunWriteAccess {
    <#
        Tests whether the current token can create and remove a temporary value
        in the machine-wide Run key. This is opt-in because it intentionally
        produces HKLM persistence telemetry.
    #>
    $runPath   = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    $probeName = "SecurityControlsTest-WriteProbe-$PID"
    $created   = $false

    Write-Host "`n[*] Checking write access to the machine-wide Run key..." -ForegroundColor Yellow
    Write-Host "    Path : $runPath" -ForegroundColor DarkGray
    Write-Host "    Note : This creates and immediately removes a temporary test value." -ForegroundColor DarkGray

    try {
        New-ItemProperty -Path $runPath -Name $probeName -PropertyType String `
            -Value "SCT HKLM write-access probe; safe to remove" -Force -ErrorAction Stop | Out-Null
        $created = $true
        Write-Host "[+] HKLM Run key is writable by this PowerShell session." -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[-] HKLM Run key is not writable by this session: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "    Run PowerShell elevated to test or use machine-wide persistence." -ForegroundColor DarkGray
        return $false
    } finally {
        if ($created) {
            try {
                Remove-ItemProperty -Path $runPath -Name $probeName -Force -ErrorAction Stop
                Write-Host "    Temporary HKLM probe value removed." -ForegroundColor DarkGray
            } catch {
                Write-Host "[!] Could not remove temporary HKLM probe value '$probeName': $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

# ==============================================================================
# SUBTEST 1: HKCU Run Key via reg.exe
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
    $command = "Set-Content -Path '$marker' -Value ('[' + (Get-Date) + '] HKCURunKey executed')"
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
# SUBTEST 2: HKCU RunOnce via PowerShell Set-ItemProperty
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
    $command      = "Set-Content -Path '$marker' -Value ('[' + (Get-Date) + '] HKCURunOnce executed')"
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
# SUBTEST 3: HKLM Run Key via reg.exe
# Machine-wide variant; requires elevation
# ==============================================================================

function Test-HKLMRunKey {
    Write-Header "HKLM Run Key via reg.exe (machine-wide variant)" "HIGH"
    Write-Host "`nPath   : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    Write-Host "Method : reg.exe adds a machine-wide value containing a Base64-encoded PS command."
    Write-Host "         The value applies to every user and requires Administrator rights to create."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 13  - RegistryEvent (Value Set) on the machine-wide Run key"
    Write-Host "  Sysmon 1   - elevated reg.exe followed by hidden powershell.exe"
    Write-Host "  EDR alert  - HKLM autorun modification has system-wide persistence impact"
    Write-Host "  SIEM rule  - HKLM Run modification followed by encoded PowerShell execution"

    $marker  = "$tempDir\art-v4.1-HKLMRunKey.txt"
    $command = "Set-Content -Path '$marker' -Value ('[' + (Get-Date) + '] HKLMRunKey executed')"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $runVal  = "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encoded"
    $runPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

    Write-Host "`n[*] Writing machine-wide Run value via reg.exe..." -ForegroundColor Yellow
    Write-Host "    Key  : $runPath" -ForegroundColor DarkGray
    Write-Host "    Value: $valueName" -ForegroundColor DarkGray
    Write-Host "    Data : powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand [base64]" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 13 - RegistryEvent (Value Set)]" -ForegroundColor DarkGray

    $regOut = reg add $runPath /V $valueName /t REG_SZ /F /D "$runVal" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  RESULT: HKLM registry write blocked, failed, or was not elevated - $regOut" -ForegroundColor Green
        return $false
    }
    Write-Host "    Write succeeded." -ForegroundColor Green

    Write-Host "`n[*] Verifying key was written..." -ForegroundColor Yellow
    reg query $runPath /V $valueName | Out-Host

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

    return (Test-ExecutionResult -Name "HKLMRunKey")
}

# ==============================================================================
# SUBTEST 4: HKLM RunOnce via PowerShell Set-ItemProperty
# Machine-wide variant; requires elevation
# ==============================================================================

function Test-HKLMRunOnce {
    Write-Header "HKLM RunOnce via Set-ItemProperty (machine-wide variant)" "HIGH"
    Write-Host "`nPath   : HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    Write-Host "Method : Set-ItemProperty writes a machine-wide one-time logon command."
    Write-Host "         The value applies to every user and requires Administrator rights to create."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 13     - RegistryEvent (Value Set) on machine-wide RunOnce"
    Write-Host "  Event 4104    - Script Block Logging: Set-ItemProperty on an HKLM persistence path"
    Write-Host "  EDR alert     - machine-wide RunOnce modification is a high-confidence event"
    Write-Host "  Process chain - elevated powershell.exe -> hidden powershell.exe"

    $marker      = "$tempDir\art-v4.1-HKLMRunOnce.txt"
    $runOncePath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    $command     = "Set-Content -Path '$marker' -Value ('[' + (Get-Date) + '] HKLMRunOnce executed')"
    $encoded     = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $runVal      = "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encoded"

    Write-Host "`n[*] Writing machine-wide RunOnce value via Set-ItemProperty..." -ForegroundColor Yellow
    Write-Host "    Path : $runOncePath" -ForegroundColor DarkGray
    Write-Host "    Name : $valueName" -ForegroundColor DarkGray
    Write-Host "    Value: powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand [base64]" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 13 - RegistryEvent (Value Set)]" -ForegroundColor DarkGray

    try {
        Set-ItemProperty -Path $runOncePath -Name $valueName -Value $runVal -ErrorAction Stop
        Write-Host "    Write succeeded." -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: HKLM registry write blocked, failed, or was not elevated - $($_.Exception.Message)" -ForegroundColor Green
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

    return (Test-ExecutionResult -Name "HKLMRunOnce")
}

# ==============================================================================
# SUBTEST 5: Startup Folder - VBS file
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
        Start-Process cscript.exe -ArgumentList ('//nologo "{0}"' -f $vbsPath) -Wait -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "StartupVBS")
}

# ==============================================================================
# SUBTEST 6: Startup Folder - BAT file
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
        Start-Process cmd.exe -ArgumentList ('/c ""{0}""' -f $batPath) -Wait -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "StartupBAT")
}

# ==============================================================================
# SUBTEST 7: SystemBC-pattern - hidden PowerShell in HKCU Run Key
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
    Write-Host "|   REGISTRY RUN KEYS / STARTUP FOLDER - ALL SUBTESTS                         |" -ForegroundColor Cyan
    Write-Host "+==============================================================================+" -ForegroundColor Cyan

    $tests = @(
        @{ Name = 'HKCURunKey';  Fn = ${function:Test-HKCURunKey}  },
        @{ Name = 'HKCURunOnce'; Fn = ${function:Test-HKCURunOnce} },
        @{ Name = 'HKLMRunKey';  Fn = ${function:Test-HKLMRunKey}  },
        @{ Name = 'HKLMRunOnce'; Fn = ${function:Test-HKLMRunOnce} },
        @{ Name = 'StartupVBS';  Fn = ${function:Test-StartupVBS}  },
        @{ Name = 'StartupBAT';  Fn = ${function:Test-StartupBAT}  },
        @{ Name = 'SystemBC';    Fn = ${function:Test-SystemBC}     }
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
        $label = if ($r.Success) { "EXECUTED" } else { "BLOCKED " }
        $color = if ($r.Success) { 'Green' }   else { 'Red' }
        Write-Host "  [$label] $($r.Name)" -ForegroundColor $color
    }
    $ok    = ($Results | Where-Object { $_.Success }).Count
    $total = $Results.Count
    Write-Host "`n  $ok of $total subtests executed successfully" -ForegroundColor Cyan
}

# ==============================================================================
# MAIN
# ==============================================================================

if ($CleanupOnly) {
    Invoke-Cleanup -Names @('HKCURunKey','HKCURunOnce','HKLMRunKey','HKLMRunOnce','StartupVBS','StartupBAT','SystemBC')
    exit 0
}

if ($CheckHKLMWriteAccess) {
    [void](Test-HKLMRunWriteAccess)
    exit 0
}

Write-Host "`n[TEST] Registry Run Keys / Startup Folder Persistence (Technique 4.1)" -ForegroundColor Cyan
Write-Host "  MITRE: T1547.001  |  Phase 4  |  Persistence`n"

switch ($Subtest) {
    'All' {
        $results = Test-All
        if (-not $NoReport) {
            Write-Report -Results $results
        }
        Write-Host "`n[*] Marker files in $tempDir (art-v4.1-*.txt) left for review." -ForegroundColor Yellow
        if (-not $NoCleanupPrompt) {
            $c = Read-Host "Clean up now? (Y/N)"
            if ($c -eq 'Y' -or $c -eq 'y') {
                Invoke-Cleanup -Names @('HKCURunKey','HKCURunOnce','HKLMRunKey','HKLMRunOnce','StartupVBS','StartupBAT','SystemBC')
            }
        }
    }
    default {
        Write-Host "+==============================================================================+" -ForegroundColor Cyan
        Write-Host "|   SINGLE SUBTEST: $Subtest" -ForegroundColor Cyan
        Write-Host "+==============================================================================+" -ForegroundColor Cyan
        Write-Host "`n[!] Have EDR/AV console visible before proceeding." -ForegroundColor Yellow
        Read-Host "    Press Enter to start"

        $success = switch ($Subtest) {
            'HKCURunKey'  { Test-HKCURunKey  }
            'HKCURunOnce' { Test-HKCURunOnce }
            'HKLMRunKey'  { Test-HKLMRunKey  }
            'HKLMRunOnce' { Test-HKLMRunOnce }
            'StartupVBS'  { Test-StartupVBS  }
            'StartupBAT'  { Test-StartupBAT  }
            'SystemBC'    { Test-SystemBC     }
        }

        $color = if ($success) { 'Green' } else { 'Red' }
        Write-Host "`n[RESULT] Subtest '$Subtest': $(if ($success) { 'EXECUTED' } else { 'BLOCKED' })" -ForegroundColor $color
        if (-not $NoCleanupPrompt) {
            $c = Read-Host "Clean up now? (Y/N)"
            if ($c -eq 'Y' -or $c -eq 'y') { Invoke-Cleanup -Names @($Subtest) }
        }
    }
}
