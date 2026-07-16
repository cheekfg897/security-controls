<#
.SYNOPSIS
    Technique 4.3: Startup Folder / Advanced Logon Persistence (T1547.001)

.DESCRIPTION
    Five subtests covering startup folder and advanced logon persistence methods,
    complementing v4.1 (core Run Keys / basic VBS+BAT startup scripts).

    Subtest 1 (JSEStartup)          - JScript Encoded (.jse) file dropped to the user
                                        startup folder and executed via cscript /E:Jscript.
                                        Different interpreter path from VBS/BAT; content-match
                                        rules that look for plain script text will miss it.

    Subtest 2 (LNKShortcut)         - .lnk shortcut created in user startup folder via
                                        WScript.Shell COM object, pointing to powershell.exe
                                        with a Base64-encoded payload as Arguments. No script
                                        file in folder - the LNK binary is the only artifact;
                                        EDR must parse the LNK structure to identify target.

    Subtest 3 (AllUsersBAT)         - BAT file dropped to the AllUsers startup folder
                                        (C:\ProgramData\...\StartUp). Fires for every user
                                        who logs in, not just the current user.
                                        Requires local admin.

    Subtest 4 (ShellFolderRedirect) - HKCU User Shell Folders Startup value redirected to
                                        an attacker-controlled directory. Windows Explorer reads
                                        this key to locate startup items - payload in the new
                                        folder runs at login without touching known startup paths.
                                        No elevation required. Value restored after test.

    Subtest 5 (WinlogonUserinit)    - Payload appended to the Winlogon Userinit registry
                                        value (HKLM). Userinit.exe runs all commands listed
                                        here at every interactive logon; less audited than
                                        Run keys. Requires local admin.
                                        Original value is backed up and restored immediately.

    All subtests write a marker file to C:\Windows\Temp\ as proof-of-execution.
    Nothing malicious runs - benign file writes only.

.PARAMETER Subtest
    Which subtest to run. Use 'All' to run all five sequentially.
    Default: JSEStartup.

.EXAMPLE
    .\v4.3-startup-folder.ps1 -Subtest JSEStartup
    .\v4.3-startup-folder.ps1 -Subtest All
#>

param(
    [ValidateSet('JSEStartup','LNKShortcut','AllUsersBAT','ShellFolderRedirect','WinlogonUserinit','All')]
    [Alias('Technique')]
    [string]$Subtest = 'JSEStartup',
    [switch]$NoCleanupPrompt,
    [switch]$NoReport,
    [switch]$NoPause,
    [switch]$CleanupOnly
)

$tempDir         = "C:\Windows\Temp"
$userStartup     = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$allUsersStartup = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$redirectDir     = "$env:TEMP\sct-startup-redirect"
$winlogonPath    = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$shellFolderPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"

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
    $marker = "$tempDir\art-v4.3-$Name.txt"
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
        Remove-Item "$tempDir\art-v4.3-$n.txt" -Force -ErrorAction Ignore
    }
    Remove-Item "$userStartup\sct-jse-test.jse"          -Force -ErrorAction Ignore
    Remove-Item "$userStartup\sct-lnk-test.lnk"          -Force -ErrorAction Ignore
    Remove-Item "$allUsersStartup\sct-allusers-test.bat"  -Force -ErrorAction Ignore
    # Restore ShellFolderRedirect if not already restored
    $defaultStartup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    Set-ItemProperty -Path $shellFolderPath -Name "Startup" -Value $defaultStartup -ErrorAction Ignore
    Remove-Item $redirectDir -Recurse -Force -ErrorAction Ignore
    # Restore WinlogonUserinit from backup value if not already restored
    $backup = Get-ItemPropertyValue -Path $winlogonPath -Name "Userinit-backup" -ErrorAction Ignore
    if ($backup) {
        Set-ItemProperty -Path $winlogonPath -Name "Userinit" -Value $backup -ErrorAction Ignore
        Remove-ItemProperty -Path $winlogonPath -Name "Userinit-backup" -Force -ErrorAction Ignore
        Write-Host "    Userinit restored from backup." -ForegroundColor DarkGray
    }
    Write-Host "[+] Cleanup complete" -ForegroundColor Green
}

# ==============================================================================
# SUBTEST 1: .jse (JScript) file in user startup folder
# Atomic Red Team: T1547.001 Test #5
# ==============================================================================

function Test-JSEStartup {
    Write-Header "JScript Encoded (.jse) File in User Startup Folder (Atomic Test #5)" "MEDIUM"
    Write-Host "`nPath   : $userStartup"
    Write-Host "Method : A .jse file is dropped to the user startup folder and executed via"
    Write-Host "         'cscript.exe /E:Jscript'. Unlike .vbs and .bat, .jse requires an"
    Write-Host "         explicit engine flag (/E:Jscript); content-match rules looking for"
    Write-Host "         plain VBScript or batch text will not match JScript syntax."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 11  - FileCreate: .jse written to startup folder path"
    Write-Host "  Sysmon 1   - cscript.exe with /E:Jscript and startup-folder path in args"
    Write-Host "  EDR alert  - JScript engine (cscript.exe /E:Jscript) launched from startup location"
    Write-Host "  SIEM rule  - .jse file extension in startup folder; rare for legitimate software"

    $jsePath = "$userStartup\sct-jse-test.jse"
    $marker  = "$tempDir\art-v4.3-JSEStartup.txt"
    $markerEscaped = $marker -replace '\\', '\\'

    $jseContent = @"
var fso = new ActiveXObject("Scripting.FileSystemObject");
var f = fso.CreateTextFile("$markerEscaped", true);
f.WriteLine("[" + new Date().toString() + "] JSEStartup executed");
f.Close();
"@

    Write-Host "`n[*] Dropping .jse to user startup folder: $jsePath" -ForegroundColor Yellow
    Write-Host "    Content: JScript FileSystemObject writes marker file" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 11 - FileCreate .jse in startup folder]" -ForegroundColor DarkGray
    try {
        Set-Content -Path $jsePath -Value $jseContent -Encoding UTF8 -ErrorAction Stop
        Write-Host "    File written: $jsePath" -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: File write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Executing via cscript.exe /E:Jscript (simulates login trigger)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - cscript.exe /E:Jscript from startup-folder path]" -ForegroundColor DarkGray
    try {
        Start-Process cscript.exe -ArgumentList ('//nologo /E:Jscript "{0}"' -f $jsePath) -Wait -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "JSEStartup")
}

# ==============================================================================
# SUBTEST 2: .lnk shortcut in user startup folder
# Atomic Red Team: T1547.001 Test #7
# ==============================================================================

function Test-LNKShortcut {
    Write-Header "Executable Shortcut (.lnk) in User Startup Folder (Atomic Test #7)" "MEDIUM"
    Write-Host "`nPath   : $userStartup"
    Write-Host "Method : WScript.Shell COM object creates a .lnk shortcut in the user startup"
    Write-Host "         folder pointing to powershell.exe with a Base64-encoded payload as"
    Write-Host "         Arguments. No script content visible in the folder - the LNK binary"
    Write-Host "         is the only artifact; EDR must parse the LNK structure to see the target."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 11  - FileCreate: .lnk written to startup folder"
    Write-Host "  Sysmon 1   - WScript.Shell COM CreateShortcut; powershell.exe spawned via lnk"
    Write-Host "  LNK parse  - EDR/SIEM parsing lnk TargetPath and Arguments fields at rest"
    Write-Host "  EDR alert  - .lnk in startup folder targeting powershell.exe -EncodedCommand"

    $lnkPath = "$userStartup\sct-lnk-test.lnk"
    $marker  = "$tempDir\art-v4.3-LNKShortcut.txt"
    $command = "Set-Content -Path '$marker' -Value ('[' + (Get-Date) + '] LNKShortcut executed')"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))

    Write-Host "`n[*] Creating .lnk shortcut via WScript.Shell COM: $lnkPath" -ForegroundColor Yellow
    Write-Host "    TargetPath : powershell.exe" -ForegroundColor DarkGray
    Write-Host "    Arguments  : -NoProfile -WindowStyle Hidden -EncodedCommand [base64]" -ForegroundColor DarkGray
    Write-Host "    WindowStyle: 7 (minimised)" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 11 - FileCreate .lnk in startup folder]" -ForegroundColor DarkGray

    try {
        $wsh             = New-Object -ComObject WScript.Shell -ErrorAction Stop
        $lnk             = $wsh.CreateShortcut($lnkPath)
        $lnk.TargetPath  = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        $lnk.Arguments   = "-NoProfile -WindowStyle Hidden -EncodedCommand $encoded"
        $lnk.WindowStyle = 7
        $lnk.Save()
        Write-Host "    Shortcut written: $lnkPath" -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: Shortcut creation blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Verifying shortcut properties (read-back via COM)..." -ForegroundColor Yellow
    $lnk2 = (New-Object -ComObject WScript.Shell).CreateShortcut($lnkPath)
    Write-Host "    TargetPath : $($lnk2.TargetPath)" -ForegroundColor DarkGray
    $argPreview = $lnk2.Arguments.Substring(0, [Math]::Min(70, $lnk2.Arguments.Length))
    Write-Host "    Arguments  : $argPreview..." -ForegroundColor DarkGray

    Write-Host "`n[*] Invoking shortcut (simulates login trigger)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - powershell.exe -WindowStyle Hidden -EncodedCommand via .lnk]" -ForegroundColor DarkGray
    try {
        Invoke-Item -Path $lnkPath -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "LNKShortcut")
}

# ==============================================================================
# SUBTEST 3: BAT in AllUsers startup folder
# Atomic Red Team: T1547.001 Test #6 (AllUsers variant)
# Requires local admin.
# ==============================================================================

function Test-AllUsersBAT {
    Write-Header "BAT File in AllUsers Startup Folder (Atomic Test #6 - AllUsers variant)" "MEDIUM"
    Write-Host "`nPath   : $allUsersStartup"
    Write-Host "Method : Batch file dropped to C:\ProgramData\...\StartUp - the AllUsers startup"
    Write-Host "         location. Fires for EVERY user who logs in, not just the current user."
    Write-Host "         Higher persistence coverage than user-startup; requires local admin to write."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 11  - FileCreate: .bat in C:\ProgramData\...\StartUp (not %APPDATA%)"
    Write-Host "  Sysmon 1   - cmd.exe spawned from C:\ProgramData startup path"
    Write-Host "  EDR alert  - Script in AllUsers startup written by a non-installer process"
    Write-Host "  SIEM rule  - Any write to $allUsersStartup from a user-session process"

    $batPath    = "$allUsersStartup\sct-allusers-test.bat"
    $marker     = "$tempDir\art-v4.3-AllUsersBAT.txt"
    $batContent = "@echo off`r`necho [%DATE% %TIME%] AllUsersBAT executed > `"$marker`""

    Write-Host "`n[*] Dropping BAT to AllUsers startup folder: $batPath" -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 11 - FileCreate .bat in C:\ProgramData\...\StartUp]" -ForegroundColor DarkGray
    try {
        Set-Content -Path $batPath -Value $batContent -Encoding ASCII -ErrorAction Stop
        Write-Host "    File written: $batPath" -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: File write blocked (elevation required) - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Executing BAT via cmd.exe (simulates any-user login trigger)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - cmd.exe spawned from C:\ProgramData startup path]" -ForegroundColor DarkGray
    try {
        Start-Process cmd.exe -ArgumentList ('/c ""{0}""' -f $batPath) -Wait -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "AllUsersBAT")
}

# ==============================================================================
# SUBTEST 4: HKCU User Shell Folders - Startup redirect
# Atomic Red Team: T1547.001 Test #11
# ==============================================================================

function Test-ShellFolderRedirect {
    Write-Header "HKCU User Shell Folders - Startup Folder Redirect (Atomic Test #11)" "HIGH"
    Write-Host "`nPath   : HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    Write-Host "Method : The 'Startup' value in User Shell Folders tells Explorer where the user's"
    Write-Host "         startup folder lives. Pointing it to an attacker-controlled directory"
    Write-Host "         causes all executables/scripts there to run at login - without placing"
    Write-Host "         any file in the known %APPDATA%\...\Startup path."
    Write-Host "         No elevation required. Value restored immediately after test."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 13  - RegistryEvent (Value Set): User Shell Folders\Startup modified"
    Write-Host "  EDR alert  - Startup value pointing to Temp/AppData non-standard path"
    Write-Host "  SIEM rule  - Shell Folders\Startup changed from expected %APPDATA% baseline"
    Write-Host "  Hunt query - Compare Startup value to expected path; alert on deviation"

    $marker      = "$tempDir\art-v4.3-ShellFolderRedirect.txt"
    $command     = "Set-Content -Path '$marker' -Value ('[' + (Get-Date) + '] ShellFolderRedirect executed')"
    $encoded     = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $batPayload  = "$redirectDir\sct-redirect-payload.bat"
    $batContent  = "@echo off`r`npowershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encoded"

    Write-Host "`n[*] Reading current Startup value (for restore)..." -ForegroundColor Yellow
    $originalStartup = (Get-ItemProperty -Path $shellFolderPath -Name "Startup" -ErrorAction Ignore).Startup
    Write-Host "    Current: $originalStartup" -ForegroundColor DarkGray

    Write-Host "`n[*] Creating redirect directory and BAT payload: $redirectDir" -ForegroundColor Yellow
    try {
        New-Item -ItemType Directory -Path $redirectDir -Force | Out-Null
        Set-Content -Path $batPayload -Value $batContent -Encoding ASCII -ErrorAction Stop
        Write-Host "    Redirect dir + payload created." -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: Redirect dir/payload creation blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Redirecting Startup folder pointer to: $redirectDir" -ForegroundColor Yellow
    Write-Host "    Key  : $shellFolderPath" -ForegroundColor DarkGray
    Write-Host "    Value: Startup" -ForegroundColor DarkGray
    Write-Host "    Data : $redirectDir" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 13 - RegistryEvent (Value Set) on User Shell Folders\Startup]" -ForegroundColor DarkGray

    try {
        Set-ItemProperty -Path $shellFolderPath -Name "Startup" -Value $redirectDir -ErrorAction Stop
        Write-Host "    Registry value updated." -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: Registry write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Verifying redirect is active..." -ForegroundColor Yellow
    $current = (Get-ItemProperty -Path $shellFolderPath -Name "Startup").Startup
    Write-Host "    Startup now points to: $current" -ForegroundColor DarkGray

    Write-Host "`n[*] Executing payload from redirect dir (simulates login trigger)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - cmd.exe launched from non-standard startup folder path]" -ForegroundColor DarkGray
    try {
        Start-Process cmd.exe -ArgumentList ('/c ""{0}""' -f $batPayload) -Wait -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        Set-ItemProperty -Path $shellFolderPath -Name "Startup" -Value $originalStartup -ErrorAction Ignore
        return $false
    }

    $result = Test-ExecutionResult -Name "ShellFolderRedirect"

    Write-Host "`n[*] Restoring Startup value immediately..." -ForegroundColor Yellow
    Set-ItemProperty -Path $shellFolderPath -Name "Startup" -Value $originalStartup -ErrorAction Ignore
    Write-Host "    Restored to: $originalStartup" -ForegroundColor DarkGray

    return $result
}

# ==============================================================================
# SUBTEST 5: Append payload to Winlogon Userinit
# Atomic Red Team: T1547.001 Test #14
# Requires local admin.
# ==============================================================================

function Test-WinlogonUserinit {
    Write-Header "Append Payload to Winlogon Userinit Key (Atomic Test #14)" "HIGH"
    Write-Host "`nPath   : HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Write-Host "Method : The Userinit value lists programs Winlogon executes at every interactive"
    Write-Host "         logon. Default: 'C:\Windows\system32\userinit.exe,'"
    Write-Host "         Appending a second command runs it at every logon under the user context."
    Write-Host "         Less commonly audited than Run keys. Requires local admin."
    Write-Host "         Original value is backed up and restored immediately after test."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 13  - RegistryEvent (Value Set): Winlogon\Userinit modified"
    Write-Host "  EDR alert  - Winlogon\Userinit value deviates from 'userinit.exe,' baseline"
    Write-Host "  SIEM rule  - Any write to HKLM\...\Winlogon\Userinit by non-system process"
    Write-Host "  Event 4657 - Registry value modified: Winlogon key"

    $marker  = "$tempDir\art-v4.3-WinlogonUserinit.txt"
    $command = "Set-Content -Path '$marker' -Value ('[' + (Get-Date) + '] WinlogonUserinit executed')"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $payload = "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encoded"

    Write-Host "`n[*] Reading and backing up current Userinit value..." -ForegroundColor Yellow
    try {
        $oldValue = Get-ItemPropertyValue -Path $winlogonPath -Name "Userinit" -ErrorAction Stop
        Write-Host "    Current Userinit : $oldValue" -ForegroundColor DarkGray
        Set-ItemProperty -Path $winlogonPath -Name "Userinit-backup" -Value $oldValue -ErrorAction Stop
        Write-Host "    Backup written   : Winlogon\Userinit-backup" -ForegroundColor DarkGray
    } catch {
        Write-Host "  RESULT: Cannot read/backup Userinit (elevation required) - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    $newValue = $oldValue + " $payload"

    Write-Host "`n[*] Appending payload to Userinit..." -ForegroundColor Yellow
    Write-Host "    Key  : $winlogonPath" -ForegroundColor DarkGray
    Write-Host "    Value: Userinit" -ForegroundColor DarkGray
    Write-Host "    New  : [original], powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand [b64]" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 13 - RegistryEvent on Winlogon\Userinit; Event 4657]" -ForegroundColor DarkGray

    try {
        Set-ItemProperty -Path $winlogonPath -Name "Userinit" -Value $newValue -ErrorAction Stop
        Write-Host "    Userinit updated." -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: Userinit write blocked - $($_.Exception.Message)" -ForegroundColor Green
        Remove-ItemProperty -Path $winlogonPath -Name "Userinit-backup" -Force -ErrorAction Ignore
        return $false
    }

    Write-Host "`n[*] Verifying modified Userinit value..." -ForegroundColor Yellow
    $current = Get-ItemPropertyValue -Path $winlogonPath -Name "Userinit" -ErrorAction Ignore
    Write-Host "    Userinit now: $current" -ForegroundColor DarkGray

    Write-Host "`n[*] Executing payload directly (simulates logon trigger)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - powershell.exe -WindowStyle Hidden -EncodedCommand]" -ForegroundColor DarkGray
    try {
        Start-Process powershell.exe -ArgumentList @(
            "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", $encoded
        ) -Wait -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        Set-ItemProperty -Path $winlogonPath -Name "Userinit" -Value $oldValue -ErrorAction Ignore
        Remove-ItemProperty -Path $winlogonPath -Name "Userinit-backup" -Force -ErrorAction Ignore
        return $false
    }

    $result = Test-ExecutionResult -Name "WinlogonUserinit"

    # Restore immediately - broken Userinit = broken logon
    Write-Host "`n[*] Restoring Userinit to original value..." -ForegroundColor Yellow
    Set-ItemProperty -Path $winlogonPath -Name "Userinit" -Value $oldValue -ErrorAction Ignore
    Remove-ItemProperty -Path $winlogonPath -Name "Userinit-backup" -Force -ErrorAction Ignore
    Write-Host "    Restored: $oldValue" -ForegroundColor DarkGray

    return $result
}

# ==============================================================================
# RUN ALL
# ==============================================================================

function Test-All {
    Write-Host "`n+==============================================================================+" -ForegroundColor Cyan
    Write-Host "|   STARTUP FOLDER / ADVANCED LOGON PERSISTENCE - ALL SUBTESTS                |" -ForegroundColor Cyan
    Write-Host "+==============================================================================+" -ForegroundColor Cyan

    $tests = @(
        @{ Name = 'JSEStartup';          Fn = ${function:Test-JSEStartup}          },
        @{ Name = 'LNKShortcut';         Fn = ${function:Test-LNKShortcut}         },
        @{ Name = 'AllUsersBAT';         Fn = ${function:Test-AllUsersBAT}         },
        @{ Name = 'ShellFolderRedirect'; Fn = ${function:Test-ShellFolderRedirect} },
        @{ Name = 'WinlogonUserinit';    Fn = ${function:Test-WinlogonUserinit}    }
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
    Invoke-Cleanup -Names @('JSEStartup','LNKShortcut','AllUsersBAT','ShellFolderRedirect','WinlogonUserinit')
    exit 0
}

Write-Host "`n[TEST] Startup Folder / Advanced Logon Persistence (Technique 4.3)" -ForegroundColor Cyan
Write-Host "  MITRE: T1547.001  |  Phase 4  |  Persistence`n"

switch ($Subtest) {
    'All' {
        $results = Test-All
        if (-not $NoReport) {
            Write-Report -Results $results
        }
        Write-Host "`n[*] Marker files in $tempDir (art-v4.3-*.txt) left for review." -ForegroundColor Yellow
        if (-not $NoCleanupPrompt) {
            $c = Read-Host "Clean up now? (Y/N)"
            if ($c -eq 'Y' -or $c -eq 'y') {
                Invoke-Cleanup -Names @('JSEStartup','LNKShortcut','AllUsersBAT','ShellFolderRedirect','WinlogonUserinit')
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
            'JSEStartup'          { Test-JSEStartup          }
            'LNKShortcut'         { Test-LNKShortcut         }
            'AllUsersBAT'         { Test-AllUsersBAT         }
            'ShellFolderRedirect' { Test-ShellFolderRedirect }
            'WinlogonUserinit'    { Test-WinlogonUserinit    }
        }

        $color = if ($success) { 'Green' } else { 'Red' }
        Write-Host "`n[RESULT] Subtest '$Subtest': $(if ($success) { 'EXECUTED' } else { 'BLOCKED' })" -ForegroundColor $color
        if (-not $NoCleanupPrompt) {
            $c = Read-Host "Clean up now? (Y/N)"
            if ($c -eq 'Y' -or $c -eq 'y') { Invoke-Cleanup -Names @($Subtest) }
        }
    }
}
