# Vector 4.2: Scheduled Task Persistence (T1053.005)

## How to run

On VM1, open PowerShell:

```powershell
# Run all 5 sub-tests in sequence (pauses between each)
.\v4.2-scheduled-task.ps1 -Technique All

# Run a single sub-test
.\v4.2-scheduled-task.ps1 -Technique SchtasksOnLogon
.\v4.2-scheduled-task.ps1 -Technique PwshCmdlet
.\v4.2-scheduled-task.ps1 -Technique B64Registry
.\v4.2-scheduled-task.ps1 -Technique SystemTask
.\v4.2-scheduled-task.ps1 -Technique HiddenXML
```

> **Sub-tests 4 (SystemTask) and 5 (HiddenXML) require running as Administrator.** Sub-tests 1, 2, and 3 do not.

Have the EDR console visible before running. Each sub-test writes a marker file to `C:\Windows\Temp\art-v4.2-<SubTestName>.txt` as proof of execution. If the file is missing after the test, the technique was blocked.

---

## Sub-tests

### Sub-test 1: SchtasksOnLogon

Windows has a built-in tool called `schtasks.exe` for managing scheduled tasks. This sub-test uses it to create a task that runs at every user login, carrying a Base64-encoded PowerShell command as its payload. This is the most common and most visible method - it leaves a lot of evidence in logs because `schtasks.exe` itself is spawned with suspicious arguments.

**Detection:** Task creation event (Event 4698), `schtasks.exe` process with `/create` and `/sc ONLOGON` in its arguments (Sysmon 1).

---

### Sub-test 2: PwshCmdlet

Same outcome as sub-test 1 - a scheduled task that runs at login - but uses native PowerShell cmdlets (`New-ScheduledTaskAction`, `Register-ScheduledTask`) instead of `schtasks.exe`. Because no `schtasks.exe` process is spawned, detections that look for that specific process will miss this entirely. The task is registered through WMI under the hood and runs as the current logged-in user. No elevation required.

**Detection:** Task creation event (Event 4698), PowerShell Script Block Logging showing `Register-ScheduledTask` (Event 4104), WMI activity without `schtasks.exe` (Sysmon 20).

---

### Sub-test 3: B64Registry

This mirrors the **Qakbot** malware technique - a two-stage approach designed to make static analysis harder. Stage 1 stores a Base64-encoded payload in a registry key (not a file). Stage 2 creates a scheduled task that runs a small loader script which reads that registry key, decodes it, and executes it in memory via `IEX`. The task definition itself looks harmless - the actual payload is hidden in the registry.

**Detection:** Registry write to a non-standard HKCU key (Sysmon 13), task creation with a `Temp` folder PS1 as its target (Event 4698), and the IEX + Base64 + registry read chain in Script Block Logging (Event 4104).

---

### Sub-test 4: SystemTask *(requires Administrator)*

Creates a scheduled task that runs as `NT AUTHORITY\SYSTEM` - the highest privilege account on Windows - at every system startup. Any code it runs operates with full system access. This is an effective privilege escalation method. Requires local admin to create.

**Detection:** Task creation event with `NT AUTHORITY\SYSTEM` as the principal (Event 4698), `schtasks.exe` with `/ru system` and `/sc onstart` arguments (Sysmon 1).

---

### Sub-test 5: HiddenXML *(requires Administrator)*

This mirrors the **TrickBot** and **Industroyer2** malware technique. It registers a scheduled task using a low-level WMI method (`PS_ScheduledTask.RegisterByXml`) with `<Hidden>true</Hidden>` set in the XML definition. The result is a task that is **completely invisible** to `schtasks /query` and the Task Scheduler GUI - it can only be found with PowerShell's `Get-ScheduledTask`. The task also masquerades as a Microsoft component in its Author and Description fields. No `schtasks.exe` process is spawned.

**Detection:** Task creation event with `<Hidden>true</Hidden>` in the XML body (Event 4698), WMI method invocation via `PS_ScheduledTask.RegisterByXml` (Sysmon 20). The absence of `schtasks.exe` in process telemetry is itself a signal.
