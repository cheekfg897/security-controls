# Technique 4.1: Registry Run Keys / Startup Folder Persistence (T1547.001)

## Contents

- [How to run](#how-to-run)
- [Subtests](#subtests)

## How to run

For complete coverage of both HKCU and HKLM, open PowerShell as Administrator on VM1. The HKCU and user-startup subtests do not require elevation, but the two HKLM subtests do.

```powershell
# Run all 7 subtests in sequence (pauses between each)
.\v4.1-registry-run-key.ps1 -Subtest All

# Run a single subtest
.\v4.1-registry-run-key.ps1 -Subtest HKCURunKey
.\v4.1-registry-run-key.ps1 -Subtest HKCURunOnce
.\v4.1-registry-run-key.ps1 -Subtest HKLMRunKey
.\v4.1-registry-run-key.ps1 -Subtest HKLMRunOnce
.\v4.1-registry-run-key.ps1 -Subtest StartupVBS
.\v4.1-registry-run-key.ps1 -Subtest StartupBAT
.\v4.1-registry-run-key.ps1 -Subtest SystemBC

# Optional: verify whether this PowerShell session can write to the machine-wide HKLM Run key.
# This creates and immediately removes one temporary registry value, so it generates telemetry.
.\v4.1-registry-run-key.ps1 -CheckHKLMWriteAccess
```

Have the EDR console visible before running. Each subtest writes a marker file to `C:\Windows\Temp\art-v4.1-<SubtestName>.txt`. If it is missing, that subtest was blocked or could not run with the current permissions.

The Run and RunOnce subtests execute their benign payload immediately to simulate the next-login trigger; SCT does not log out or reboot the VM. Choose cleanup when prompted to remove the test values. The complete non-interactive Module 4 run performs this cleanup automatically.

`-CheckHKLMWriteAccess` remains available as a quick permission check. It creates and immediately removes a temporary probe value without running a payload.

---

## Subtests

### Subtest 1: HKCURunKey

Windows has a registry location called the **Run key** that acts as a start-on-login list. Anything listed there runs automatically every time the user logs in. This subtest uses a built-in Windows tool (`reg.exe`) to add a fake entry to that list. The entry is a PowerShell command disguised in Base64 encoding so it does not look like plain text. It then immediately runs that command to simulate what would happen at next login.

**Detection:** `reg.exe` writing to the Run key (Sysmon 13), and a hidden PowerShell process with `-EncodedCommand` (Sysmon 1).

---

### Subtest 2: HKCURunOnce

Same start-on-login idea as subtest 1, but uses a different location called **RunOnce** - it fires only once after the next login, then Windows deletes it automatically. It also uses a different method to write the entry: a PowerShell cmdlet (`Set-ItemProperty`) instead of `reg.exe`. This produces different-looking telemetry, testing whether your controls catch both methods.

**Detection:** PowerShell cmdlet writing to RunOnce (Sysmon 13, Event 4104), and a hidden child PowerShell process.

---

### Subtest 3: HKLMRunKey

This is the machine-wide version of subtest 1. It uses `reg.exe` to write a benign encoded PowerShell command to `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, then executes the command immediately to simulate its next-login behavior. Because HKLM applies to every user, this subtest requires Administrator rights.

**Detection:** Elevated `reg.exe` writing to the HKLM Run key (Sysmon 13), followed by hidden encoded PowerShell execution (Sysmon 1).

---

### Subtest 4: HKLMRunOnce

This is the machine-wide version of subtest 2. It uses `Set-ItemProperty` to write a one-time benign PowerShell command to `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`, then executes it immediately to simulate the next-login trigger. This subtest requires Administrator rights.

**Detection:** PowerShell writing to HKLM RunOnce (Sysmon 13 and Event 4104), followed by a hidden child PowerShell process.

---

### Subtest 5: StartupVBS

Windows has a Startup folder - any file placed there runs automatically when the user logs in. This subtest drops a `.vbs` (Visual Basic Script) file into that folder and immediately runs it via `cscript.exe` to simulate the login trigger. No registry changes at all.

**Detection:** VBS file created in the startup folder (Sysmon 11), and `cscript.exe` running from that location (Sysmon 1).

---

### Subtest 6: StartupBAT

Same Startup folder behavior as subtest 5, but uses a `.bat` (batch file) instead of `.vbs`, and runs it with `cmd.exe`. Different file type and launcher produce different telemetry - this checks whether controls catch both script types.

**Detection:** BAT file created in the startup folder (Sysmon 11), and `cmd.exe` running from that location (Sysmon 1).

---

### Subtest 7: SystemBC

This mimics a real malware family called **SystemBC**, which is sold as a service to criminals. SystemBC's known signature is writing a hidden PowerShell command to the Run key under a specific value name: `socks5_powershell`. This subtest reproduces that exact pattern - same registry key, same value name, same hidden window flags - so you can verify whether your EDR has a rule for this specific known-bad indicator.

**Detection:** Run key write with value name `socks5_powershell` (Sysmon 13, known IOC), and hidden PowerShell with `-ExecutionPolicy Bypass` (Sysmon 1).
