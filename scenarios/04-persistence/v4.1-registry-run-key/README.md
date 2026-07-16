# Technique 4.1: Registry Run Keys / Startup Folder Persistence (T1547.001)

## How to run

On VM1, open PowerShell (no elevation required for the standard HKCU/startup tests):

```powershell
# Run all 5 subtests in sequence (pauses between each)
.\v4.1-registry-run-key.ps1 -Subtest All

# Run a single subtest
.\v4.1-registry-run-key.ps1 -Subtest HKCURunKey
.\v4.1-registry-run-key.ps1 -Subtest HKCURunOnce
.\v4.1-registry-run-key.ps1 -Subtest StartupVBS
.\v4.1-registry-run-key.ps1 -Subtest StartupBAT
.\v4.1-registry-run-key.ps1 -Subtest SystemBC

# Optional: verify whether this PowerShell session can write to the machine-wide HKLM Run key.
# This creates and immediately removes one temporary registry value, so it generates telemetry.
.\v4.1-registry-run-key.ps1 -CheckHKLMWriteAccess
```

Have the EDR console visible before running. Each subtest writes a marker file to `C:\Windows\Temp\art-v4.1-<SubtestName>.txt`. If it is missing, that subtest was blocked.

The normal subtests use `HKCU`, which does not need elevation. `HKLM` is machine-wide and normally requires an elevated PowerShell session. `-CheckHKLMWriteAccess` is an opt-in capability check only; it does not leave an autorun value behind.

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

### Subtest 3: StartupVBS

Windows has a Startup folder - any file placed there runs automatically when the user logs in. This subtest drops a `.vbs` (Visual Basic Script) file into that folder and immediately runs it via `cscript.exe` to simulate the login trigger. No registry changes at all.

**Detection:** VBS file created in the startup folder (Sysmon 11), and `cscript.exe` running from that location (Sysmon 1).

---

### Subtest 4: StartupBAT

Same Startup folder behavior as subtest 3, but uses a `.bat` (batch file) instead of `.vbs`, and runs it with `cmd.exe`. Different file type and launcher produce different telemetry - this checks whether controls catch both script types.

**Detection:** BAT file created in the startup folder (Sysmon 11), and `cmd.exe` running from that location (Sysmon 1).

---

### Subtest 5: SystemBC

This mimics a real malware family called **SystemBC**, which is sold as a service to criminals. SystemBC's known signature is writing a hidden PowerShell command to the Run key under a specific value name: `socks5_powershell`. This subtest reproduces that exact pattern - same registry key, same value name, same hidden window flags - so you can verify whether your EDR has a rule for this specific known-bad indicator.

**Detection:** Run key write with value name `socks5_powershell` (Sysmon 13, known IOC), and hidden PowerShell with `-ExecutionPolicy Bypass` (Sysmon 1).
