# Vector 4.1: Registry Run Keys / Startup Folder Persistence (T1547.001)

## How to run

On VM1, open PowerShell (no elevation required for the standard HKCU/startup tests):

```powershell
# Run all 5 sub-tests in sequence (pauses between each)
.\v4.1-registry-run-key.ps1 -Technique All

# Run a single sub-test
.\v4.1-registry-run-key.ps1 -Technique HKCURunKey
.\v4.1-registry-run-key.ps1 -Technique HKCURunOnce
.\v4.1-registry-run-key.ps1 -Technique StartupVBS
.\v4.1-registry-run-key.ps1 -Technique StartupBAT
.\v4.1-registry-run-key.ps1 -Technique SystemBC

# Optional: verify whether this PowerShell session can write to the machine-wide HKLM Run key.
# This creates and immediately removes one temporary registry value, so it generates telemetry.
.\v4.1-registry-run-key.ps1 -CheckHKLMWriteAccess
```

Have the EDR console visible before running. Each sub-test writes a marker file to `C:\Windows\Temp\art-v4.1-<SubTestName>.txt` as proof of execution. If the file is missing after the test, the technique was blocked.

The normal sub-tests use `HKCU`, which does not need elevation. `HKLM` is machine-wide and normally requires an elevated PowerShell session. `-CheckHKLMWriteAccess` is an opt-in capability check only; it does not leave an autorun value behind.

---

## Sub-tests

### Sub-test 1: HKCURunKey

Windows has a registry location called the **Run key** that acts as a start-on-login list. Anything listed there runs automatically every time the user logs in. This sub-test uses a built-in Windows tool (`reg.exe`) to add a fake entry to that list. The entry is a PowerShell command disguised in Base64 encoding so it does not look like plain text. It then immediately runs that command to simulate what would happen at next login.

**Detection:** `reg.exe` writing to the Run key (Sysmon 13), and a hidden PowerShell process with `-EncodedCommand` (Sysmon 1).

---

### Sub-test 2: HKCURunOnce

Same start-on-login idea as sub-test 1, but uses a different location called **RunOnce** - it fires only once after the next login, then Windows deletes it automatically. It also uses a different method to write the entry: a PowerShell cmdlet (`Set-ItemProperty`) instead of `reg.exe`. This produces different-looking telemetry, testing whether your controls catch both methods.

**Detection:** PowerShell cmdlet writing to RunOnce (Sysmon 13, Event 4104), and a hidden child PowerShell process.

---

### Sub-test 3: StartupVBS

Windows has a Startup folder - any file placed there runs automatically when the user logs in. This sub-test drops a `.vbs` (Visual Basic Script) file into that folder and immediately runs it via `cscript.exe` to simulate the login trigger. No registry changes at all.

**Detection:** VBS file created in the startup folder (Sysmon 11), and `cscript.exe` running from that location (Sysmon 1).

---

### Sub-test 4: StartupBAT

Same Startup folder technique as sub-test 3, but uses a `.bat` (batch file) instead of `.vbs`, and runs it with `cmd.exe`. Different file type and launcher produce different telemetry - this checks whether controls catch both script types.

**Detection:** BAT file created in the startup folder (Sysmon 11), and `cmd.exe` running from that location (Sysmon 1).

---

### Sub-test 5: SystemBC

This mimics a real malware family called **SystemBC**, which is sold as a service to criminals. SystemBC's known signature is writing a hidden PowerShell command to the Run key under a specific value name: `socks5_powershell`. This sub-test reproduces that exact pattern - same registry key, same value name, same hidden window flags - so you can verify whether your EDR has a rule for this specific known-bad indicator.

**Detection:** Run key write with value name `socks5_powershell` (Sysmon 13, known IOC), and hidden PowerShell with `-ExecutionPolicy Bypass` (Sysmon 1).
