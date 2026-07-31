# Technique 4.3: Startup Folder / Advanced Logon Persistence (T1547.001)

## Contents

- [How to run](#how-to-run)
- [Subtests](#subtests)

## How to run

On VM1, open PowerShell:

```powershell
# Run all 5 subtests in sequence (pauses between each)
.\v4.3-startup-folder.ps1 -Subtest All

# Run a single subtest
.\v4.3-startup-folder.ps1 -Subtest JSEStartup
.\v4.3-startup-folder.ps1 -Subtest LNKShortcut
.\v4.3-startup-folder.ps1 -Subtest AllUsersBAT
.\v4.3-startup-folder.ps1 -Subtest ShellFolderRedirect
.\v4.3-startup-folder.ps1 -Subtest WinlogonUserinit
```

> **Subtests 3 (AllUsersBAT) and 5 (WinlogonUserinit) require running as Administrator.**

> **Subtest 5 modifies a critical system registry value (Winlogon Userinit). The script restores it immediately after the test. Do not terminate the script mid-run during this subtest.**

Have the EDR console visible before running. Each subtest writes a marker file to `C:\Windows\Temp\art-v4.3-<SubtestName>.txt`. A missing marker means the payload was not observed; use the security-console evidence to decide whether a control blocked it.

On an interactive rerun, the launcher asks before deleting an existing marker. The direct script applies the same rule to verified SCT marker and payload files. `ShellFolderRedirect` also asks before removing and rebuilding its SCT-owned `%TEMP%\sct-startup-redirect` directory. Artifacts that cannot be verified as SCT-owned are preserved and the subtest stops.

This technique extends Technique 4.1: 4.1 covers basic startup folder drops and Run key writes, while 4.3 covers less common variations.

---

## Subtests

### Subtest 1: JSEStartup

Drops a `.jse` (JScript Encoded) file into the user's startup folder and runs it via `cscript.exe`. JScript is a different scripting engine from VBScript - detections that match on plain VBScript or batch file text will not match JScript syntax. The `.jse` extension is also rare in legitimate software, making it a strong signal on its own.

**Detection:** `.jse` file created in the startup folder (Sysmon 11), `cscript.exe` launched with `/E:Jscript` from that path (Sysmon 1).

---

### Subtest 2: LNKShortcut

Creates a `.lnk` shortcut file in the user's startup folder that points to `powershell.exe` with a Base64-encoded payload in its arguments. Unlike a script file, there is no readable text content in the folder - just a binary shortcut. A detection that looks for suspicious text inside startup folder files will miss this entirely. The EDR has to parse the binary LNK structure to see where it points.

**Detection:** `.lnk` file created in the startup folder (Sysmon 11), PowerShell process spawned via the shortcut with `-EncodedCommand` (Sysmon 1).

---

### Subtest 3: AllUsersBAT *(requires Administrator)*

Drops a batch file into the **AllUsers** startup folder (`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`) rather than the current user's startup folder. The difference is scope - this fires for every user who logs into the machine, not just one. Requires admin to write to `C:\ProgramData`.

**Detection:** BAT file created in `C:\ProgramData\...\StartUp` (Sysmon 11 - note the different path from `%APPDATA%`), `cmd.exe` spawned from that path (Sysmon 1).

---

### Subtest 4: ShellFolderRedirect

Windows reads a registry value called **User Shell Folders - Startup** to find where the user's startup folder is. This subtest changes that value to point at an attacker-controlled directory instead of the real startup folder. Any file placed in that new directory will run at login - without anything being written to the known `%APPDATA%\...\Startup` path that most detections watch. No elevation required. The value is restored immediately after the test.

**Detection:** The `Startup` value in User Shell Folders modified to a non-standard path (Sysmon 13), execution from an unexpected directory at login.

---

### Subtest 5: WinlogonUserinit *(requires Administrator)*

The **Winlogon Userinit** registry value lists programs that Windows runs at every interactive logon. Normally it contains only `userinit.exe`. This subtest appends a PowerShell command to that value so it runs alongside `userinit.exe` at every login. This location is less commonly monitored than Run keys, making it harder to catch with basic rules. Requires admin to modify `HKLM`. The original value is backed up and restored immediately after the test.

> Do not terminate the script mid-run during this subtest - if the restore step is skipped, the Userinit value will be left in a modified state, which can break the logon process.

**Detection:** `Winlogon\Userinit` value modified (Sysmon 13, Event 4657), any deviation from the `userinit.exe,` baseline should alert.
