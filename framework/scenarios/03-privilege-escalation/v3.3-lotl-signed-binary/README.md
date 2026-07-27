# Technique 3.3: Living-off-the-Land Signed Binary Proxy Execution (T1218)

## How to run

On VM1, open PowerShell from this folder:

```powershell
# Run all 4 subtests in sequence (pauses between each)
.\v3.3-lotl-signed-binary.ps1 -Subtest All

# Run a single subtest
.\v3.3-lotl-signed-binary.ps1 -Subtest MshtaHTA
.\v3.3-lotl-signed-binary.ps1 -Subtest Regsvr32SCT
.\v3.3-lotl-signed-binary.ps1 -Subtest Rundll32Advpack
.\v3.3-lotl-signed-binary.ps1 -Subtest InfDefaultInstall
```

You can also run it through the main launcher:

```powershell
.\Start-SCT.ps1
```

Select Module 3, then Technique 3.3.

Have the EDR console visible before running. Each subtest writes a marker file to `C:\Windows\Temp\art-v3.3-<SubtestName>.txt` as proof of execution. If the marker is missing, that subtest was blocked or unsupported.

This technique is self-contained for offline submission. It does not download Atomic Red Team payloads and does not require the Atomic Red Team folder at runtime. Temporary HTA, SCT, and INF payload files are generated under `%TEMP%\sct-v3.3-lolbin`.

---

## Subtests

### Subtest 1: MshtaHTA

Creates a local `.hta` file and executes it with `mshta.exe`. The HTA contains VBScript that writes a benign marker file. This mirrors common Atomic Red Team coverage for **T1218.005: Mshta**, but uses a local payload so the test works offline.

**Detection:** `mshta.exe` process creation with a user-writable `.hta` path, `.hta` file creation in `%TEMP%`, script execution by a signed Microsoft binary.

---

### Subtest 2: Regsvr32SCT

Creates a local `.sct` COM scriptlet and executes it with:

```text
regsvr32.exe /s /u /i:<scriptlet> scrobj.dll
```

This mirrors the classic Regsvr32 scriptlet execution pattern, often called Squiblydoo. The scriptlet only writes a benign marker file and does not register a COM object permanently.

**Detection:** `regsvr32.exe` with `/i:` and `scrobj.dll` in the command line, `scrobj.dll` module load, `.sct` file creation in `%TEMP%`.

---

### Subtest 3: Rundll32Advpack

Creates a local INF file with a `RunPreSetupCommands` section, then calls:

```text
rundll32.exe advpack.dll,LaunchINFSection <inf>,DefaultInstall_SingleUser,1,
```

The INF launches a Base64-encoded PowerShell marker-file write. This covers a common **T1218.011: Rundll32** signed-binary proxy path without needing an external payload file.

**Detection:** `rundll32.exe` command line containing `advpack.dll,LaunchINFSection`, INF file creation in `%TEMP%`, PowerShell child execution from installer helper logic.

---

### Subtest 4: InfDefaultInstall

Creates a local INF file with `RunPreSetupCommands` and executes it through `InfDefaultInstall.exe`. This tests a second signed installer binary that can proxy execution of setup commands.

**Detection:** `InfDefaultInstall.exe` launched with a user-writable INF path, INF file creation in `%TEMP%`, interpreter child process spawned from installer execution.

---

## Cleanup

At the end of a single test or `All`, the script asks whether to clean up. Cleanup removes:

- `C:\Windows\Temp\art-v3.3-*.txt`
- `%TEMP%\sct-v3.3-lolbin`

If you want to review marker files or EDR telemetry first, answer `N` and clean up later by rerunning the relevant subtest and choosing cleanup, or manually deleting those paths.
