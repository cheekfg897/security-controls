# Security Controls Testing Framework (SCT)

SCT is a PowerShell lab framework for checking whether EDR and antivirus products detect or block simulated attack techniques. Tests are mapped to MITRE ATT&CK and include guided execution, result capture, and cleanup.

> **Lab VMs only - never run SCT on a production or connected business system.**

## Table of contents

- [One naming model](#one-naming-model)
- [Getting started](#getting-started)
  - [Lab requirements](#lab-requirements)
  - [Install](#install)
  - [Configure Sysmon telemetry](#configure-sysmon-telemetry)
  - [Which script do I run?](#which-script-do-i-run)
  - [Run SCT normally](#run-sct-normally)
  - [Malware samples](#malware-samples)
  - [Run Module 4 non-interactively](#run-module-4-non-interactively)
  - [Complete and package one product's results](#complete-and-package-one-products-results)
- [Built-in modules](#built-in-modules)
- [Project structure](#project-structure)
- [Adding a technique](#adding-a-technique)
- [Documentation](#documentation)

## One naming model

SCT uses the same three terms in metadata, menus, scripts, results, and documentation:

| Term | Meaning | Example |
|---|---|---|
| **Module** | A broad security-testing category. | `04 Persistence` |
| **Technique** | One numbered test scenario inside a module. | `4.2 Scheduled Task / Job` |
| **Subtest** | An optional selectable variation of a technique. | `HiddenXML` |

`attack_id` is the MITRE ATT&CK mapping; it is not another level in the SCT hierarchy.

## Getting started

### Lab requirements

- An isolated Windows 10/11 VM with a snapshot.
- PowerShell 5.1 or later.
- An active EDR or antivirus product to test.
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon), installed
  with SCT's [`config/sysmon-sct.xml`](config/sysmon-sct.xml). A default Sysmon
  installation does not enable all telemetry used by SCT.
- Most techniques use one VM. Techniques 1.3 and remote subtests in 1.5 require a second Windows VM on the same isolated lab network.

### Install

```powershell
git clone https://github.com/cheekfg897/security-controls.git
Set-Location security-controls
Set-Location framework
```

### Configure Sysmon telemetry

SCT includes a ready-to-use Sysmon configuration at
[`config/sysmon-sct.xml`](config/sysmon-sct.xml). **The XML file is required:**
installing Sysmon with its default settings does not enable all event types
used by the scenarios.

The included lab configuration collects:

| Sysmon event | SCT evidence |
|---|---|
| 1 | Process creation and parent/child command lines |
| 3 | Network connections used by download and fileless tests |
| 7 | `dxgi.dll` and `scrobj.dll` image loads used by sideloading/LOLBin tests |
| 11 | File creation and payload delivery |
| 12-14 | Registry creation, value changes, and renames |
| 19-21 | Permanent WMI filter, consumer, and binding creation |

The configuration is intentionally broad for a short-lived isolated lab VM.
Do not deploy it unchanged to production endpoints.

Download and extract Sysmon from Microsoft into `C:\Sysmon`. Then open
**PowerShell as Administrator**, change to the repository root, and paste:

```powershell
$sysmonExe = 'C:\Sysmon\Sysmon64.exe'
$sysmonConfig = (Resolve-Path '.\framework\config\sysmon-sct.xml').Path
$sysmonServices = @(Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue)

if (-not (Test-Path -LiteralPath $sysmonExe -PathType Leaf)) {
    throw "Sysmon executable not found: $sysmonExe"
}

if ($sysmonServices.Count -eq 0) {
    & $sysmonExe -accepteula -i $sysmonConfig
} else {
    $sysmonServices |
        Where-Object Status -ne 'Running' |
        Start-Service
    & $sysmonExe -c $sysmonConfig
}

# Retain up to 512 MiB so broad lab telemetry does not roll over too quickly.
wevtutil.exe sl Microsoft-Windows-Sysmon/Operational /e:true /ms:536870912
```

If the download contains `Sysmon.exe` instead, change only `$sysmonExe`.
The `-i` command installs Sysmon with the XML; `-c` updates an existing
installation immediately without a reboot.

Verify the service, active configuration, and event channel:

```powershell
Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue
& $sysmonExe -c
Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational |
    Select-Object LogName, IsEnabled, RecordCount, MaximumSizeInBytes
```

At least one Sysmon service must show `Running`, and the event log must show
`IsEnabled` as `True`. If applying the XML reports a schema error, use the
latest Sysmon release from Microsoft; do not fall back to the default
configuration.

Sysmon does not provide every Windows event referenced by SCT. Enable
PowerShell Script Block Logging for Event 4104 and scheduled-task auditing for
Event 4698 from the same elevated PowerShell session:

```powershell
$scriptBlockKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $scriptBlockKey -Force | Out-Null
New-ItemProperty -Path $scriptBlockKey -Name EnableScriptBlockLogging `
    -PropertyType DWord -Value 1 -Force | Out-Null

auditpol.exe /set /subcategory:"Other Object Access Events" /success:enable
wevtutil.exe sl Microsoft-Windows-TaskScheduler/Operational /e:true
wevtutil.exe sl Microsoft-Windows-WMI-Activity/Operational /e:true
```

Start a new PowerShell process after enabling Script Block Logging. Sysmon
events confirm that activity was recorded; they do not by themselves mean the
EDR/AV raised a detection. Record the product verdict separately in the SCT
result fields.

### Which script do I run?

| I want to... | Run this |
|---|---|
| Run the security tests | `.\Start-SCT.ps1` |
| Open module, review, and validation tools | `.\Start-SCT.ps1`, then select `[M] Manage SCT` |
| Create a product profile before or after testing | `.\Start-SCT.ps1`, then answer the startup prompt or select `[N]` |
| Select an existing configuration | `.\Start-SCT.ps1`, then select `[C]` |
| Fill detected/not-detected and blocked/not-blocked status | Edit `results/<control-id>/results-module-<id>.csv` directly |
| Check the completed results | `.\Start-SCT.ps1`, then select `[M]` -> `[4]` |
| Build a comparison ZIP | `.\Start-SCT.ps1`, then select `[M]` -> `[5]` |
| Compare two or more product ZIPs | `.\Start-SCT.ps1`, then select `[M]` -> `[6]` |
| Open the local comparison web app | `..\ai-system\.venv\Scripts\python.exe -m sct_ai web --repository-root .` |
| Add a new test module | `.\scripts\authoring\Add-SCTModule.ps1` |
| Check module files after editing them | `.\scripts\validation\Check-SCTModules.ps1` |

The remaining utilities are listed by purpose in [`scripts/README.md`](scripts/README.md).

### Run SCT normally

On the isolated lab VM, open PowerShell 5.1 or later. From the `framework`
directory, run:

```powershell
.\Start-SCT.ps1
```

SCT first asks for a session name, which identifies the result workspace for
the run. It then asks whether to create a new control profile. Answer **No** to
continue immediately in draft-session mode: modules remain available and all
observations are saved, but validation and comparison packaging remain
unavailable until the profile is created.

Answer **Yes**, or choose `[N] Create a control profile for this session` later
from the Main Menu, to run the profile setup. Existing draft results are kept.
Only the display name is required; press Enter to skip optional vendor, product,
version, agent, policy, mode, setting, exclusion, log, and notes fields.

Skipped text details are stored as `Not recorded`, and a skipped policy mode is
stored as `custom`, keeping the profile valid. Finalizing the session writes
`results/<session-id>/<session-id>-control-profile.json`. The same workspace
contains one `test-catalog-module-<id>.csv` per discovered module and routes
each observation to that module's `results-module-<id>.csv`.

Choose `[C] Select Existing Configuration` to switch from the current session
to a finalized product workspace already under `results/`.

You can also select an existing configuration at launch:

```powershell
.\Start-SCT.ps1 -ControlProfilePath .\results\sentinelone\sentinelone-control-profile.json
```

> Start with a standard PowerShell session unless the selected technique says it requires Administrator rights. Do not run Technique 3.2 (UAC Bypass) from an already elevated session because existing elevation invalidates the test.

Choose a module, then a technique, then a subtest when the technique provides them. `EXECUTED` means the expected execution marker was created; `NOT_EXECUTED` means it was absent; `ERROR` means the technique script failed or rejected a prerequisite. Marker absence does not prove that the security control blocked the activity. Record the control decision separately in `action_status`, and press `V` in the main menu to view the result summary.

Results are appended directly to `results/<control-id>/results-module-<id>.csv`. The generated observation fields and the human review fields live in the same CSV; there is no raw/analysis copy step. Running a subtest technique directly produces console output and markers but does not invoke the central writer unless that script accepts and is given `-ResultsPath`.

Before testing, confirm the security product is active with a check from [`sanity_checks/`](sanity_checks/README.md).

### Malware samples

| Technique | Sample source |
|---|---|
| **1.1 Malware Payload Delivery** | Put ZIP files in `samples/`, then select one or combine all ZIPs. ZIPs inside a selected ZIP are detected and can be included after an explicit prompt. |
| **1.2 Removable Media** | Pre-load samples on an authorised USB drive; SCT requests its drive letter. |
| **1.3 Internet Download** | Host samples on a second VM with `v1.3-server.ps1`. |
| **1.4, 1.5, 1.6** | Self-contained or in-memory; no local sample archives are required. |

See the [sample guide](samples/README.md) for ZIP layouts and password-protected archives.

> **Technique 1.2 validation note:** USB delivery has not been validated in the current environment. A virtual disk does not validate USB device-control monitoring.

### Run Module 4 non-interactively

From an Administrator PowerShell session:

```powershell
.\Start-SCT.ps1 `
    -ControlProfilePath .\results\sentinelone\sentinelone-control-profile.json `
    -RunModule 04 -NonInteractive
```

This runs all 19 persistence subtests, including the HKCU and HKLM Run/RunOnce and permanent WMI consumer cases, records one row per subtest with a shared `run_id`, and performs cleanup after each technique.

### Complete and package one product's results

Run this workflow for each product. It uses PowerShell only; Python, Docker, and an AI model are not required.

Create the workspace through Main Menu option `[N]`, Manage SCT option `[3]`,
or run:

```powershell
.\scripts\review\Setup-SCTControl.ps1
```

The workspace contains the product configuration plus stable result/catalogue files for each module:

```text
results/<control-id>/
|-- <control-id>-control-profile.json
|-- results-module-01.csv
|-- test-catalog-module-01.csv
|-- results-module-02.csv
`-- test-catalog-module-02.csv
```

The profile records the exact product versions, policy mode, product-specific settings, exclusions, and optional local-log locations used during the test. Do not store passwords, API tokens, or other secrets in it.

Run SCT with that workspace selected. SCT creates a module result file on its first observation. After testing, open each `results-module-<id>.csv` in Excel and fill only these fields:

| Field | Allowed values |
|---|---|
| `detection_status` | Complete `detection=` with `detected` or `not_detected` |
| `action_status` | Complete `action=` with `blocked` or `not_blocked` |

New rows also place `notes=` in `reviewer_notes`. Type after each equals sign,
for example `detection=detected`, `action=blocked`, and
`notes=Quarantined during extraction`. Replacing the complete prompt with the
value remains supported. Packaging removes the prompts automatically.

Result files use a review-first layout: technique name, subtest, input,
execution outcome, and the editable review fields appear first. Run
metadata, the internal technique ID, script path, and SHA-256 remain at the end
of each row for validation and AI comparison.

Module 01 records exactly one `test_stage=write` row per payload attempt.
`execution_status` is `executed` or `not_executed`; delivery, Sysmon, and error
details remain in `source_result`. A payload removed on sight therefore remains
one `not_executed` row. Generated observations never determine the review
fields; reviewers credit only the product under test.

`action_status` is intentionally binary because product logs often show only
that an action was blocked, not whether the block happened before or after a
particular execution boundary. Legacy `blocked_before_execution` and
`blocked_after_execution` values are accepted as `blocked` when older
workspaces are packaged.

Save the module result files in place, then validate and package the workspace through Manage SCT options `[4]` and `[5]`, or run:

```powershell
.\scripts\validation\Check-SCTResults.ps1 `
    -ControlProfilePath .\results\sentinelone\sentinelone-control-profile.json

.\scripts\review\Build-SCTComparisonPackage.ps1 `
    -ControlProfilePath .\results\sentinelone\sentinelone-control-profile.json
```

The package is written to `submissions/<control-id>.zip` and contains
`control-profile.json` plus the authoritative result/catalogue pair for every
tested module. Repeat for the second product and submit the two ZIP files to
the comparison system.

#### Workspace and package naming

| Location | Required name | Purpose |
|---|---|---|
| Product workspace | `results/<control-id>/<control-id>-control-profile.json` | Product-specific profile used while running and reviewing tests |
| Product workspace | `test-catalog-module-<id>.csv` | Test descriptions; one catalogue is retained for every discovered module |
| Product workspace | `results-module-<id>.csv` | Observations; created only after that module has results |
| Submission folder | `submissions/<control-id>.zip` | Final ZIP accepted by the comparison application |
| Inside the submission ZIP | `control-profile.json` | Canonical product-independent profile name |
| Inside the submission ZIP | Matching `results-module-<id>.csv` and `test-catalog-module-<id>.csv` pairs | Only modules that actually have results |

Do not compress or upload a directory from `results/` directly. A workspace
intentionally contains catalogues for untested modules and uses a
product-specific profile filename, so a raw workspace ZIP is not a comparison
package. Always use Manage SCT option `[5]` or
`Build-SCTComparisonPackage.ps1`; the builder renames the profile and excludes
catalogues without matching results. Use `-Force` when rebuilding an existing
submission after results change.

### Compare products

After building at least two product ZIPs and completing the one-time Python
installation in [`ai-system/README.md`](../ai-system/README.md), start the local,
air-gap-compatible web application:

```powershell
..\ai-system\.venv\Scripts\python.exe -m sct_ai web --repository-root .
```

The repository-owned Python engine validates each package, matches equivalent
cases, calculates detection/action rates and weighted rankings, and can use an
allowlisted hosted or local Ollama model to explain the verified evidence. The
model cannot alter calculated values or the deterministic recommendation.
Generated runs are stored separately under `../ai-system/comparisons/<comparison-id>/`;
source ZIPs and authoritative result CSVs are never changed.

See [AI-assisted control comparison](../ai-system/README.md) for setup,
scoring, provider configuration, shared proof-of-concept mode, and offline
installation.

## Built-in modules

| # | Module | Status | Techniques |
|---|---|---|---|
| 1 | Malware Delivery | Active | 1.1 Malware Payload Delivery; 1.2 Removable Media; 1.3 Internet Download; 1.4 Trojanised COTS; 1.5 Fileless PowerShell; 1.6 DLL Sideloading |
| 2 | Exploitation | Active | 2.1 Malicious Macro; 2.2 CVE Simulation |
| 3 | Privilege Escalation | Partial | 3.1 Process Hollowing *(planned)*; 3.2 UAC Bypass; 3.3 LOLBin Signed Binary |
| 4 | Persistence | Active | 4.1 Registry Run Keys (HKCU/HKLM); 4.2 Scheduled Tasks; 4.3 Advanced Startup Folder; 4.4 WMI Event Subscription |

See the [control matrix](docs/reference/control-matrix.md) for implementation status and ATT&CK mappings.

## Project structure

```text
security-controls/
|-- ai-system/          # Isolated comparison engine, web app, config, outputs, and tests
`-- framework/
    |-- Start-SCT.ps1   # Main launcher
    |-- config/         # Control-profile schema/example and Sysmon lab XML
    |-- core/           # Discovery, execution, markers, and results
    |-- docs/           # Indexed architecture, guides, and reference docs
    |-- results/        # Per-product profiles and generated result workspaces
    |-- samples/        # Local malware ZIPs (gitignored)
    |-- sanity_checks/  # EDR/AV verification checks
    |-- scenarios/      # Module metadata and technique scripts
    |   `-- <module>/
    |       |-- module.json
    |       |-- test-catalog.csv
    |       `-- <technique>/
    |-- scripts/        # Authoring, review, validation, and shared utilities
    |-- submissions/    # Generated one-ZIP-per-product comparison packages
    `-- tests/          # Framework/workflow regression tests and suite runner
```

The `tests/` folder verifies SCT's internal schema and framework behavior after code changes; it does not run security techniques or test an endpoint product. Run the full suite with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
```

## Adding a technique

Add one object to the module's `techniques` array. A technique with no subtests needs only four fields:

```json
{
  "id": "4.5",
  "name": "Windows Service Persistence",
  "attack_id": "T1543.003",
  "script": "v4.5-windows-service/v4.5-windows-service.ps1"
}
```

Add `subtests` only when the user should choose between named variations:

```json
{
  "id": "4.5",
  "name": "Windows Service Persistence",
  "attack_id": "T1543.003",
  "script": "v4.5-windows-service/v4.5-windows-service.ps1",
  "subtests": ["ScExeCreate", "PowerShellCreate"]
}
```

SCT automatically adds the `All` choice and derives marker paths. Do not add `type`, `supports`, `All`, individual-test lists, defaults, or marker templates to `module.json`.

Subtest scripts accept `-Subtest`, include `All` in their `ValidateSet`, and write successful markers using:

```text
C:\Windows\Temp\art-v<technique-id>-<subtest>.txt
```

For a planned technique, add only `"status": "planned"`; remove that field when the script is ready.

Use the guided module command and checks:

```powershell
.\scripts\authoring\Add-SCTModule.ps1
.\scripts\validation\Check-SCTModules.ps1
.\scripts\validation\Check-SCTTestDescriptions.ps1
```

`Add-SCTModule.ps1` creates `module.json` and then asks for each test's descriptions. Every new technique/subtest needs one scenario `test-catalog.csv` row. Workspace setup automatically creates `test-catalog-module-<id>.csv`; the first observation creates `results-module-<id>.csv`. All framework-managed result writers use the canonical schema in `core/SCT-Results.ps1`.

See [Project Structure](docs/guides/project-structure.md) for the full authoring workflow and [Framework Design](docs/architecture/framework-design.md) for how SCT infers execution behavior without a metadata type field.

## Documentation

- [Documentation Index](docs/README.md) - the entry point for architecture, guides, and reference material.
- [Framework Design](docs/architecture/framework-design.md) - schema, execution inference, markers, and results.
- [Project Structure](docs/guides/project-structure.md) - where files belong and how to add modules or techniques.
- [Control Matrix](docs/reference/control-matrix.md) - status and ATT&CK mapping for every technique.
- [Threat Scenarios](docs/reference/threat-scenarios.md) - purpose, prerequisites, and operating notes.
- [Sample Guide](samples/README.md) - ZIP layouts and sample handling.
- [Sanity Checks](sanity_checks/README.md) - verify the endpoint control before testing.
- [Results Workspaces](results/README.md) - per-product profile, results, and catalogue layout.
- [Comparison Submissions](submissions/README.md) - the exact three-file ZIP format.
