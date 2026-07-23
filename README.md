# Security Controls Testing Framework (SCT)

SCT is a PowerShell lab framework for checking whether EDR and antivirus products detect or block simulated attack techniques. Tests are mapped to MITRE ATT&CK and include guided execution, result capture, and cleanup.

> **Lab VMs only - never run SCT on a production or connected business system.**

## Table of contents

- [One naming model](#one-naming-model)
- [Getting started](#getting-started)
  - [Lab requirements](#lab-requirements)
  - [Install](#install)
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
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) is recommended and is required for fileless-test result collection.
- Most techniques use one VM. Techniques 1.3 and remote subtests in 1.5 require a second Windows VM on the same isolated lab network.

### Install

```powershell
git clone https://github.com/cheekfg897/security-controls.git
Set-Location security-controls
```

### Which script do I run?

| I want to... | Run this |
|---|---|
| Run the security tests | `.\Start-SCT.ps1` |
| Open module, review, and validation tools | `.\Start-SCT.ps1`, then select `[M] Manage SCT` |
| Create a product workspace | `.\Start-SCT.ps1`, then select `[M]` → `[3]` |
| Fill detection and action status | Edit `results/<control-id>/results-module-<id>.csv` directly |
| Check the completed results | `.\Start-SCT.ps1`, then select `[M]` -> `[4]` |
| Build a comparison ZIP | `.\Start-SCT.ps1`, then select `[M]` -> `[5]` |
| Add a new test module | `.\scripts\authoring\Add-SCTModule.ps1` |
| Check module files after editing them | `.\scripts\validation\Check-SCTModules.ps1` |

The remaining utilities are listed by purpose in [`scripts/README.md`](scripts/README.md).

### Run SCT normally

On the isolated lab VM, open PowerShell 5.1 or later. From the repository directory, run:

```powershell
.\Start-SCT.ps1
```

SCT displays the module menu immediately. Before testing a new product, select `[M] Manage SCT` and then `[3] Create or update a control workspace`. Setup records the product and policy configuration in `results/<control-id>/control-profile.json` and creates one `test-catalog-module-<id>.csv` per discovered module. SCT routes each observation to that module's `results-module-<id>.csv`.

When more than one workspace exists, select `[C] Select Control Workspace` before testing. You can also select one at launch:

```powershell
.\Start-SCT.ps1 -ControlProfilePath .\results\sentinelone\control-profile.json
```

> Start with a standard PowerShell session unless the selected technique says it requires Administrator rights. Do not run Technique 3.2 (UAC Bypass) from an already elevated session because existing elevation invalidates the test.

Choose a module, then a technique, then a subtest when the technique provides them. `EXECUTED` means the expected execution marker was created; `BLOCKED` means it was not created. These labels describe the test observation only. They do not prove whether the security control detected the activity, blocked it before execution, or blocked it after execution. Press `V` in the main menu to view the result summary.

Results are appended directly to `results/<control-id>/results-module-<id>.csv`. The generated observation fields and the human review fields live in the same CSV; there is no raw/analysis copy step. Running a subtest technique directly produces console output and markers but does not invoke the central writer unless that script accepts and is given `-ResultsPath`.

Before testing, confirm the security product is active with a check from [`sanity_checks/`](sanity_checks/README.md).

### Malware samples

| Technique | Sample source |
|---|---|
| **1.1 Disk Drop** | Put ZIP files in `samples/`, then select one or combine all ZIPs. |
| **1.2 Removable Media** | Pre-load samples on an authorised USB drive; SCT requests its drive letter. |
| **1.3 Internet Download** | Host samples on a second VM with `v1.3-server.ps1`. |
| **1.4, 1.5, 1.6** | Self-contained or in-memory; no local sample archives are required. |

See the [sample guide](samples/README.md) for ZIP layouts and password-protected archives.

> **Technique 1.2 validation note:** USB delivery has not been validated in the current environment. A virtual disk does not validate USB device-control monitoring.

### Run Module 4 non-interactively

From an Administrator PowerShell session:

```powershell
.\Start-SCT.ps1 `
    -ControlProfilePath .\results\sentinelone\control-profile.json `
    -RunModule 04 -NonInteractive
```

This runs all 19 persistence subtests, including the HKCU and HKLM Run/RunOnce and permanent WMI consumer cases, records one row per subtest with a shared `run_id`, and performs cleanup after each technique.

### Complete and package one product's results

Run this workflow for each product. It uses PowerShell only; Python, Docker, and an AI model are not required.

Create the workspace through Manage SCT option `[3]`, or run:

```powershell
.\scripts\review\Setup-SCTControl.ps1
```

The workspace contains the product configuration plus stable result/catalogue files for each module:

```text
results/<control-id>/
|-- control-profile.json
|-- results-module-01.csv
|-- test-catalog-module-01.csv
|-- results-module-02.csv
`-- test-catalog-module-02.csv
```

The profile records the exact product versions, policy mode, product-specific settings, exclusions, and optional local-log locations used during the test. Do not store passwords, API tokens, or other secrets in it.

Run SCT with that workspace selected. SCT creates a module result file on its first observation. After testing, open each `results-module-<id>.csv` in Excel and fill only these fields:

| Field | Allowed values |
|---|---|
| `detection_status` | `detected`, `not_detected` |
| `action_status` | `blocked_before_execution`, `blocked_after_execution`, `not_blocked` |

`execution_status` is generated separately as `executed`, `not_executed`, or blank when it is not applicable; it never determines the review fields. A test may execute and then be detected, execute and later be blocked, or execute without detection. Timestamps remain so a reviewer can correlate each row with the product console or local logs.

Save the module result files in place, then validate and package the workspace through Manage SCT options `[4]` and `[5]`, or run:

```powershell
.\scripts\validation\Check-SCTResults.ps1 `
    -ControlProfilePath .\results\sentinelone\control-profile.json

.\scripts\review\Build-SCTComparisonPackage.ps1 `
    -ControlProfilePath .\results\sentinelone\control-profile.json
```

The package is written to `submissions/<control-id>.zip` and contains `control-profile.json` plus the authoritative result/catalogue pair for every tested module. Repeat for the second product and submit the two ZIP files to the comparison system.

## Built-in modules

| # | Module | Status | Techniques |
|---|---|---|---|
| 1 | Malware Delivery | Active | 1.1 Disk Drop; 1.2 Removable Media; 1.3 Internet Download; 1.4 Trojanised COTS; 1.5 Fileless PowerShell; 1.6 DLL Sideloading |
| 2 | Exploitation | Active | 2.1 Malicious Macro; 2.2 CVE Simulation |
| 3 | Privilege Escalation | Partial | 3.1 Process Hollowing *(planned)*; 3.2 UAC Bypass; 3.3 LOLBin Signed Binary |
| 4 | Persistence | Active | 4.1 Registry Run Keys (HKCU/HKLM); 4.2 Scheduled Tasks; 4.3 Advanced Startup Folder; 4.4 WMI Event Subscription |

See the [control matrix](docs/reference/control-matrix.md) for implementation status and ATT&CK mappings.

## Project structure

```text
security-controls/
|-- Start-SCT.ps1       # Main launcher
|-- config/             # Control-profile example and JSON schema
|-- core/               # Discovery, execution, markers, and results
|-- docs/               # Indexed architecture, guides, and reference docs
|-- results/            # Per-product profiles and generated result workspaces
|-- samples/            # Local malware ZIPs (gitignored)
|-- sanity_checks/      # EDR/AV verification checks
|-- scenarios/          # Module metadata and technique scripts
|   `-- <module>/
|       |-- module.json
|       |-- test-catalog.csv
|       `-- <technique>/
|-- scripts/            # Authoring, review, validation, and shared utilities
|-- submissions/        # Generated one-ZIP-per-product comparison packages
`-- tests/              # Framework/workflow regression tests and suite runner
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
