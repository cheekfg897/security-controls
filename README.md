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
  - [Prepare one VM's results for review](#prepare-one-vms-results-for-review)
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
| Describe the control installed in this VM | `.\scripts\Setup-SCTControl.ps1` |
| Prepare finished test results for Excel review | `.\scripts\Prepare-SCTResultsForReview.ps1` |
| Fill detection and action status | No script: edit `results-for-review.csv` in Excel |
| Check the completed Excel CSV | `.\scripts\Check-SCTReviewedResults.ps1` |
| Add a new test module | `.\scripts\Add-SCTModule.ps1` |
| Check module files after editing them | `.\scripts\Check-SCTModules.ps1` |

The remaining utilities are listed by purpose in [`scripts/README.md`](scripts/README.md).

### Run SCT normally

On the isolated lab VM, open PowerShell 5.1 or later. From the repository directory, run:

```powershell
.\Start-SCT.ps1
```

SCT asks for the security product name, then displays the module and technique menus. To provide the product name at launch instead of being prompted:

```powershell
.\Start-SCT.ps1 -Control SentinelOne
```

> Start with a standard PowerShell session unless the selected technique says it requires Administrator rights. Do not run Technique 3.2 (UAC Bypass) from an already elevated session because existing elevation invalidates the test.

Choose a module, then a technique, then a subtest when the technique provides them. `EXECUTED` means the expected execution marker was created; `BLOCKED` means it was not created. These labels describe the test observation only. They do not prove whether the security control detected the activity, blocked it before execution, or blocked it after execution. Press `V` in the main menu to view the result summary.

Results are written to:

- `results/raw/test-results.csv` for subtest outcomes.
- `results/raw/results.csv` for sample-delivery outcomes.

Interactive subtest selections append to `test-results.csv` after the technique script returns. Running a technique script directly produces its console output and markers but does not invoke the central CSV writer.

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
.\Start-SCT.ps1 -Control SentinelOne -RunModule 04 -NonInteractive
```

This runs all 19 persistence subtests, including the HKCU and HKLM Run/RunOnce and permanent WMI consumer cases, records one row per subtest with a shared `run_id`, and performs cleanup after each technique.

### Prepare one VM's results for review

Run this workflow inside each test VM after its SCT tests finish. It uses PowerShell only; Python, Docker, and an AI model are not required.

First create a JSON profile describing the exact control, product versions, policy mode, product-specific settings, exclusions, and optional local log locations used during the test:

```powershell
.\scripts\Setup-SCTControl.ps1
```

The setup command validates the profile before saving it. You can also copy [`config/control-profile.example.json`](config/control-profile.example.json) and edit it directly; after a manual edit, check it with `.\scripts\Check-SCTControlProfile.ps1 -Path .\config\control-profile.local.json`. Do not store passwords, API tokens, or other secrets in the profile.

Then join the raw results to the standard test descriptions:

```powershell
.\scripts\Prepare-SCTResultsForReview.ps1 `
    -ControlProfilePath .\config\control-profile.local.json
```

This leaves both raw CSV files unchanged and creates:

- `results/analysis/results-for-review.csv` — Excel-ready result rows with the technique script, sample name/hash when available, execution observation, and two blank human-review fields.
- `results/analysis/test-catalog.csv` — one combined description of every test and subtest, including its objective, behavior, and success indicator.

Open `results-for-review.csv` in Excel and fill only these fields:

| Field | Allowed values |
|---|---|
| `detection_status` | `detected`, `not_detected` |
| `action_status` | `blocked_before_execution`, `blocked_after_execution`, `not_blocked` |

`execution_status` is derived separately as `executed` or `not_executed`; it never determines the two review fields. A test may execute and then be detected, execute and later be blocked, or execute without detection. Timestamps remain in the output so a reviewer can correlate each row with the product console or local logs.

Save the reviewed copy as `reviewed-results.csv`, then validate it:

```powershell
.\scripts\Check-SCTReviewedResults.ps1 `
    -Path .\results\analysis\reviewed-results.csv
```

For an eventual comparison, copy the profile, reviewed result CSV, and generated test catalogue from Control A's VM into one folder, and do the same for Control B. AI comparison is deliberately outside this first workflow.

## Built-in modules

| # | Module | Status | Techniques |
|---|---|---|---|
| 1 | Malware Delivery | Active | 1.1 Disk Drop; 1.2 Removable Media; 1.3 Internet Download; 1.4 Trojanised COTS; 1.5 Fileless PowerShell; 1.6 DLL Sideloading |
| 2 | Exploitation | Partial | 2.1 Malicious Macro *(planned)*; 2.2 CVE Simulation |
| 3 | Privilege Escalation | Partial | 3.1 Process Hollowing *(planned)*; 3.2 UAC Bypass; 3.3 LOLBin Signed Binary |
| 4 | Persistence | Active | 4.1 Registry Run Keys (HKCU/HKLM); 4.2 Scheduled Tasks; 4.3 Advanced Startup Folder; 4.4 WMI Event Subscription |

See the [control matrix](docs/control-matrix.md) for implementation status and ATT&CK mappings.

## Project structure

```text
security-controls/
|-- Start-SCT.ps1       # Main launcher
|-- config/             # Control-profile example and JSON schema
|-- core/               # Discovery, execution, markers, and results
|-- docs/               # Detailed documentation
|-- results/            # Generated result files
|-- samples/            # Local malware ZIPs (gitignored)
|-- sanity_checks/      # EDR/AV verification checks
|-- scenarios/          # Module metadata and technique scripts
|   `-- <module>/
|       |-- module.json
|       |-- test-catalog.csv
|       `-- <technique>/
|-- scripts/            # Scaffolding and validation utilities
`-- tests/              # Developer regression tests for SCT schema and framework behavior
```

The `tests/` folder verifies SCT's internal schema and framework behavior after code changes; it does not run security techniques or test an endpoint product.

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
.\scripts\Add-SCTModule.ps1
.\scripts\Check-SCTModules.ps1
.\scripts\Check-SCTTestDescriptions.ps1
```

`Add-SCTModule.ps1` creates `module.json` and then asks for each test's descriptions. Every new technique/subtest needs one `test-catalog.csv` row. Different modules may continue producing different raw CSV shapes; the preparation command is the boundary that maps supported raw rows into the stable review columns. Catalogue validation fails with a precise missing-row message instead of silently omitting a new test.

See [Project Structure](docs/project-structure.md) for the full authoring workflow and [Framework Design](docs/framework-design.md) for how SCT infers execution behavior without a metadata type field.

## Documentation

- [Framework Design](docs/framework-design.md) - schema, execution inference, markers, and results.
- [Project Structure](docs/project-structure.md) - where files belong and how to add modules or techniques.
- [Control Matrix](docs/control-matrix.md) - status and ATT&CK mapping for every technique.
- [Threat Scenarios](docs/threat-scenarios.md) - purpose, prerequisites, and operating notes.
- [Sample Guide](samples/README.md) - ZIP layouts and sample handling.
- [Sanity Checks](sanity_checks/README.md) - verify the endpoint control before testing.
