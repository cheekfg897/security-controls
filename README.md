# Security Controls Testing Framework (SCT)

Security Controls Testing Framework (SCT) is a PowerShell lab framework for testing whether endpoint detection and response (EDR) or antivirus (AV) products detect and block simulated attack techniques. It provides repeatable MITRE ATT&CK-mapped scenarios, guided execution, result capture, and cleanup.

> **Lab VMs only — never run SCT on a production or networked machine.**

---

## Table of contents

- [Getting started](#getting-started)
  - [Requirements](#requirements)
  - [Install and run](#install-and-run)
  - [Using malware samples](#using-malware-samples)
  - [Run Module 4 non-interactively](#run-module-4-non-interactively)
- [Built-in modules](#built-in-modules)
- [Project structure](#project-structure)
- [Documentation](#documentation)
- [Extending SCT](#extending-sct)
- [Reference](#reference)
  - [Vector types](#vector-types)

---

<a id="getting-started"></a>

## Getting started

<a id="requirements"></a>

### Requirements

- An isolated Windows 10/11 VM with a snapshot.
- PowerShell 5.1 or later; no external PowerShell modules are required.
- An active EDR/AV product to test.
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) is recommended and required for fileless-test result collection. See the [Sysmon setup guide](scenarios/01-malware-introduction/v1.1-known-malware/README.md#sysmon-setup-check).
- Most tests use one VM. Vector 1.3 and the remote Vector 1.5 techniques require a second Windows VM on the same isolated network.

<a id="install-and-run"></a>

### Install and run

Open PowerShell on the lab VM:

```powershell
git clone https://github.com/cheekfg897/security-controls.git
Set-Location security-controls
.\Start-SCT.ps1
```

Before testing, confirm the security product is active with a check from [`sanity_checks/`](sanity_checks/README.md). To skip the product-name prompt:

```powershell
.\Start-SCT.ps1 -Control SentinelOne
```

Select a module, vector, and sub-technique when prompted, then monitor the EDR/AV console. `EXECUTED` means the technique ran without being blocked; `BLOCKED` means the control prevented it. Press `V` in the main menu to view the current summary.

Results are written to:

- `results/raw/technique-results.csv` for technique and fileless tests.
- `results/raw/results.csv` for malware-delivery tests.

<a id="using-malware-samples"></a>

### Using malware samples

| Vector | Sample source |
|---|---|
| **1.1 Disk Drop** | Put ZIP files in `samples/`, then select one or combine all ZIPs in the launcher. |
| **1.2 Removable Media** | Pre-load samples on an authorised USB drive; the launcher requests its drive letter. |
| **1.3 Internet Download** | Host samples on a second VM with `v1.3-server.ps1`. |
| **1.4, 1.5, 1.6** | Self-contained or in-memory; local techniques do not require sample files. |

For ZIP layouts and password-protected archives, see the [sample guide](samples/README.md).

> **Vector 1.2 validation note:** USB delivery has not been validated in the current environment. Test it only on an authorised lab endpoint with physical USB passthrough; a virtual disk does not validate USB device-control monitoring.

<a id="run-module-4-non-interactively"></a>

### Run Module 4 non-interactively

From an Administrator PowerShell session:

```powershell
.\Start-SCT.ps1 -Control SentinelOne -RunModule 04 -NonInteractive
```

This runs all 15 persistence sub-tests, records one row per sub-test with a shared `run_id`, and performs each vector's cleanup.

---

<a id="built-in-modules"></a>

## Built-in modules

| # | Module | Status | Vectors |
|---|---|---|---|
| 1 | Malware Introduction | Active | 1.1 Disk Drop; 1.2 Removable Media; 1.3 Internet Download; 1.4 Trojanised COTS; 1.5 Fileless PowerShell; 1.6 DLL Sideloading |
| 2 | Exploitation | Partial | 2.1 Malicious Macro *(planned)*; 2.2 CVE Simulation |
| 3 | Privilege Escalation | Partial | 3.1 Process Hollowing *(planned)*; 3.2 UAC Bypass; 3.3 LOLBin Signed Binary |
| 4 | Persistence | Active | 4.1 Registry Run Keys; 4.2 Scheduled Tasks; 4.3 Advanced Startup Folder |

See the [control matrix](docs/control-matrix.md) for vector types, implementation status, and MITRE ATT&CK mappings.

---

<a id="project-structure"></a>

## Project structure

```text
security-controls/
├── Start-SCT.ps1       # Main launcher
├── core/               # Discovery, dispatch, and result logic
├── docs/               # Detailed documentation
├── results/            # Generated raw and analysed results
├── samples/            # Local malware ZIP store (samples are gitignored)
├── sanity_checks/      # EDR/AV verification checks
├── scenarios/          # Module metadata and vector scripts
│   └── <module>/
│       ├── module.json
│       └── <vector>/
└── scripts/            # Module scaffolding and result utilities
```

See [Project Structure](docs/project-structure.md) for folder conventions and where to add modules, vectors, samples, and documentation.

---

<a id="documentation"></a>

## Documentation

- [Framework Design](docs/framework-design.md) — discovery, execution, vector dispatch, outcomes, and result storage.
- [Control Matrix](docs/control-matrix.md) — implementation status and MITRE ATT&CK mapping for every vector.
- [Threat Scenarios](docs/threat-scenarios.md) — scenario purpose, prerequisites, and operational notes.
- [Project Structure](docs/project-structure.md) — repository navigation and extension conventions.
- [Sample Guide](samples/README.md) — ZIP layouts, adding samples, and handling guidance.
- [Sanity Checks](sanity_checks/README.md) — confirm the endpoint control is active before testing.

---

<a id="extending-sct"></a>

## Extending SCT

SCT discovers modules from `scenarios/*/module.json` at startup, so extending it does not require launcher changes.

To add a vector:

1. Create a vector folder and PowerShell script inside the relevant module.
2. Add its metadata to the module's `vectors` array.
3. Follow the contract for its [vector type](#vector-types), including marker files for `technique` vectors.
4. Restart `Start-SCT.ps1`.

To scaffold a module, run `.\scripts\New-SCTModuleJson.ps1` and add scripts at the generated metadata paths. See [Project Structure](docs/project-structure.md#adding-a-vector) for the full conventions.

---

<a id="reference"></a>

## Reference

<a id="vector-types"></a>

### Vector types

A vector type tells the launcher how to collect input, execute the script, and evaluate the result.

| Type | Launcher behaviour |
|---|---|
| `technique` | Selects sub-techniques, passes `-Technique`, checks marker files, and logs outcomes. |
| `fileless` | Runs in-memory techniques and requests a server only for remote techniques. |
| `malware-batch` | Selects and extracts ZIPs from `samples/`. |
| `removable-media` | Requests a removable-drive letter. |
| `client-server` | Requests the companion server's IP address and port. |
| `simple` | Runs the script without vector-specific input. |
| `not-implemented` | Displays a placeholder and does not run a test. |

The complete `module.json` field reference is in [Framework Design](docs/framework-design.md#module-metadata).
