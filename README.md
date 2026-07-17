# Security Controls Testing Framework (SCT)

SCT is a PowerShell lab framework for checking whether EDR and antivirus products detect or block simulated attack techniques. Tests are mapped to MITRE ATT&CK and include guided execution, result capture, and cleanup.

> **Lab VMs only - never run SCT on a production or connected business system.**

## One naming model

SCT uses the same three terms in metadata, menus, scripts, results, and documentation:

| Term | Meaning | Example |
|---|---|---|
| **Module** | A broad security-testing category. | `04 Persistence` |
| **Technique** | One numbered test scenario inside a module. | `4.2 Scheduled Task / Job` |
| **Subtest** | An optional selectable variation of a technique. | `HiddenXML` |

`attack_id` is the MITRE ATT&CK mapping; it is not another level in the SCT hierarchy.

## Getting started

### Requirements

- An isolated Windows 10/11 VM with a snapshot.
- PowerShell 5.1 or later.
- An active EDR or antivirus product to test.
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) is recommended and is required for fileless-test result collection.
- Most techniques use one VM. Techniques 1.3 and remote subtests in 1.5 require a second Windows VM on the same isolated lab network.

### Install and run

```powershell
git clone https://github.com/cheekfg897/security-controls.git
Set-Location security-controls
.\Start-SCT.ps1
```

To skip the product-name prompt:

```powershell
.\Start-SCT.ps1 -Control SentinelOne
```

Choose a module, then a technique, then a subtest when the technique provides them. `EXECUTED` means the subtest completed without being blocked; `BLOCKED` means the expected marker was not created. Press `V` in the main menu to view the result summary.

Results are written to:

- `results/raw/test-results.csv` for subtest outcomes.
- `results/raw/results.csv` for sample-delivery outcomes.

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

This runs all 15 persistence subtests, records one row per subtest with a shared `run_id`, and performs cleanup after each technique.

## Built-in modules

| # | Module | Status | Techniques |
|---|---|---|---|
| 1 | Malware Delivery | Active | 1.1 Disk Drop; 1.2 Removable Media; 1.3 Internet Download; 1.4 Trojanised COTS; 1.5 Fileless PowerShell; 1.6 DLL Sideloading |
| 2 | Exploitation | Partial | 2.1 Malicious Macro *(planned)*; 2.2 CVE Simulation |
| 3 | Privilege Escalation | Partial | 3.1 Process Hollowing *(planned)*; 3.2 UAC Bypass; 3.3 LOLBin Signed Binary |
| 4 | Persistence | Active | 4.1 Registry Run Keys; 4.2 Scheduled Tasks; 4.3 Advanced Startup Folder |

See the [control matrix](docs/control-matrix.md) for implementation status and ATT&CK mappings.

## Project structure

```text
security-controls/
|-- Start-SCT.ps1       # Main launcher
|-- core/               # Discovery, execution, markers, and results
|-- docs/               # Detailed documentation
|-- results/            # Generated result files
|-- samples/            # Local malware ZIPs (gitignored)
|-- sanity_checks/      # EDR/AV verification checks
|-- scenarios/          # Module metadata and technique scripts
|   `-- <module>/
|       |-- module.json
|       `-- <technique>/
`-- scripts/            # Scaffolding and validation utilities
```

## Adding a technique

Add one object to the module's `techniques` array. A technique with no subtests needs only four fields:

```json
{
  "id": "4.4",
  "name": "WMI Subscription Persistence",
  "attack_id": "T1546.003",
  "script": "4.4-wmi-subscription/4.4-wmi-subscription.ps1"
}
```

Add `subtests` only when the user should choose between named variations:

```json
{
  "id": "4.4",
  "name": "WMI Subscription Persistence",
  "attack_id": "T1546.003",
  "script": "4.4-wmi-subscription/4.4-wmi-subscription.ps1",
  "subtests": ["EventFilter", "EventConsumer"]
}
```

SCT automatically adds the `All` choice and derives marker paths. Do not add `type`, `supports`, `All`, individual-test lists, defaults, or marker templates to `module.json`.

Subtest scripts accept `-Subtest`, include `All` in their `ValidateSet`, and write successful markers using:

```text
C:\Windows\Temp\art-v<technique-id>-<subtest>.txt
```

For a planned technique, add only `"status": "planned"`; remove that field when the script is ready.

Use the guided generator and validator:

```powershell
.\scripts\New-SCTModuleJson.ps1
.\scripts\Test-SCTModuleJson.ps1
```

See [Project Structure](docs/project-structure.md) for the full authoring workflow and [Framework Design](docs/framework-design.md) for how SCT infers execution behavior without a metadata type field.

## Documentation

- [Framework Design](docs/framework-design.md) - schema, execution inference, markers, and results.
- [Project Structure](docs/project-structure.md) - where files belong and how to add modules or techniques.
- [Control Matrix](docs/control-matrix.md) - status and ATT&CK mapping for every technique.
- [Threat Scenarios](docs/threat-scenarios.md) - purpose, prerequisites, and operating notes.
- [Sample Guide](samples/README.md) - ZIP layouts and sample handling.
- [Sanity Checks](sanity_checks/README.md) - verify the endpoint control before testing.
