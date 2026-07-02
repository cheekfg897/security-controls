# Endpoint Security Controls Testing Framework (SCT)

A structured, extensible framework for evaluating endpoint security controls — **Morphisec**, **Carbon Black EDR**, **SentinelOne**, **Antivirus**, and others — across threat scenarios mapped to the MITRE ATT&CK framework.

Run `Start-SCT.ps1` from any Windows 10/11 lab VM to get a menu-driven test session.

---

## Project Overview

This framework simulates realistic attack techniques in an isolated lab environment and measures how effectively each security control detects, prevents, or misses them. Results are captured in a structured CSV for comparative analysis.

**Environment:** Isolated Windows VM (lab only — never run on production)  
**Controls evaluated:** Morphisec · Carbon Black EDR · SentinelOne · Antivirus  
**Mapping:** MITRE ATT&CK

---

## Quick Start

```powershell
# In an isolated lab VM, from the repo root:
.\Start-SCT.ps1

# Or pre-set the control name to skip the prompt:
.\Start-SCT.ps1 -Control SentinelOne
```

On launch you will see:
1. A welcome banner with a safety warning
2. A prompt for the security product under test (one time, reused for all tests)
3. A numbered menu of test modules, auto-discovered from `scenarios/`

Navigate with numbers, `[V]` for results summary, `[Q]` to quit.

---

## Repo Structure

```
security-controls/
│
├── Start-SCT.ps1                  # Main launcher - run this
├── core/
│   └── SCT-Core.ps1               # Shared menu, dispatch, and utility functions
│
├── samples/                       # Malware ZIP archives (gitignored - never commit real malware)
│   └── README.md                  # How to add sample ZIPs
│
├── scenarios/
│   ├── 01-malware-introduction/
│   │   ├── module.json            # Module descriptor (read by launcher)
│   │   ├── v1.1-known-malware/
│   │   ├── v1.2-removable-media/
│   │   ├── v1.3-download-internet/
│   │   ├── v1.4-trojanised-cots/
│   │   ├── v1.5-fileless-powershell/
│   │   └── v1.6-dll-sideloading/
│   ├── 02-exploitation/
│   │   └── module.json
│   ├── 03-privilege-escalation/
│   │   └── module.json
│   └── 04-persistence/
│       ├── module.json
│       ├── v4.1-registry-run-key/
│       ├── v4.2-scheduled-task/
│       └── v4.3-startup-folder/
│
├── results/
│   ├── raw/                       # results.csv and summary.csv (gitignored)
│   └── analysis/                  # Processed findings and notes
│
├── scripts/
│   ├── run-scenario.ps1           # Legacy per-script wrapper
│   └── collect-results.py         # Parses results.csv into structured data
│
└── docs/
    ├── framework-design.md
    ├── threat-scenarios.md
    └── control-matrix.md
```

---

## Test Modules

| # | Module | MITRE Tactics | Vectors |
|---|--------|---------------|---------|
| 1 | Malware Introduction | Execution, Initial Access | 6 |
| 2 | Exploitation | Execution, Privilege Escalation | 2 (stubs) |
| 3 | Privilege Escalation | Privilege Escalation, Defense Evasion | 3 (stubs) |
| 4 | Persistence | Persistence | 3 |

Modules 2 and 3 are placeholders — add scripts and change `"type"` in their `module.json` to activate them.

---

## How It Works

The launcher scans `scenarios/*/module.json` at startup. Each `module.json` describes the module and its vectors; the launcher uses the `"type"` field to decide how to call each script:

| Type | What the launcher does |
|---|---|
| `malware-batch` | Shows ZIP list from `samples/`, extracts chosen ZIP, calls script with `-SourcePath -Control` |
| `removable-media` | Prompts for drive letter, calls script with `-DriveLetter -Control` |
| `client-server` | Prompts for server IP/port, calls victim script with `-ServerIP -Port -Control` |
| `technique` | Shows sub-menu of technique names, calls script with `-Technique <name>` |
| `fileless` | Shows technique sub-menu; only prompts for server IP when the selected technique is listed in `remote_techniques` — local techniques run without a server VM. Nothing is written to disk. |
| `simple` | Runs the script directly with no extra parameters |
| `not-implemented` | Shows a placeholder message — replace the script and change the type to activate |

The `-Control` tag (e.g. `SentinelOne`) is entered once at startup and passed automatically to every script that supports it, so all result rows in `results.csv` are consistently tagged.

---

## Extending the Framework

### Adding a new malware sample to an existing vector

1. Prepare samples on a separate, unprotected machine
2. Generate a `manifest.csv` using the helper:
   ```powershell
   .\scenarios\01-malware-introduction\New-Manifest.ps1 -FolderPath C:\MySamples -OutputPath .\my-manifest.csv
   ```
3. Create a ZIP containing `manifest.csv` and all sample files at the ZIP root
4. Copy the ZIP into `samples/`
5. Run `Start-SCT.ps1 → Malware Introduction → Vector 1.1` and select the ZIP

See [samples/README.md](samples/README.md) for the full `manifest.csv` schema.

---

### Adding a new vector to an existing module

1. Create a folder for the vector inside the relevant `scenarios/XX-*/` directory
2. Write the PowerShell script (see existing vectors as reference)
3. Open `scenarios/XX-*/module.json` and add a new entry to the `"vectors"` array:

```json
{
  "id": "4.4",
  "name": "WMI Subscription Persistence",
  "description": "Creates a permanent WMI event subscription to execute a payload on system events. MITRE T1546.003.",
  "mitre": "T1546.003",
  "script": "v4.4-wmi-subscription/v4.4-wmi-subscription.ps1",
  "type": "technique",
  "techniques": ["EventFilter", "EventConsumer", "FilterToConsumerBinding", "All"],
  "individual_techniques": ["EventFilter", "EventConsumer", "FilterToConsumerBinding"],
  "marker_file": "C:\\Windows\\Temp\\art-v4.4-{technique}.txt",
  "default_technique": "All",
  "supports": ["technique"]
}
```

> **`individual_techniques`** is `techniques` minus `"All"`. The launcher checks one marker file per entry when `All` is selected.
>
> **`marker_file`** must match what your script actually writes. If your script writes `C:\Windows\Temp\art-v4.4-EventFilter.txt`, then the template is `C:\\Windows\\Temp\\art-v4.4-{technique}.txt`. The `{technique}` placeholder is substituted with each technique name at runtime. Without these two fields the test runs but no result row is written.

4. Restart `Start-SCT.ps1` — the new vector appears automatically.

**Script conventions for `technique` type scripts:**
- Accept `-Technique` with `[ValidateSet(...)]` matching the names in module.json
- Write a marker file named `C:\Windows\Temp\art-v<vector_id>-<TechniqueName>.txt` as proof-of-execution — the launcher checks for this file automatically after the script exits to determine `EXECUTED` or `BLOCKED`
- Include an `Invoke-Cleanup` function and prompt the tester to clean up at the end
- Add `marker_file` and `individual_techniques` to your module.json entry (see schema below) so the launcher knows where to look

**Script conventions for `malware-batch` type scripts:**
- Accept `-SourcePath`, `-Control`, `-ManifestPath`, `-ResultsPath`, `-DryRun`, `-Summarize`
- Append results to the shared `results.csv` (see `Write-ResultRow` in v1.1)

---

### Adding a new module (scenario category)

1. Create a new numbered folder under `scenarios/`:
   ```
   scenarios/05-lateral-movement/
   ```

2. Create `module.json` in that folder:
   ```json
   {
     "id": "05",
     "display_name": "Lateral Movement",
     "description": "Tests detection of techniques used to move between hosts in the network",
     "mitre_tactics": ["Lateral Movement"],
     "vectors": [
       {
         "id": "5.1",
         "name": "Pass-the-Hash (SMB)",
         "description": "Authenticates to a remote host using a captured NTLM hash without the plaintext password. MITRE T1550.002.",
         "mitre": "T1550.002",
         "script": "v5.1-pass-the-hash/v5.1-pth.ps1",
         "type": "simple",
         "supports": []
       }
     ]
   }
   ```

3. Create the script at the path specified in `"script"` (relative to the module folder)

4. Restart `Start-SCT.ps1` — the new module appears as a numbered menu option automatically

No changes to `Start-SCT.ps1` or `core/SCT-Core.ps1` are needed.

---

### module.json schema reference

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Two-digit module number, e.g. `"05"` |
| `display_name` | string | Yes | Shown in the main menu |
| `description` | string | Yes | One-line summary shown under the menu item |
| `mitre_tactics` | array | Yes | MITRE tactic names, e.g. `["Persistence"]` |
| `vectors` | array | Yes | Array of vector objects (see below) |

**Vector object fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Vector number, e.g. `"4.4"` |
| `name` | string | Yes | Short display name |
| `description` | string | Yes | One-sentence description |
| `mitre` | string | Yes | MITRE technique ID, e.g. `"T1546.003"` |
| `script` | string | Yes | Path to the PS1 script, relative to the module folder |
| `type` | string | Yes | One of: `malware-batch`, `removable-media`, `client-server`, `technique`, `fileless`, `simple`, `not-implemented` |
| `techniques` | array | `technique` / `fileless` types | List of technique names passed to `-Technique`. Include `"All"` at the end if the script supports running everything in sequence. |
| `individual_techniques` | array | `technique` type only | The same list **minus** `"All"` — the launcher checks one marker file per entry when `All` is selected. Must match exactly what the script appends to the marker filename. |
| `marker_file` | string | `technique` type only | Absolute path template for the proof-of-execution marker file. Use `{technique}` as a placeholder for the technique name, e.g. `"C:\\Windows\\Temp\\art-v4.4-{technique}.txt"`. The launcher substitutes the selected technique name and checks whether the file was written after the test started. |
| `remote_techniques` | array | `fileless` type only | Subset of `techniques` that require a server VM. The launcher only prompts for server IP when one of these is selected. |
| `default_technique` | string | No | Default selection shown in the menu (informational only, not enforced). |
| `supports` | array | No | Informational list of supported parameters (not enforced by launcher). |

---

## Running Tests

> **All tests must run inside the isolated lab VM only. Never run on a production or networked machine.**

1. Clone the repo into the lab VM
2. Run `.\Start-SCT.ps1`
3. Enter the security product name when prompted
4. Select a module, then a vector
5. Follow the on-screen prompts (EDR console prep, technique selection, etc.)
6. Review results at `results/raw/results.csv`

Use `[V]` from the main menu for a live summary grouped by control and vector.

---

## Results

Every malware-batch and removable-media test run appends rows to `results/raw/results.csv`:

| Column | Description |
|---|---|
| `timestamp` | ISO-8601 timestamp |
| `control` | Security product name from the launcher prompt |
| `vector` | Vector ID (e.g. `1.1`) |
| `delivery_method` | How the sample was delivered |
| `sample_id` | From `manifest.csv` |
| `classification` | `benign`, `dual_use`, `malware`, or `unspecified` |
| `stage` | `write` or `execution` |
| `delivery_success` | `True`/`False` — did the file land or process start |
| `sysmon_event_found` | `True`/`False` — did Sysmon log a matching event |
| `notes` | SHA-256 result, exit code, or error detail |

Run `scripts/collect-results.py` to parse the CSV into a structured report.

---

## Lab Environment

- **OS:** Windows 10 or Windows 11 (isolated VM, no network access to production)
- **Shell:** PowerShell 5.1+ (no external modules required)
- **Logging:** Windows Event Log + Sysmon (SwiftOnSecurity config recommended)
- **Tooling:** PowerShell, Python 3 (optional, for collect-results.py)

---

## Project Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Foundation & Scenario Design | Complete |
| 2 | Build & Execute | In Progress |
| 3 | Analysis | Pending |
| 4 | Reporting | Pending |
