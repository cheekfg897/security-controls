# Framework Design

SCT is metadata-driven. The launcher discovers `scenarios/*/module.json`, validates each file, shows the module and technique menus, infers how a script must be launched, and records normalized results.

## Naming hierarchy

```text
Module
`-- Technique
    `-- Subtest (optional)
```

- A **module** is a broad testing category such as Persistence.
- A **technique** is one numbered scenario such as 4.2 Scheduled Task / Job.
- A **subtest** is an optional implementation variation such as HiddenXML.
- `attack_id` maps the technique to MITRE ATT&CK; it does not define another SCT hierarchy level.

The old `vector` and overloaded `technique` terminology is no longer part of the authoring model.

## Main components

| Component | Responsibility |
|---|---|
| `Start-SCT.ps1` | Entry point, path setup, product selection, and interactive/non-interactive mode. |
| `core/SCT-Core.ps1` | Manifest validation, menus, inferred execution, marker checks, cleanup, and summaries. |
| `scenarios/*/module.json` | Module, technique, and optional subtest metadata. |
| Technique scripts | Perform tests and technique-specific cleanup. |
| `scripts/New-SCTModuleJson.ps1` | Generate a new manifest through guided prompts. |
| `scripts/Test-SCTModuleJson.ps1` | Validate every manifest and script contract. |

## Simplified `module.json`

### Module fields

| Field | Required | Purpose |
|---|---|---|
| `id` | Yes | Two-digit module ID, for example `"04"`. |
| `name` | Yes | Module name shown in the launcher. |
| `description` | No | Short explanation shown below the module name. |
| `techniques` | Yes | Array of technique definitions. |

### Technique fields

| Field | Required | Purpose |
|---|---|---|
| `id` | Yes | Number in `module.technique` form, for example `"4.2"`. |
| `name` | Yes | Technique name shown in the launcher. |
| `attack_id` | Yes | MITRE ATT&CK technique or sub-technique ID. |
| `script` | Yes | PowerShell path relative to the module folder. |
| `description` | No | Short explanation shown in the technique menu. |
| `subtests` | No | Real selectable subtests. Do not include run-all entries. |
| `server_subtests` | No | Subset of `subtests` that need a companion server VM. |
| `status` | No | Use `"planned"` only while the technique is unavailable. |

Minimal runnable technique:

```json
{
  "id": "4.4",
  "name": "WMI Subscription Persistence",
  "attack_id": "T1546.003",
  "script": "4.4-wmi-subscription/4.4-wmi-subscription.ps1"
}
```

Technique with subtests:

```json
{
  "id": "4.4",
  "name": "WMI Subscription Persistence",
  "description": "Tests permanent WMI event subscription persistence.",
  "attack_id": "T1546.003",
  "script": "4.4-wmi-subscription/4.4-wmi-subscription.ps1",
  "subtests": ["EventFilter", "EventConsumer"]
}
```

SCT rejects unknown metadata fields. In particular, authors do not declare execution types, supported parameters, duplicated individual-test arrays, defaults, run-all values, or marker templates.

## Execution inference

There is no author-facing `type` field. SCT derives the launch behavior from the technique definition and the script's parameter block, in this order:

| Signal | Launcher behavior |
|---|---|
| `subtests` exists | Show subtests, pass `-Subtest`, check standard markers, and log one row per subtest. |
| Script accepts `-SourcePath` | Select and extract sample ZIPs, then pass the staging folder. |
| Script accepts `-DriveLetter` | Request removable media and pass its drive letter. |
| Script accepts `-ServerIP` | Request the companion server address and port. |
| None of the above | Run the script directly. |

This makes the PowerShell parameter block the single source of truth for required launcher input. `server_subtests` is needed only when some subtests require a server and others do not.

## Subtest contract

A technique that declares `subtests` must:

1. Accept `-Subtest`.
2. Validate every declared subtest plus `All`.
3. When applicable, accept `AllLocal` and `AllRemote` for mixed local/server subtests.
4. Write one marker for every subtest that completes:

```text
C:\Windows\Temp\art-v<technique-id>-<subtest>.txt
```

The launcher derives the `All` choices and marker filenames. Before execution it removes only the expected markers for the selected run. After execution:

- `EXECUTED` means the new marker exists.
- `BLOCKED` means the marker is absent.

Existing scripts retain `-Technique` as a backward-compatible alias, but new scripts and all SCT-facing guidance use `-Subtest`.

## Validation

Run this after editing any manifest or script contract:

```powershell
.\scripts\Test-SCTModuleJson.ps1
```

Validation rejects unknown/legacy fields, missing required fields, malformed or duplicate IDs, empty/duplicate/reserved subtests, invalid `server_subtests`, missing scripts, and subtest scripts without `-Subtest`.

## Non-interactive Module 04 run

```powershell
.\Start-SCT.ps1 -Control SentinelOne -RunModule 04 -NonInteractive
```

Module 04 must contain only techniques with subtests. Each script must also accept `-NoPause`, `-NoReport`, and `-CleanupOnly`. SCT records all outcomes before cleaning up each technique.

## Result storage

| File | Contents |
|---|---|
| `results/raw/test-results.csv` | `timestamp`, `run_id`, `control`, `technique_id`, `technique_name`, `subtest`, `outcome`, and `notes`. |
| `results/raw/results.csv` | Sample-delivery rows keyed by `technique_id`. |

Legacy generated CSV columns are read for compatibility, but all newly created files use the simplified names. Generated results and real malware samples should remain uncommitted.
