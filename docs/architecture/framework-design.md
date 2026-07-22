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
| `core/SCT-Results.ps1` | Canonical result columns, schema checking, and append-only result writing. |
| `scenarios/*/module.json` | Module, technique, and optional subtest metadata. |
| `scenarios/*/test-catalog.csv` | Human-readable objective, behavior, and success indicator for every test/subtest. |
| Technique scripts | Perform tests and technique-specific cleanup. |
| `scripts/authoring/Add-SCTModule.ps1` | Add a module definition and its test descriptions through guided prompts. |
| `scripts/review/Setup-SCTControl.ps1` | Create a product workspace, control profile, and combined test catalogue. |
| `scripts/review/Build-SCTComparisonPackage.ps1` | Validate and package one product's three comparison files. |
| `scripts/validation/Check-SCTModules.ps1` | Check every manifest and script contract. |

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
  "id": "4.5",
  "name": "Windows Service Persistence",
  "attack_id": "T1543.003",
  "script": "v4.5-windows-service/v4.5-windows-service.ps1"
}
```

Technique with subtests:

```json
{
  "id": "4.5",
  "name": "Windows Service Persistence",
  "description": "Tests Windows service creation through native tools.",
  "attack_id": "T1543.003",
  "script": "v4.5-windows-service/v4.5-windows-service.ps1",
  "subtests": ["ScExeCreate", "PowerShellCreate"]
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

These are marker observations, not final security-control verdicts. In particular, `EXECUTED` does not mean `not_detected` or `not_blocked`: a control may detect the activity without preventing it, or allow initial execution and block a later step.

Existing scripts retain `-Technique` as a backward-compatible alias, but new scripts and all SCT-facing guidance use `-Subtest`.

## Validation

Run this after editing any manifest or script contract:

```powershell
.\scripts\validation\Check-SCTModules.ps1
.\scripts\validation\Check-SCTTestDescriptions.ps1
```

Validation rejects unknown/legacy fields, missing required fields, malformed or duplicate IDs, empty/duplicate/reserved subtests, invalid `server_subtests`, missing scripts, and subtest scripts without `-Subtest`.

## Non-interactive Module 04 run

```powershell
.\Start-SCT.ps1 `
    -ControlProfilePath .\results\sentinelone\control-profile.json `
    -RunModule 04 -NonInteractive
```

Module 04 must contain only techniques with subtests. Each script must also accept `-NoPause`, `-NoReport`, and `-CleanupOnly`. SCT records all outcomes before cleaning up each technique.

## Result storage

| File | Contents |
|---|---|
| `results/<control-id>/control-profile.json` | Product, version, agent, policy, settings, exclusions, and local-log context. |
| `results/<control-id>/results.csv` | Generated observations plus reviewer-entered detection, action, and notes fields. |
| `results/<control-id>/test-catalog.csv` | Combined test descriptions generated from all module catalogues. |

All framework-managed writers use one fixed result schema. Generated results and real malware samples should remain uncommitted.

Each interactive subtest selection receives an `I<technique>-...` run ID. A non-interactive Module 04 run uses one shared `M04-...` run ID for all of its technique rows.

There is no raw/analysis conversion or separate reviewed copy. SCT appends generated observations to `results.csv` and leaves the control verdict fields blank. The reviewer edits that same file and enters:

- `detection_status`: `detected` or `not_detected`.
- `action_status`: `blocked_before_execution`, `blocked_after_execution`, or `not_blocked`.

The reviewer may also fill `reviewer_notes`. The completed file is checked with `Check-SCTResults.ps1`, then packaged with its sibling profile and catalogue by `Build-SCTComparisonPackage.ps1`. Keeping execution, detection, and action separate avoids inferring control behavior from a marker or process-launch result.

The package builder writes `submissions/<control-id>.zip`. Two products therefore produce two self-contained ZIP files for the comparison system.
