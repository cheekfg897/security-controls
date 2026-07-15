# Framework Design

SCT is a metadata-driven PowerShell framework. The launcher discovers modules from `scenarios/*/module.json`, presents the prompts required by each vector type, runs the selected script, and writes normalized results.

## Main components

| Component | Responsibility |
|---|---|
| `Start-SCT.ps1` | Entry point, path setup, product selection, and interactive/non-interactive mode. |
| `core/SCT-Core.ps1` | Discovery, menus, dispatch, marker checks, cleanup coordination, and summaries. |
| `scenarios/*/module.json` | Module and vector metadata consumed at startup. |
| Vector scripts | Perform isolated tests and vector-specific cleanup. |
| `results/raw/` | Store generated CSV result files. |

## Execution flow

1. Scan each immediate `scenarios/` subfolder for `module.json`.
2. Validate and sort the discovered modules.
3. Let the user select a module, vector, and—when supported—a sub-technique.
4. Use the vector's `type` to determine its prompts and parameters.
5. Run the selected script in the lab VM.
6. Evaluate output or marker files, record the result, and perform cleanup.

Non-interactive execution is currently supported for Module 04:

```powershell
.\Start-SCT.ps1 -Control SentinelOne -RunModule 04 -NonInteractive
```

## Module metadata

Each module folder contains one `module.json` file.

### Module fields

| Field | Required | Purpose |
|---|---|---|
| `id` | Yes | Two-digit module ID, such as `"04"`. |
| `display_name` | Yes | Name shown in the launcher. |
| `description` | Yes | Short module purpose. |
| `mitre_tactics` | Yes | MITRE ATT&CK tactics covered by the module. |
| `vectors` | Yes | Array of vector definitions. |

### Vector fields

| Field | Required | Purpose |
|---|---|---|
| `id` | Yes | Vector ID, such as `"4.3"`. |
| `name` | Yes | Display name. |
| `description` | Yes | Short explanation of the test. |
| `mitre` | Yes | MITRE ATT&CK technique ID. |
| `script` | Yes | Script path relative to the module folder. |
| `type` | Yes | Dispatch contract used by the launcher. |
| `techniques` | `technique` / `fileless` | Values accepted by the script's `-Technique` parameter. |
| `individual_techniques` | `technique` | Techniques evaluated when `All` is selected; exclude `All` itself. |
| `marker_file` | `technique` | Marker path template containing `{technique}`. |
| `remote_techniques` | `fileless` | Techniques that require a companion server. |
| `default_technique` | No | Informational default shown for the vector. |

## Vector dispatch

| Type | Input and execution model |
|---|---|
| `technique` | Select a technique, pass `-Technique`, and evaluate its marker file. |
| `fileless` | Select an in-memory technique and collect server details only when needed. |
| `malware-batch` | Select/extract ZIP content and pass a staging path. |
| `removable-media` | Collect a drive letter and test files from that device. |
| `client-server` | Collect the companion server's IP address and port. |
| `simple` | Run the vector script directly. |
| `not-implemented` | Show a placeholder without execution. |

## Outcomes and marker files

`technique` vectors write one marker file per completed sub-technique. SCT removes old expected markers before execution, then classifies each sub-technique:

- `EXECUTED` — the new marker exists, so the technique completed.
- `BLOCKED` — the expected marker is absent, so the endpoint control prevented completion.

The metadata template must exactly match the filename written by the script:

```json
"marker_file": "C:\\Windows\\Temp\\art-v4.3-{technique}.txt"
```

## Result storage

| File | Contents |
|---|---|
| `results/raw/technique-results.csv` | Technique and fileless outcomes, including control, vector, technique, outcome, notes, and `run_id`. |
| `results/raw/results.csv` | Malware-delivery results produced by the relevant vector scripts. |

Generated results and real malware samples should remain uncommitted. Use the launcher summary (`V`) or utilities under `scripts/` to review results.
