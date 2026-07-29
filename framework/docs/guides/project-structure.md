# Project Structure

This guide explains where SCT configuration and technique code belong.

## Repository layout

```text
security-controls/
|-- ai-system/
|   |-- config/
|   |-- comparisons/
|   |   `-- <comparison-id>/
|   |-- requirements/
|   |-- scripts/
|   |-- src/
|   |   `-- sct_ai/
|   |       |-- skills/
|   |       |-- templates/
|   |       `-- static/
|   `-- tests/
|       `-- python/
`-- framework/
    |-- Start-SCT.ps1
    |-- config/
    |   |-- control-profile.example.json
    |   `-- control-profile.schema.json
    |-- core/
    |   |-- SCT-Core.ps1
    |   `-- SCT-Results.ps1
    |-- docs/
    |   |-- README.md
    |   |-- architecture/
    |   |-- guides/
    |   `-- reference/
    |-- results/
    |   `-- <control-id>/
    |       |-- <control-id>-control-profile.json
    |       |-- results-module-01.csv
    |       `-- test-catalog-module-01.csv
    |-- samples/
    |-- sanity_checks/
    |-- scenarios/
    |   |-- 01-malware-delivery/
    |   |-- 02-exploitation/
    |   |-- 03-privilege-escalation/
    |   `-- 04-persistence/
    |-- scripts/
    |   |-- authoring/
    |   |-- common/
    |   |-- review/
    |   `-- validation/
    |-- submissions/
    |   `-- <control-id>.zip
    `-- tests/
        |-- framework/
        |-- workflows/
        `-- Run-Tests.ps1
```

| Content | Location |
|---|---|
| Launcher parameters and startup | `framework/Start-SCT.ps1` |
| Discovery, validation, execution, markers, and summaries | `framework/core/SCT-Core.ps1` |
| Module metadata | `framework/scenarios/<module>/module.json` |
| Per-test descriptions | `framework/scenarios/<module>/test-catalog.csv` |
| Technique scripts and local guidance | Inside the relevant module folder |
| Local malware archives | `framework/samples/` |
| Pre-test control checks | `framework/sanity_checks/` |
| Product configuration and generated outputs | `framework/results/<control-id>/` |
| Architecture, contributor guides, and reference material | `framework/docs/` |
| Comparison engine, web app, config, generated reports, scripts, and tests | `ai-system/` |
| Model adapters and runtime skills | `ai-system/src/sct_ai/` |
| Generated reports and the local web job index | `ai-system/comparisons/` |
| Module and catalogue authoring utilities | `framework/scripts/authoring/` |
| Comparison, web, model-import, and offline-bundle utilities | `ai-system/scripts/` |
| Control-workspace setup and comparison packaging | `framework/scripts/review/` |
| Profile, module, catalogue, and result validators | `framework/scripts/validation/` |
| Shared script implementation | `framework/scripts/common/` |
| Dependency-free framework and workflow regression tests | `framework/tests/` |

Real malware samples and generated results should not be committed.

## Module layout

A module is a numbered folder containing one `module.json`. Technique script paths are relative to that folder:

```text
scenarios/04-persistence/
|-- module.json
|-- test-catalog.csv
|-- v4.1-registry-run-key/
|   |-- README.md
|   `-- v4.1-registry-run-key.ps1
|-- v4.2-scheduled-task/
|-- v4.3-startup-folder/
`-- v4.4-wmi-event-subscription/
```

Folder and script names can retain existing `v` prefixes; the SCT hierarchy comes from `module.json`, where these entries are techniques.

## Adding a technique

1. Add the PowerShell script and, if setup is non-trivial, a nearby `README.md`.
2. Add one object to the module's `techniques` array.
3. Add one `test-catalog.csv` row for the technique, or one row per subtest.
4. Run `scripts/validation/Check-SCTModules.ps1` and `scripts/validation/Check-SCTTestDescriptions.ps1`.
5. Restart `Start-SCT.ps1` and confirm the technique appears.

Minimal entry:

```json
{
  "id": "4.5",
  "name": "Windows Service Persistence",
  "attack_id": "T1543.003",
  "script": "v4.5-windows-service/v4.5-windows-service.ps1"
}
```

If the technique has selectable variations, add one `subtests` array:

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

Do not list `All`; SCT adds it automatically. The script accepts `-Subtest`, validates both names plus `All`, and writes successful markers as:

```text
C:\Windows\Temp\art-v4.5-ScExeCreate.txt
C:\Windows\Temp\art-v4.5-PowerShellCreate.txt
```

When the technique has subtests, the authoring generator asks whether every subtest needs a companion server VM. If yes, it records all subtests in `server_subtests`. If only some need a server, enter those exact subtest names as a comma-separated list; leave it blank when none need one. The names must also exist in `subtests`.

Use `"status": "planned"` for an unavailable technique. The script path may be reserved before the file exists; remove `status` when implementation is ready.

## Adding a module

Run the guided generator from the `framework` directory:

```powershell
.\scripts\authoring\Add-SCTModule.ps1
```

Use `-NoWrite` to preview the JSON. The command asks for module details, technique details, optional subtests, optional server-dependent subtests, and then the descriptions for those tests.

After adding scripts, validate everything:

```powershell
.\scripts\validation\Check-SCTModules.ps1
.\scripts\validation\Check-SCTTestDescriptions.ps1
```

When adding techniques to an existing module, run `scripts/authoring/Describe-SCTModuleTests.ps1` to add their descriptions. It preserves existing rows and prompts only for a new or incomplete technique/subtest's objective, what it does, and success indicator. SCT discovers valid modules automatically; no central module list needs updating.

## Test catalogue

Every module has one `test-catalog.csv` with this fixed header:

```text
technique_id,subtest,objective,what_it_does,success_indicator
```

A technique without subtests has one row with an empty `subtest`. A technique with subtests has one row per named subtest. This keeps detailed explanations out of result rows while giving a human or later AI system an exact join through `technique_id` and `subtest`.

Framework-managed writers append the canonical schema defined in `core/SCT-Results.ps1` to the selected module's `results-module-<id>.csv`. Reviewer-facing context and editable verdict fields precede machine-facing provenance such as the run ID, internal technique ID, script path, and SHA-256. New writers must use `Write-SCTResultRow` so every test remains compatible with direct review, validation, and packaging.

## Per-product result workspace

`results/<control-id>/<control-id>-control-profile.json` records the exact control configuration used for that product's test series. Each `results-module-<id>.csv` contains generated observations and reviewer statuses for one module; its matching `test-catalog-module-<id>.csv` describes that module's tests. The catalogue rows include `module_id` and `module_name`.

After reviewing the module result files, validate the workspace and generate `submissions/<control-id>.zip`. Each archive contains the profile plus the result/catalogue pair for every tested module. Repeat for the second product to produce the two inputs required by the comparison system.

Everything under each generated control workspace is gitignored. The reusable example and JSON schema remain in `config/`; environment-specific profiles belong with their result evidence under `results/`.

## Adding samples

Put malware archives in `samples/` only for Technique 1.1. Technique 1.2 reads removable media, Technique 1.3 uses a companion server directory, and the remaining Module 01 techniques are self-contained or in-memory.

See the [Sample Guide](../../samples/README.md) for ZIP layouts and handling precautions.
