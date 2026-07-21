# Project Structure

This guide explains where SCT configuration and technique code belong.

## Repository layout

```text
security-controls/
|-- Start-SCT.ps1
|-- config/
|   |-- control-profile.example.json
|   `-- control-profile.schema.json
|-- core/
|   `-- SCT-Core.ps1
|-- docs/
|-- results/
|   |-- raw/
|   `-- analysis/
|-- samples/
|-- sanity_checks/
|-- scenarios/
|   |-- 01-malware-delivery/
|   |-- 02-exploitation/
|   |-- 03-privilege-escalation/
|   `-- 04-persistence/
`-- scripts/
    |-- Add-SCTModule.ps1
    |-- Check-SCTControlProfile.ps1
    |-- Check-SCTModules.ps1
    |-- Check-SCTReviewedResults.ps1
    |-- Check-SCTTestDescriptions.ps1
    |-- Describe-SCTModuleTests.ps1
    |-- Prepare-SCTResultsForReview.ps1
    `-- Setup-SCTControl.ps1
```

| Content | Location |
|---|---|
| Launcher parameters and startup | `Start-SCT.ps1` |
| Discovery, validation, execution, markers, and summaries | `core/SCT-Core.ps1` |
| Module metadata | `scenarios/<module>/module.json` |
| Per-test descriptions | `scenarios/<module>/test-catalog.csv` |
| Technique scripts and local guidance | Inside the relevant module folder |
| Local malware archives | `samples/` |
| Pre-test control checks | `sanity_checks/` |
| Generated CSV files | `results/raw/` |
| Architecture and operator guidance | `docs/` |
| Profile, catalogue, manifest, and review-CSV utilities | `scripts/` |

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
4. Run `scripts/Check-SCTModules.ps1` and `scripts/Check-SCTTestDescriptions.ps1`.
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

If only some subtests need a server VM, list those names once more in `server_subtests`. They must also exist in `subtests`.

Use `"status": "planned"` for an unavailable technique. The script path may be reserved before the file exists; remove `status` when implementation is ready.

## Adding a module

Run the guided generator from the repository root:

```powershell
.\scripts\Add-SCTModule.ps1
```

Use `-NoWrite` to preview the JSON. The command asks for module details, technique details, optional subtests, optional server-dependent subtests, and then the descriptions for those tests.

After adding scripts, validate everything:

```powershell
.\scripts\Check-SCTModules.ps1
.\scripts\Check-SCTTestDescriptions.ps1
```

When adding techniques to an existing module, run `Describe-SCTModuleTests.ps1` to add their descriptions. It preserves existing rows and prompts only for a new or incomplete technique/subtest's objective, what it does, and success indicator. SCT discovers valid modules automatically; no central module list needs updating.

## Test catalogue

Every module has one `test-catalog.csv` with this fixed header:

```text
technique_id,subtest,objective,what_it_does,success_indicator
```

A technique without subtests has one row with an empty `subtest`. A technique with subtests has one row per named subtest. This keeps detailed explanations out of result rows while giving a human or later AI system an exact join through `technique_id` and `subtest`.

Raw result formats may differ between modules. New raw formats do not require changing existing CSVs or catalogues, but `Prepare-SCTResultsForReview.ps1` must know how to map that format before it can be included in the stable review CSV.

## Per-VM control profile and review files

`config/control-profile.local.json` records the exact control configuration used in one VM. It is JSON because settings, exclusions, and local log sources are nested and product-specific. The generated result remains CSV so it can be reviewed in Excel.

The local profile and everything under `results/analysis/` are gitignored. Keep one copy with each VM's reviewed results rather than committing environment-specific configuration or potentially sensitive data.

## Adding samples

Put malware archives in `samples/` only for Technique 1.1. Technique 1.2 reads removable media, Technique 1.3 uses a companion server directory, and the remaining Module 01 techniques are self-contained or in-memory.

See the [Sample Guide](../samples/README.md) for ZIP layouts and handling precautions.
