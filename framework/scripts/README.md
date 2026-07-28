# Script guide

Run scripts from the repository root. Scripts are grouped by the workflow they support, while filenames describe the operator action.

For interactive use, run `.\Start-SCT.ps1` and select `[M] Manage SCT`. The direct commands below remain useful for automation and troubleshooting.

## Product workflow

| Order | Purpose | Command |
|---|---|---|
| 1 | Create the product workspace and record its control policy | `.\scripts\review\Setup-SCTControl.ps1` |
| 2 | Run tests | `.\Start-SCT.ps1` |
| 3 | Enter `detected`/`not_detected` and `blocked`/`not_blocked` | Open each `results\<control-id>\results-module-<id>.csv` in Excel |
| 4 | Check the completed results | `.\scripts\validation\Check-SCTResults.ps1 -ControlProfilePath .\results\<control-id>\control-profile.json` |
| 5 | Build that product's comparison ZIP | `.\scripts\review\Build-SCTComparisonPackage.ps1 -ControlProfilePath .\results\<control-id>\control-profile.json` |

There is no raw/analysis conversion step and no second review CSV. SCT writes observations to the authoritative `results-module-<id>.csv`; a person fills `detection_status`, binary `action_status` (`blocked` or `not_blocked`), and optional `reviewer_notes` directly in each tested module file because execution alone cannot determine what the control detected or blocked.

For interactive setup, only the configuration display name is required.
Press Enter to accept the derived control id or skip an optional field.
Skipped text values are recorded as `Not recorded`, while a skipped policy
mode is recorded as `custom`, so the resulting profile remains valid.

Convert an older combined workspace with:

```powershell
.\scripts\review\Convert-SCTLegacyWorkspace.ps1 `
    -ControlProfilePath .\results\<control-id>\control-profile.json
```

Repeat the workflow for the second product. The package builder writes `submissions/<control-id>.zip`, giving the comparison system one ZIP per product.

## Comparison workflow

| Purpose | Command |
|---|---|
| Compare two or more ZIPs | `..\ai-system\scripts\Compare-SCTControls.ps1` |
| Start the local web app | `..\ai-system\.venv\Scripts\python.exe -m sct_ai web --repository-root .` |
| Start trusted-network proof-of-concept mode | `..\ai-system\.venv\Scripts\python.exe -m sct_ai web --repository-root . --shared --host 0.0.0.0` |
| Build an offline dependency/model bundle | `..\ai-system\scripts\Build-SCTOfflineBundle.ps1` |
| Verify and install an offline bundle | `..\ai-system\scripts\Install-SCTOfflineBundle.ps1` |
| Import an approved Ollama model | `..\ai-system\scripts\Import-SCTOllamaModel.ps1` |

The comparison engine never edits source ZIPs. Metrics, optional AI analysis,
reports, and provenance are written under `../ai-system/comparisons/<comparison-id>/`. See
the [isolated AI comparison system](../../ai-system/README.md).

`scripts/validation/Check-SCTControlProfile.ps1` is an optional standalone check for an edited control JSON. The setup script already checks newly generated profiles before writing them to `results/<control-id>/`.

## Authoring workflow

| Purpose | Command |
|---|---|
| Add a module and describe its tests | `.\scripts\authoring\Add-SCTModule.ps1` |
| Add or repair descriptions after editing a module | `.\scripts\authoring\Describe-SCTModuleTests.ps1 -ModulePath .\scenarios\<module>\module.json` |
| Check module definitions and script parameters | `.\scripts\validation\Check-SCTModules.ps1` |
| Check every test has a description | `.\scripts\validation\Check-SCTTestDescriptions.ps1` |

`Add-SCTModule.ps1` creates the module definition and then starts the test-description prompts. Technique PowerShell files are still written inside the new module folder.

## Layout

- `authoring/` creates and describes modules and techniques.
- `review/` creates product workspaces, converts legacy workspaces, and builds comparison packages.
- `validation/` checks committed metadata and operator-produced files.
- `common/` contains shared implementation and is not run directly.

Comparison launchers, configuration, dependencies, generated runs, and tests
are intentionally isolated under `../ai-system/`.
