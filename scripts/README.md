# Script guide

Run scripts from the repository root. Scripts are grouped by the workflow they support, while filenames describe the operator action.

For interactive use, run `.\Start-SCT.ps1` and select `[M] Manage SCT`. The direct commands below remain useful for automation and troubleshooting.

## Product workflow

| Order | Purpose | Command |
|---|---|---|
| 1 | Create the product workspace and record its control policy | `.\scripts\review\Setup-SCTControl.ps1` |
| 2 | Run tests | `.\Start-SCT.ps1` |
| 3 | Enter detection and action status | Open `results\<control-id>\results.csv` in Excel |
| 4 | Check the completed results | `.\scripts\validation\Check-SCTResults.ps1 -Path .\results\<control-id>\results.csv` |
| 5 | Build that product's comparison ZIP | `.\scripts\review\Build-SCTComparisonPackage.ps1 -ControlProfilePath .\results\<control-id>\control-profile.json` |

There is no raw/analysis conversion step and no second review CSV. SCT writes observations to `results.csv`; a person fills `detection_status`, `action_status`, and optional `reviewer_notes` directly in that file because execution alone cannot determine what the control detected or blocked.

Repeat the workflow for the second product. The package builder writes `submissions/<control-id>.zip`, giving the comparison system one ZIP per product.

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
- `review/` creates product workspaces and comparison packages.
- `validation/` checks committed metadata and operator-produced files.
- `common/` contains shared implementation and is not run directly.
