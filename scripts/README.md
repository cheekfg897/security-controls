# Script guide

Run scripts from the repository root. The filename describes the operator action rather than the file format it creates.

## Normal VM workflow

| Order | Purpose | Command |
|---|---|---|
| 1 | Record the security control and policy used in this VM | `.\scripts\Setup-SCTControl.ps1` |
| 2 | Run tests | `.\Start-SCT.ps1` |
| 3 | Prepare raw results for human review | `.\scripts\Prepare-SCTResultsForReview.ps1 -ControlProfilePath .\config\control-profile.local.json` |
| 4 | Enter detection and action status | Open `results\analysis\results-for-review.csv` in Excel |
| 5 | Check the completed review CSV | `.\scripts\Check-SCTReviewedResults.ps1 -Path .\results\analysis\reviewed-results.csv` |

There is intentionally no “add control status” script. A person fills `detection_status` and `action_status` in Excel because execution alone cannot determine what the control detected or blocked.

`Check-SCTControlProfile.ps1` is an optional standalone check for an edited control JSON. The setup script already checks newly generated profiles before writing them.

## Adding modules or techniques

| Purpose | Command |
|---|---|
| Add a module and describe its tests | `.\scripts\Add-SCTModule.ps1` |
| Add or repair descriptions after editing a module | `.\scripts\Describe-SCTModuleTests.ps1 -ModulePath .\scenarios\<module>\module.json` |
| Check module definitions and script parameters | `.\scripts\Check-SCTModules.ps1` |
| Check every test has a description | `.\scripts\Check-SCTTestDescriptions.ps1` |

`Add-SCTModule.ps1` creates the module definition and then starts the test-description prompts. Technique PowerShell files are still written inside the new module folder.

## Internal file

`_SCT-ReviewHelpers.ps1` contains shared functions used by the review scripts. Do not run it directly.
