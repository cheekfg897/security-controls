# Results workspaces

SCT keeps each product's configuration and outputs together:

```text
results/
`-- <control-id>/
    |-- control-profile.json
    |-- results-module-01.csv
    |-- test-catalog-module-01.csv
    |-- results-module-02.csv
    `-- test-catalog-module-02.csv
```

Create a workspace through `.\Start-SCT.ps1` -> `[M] Manage SCT` -> `[3] Create or update a control workspace`. Setup creates one catalogue per discovered module. The launcher creates and appends to `results-module-<id>.csv` when that module first records an observation. Use `[C] Select Control Workspace` to switch between products.

After testing, open each `results-module-<id>.csv` and fill `detection_status`, `action_status`, and optional `reviewer_notes`. Do not copy or rename the files. Validate them through Manage SCT option `[4]`, then build `<control-id>.zip` through option `[5]`.

Module IDs make filenames stable. Adding Module 05 automatically creates `test-catalog-module-05.csv`; its first observation creates `results-module-05.csv`. Changing the module display name does not rename either file.

Legacy workspaces containing combined `results.csv` and `test-catalog.csv` must be converted before use:

```powershell
.\scripts\review\Convert-SCTLegacyWorkspace.ps1 `
    -ControlProfilePath .\results\<control-id>\control-profile.json
```

Control workspaces are gitignored because profiles and results may contain environment-sensitive information. The reusable profile example and schema remain under `config/`.
