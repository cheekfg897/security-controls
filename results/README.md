# Results workspaces

SCT keeps each product's configuration and outputs together:

```text
results/
`-- <control-id>/
    |-- control-profile.json
    |-- results.csv
    `-- test-catalog.csv
```

Create a workspace through `.\Start-SCT.ps1` -> `[M] Manage SCT` -> `[3] Create or update a control workspace`. The launcher selects a newly created profile and appends subsequent test observations directly to that workspace's `results.csv`. Use `[C] Select Control Workspace` to switch between products.

After testing, open `results.csv` and fill `detection_status`, `action_status`, and optional `reviewer_notes` in the same file. Do not copy or rename it. Validate it through Manage SCT option `[4]`, then build `<control-id>.zip` through option `[5]`. If you later correct the CSV, options `[4]` and `[5]` validate it and replace that product's generated ZIP.

Control workspaces are gitignored because profiles and results may contain environment-sensitive information. The reusable profile example and schema remain under `config/`.
