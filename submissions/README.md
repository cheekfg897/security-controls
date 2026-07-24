# Comparison submissions

Validated comparison packages are generated here as `<control-id>.zip`. Each archive contains:

- `control-profile.json`
- `results-module-<id>.csv` for every tested module
- the matching `test-catalog-module-<id>.csv` for every included result file

New packages store `action_status` as only `blocked` or `not_blocked`.
Timing-specific blocked values from older workspaces are accepted but
normalized to `blocked` while the ZIP is built.

Generate one ZIP for each product through `.\Start-SCT.ps1` -> `[M] Manage SCT` -> `[5] Build comparison ZIP`. Rebuilding through the menu replaces that product's existing generated ZIP after validating all module result files.

Compare two or more generated ZIPs through Manage SCT option `[6]`, or start
the local web application:

```powershell
.\ai-system\scripts\Start-SCTComparisonWeb.ps1
```

The application reads these archives without changing them and writes generated
metrics and reports under `ai-system/comparisons/`.
