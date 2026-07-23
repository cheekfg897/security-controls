# Comparison submissions

Validated comparison packages are generated here as `<control-id>.zip`. Each archive contains:

- `control-profile.json`
- `results-module-<id>.csv` for every tested module
- the matching `test-catalog-module-<id>.csv` for every included result file

Generate one ZIP for each product through `.\Start-SCT.ps1` -> `[M] Manage SCT` -> `[5] Build comparison ZIP`. Rebuilding through the menu replaces that product's existing generated ZIP after validating all module result files.
