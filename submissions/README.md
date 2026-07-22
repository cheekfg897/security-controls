# Comparison submissions

Validated comparison packages are generated here as `<control-id>.zip`. Each archive contains exactly:

- `control-profile.json`
- `results.csv`
- `test-catalog.csv`

Generate one ZIP for each product through `.\Start-SCT.ps1` -> `[M] Manage SCT` -> `[5] Build comparison ZIP`. Rebuilding through the menu replaces that product's existing generated ZIP after validating the current `results.csv`.
