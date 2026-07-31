# Results workspaces

SCT keeps each product's configuration and outputs together:

```text
results/
`-- <control-id>/
    |-- <control-id>-control-profile.json
    |-- results-module-01.csv
    |-- test-catalog-module-01.csv
    |-- results-module-02.csv
    `-- test-catalog-module-02.csv
```

The launcher asks for a session name and creates this workspace before any
profile is required. If the operator declines the startup profile prompt, the
workspace initially contains catalogues and result CSVs but no JSON:

```text
results/
`-- <session-id>/
    |-- results-module-01.csv
    |-- test-catalog-module-01.csv
    `-- test-catalog-module-02.csv
```

Choose `[N] Create a control profile for this session` at any time to add
`<session-id>-control-profile.json` without deleting existing observations.
Only the display name is required during interactive setup; optional details
can be skipped. Validation and comparison packaging require this finalized
profile. Use `[C] Select Existing Configuration` to choose or switch to an
already finalized product workspace.

Profiles can also be created independently through `[M] Manage SCT` -> `[3]
Create or update a control configuration/workspace`. Setup creates one
catalogue per discovered module. The launcher creates and appends to
`results-module-<id>.csv` when that module first records an observation.

If `results-module-<id>.csv` files already exist under the target `control-id` (for example, left over from a previous control tested in the same workspace), Setup asks whether to delete them before continuing, so the new control starts from a clean results set instead of inheriting the previous product's observations. Answer no (or just re-run without confirming) to keep appending to the existing files instead.

After testing, open each `results-module-<id>.csv` and complete the generated
`detection=`, `action=`, and optional `notes=` prompts. For example, enter
`detection=detected`, `action=blocked`, and `notes=Quarantined`. Replacing a
prompt with the bare allowed value remains supported. The action result is
intentionally binary because product logs do not reliably distinguish blocking
before and after execution. Do not copy or rename the files. Validate them
through Manage SCT option `[4]`, then build `<control-id>.zip` through option
`[5]`; packaging strips the prompt labels.

The CSV is ordered for review: the technique, input, stage, generated execution
observation, and editable review fields come first. Technical provenance such
as the run ID, internal technique ID, script path, and SHA-256 remains at the
right of the same row for validation and comparison; SHA-256 is the final
column. Technique 1.1 uses a compact executable label capped to fit the review
area, while its generated inventory retains the complete archive member path.

Module IDs make filenames stable. Adding Module 05 automatically creates `test-catalog-module-05.csv`; its first observation creates `results-module-05.csv`. Changing the module display name does not rename either file.

Legacy workspaces containing combined `results.csv` and `test-catalog.csv` must be converted before use:

```powershell
.\scripts\review\Convert-SCTLegacyWorkspace.ps1 `
    -ControlProfilePath .\results\<control-id>\<control-id>-control-profile.json
```

Control workspaces are gitignored because profiles and results may contain environment-sensitive information. The reusable profile example and schema remain under `config/`.
