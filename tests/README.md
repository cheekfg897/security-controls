# Tests

The main SCT PowerShell regression suite is dependency-free. The isolated
AI comparison subsystem owns its Python and surface tests under
`ai-system/tests/`. None of these tests execute security techniques or evaluate
an endpoint product.

Run the complete suite from the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
```

Run the AI comparison system suite separately (its dependency-free surface
checks still run when optional Python packages are absent):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ai-system\tests\Run-Tests.ps1
```

## Layout

- `framework/` checks module schema, workflow inference, markers, and result recording.
- `workflows/` checks product setup, in-place result review, validation, and ZIP packaging.
- `Run-Tests.ps1` discovers and runs every `Test-*.ps1` file below those folders.

`ai-system/tests/python/` checks safe ZIP handling, scoring, AI evidence
contracts, FastAPI routes, browser controls, and SQLite jobs.

Keep a test near the responsibility it verifies. Add another category only when a genuinely separate responsibility appears.
