# Tests

These are dependency-free PowerShell regression tests for SCT itself. They do not execute security techniques or evaluate an endpoint product.

Run the complete suite from the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
```

## Layout

- `framework/` checks module schema, workflow inference, markers, and result recording.
- `workflows/` checks product setup, in-place result review, validation, and ZIP packaging.
- `Run-Tests.ps1` discovers and runs every `Test-*.ps1` file below those folders.

Keep a test near the responsibility it verifies. Add another category only when a genuinely separate responsibility appears.
