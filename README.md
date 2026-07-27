# Security Controls Testing

This repository contains two deliberately separated components:

| Component | Purpose | Entry point |
|---|---|---|
| [`framework/`](framework/README.md) | Runs endpoint security-control scenarios and produces reviewed comparison packages. | `.\framework\Start-SCT.ps1` |
| [`ai-system/`](ai-system/README.md) | Validates and compares completed framework packages, with optional AI-assisted analysis. | `.\ai-system\.venv\Scripts\python.exe -m sct_ai web` |

## Run the framework

From the repository root:

```powershell
.\framework\Start-SCT.ps1
```

Framework code, scenarios, samples, generated workspaces, submissions,
documentation, and regression tests all live under `framework/`.

## Run the comparison system

Follow the [AI-system setup guide](ai-system/README.md), then start it from the
repository root:

```powershell
.\ai-system\.venv\Scripts\python.exe -m sct_ai web `
    --repository-root .\framework
```

The AI system reads completed packages from `framework/submissions/`; its own
configuration, runtime code, tests, and generated comparison reports remain
under `ai-system/`.

## Tests

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File .\framework\tests\Run-Tests.ps1

powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File .\ai-system\tests\Run-Tests.ps1
```

Lab use only. Run endpoint test scenarios only in an isolated environment.
