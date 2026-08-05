# Security Controls Testing

Security Controls Testing (SCT) is a lab tool for running simulated attack
techniques and recording how endpoint security products respond.

> **Want to run SCT? Start in [`framework/`](framework/README.md).**
>
> `framework` is the main SCT application. Run `Start-SCT.ps1` from that
> folder. Do not start in `ai-system`; it is an optional tool for comparing
> results after the security tests are complete.

Run SCT from the repository root with:

```powershell
.\framework\Start-SCT.ps1
```

Lab use only. Run security test scenarios on an isolated Windows VM, never on a
production or connected business system.

## What does "framework" mean?

In this repository, **framework** means the complete PowerShell-based testing
application. It provides the menu, attack scenarios, result collection,
validation, and packaging workflow used to test an EDR or antivirus product.
It is not a supporting library that must be called through `ai-system`.

The normal user workflow starts and remains in `framework`:

1. Open [`framework/`](framework/README.md).
2. Run `Start-SCT.ps1`.
3. Name the test session and optionally create or select a product profile.
4. Run the test scenarios and review the results.
5. Create the profile later if needed, then validate the results and build a comparison ZIP.

The [`framework/README.md`](framework/README.md) contains the requirements,
setup instructions, menu guide, and complete testing workflow.

## What is `ai-system`?

`ai-system` is a separate, optional comparison application. It does **not** run
the endpoint security tests. It accepts two or more completed ZIP packages
created by `framework`, calculates comparable scores and rankings, and can
optionally use an approved AI model for a blinded advisory assessment that is
shown separately from the deterministic Python recommendation.

Only open [`ai-system/`](ai-system/README.md) when you already have completed
framework packages to compare, or when you are developing the comparison
application.

```text
framework                 ai-system
run tests                 compare completed packages
record results     ->     calculate metrics and rankings
build ZIPs                generate comparison reports
```

## Repository structure

```text
security-controls/
|-- README.md                 # Start here
|-- framework/                # Main user-facing SCT application
|   |-- Start-SCT.ps1         # Main launcher: run this
|   |-- config/               # Product-profile files and ready-to-use Sysmon XML
|   |-- core/                 # Menu, discovery, execution, and result logic
|   |-- docs/                 # Framework design, guides, and references
|   |-- results/              # Generated workspaces and reviewed test results
|   |-- samples/              # Local test samples
|   |-- sanity_checks/        # Checks that an EDR/AV product is active
|   |-- scenarios/            # Test modules and technique scripts
|   |-- scripts/              # Authoring, review, and validation utilities
|   |-- submissions/          # Completed comparison ZIP packages
|   `-- tests/                # PowerShell framework regression tests
`-- ai-system/                # Optional result-comparison application
    |-- config/               # Comparison policy and AI-provider examples
    |-- comparisons/          # Generated comparison reports
    |-- requirements/         # Pinned Python dependency lists
    |-- scripts/              # Setup, offline-install, and compatibility tools
    |-- src/sct_ai/           # Python engine, web app, templates, and assets
    `-- tests/                # Python and PowerShell regression tests
```

Generated content under `framework/results/`, `framework/submissions/`, and
`ai-system/comparisons/` is kept with the component that creates or consumes
it.

## Which folder should I use?

| I want to... | Go to |
|---|---|
| Set up or run SCT | [`framework/`](framework/README.md) |
| Run an endpoint security test | [`framework/`](framework/README.md) |
| Record, validate, or package test results | [`framework/`](framework/README.md) |
| Add a test module or technique | [`framework/`](framework/README.md#adding-a-technique) |
| Compare two or more completed result ZIPs | [`ai-system/`](ai-system/README.md) |
| Configure optional independent AI assessment | [`ai-system/`](ai-system/README.md#choose-and-configure-an-ai-model) |

## Developer tests

Run the framework tests:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File .\framework\tests\Run-Tests.ps1
```

Run the optional comparison application's tests:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File .\ai-system\tests\Run-Tests.ps1
```
