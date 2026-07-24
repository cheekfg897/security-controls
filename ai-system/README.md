# SCT comparison web application

This folder contains the Security Control Testing (SCT) comparison engine,
web application, optional AI explanation workflow, and offline-installation
tools.

The normal way to use it is:

1. Install the Python dependencies once.
2. Start the local web application.
3. Select or upload two or more validated result ZIPs.
4. Configure module, detection, and blocking weights in the browser.
5. Run the deterministic comparison.
6. Optionally ask an allowlisted local or hosted model to explain the results.

The scoring engine is authoritative. AI can explain calculated evidence, but it
cannot calculate scores, change rankings, or select a different winner.

## Find what you need

| I want to... | Go to |
|---|---|
| See what is required | [Requirements at a glance](#requirements-at-a-glance) |
| Install the application | [Quick start](#quick-start) |
| Run the local web application | [Quick start: Start the web application](#4-start-the-web-application) |
| Learn how to use the web interface | [Using the web application](#using-the-web-application) |
| Choose a model and configure its API key | [Choose and configure an AI model](#choose-and-configure-an-ai-model) |
| Run a comparison from the command line | [Command-line use](#command-line-use) |
| Allow access from a trusted lab network | [Shared-network mode](#shared-network-mode) |
| Host the ASGI application | [ASGI hosting](#asgi-hosting) |
| Install in an air-gapped environment | [Air-gapped installation](#air-gapped-installation) |
| Understand the generated output | [Generated files](#generated-files) |
| Understand the folders, source, and HTML | [Developer guide](DEVELOPER_GUIDE.md) |
| Fix a problem | [Troubleshooting](#troubleshooting) |
| Run the regression tests | [Tests](#tests) |
| Review the security boundaries | [Security boundary](#security-boundary) |

### Full contents

- [Requirements at a glance](#requirements-at-a-glance)
- [Quick start](#quick-start)
  - [1. Check Python](#1-check-python)
  - [2. Create the private Python environment](#2-create-the-private-python-environment)
  - [3. Install the Python application](#3-install-the-python-application)
  - [4. Start the web application](#4-start-the-web-application)
- [Using the web application](#using-the-web-application)
- [Choose and configure an AI model](#choose-and-configure-an-ai-model)
- [What the AI workflow does](#what-the-ai-workflow-does)
- [Generated files](#generated-files)
- [Command-line use](#command-line-use)
- [Shared-network mode](#shared-network-mode)
- [ASGI hosting](#asgi-hosting)
- [Air-gapped installation](#air-gapped-installation)
- [Developer documentation](#developer-documentation)
- [Troubleshooting](#troubleshooting)
- [Tests](#tests)
- [Security boundary](#security-boundary)

## Requirements at a glance

To install and start the application, you need:

- This repository on the machine where the application will run.
- A supported 64-bit CPython 3.11 or newer within the Python 3 series.
- The Python dependencies installed from a package index or from the
  [air-gapped installation](#air-gapped-installation) bundle.

To perform a comparison, you also need at least two valid SCT result ZIPs.
These can already be present under `submissions\` or be uploaded through the
web application.

AI is optional. Metrics, scoring, ranking, and deterministic reports work
without Ollama, an OpenAI API key, or any other model provider. Node.js, npm,
Docker, and a separate database server are not required.

## Quick start

Run all commands from the repository root, not from inside `ai-system`.

### 1. Check Python

The application supports 64-bit CPython 3.11 or newer within the Python 3
series, including Python 3.13 and 3.14:

```powershell
python --version
```

When several Python versions are installed through the Windows Python launcher,
you can select one explicitly:

```powershell
py -3.14 --version
```

If neither command finds a supported runtime, install a supported x64 Python
version or use the offline installation workflow later in this document.

### 2. Create the private Python environment

Only do this when `ai-system\.venv` does not already exist:

```powershell
py -3.14 -m venv .\ai-system\.venv
```

Replace `3.14` with the installed version you want to test, such as `3.13`.
If the `py` launcher is unavailable, use `python -m venv
.\ai-system\.venv`. A virtual environment is tied to the Python version that
created it and should not be copied between testers.

You do not need to activate the environment. The commands below invoke its
Python executable directly.

### 3. Install the Python application

```powershell
.\ai-system\.venv\Scripts\python.exe -m pip install `
    --editable ".\ai-system[all]"
```

This installs the `sct_ai` package, its Python command-line entry points, the
web dependencies, and the optional AI integrations. For a metrics-only
installation, use `--editable ".\ai-system[web]"`.

No Node.js, npm, frontend build, database server, or Docker container is
required. The application uses FastAPI, server-rendered HTML, a local SQLite
job index, and browser assets included in this repository.

### 4. Start the web application

```powershell
.\ai-system\.venv\Scripts\python.exe -m sct_ai web
```

Open:

```text
http://127.0.0.1:8000
```

Keep the Python server terminal open while using the application. Press
`Ctrl+C` in that terminal to stop it.

The optional `Start-SCTComparisonWeb.ps1` wrapper remains available for older
Windows workflows, but it launches this same Python command and is no longer
the primary startup method.

## Using the web application

The home page is arranged in the same order as a comparison run.

### Step 1: Select result packages

Select existing ZIPs from `submissions\`, upload additional ZIPs, or combine
both methods.

Requirements:

- At least two and no more than twenty ZIPs.
- Each ZIP must be no larger than 100 MB.
- Every package must have a unique control ID.
- Every result module must have a matching test catalogue.
- Unsafe paths, duplicate entries, encrypted entries, unexpected files, and
  unsafe compression ratios are rejected.

Use **Validate packages** before running a comparison. The preflight result
shows each control ID, case count, trial count, and submitted module IDs.

Uploads are copied to a generated staging directory. They are removed when the
job finishes. ZIPs already stored under `submissions\` are never modified.

### Step 2: Set module weights

The page shows one numeric field for each repository module:

- Module 01: Malware Delivery
- Module 02: Exploitation
- Module 03: Privilege Escalation
- Module 04: Persistence

Module weights describe business importance. A module with a 40% weight has
twice the ranking influence of a module with a 20% weight.

The modules contained in the selected ZIPs must have positive weights totaling
100%. Set modules not present in the selected packages to 0%. The server
validates this again before starting the job.

Examples:

```text
Equal importance:       25 / 25 / 25 / 25
Delivery emphasized:   40 / 20 / 20 / 20
Modules 01 and 02 only: 60 / 40 /  0 /  0
```

Module weighting occurs after cases have been matched and averaged. It cannot
make a product-only case comparable.

### Step 3: Choose detection and blocking scoring

The GUI provides four scoring modes.

#### Automatic

This is the recommended default.

- If every submitted control profile has `default_mode: detect_only`, scoring
  resolves to 100% detection and 0% blocking.
- If any submitted control is `detect_and_block` or `custom`, scoring resolves
  to prevention-first: 40% detection and 60% blocking.

The completed comparison page and generated reports show the mode that was
actually used.

#### Detection only

Detection contributes 100% and blocking contributes 0%.

Use this when blocking was intentionally disabled or when the evaluation is
only intended to measure visibility. Blocking outcomes remain visible in the
reports but do not affect the score.

#### Prevention first

Detection contributes 40% and the binary blocked/not-blocked rate contributes
60%.

#### Custom

Enter any detection and blocking percentages from 0 to 100. The two values
must total 100%.

Examples:

```text
Detection emphasized: 75% detection / 25% blocking
Equal emphasis:       50% detection / 50% blocking
Prevention emphasized: 25% detection / 75% blocking
```

For each case:

```text
case score =
    detection rate × detection weight
  + blocked rate × blocking weight
```

Blocking is intentionally binary:

- `blocked` receives full blocking credit.
- `not_blocked` receives no blocking credit.

The framework does not require reviewers to decide whether blocking happened
before or after execution because product logs often do not expose that timing
reliably. Older timing-specific values are accepted and normalized to
`blocked`.

Repeated trials are averaged inside their case first. Cases are then averaged
inside their module. This prevents frequently repeated tests from silently
dominating a module.

### Step 4: Set decision thresholds

**Minimum comparable weight** defaults to 80%.

The ranking uses only cases shared by every submitted control. If the modules
containing shared cases represent less than this threshold, the result is
provisional and the engine does not recommend a product.

**Tie margin** defaults to 2 points.

When the top two scores are within this margin, the result is reported as
`no_clear_winner`.

### Step 5: Optionally enable AI explanation

Metrics-only mode is always available and does not contact an AI provider.

When AI is configured:

1. Select **Run AI evidence skills**.
2. Select an allowlisted provider and model.
3. Run the comparison normally.

The deterministic comparison is completed and saved before any model request.
If AI configuration or output validation fails, the metrics and deterministic
reports remain available.

### Step 6: Validate and run

Use **Validate packages** to check the ZIPs first, then select
**Run comparison**.

The browser opens a progress page. The application performs:

```text
package validation
        ↓
case matching and deterministic metrics
        ↓
coverage, pairwise differences, and ranking
        ↓
deterministic reports
        ↓ optional
validated AI evidence explanation
```

When complete, the browser displays:

- The resolved scoring mode and weights.
- Comparable coverage.
- The verified ranking or no-winner reason.
- Per-control and per-module metrics.
- Pairwise score differences.
- Optional AI findings.
- Expandable evidence records.
- Downloadable output files.

## Choose and configure an AI model

AI is optional. Leave **Run AI evidence skills** unchecked when deterministic
metrics and reports are sufficient. No provider or API key is contacted in
metrics-only mode.

AI configuration is server-side. Browser users can select only the exact
provider/model pairs allowlisted by the administrator.

### 1. Choose a provider

| Provider | Choose it when | API key |
|---|---|---|
| Local Ollama | Model data must remain on the machine or isolated lab network, and the machine can run the approved model. | Not required by this application. |
| Hosted OpenAI | The organization permits the approved evidence payload to be sent to OpenAI and has an approved model/API project. | Required through an environment variable. |
| OpenAI-compatible endpoint | The organization operates or approves another chat-completions-compatible service. | Normally required through an environment variable. |

For a hosted provider, confirm its data-handling approval before enabling AI.
The deterministic comparison does not require any external provider.

### 2. Create the server allowlist

Copy the example configuration:

```powershell
Copy-Item .\ai-system\config\ai-providers.example.json `
    .\ai-system\config\config.local.ai.json
```

Edit `config.local.ai.json`. Under the selected provider, replace the
placeholder in `models` with the exact model identifier exposed by Ollama or
the hosted endpoint:

```json
{
  "models": ["exact-approved-model-id"]
}
```

Choose a model that is:

- Approved for the classification of evidence being compared.
- Available to the configured account or local runtime.
- Compatible with chat-style requests and structured JSON responses.
- Small enough for the local machine, or within the hosted service's approved
  cost and latency limits.

The application does not automatically discover, download, or choose a model.
Every allowed model must be named explicitly. Placeholder names containing
angle brackets are hidden from the web interface.

Local configuration files are gitignored.

### 3. Configure the selected provider

#### Local Ollama

Install and start Ollama separately, then list the locally available model
names:

```powershell
ollama list
```

The value in `models` must exactly match the imported Ollama name:

```json
{
  "type": "ollama",
  "base_url": "http://127.0.0.1:11434",
  "models": ["sct-approved"]
}
```

To import an approved GGUF or supported Safetensors model:

```powershell
.\ai-system\scripts\Import-SCTOllamaModel.ps1 `
    -ModelPath D:\ApprovedModels\model.gguf `
    -ModelName sct-approved
```

The model's learned weights are stored and run by Ollama, not by this Python
application. No model weights are committed under `ai-system`.

#### Hosted OpenAI

Configure the exact approved model and the name of the environment variable
that will hold the API key:

```json
{
  "type": "openai",
  "models": ["exact-approved-model-id"],
  "api_key_env": "OPENAI_API_KEY"
}
```

Set that environment variable in the same PowerShell session before starting
the web application:

```powershell
$openAIKey = Read-Host 'OpenAI API key' -AsSecureString
$openAICredential = [System.Management.Automation.PSCredential]::new(
    'unused',
    $openAIKey
)
$env:OPENAI_API_KEY = $openAICredential.GetNetworkCredential().Password
Remove-Variable openAICredential, openAIKey
```

Enter the key issued for the approved API project when prompted.

#### OpenAI-compatible endpoint

Configure the approved HTTPS API base URL, exact model identifier, and the
environment variable that contains its key:

```json
{
  "type": "openai-compatible",
  "base_url": "https://approved-model-endpoint.example/v1",
  "models": ["exact-approved-model-id"],
  "api_key_env": "SCT_AI_API_KEY"
}
```

Then set the matching variable before startup:

```powershell
$compatibleKey = Read-Host 'Compatible API key' -AsSecureString
$compatibleCredential = [System.Management.Automation.PSCredential]::new(
    'unused',
    $compatibleKey
)
$env:SCT_AI_API_KEY = $compatibleCredential.GetNetworkCredential().Password
Remove-Variable compatibleCredential, compatibleKey
```

Users cannot submit an arbitrary model URL through the browser.

### 4. Protect the API key

- Put only the environment-variable name in `config.local.ai.json`, never the
  secret value.
- Do not commit keys, paste them into comparison policies, or include them in
  command history or screenshots.
- Use a key scoped to the approved project and provider permissions.
- The `$env:` examples set the key for the current PowerShell process and
  programs started from it. Open a new session or remove the variable when it
  is no longer needed.

### 5. Start and verify

Start the application from the same terminal in which a hosted API key was
set:

```powershell
.\ai-system\.venv\Scripts\python.exe -m sct_ai web
```

Open `http://127.0.0.1:8000`, enable **Run AI evidence skills**, and confirm
the expected provider/model pair appears in the dropdown. If it does not,
check the model spelling, remove placeholder angle brackets, confirm the API
key variable is set, and restart the server after configuration changes.

## What the AI workflow does

The optional workflow makes four sequential model calls:

1. `profile-context`
2. `module-analysis`
3. `cross-control-synthesis`
4. `qualified-recommendation`

These are versioned prompt-and-schema stages, not autonomous or parallel
agents. One selected model client runs the stages in order. Later stages can
receive validated earlier output.

All definitions now live in the consolidated
`src\sct_ai\skills.json` catalog.

Each response must:

- Match its JSON schema.
- Reference known control IDs.
- Cite exact evidence IDs from `comparison.json`.
- Avoid unsupported percentage claims.
- Return the deterministic recommendation exactly, including `null` when
  evidence is insufficient or scores are tied.

A skill receives one correction attempt when its first response is invalid.

Remote-provider payloads omit raw CSV rows, reviewer notes, source results,
sample names, local log paths, exclusion values, and detailed settings by
default. A local server configuration may explicitly allow policy-setting
details.

## Generated files

Each run is written to:

```text
ai-system\comparisons\<comparison-id>\
```

Artifacts:

```text
comparison.json       authoritative calculated evidence and ranking
ai-analysis.json      optional validated AI output
technical-report.md   detailed human-readable report
executive-summary.md  short decision-focused report
report.html           portable standalone HTML report
run-manifest.json     inputs, Python version, status, timestamps, artifacts, and errors
```

The web job index is:

```text
ai-system\comparisons\index.sqlite3
```

Run manifests remain the source of truth. The web application re-imports them
into SQLite when it starts.

Generated comparison data is gitignored because it may contain sensitive
evaluation context.

## Command-line use

The web GUI is recommended for interactive use. The same engine is available
through the installed Python module.

Create a local policy file:

```powershell
Copy-Item .\ai-system\config\comparison-policy.example.json `
    .\ai-system\config\config.local.comparison.json
```

An automatic policy looks like:

```json
{
  "schema_version": "1.0",
  "module_weights": {
    "01": 25,
    "02": 25,
    "03": 25,
    "04": 25
  },
  "minimum_comparable_weight": 80,
  "tie_margin": 2,
  "scoring_mode": "auto"
}
```

A custom scoring policy adds:

```json
{
  "scoring_mode": "custom",
  "detection_weight": 70,
  "blocking_weight": 30
}
```

Run metrics and ranking:

```powershell
.\ai-system\.venv\Scripts\python.exe -m sct_ai compare `
    --package .\submissions\control-a.zip `
    --package .\submissions\control-b.zip `
    --policy .\ai-system\config\config.local.comparison.json
```

Add local AI analysis:

```powershell
.\ai-system\.venv\Scripts\python.exe -m sct_ai compare `
    --package .\submissions\control-a.zip `
    --package .\submissions\control-b.zip `
    --policy .\ai-system\config\config.local.comparison.json `
    --provider local-ollama `
    --model sct-approved `
    --provider-config .\ai-system\config\config.local.ai.json
```

The installed Python module is the primary interface:

```text
python -m sct_ai validate --package <zip> --package <zip>
python -m sct_ai compare --package <zip> --package <zip> --policy <json>
python -m sct_ai web --host 127.0.0.1 --port 8000
```

Use the virtual environment's `python.exe` in place of `python` when the
environment is not activated. The installation also provides `sct-web` and
`sct-compare` console commands for environments that place console scripts on
`PATH`; `python -m sct_ai` remains the portable interface. Selecting Python
3.13 versus 3.14 happens when the virtual environment is created, so the
application runs under that interpreter without a separate runtime-selection
layer.

The PowerShell comparison scripts remain optional wrappers for existing SCT
menu integration.

## Shared-network mode

Local mode binds only to loopback. To expose the proof of concept on a trusted,
isolated lab network:

```powershell
.\ai-system\.venv\Scripts\python.exe -m sct_ai web `
    --shared `
    --host 0.0.0.0 `
    --port 8000 `
    --workers 2
```

Shared mode has no authentication and no built-in TLS. Do not expose it to an
untrusted network. A production deployment requires a separate design for
authentication, authorization, TLS, audit logging, secrets, rate limiting,
backups, and operational monitoring.

`--workers` controls background comparison concurrency:

The default is one; the maximum is eight. These are background job threads,
not separate web-server processes or AI agents.

## ASGI hosting

The package exports the conventional ASGI target `sct_ai.asgi:app`. A hosting
platform can install `.[all]`, configure environment variables, and start:

```text
python -m uvicorn sct_ai.asgi:app --host 0.0.0.0 --port 8000 --workers 1
```

Configuration:

| Variable | Purpose |
|---|---|
| `SCT_REPOSITORY_ROOT` | Repository directory containing `scenarios/` and `submissions/` |
| `SCT_SYSTEM_ROOT` | Writable persistent directory for `comparisons/` and the SQLite index |
| `SCT_SHARED_MODE` | Set to `true` for a non-loopback deployment |
| `SCT_PROVIDER_CONFIG` | Optional path to the server-side AI provider configuration |
| `SCT_JOB_WORKERS` | Background comparison threads, from 1 to 8 |

Run one Uvicorn process because the current background queue is in-process.
Increase `SCT_JOB_WORKERS` for comparison concurrency. A public deployment
still requires an authenticated TLS reverse proxy and the operational controls
listed above; the ASGI entry point makes hosting straightforward but does not
turn the proof of concept into a secured public service.

## Air-gapped installation

Offline wheel bundles are specific to a Python minor version because some
dependencies contain compiled components. Build one bundle for each Python
minor version that will be used. On an approved connected Windows staging
machine with the target runtime installed:

```powershell
.\ai-system\scripts\Build-SCTOfflineBundle.ps1 `
    -PythonVersion 3.14 `
    -OutputPath D:\Transfer\sct-comparison-python314 `
    -ModelPath D:\ApprovedModels\model.gguf
```

The bundle contains the pinned dependency wheelhouse and a SHA-256 manifest
that records its Python version.

Inside the air gap, install the matching Python minor version and its bundle:

```powershell
.\ai-system\scripts\Install-SCTOfflineBundle.ps1 `
    -BundlePath D:\Transfer\sct-comparison-python314
```

The installer verifies every transferred file and installs without consulting
a package index. It rejects installation when the machine does not have the
Python minor version recorded in the manifest.

Import the model separately into Ollama:

```powershell
.\ai-system\scripts\Import-SCTOllamaModel.ps1 `
    -ModelPath D:\Transfer\sct-comparison-python314\models\model.gguf `
    -ModelName sct-approved
```

## Developer documentation

The complete source tree, PowerShell and Python file responsibilities, HTML
template flow, browser assets, architecture, generated files, and test guide
are maintained separately in
[DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md).

## Troubleshooting

### FastAPI or Uvicorn is not installed

Symptom:

```text
FastAPI web dependencies are not installed
```

Fix:

```powershell
.\ai-system\.venv\Scripts\python.exe -m pip install `
    --editable ".\ai-system[all]"
```

### The page does not open

- Confirm the Python server process is still running.
- Use `http://127.0.0.1:8000`, not HTTPS.
- Try another port:

```powershell
.\ai-system\.venv\Scripts\python.exe -m sct_ai web --port 8080
```

### No AI models appear

- Confirm `ai-system\config\config.local.ai.json` exists.
- Remove placeholder angle brackets from the model name.
- Confirm the model is allowlisted under the selected provider.
- Restart the web application after changing the configuration.
- For Ollama, confirm `ollama list` shows the configured model.

Metrics-only comparisons remain available without an AI provider.

### Module weights are rejected

- Use **Validate packages** to see which modules are present.
- Give every present module a positive value.
- Set absent modules to 0.
- Confirm the present-module values total exactly 100.

### Custom scoring is rejected

Detection and blocking weights must each be between 0 and 100 and together
must total exactly 100.

### A run is provisional

The modules containing cases shared by every control have less total weight
than **Minimum comparable weight**. Add comparable evidence or intentionally
lower the threshold with a documented justification.

### No clear winner is reported

The top scores are within the configured tie margin. This is an intentional
decision rule, not an AI failure.

## Tests

Run the complete regression suite:

```powershell
.\ai-system\tests\Run-Tests.ps1
```

To verify a particular installed runtime, add `-PythonVersion`, for example
`-PythonVersion 3.13` or `-PythonVersion 3.14`. Run the suite separately under
each version that the deployment will support.

The suite checks package safety, deterministic scoring, automatic detect-only
behavior, custom weights, coverage rules, tie handling, output preservation,
the web surface, and AI evidence validation.

## Security boundary

- Source ZIPs under `submissions\` and workspaces under `results\` are treated
  as read-only.
- Uploads receive generated staging names and are deleted after their job.
- Web forms use same-site double-submit CSRF protection.
- Pages use automatic HTML escaping and a restrictive Content Security Policy.
- Browser code makes self-origin requests only and uses no CDN.
- API keys are read from server environment variables.
- Provider names, model names, and endpoints are server-allowlisted.
- The model receives structured evidence and cannot change the deterministic
  ranking.
