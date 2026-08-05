# SCT comparison developer guide

This document explains the repository-owned structure of `ai-system`, the
responsibility of every PowerShell script and source file, and how the Python,
HTML, CSS, and JavaScript parts work together.

For installation, model selection, API-key configuration, and normal
operation, start with [README.md](README.md).

## Contents

- [Complete structure](#complete-structure)
- [How the source files connect](#how-the-source-files-connect)
- [Top-level, configuration, and dependency files](#top-level-configuration-and-dependency-files)
- [PowerShell scripts](#powershell-scripts)
- [Python source modules](#python-source-modules)
- [AI skill catalogue](#ai-skill-catalogue)
- [HTML templates and page flow](#html-templates-and-page-flow)
- [Browser assets](#browser-assets)
- [Tests](#tests)
- [Generated files and directories](#generated-files-and-directories)

## Complete structure

Runtime folders and files that are created locally are marked as generated.

```text
ai-system\
|-- README.md
|-- DEVELOPER_GUIDE.md
|-- THIRD_PARTY_NOTICES.md
|-- pyproject.toml
|-- config\
|   |-- ai-providers.example.json
|   `-- comparison-policy.example.json
|-- requirements\
|   |-- ai.txt
|   |-- all.txt
|   |-- build.txt
|   `-- web.txt
|-- scripts\
|   |-- Build-SCTOfflineBundle.ps1
|   |-- Compare-SCTControls.ps1
|   |-- Import-SCTOllamaModel.ps1
|   |-- Install-SCTOfflineBundle.ps1
|   |-- SCT-ComparisonHelpers.ps1
|   `-- Start-SCTComparisonWeb.ps1
|-- src\
|   `-- sct_ai\
|       |-- __init__.py
|       |-- __main__.py
|       |-- ai_workflow.py
|       |-- asgi.py
|       |-- cli.py
|       |-- errors.py
|       |-- jobs.py
|       |-- metrics.py
|       |-- packages.py
|       |-- reports.py
|       |-- service.py
|       |-- skills.json
|       |-- util.py
|       |-- web.py
|       |-- __pycache__\                         [generated Python bytecode]
|       |-- static\
|       |   |-- app.css
|       |   |-- app.js
|       |   |-- htmx.min.js
|       |   `-- HTMX-LICENSE.txt
|       `-- templates\
|           |-- base.html
|           |-- comparison.html
|           |-- index.html
|           |-- job.html
|           `-- preflight.html
|-- tests\
|   |-- __init__.py
|   |-- Run-Tests.ps1
|   |-- Test-AISystemSurface.ps1
|   `-- python\
|       |-- __init__.py
|       |-- helpers.py
|       |-- test_ai_skills.py
|       |-- test_comparison_engine.py
|       |-- test_runtime.py
|       `-- test_web.py
|-- comparisons\
|   |-- README.md
|   |-- index.sqlite3                         [generated]
|   |-- .staging\                             [generated, temporary]
|   `-- <comparison-id>\                      [generated]
|       |-- comparison.json
|       |-- ai-analysis.json                  [only for AI runs]
|       |-- technical-report.md
|       |-- executive-summary.md
|       |-- report.html
|       `-- run-manifest.json
|-- .tools\                                   [generated bootstrap files]
|-- .venv\                                    [generated Python environment]
`-- offline-bundles\                          [generated when built locally]
```

## How the source files connect

```text
Browser
  -> web.py
     -> jobs.py
        -> service.py

PowerShell wrappers or python -m sct_ai
  -> cli.py
     -> service.py

service.py
  -> packages.py  (validate and normalize ZIP inputs)
  -> metrics.py   (calculate evidence, scores, coverage, and ranking)
  -> reports.py   (write Markdown and standalone HTML)
  -> ai_workflow.py + skills.json  (optional evidence explanation)

web.py
  -> templates\  (server-rendered HTML pages)
  -> static\     (CSS, form behavior, HTMX, and job polling)
```

The CLI and web application share the same validation, metrics, reporting, and
optional AI implementation. The web layer does not contain a second
comparison engine.

## Top-level, configuration, and dependency files

| Path | Purpose |
|---|---|
| `README.md` | Operator guide for installation, model/provider selection, API-key configuration, running comparisons, deployment, and troubleshooting. |
| `DEVELOPER_GUIDE.md` | This source-tree, architecture, frontend, and testing reference. |
| `THIRD_PARTY_NOTICES.md` | Records the vendored HTMX version, source, SHA-256 value, and licence location. Python packages are not vendored in Git. |
| `pyproject.toml` | Defines the `sct-comparison` Python package, supported Python range, pinned optional dependency groups, console commands, `src` package layout, and packaged templates/static assets. |
| `config\ai-providers.example.json` | Example server-side allowlist for Ollama, hosted OpenAI, and OpenAI-compatible providers. It names permitted models, endpoints, API-key environment variables, timeouts, retries, and whether detailed policy settings may be sent. |
| `config\comparison-policy.example.json` | Example deterministic ranking policy containing module weights, comparable-coverage threshold, tie margin, and scoring mode. |
| `requirements\build.txt` | Pins the build backend dependency, currently setuptools, used by online and offline installation. |
| `requirements\web.txt` | Pins only the FastAPI, Uvicorn, templating, multipart-upload, and HTTP test/client dependencies needed by the web surface. |
| `requirements\ai.txt` | Pins the LangChain provider adapters and Pydantic dependencies needed by optional AI analysis. |
| `requirements\all.txt` | Combined pinned web and AI top-level dependencies used for a full install and offline wheel bundle. |
| `comparisons\README.md` | Explains generated run artifacts, the SQLite job index, manifest recovery, and the read-only boundary around source packages and workspaces. |

## PowerShell scripts

All six files under `scripts\` are Windows convenience, installation, or
offline-management tools. The comparison logic itself is in `src\sct_ai`.

### `scripts\Build-SCTOfflineBundle.ps1`

Builds a transferable, checksummed offline installation bundle on an approved
connected Windows machine.

- Finds the requested supported Python 3 minor version through
  `SCT-ComparisonHelpers.ps1`.
- Refuses to use a drive root or the `ai-system` root as its output directory.
- Downloads binary wheels for `requirements\all.txt` and
  `requirements\build.txt`.
- Optionally copies an explicitly supplied model file or directory.
- Records every bundled file's relative path, size, and SHA-256 value in
  `bundle-manifest.json`, along with the required Python minor version.
- Refuses to replace an existing bundle unless `-Force` is supplied.

### `scripts\Compare-SCTControls.ps1`

PowerShell wrapper for `python -m sct_ai compare`.

- Accepts package paths or interactively selects packages from the
  framework's `framework\submissions\` directory when none are supplied.
- Resolves package, policy, and provider-configuration paths before invoking
  Python.
- Passes the output directory, optional comparison ID, Python version, and
  `-Force` behavior to the Python CLI.
- Requires a model and provider configuration when AI analysis is enabled.
- Defaults generated output to `ai-system\comparisons`.

This script does not parse packages or calculate scores itself; it delegates
those operations to the installed `sct_ai` package.

### `scripts\Import-SCTOllamaModel.ps1`

Imports an approved local GGUF or supported Safetensors model into Ollama.

- Resolves the model path and checks that the requested Ollama model name uses
  the permitted character set.
- Creates a temporary `Modelfile` whose `FROM` instruction points to the
  supplied model.
- Runs `ollama create`, verifies the result with `ollama show`, and fails when
  either command fails.
- Removes its temporary directory in a `finally` block.

### `scripts\Install-SCTOfflineBundle.ps1`

Verifies and installs a previously built wheel bundle without contacting a
package index.

- Requires a version 1.0 manifest with a supported Python 3 minor version.
- Resolves every manifest path, rejects paths that escape the bundle, and
  verifies every recorded SHA-256 checksum before installation.
- Refuses to overwrite an existing virtual environment.
- Finds the exact Python minor version recorded in the bundle.
- Creates `.venv`, installs build dependencies and application dependencies
  with `--no-index`, and then installs `ai-system` as an editable package
  without build isolation or dependency resolution.

### `scripts\SCT-ComparisonHelpers.ps1`

Shared support library dot-sourced by the other PowerShell scripts.

- `Test-SCTSupportedPythonVersion` accepts Python 3.11 or newer within the
  Python 3 series.
- `Get-SCTComparisonPython` searches the local `.venv`, the Windows `py`
  launcher, and `python`/`python3` commands. It can require an exact minor
  version and returns the executable, launcher prefix, and detected version.
- `Invoke-SCTComparisonPython` temporarily adds `ai-system\src` to
  `PYTHONPATH`, invokes the selected interpreter, returns its exit code, and
  restores the previous environment.
- `Select-SCTComparisonPackages` lists ZIPs under `framework\submissions\` and validates
  an interactive selection of at least two distinct menu entries.

This is a library file; it is not normally run directly.

### `scripts\Start-SCTComparisonWeb.ps1`

PowerShell wrapper for `python -m sct_ai web`.

- Defaults to loopback address `127.0.0.1`, port 8000, and one background
  comparison worker.
- Requires `-Shared` before accepting a non-loopback address and displays the
  no-authentication/no-TLS warning in shared mode.
- Accepts one to eight job workers and an optional exact Python minor version.
- Automatically uses `config\config.local.ai.json` when it exists, or accepts
  an explicit provider-configuration path.
- Delegates startup to the Python CLI through the shared Python-discovery
  helper.

## Python source modules

| Path | Responsibilities |
|---|---|
| `src\sct_ai\__init__.py` | Marks `sct_ai` as a package, describes it as the evidence-first comparison engine, and exposes package version `0.2.0`. |
| `src\sct_ai\__main__.py` | Implements `python -m sct_ai` by calling `cli.main()` and returning its process exit code. |
| `src\sct_ai\ai_workflow.py` | Implements the optional five-stage LangChain workflow. It validates the provider/model against the server allowlist, creates Ollama/OpenAI clients, loads `skills.json`, constructs sanitized evidence-limited payloads, blinds calls 1-4 to the deterministic winner/rank order, validates input/output schemas, rejects unknown controls or evidence IDs and unsupported percentage claims, validates the independent AI preference, reconciles it with the separately calculated Python result, and allows one correction attempt for invalid model output. |
| `src\sct_ai\asgi.py` | Conventional hosted-ASGI entry point. It creates the exported `app` object from `SCT_*` environment variables by calling `web.create_app_from_env()`. |
| `src\sct_ai\cli.py` | Defines the `validate`, `compare`, and `web` subcommands. It prints package preflight JSON, starts comparisons through `service.py`, launches the web server, selects the default system root, prints progress, and maps validation, comparison, AI, and startup failures to distinct exit codes. It also supplies the installed `sct-web` entry point. |
| `src\sct_ai\errors.py` | Defines the application exception hierarchy: base `SCTComparisonError`, plus package-validation, policy-validation, AI-configuration, and AI-output errors. |
| `src\sct_ai\jobs.py` | Implements durable web-job metadata and the in-process queue. `JobStore` maintains the SQLite job table, marks unfinished jobs interrupted after restart, lists recent runs, and imports missing rows from run manifests. `ComparisonJobManager` runs comparisons in a bounded thread pool, records progress/failure, and cleans staged uploads. |
| `src\sct_ai\metrics.py` | Contains the authoritative deterministic scoring engine. It validates policies, resolves scoring modes, averages repeated trials within cases, builds breakdowns, calculates global and pairwise comparability, applies module weights and decision rules, produces rankings, and emits stable evidence records. |
| `src\sct_ai\packages.py` | Safely reads and normalizes result ZIPs. It enforces archive limits; rejects traversal, directories, links, encryption, duplicates, unexpected files, malformed schemas, invalid profiles, and result/catalogue mismatches; normalizes legacy blocking values; groups repeated rows into cases; and requires unique control IDs. |
| `src\sct_ai\reports.py` | Produces the detailed technical Markdown report, concise executive Markdown summary, and portable standalone HTML report from calculated data, optionally adding validated AI findings. Dynamic HTML text is escaped. |
| `src\sct_ai\service.py` | Orchestrates a complete run for CLI and web callers. It validates inputs, creates the output directory and manifest, loads policy, invokes metrics, writes deterministic artifacts first, optionally runs AI, regenerates reports, reports progress, and records completed status with an explicit AI-unavailable state when only the optional provider workflow fails. |
| `src\sct_ai\util.py` | Shared deterministic helpers for UTC timestamps, streaming SHA-256 hashing, stable IDs, consistently formatted JSON, duplicate-key and invalid-number rejection, and safe comparison-ID normalization. |
| `src\sct_ai\web.py` | Defines the FastAPI application and Uvicorn startup path. It discovers modules and providers, applies security headers and CSRF checks, stages uploads, validates forms, creates background jobs, exposes status/rerun routes, renders results, restricts downloads, reads deployment environment variables, and enforces explicit shared mode for non-loopback binding. |

The main runtime call path is `cli.py` or `web.py` -> `service.py` ->
`packages.py` and `metrics.py` -> `reports.py`, with `ai_workflow.py` invoked
only when AI analysis is explicitly selected.

## AI skill catalogue

`src\sct_ai\skills.json` is the single versioned runtime catalogue for the
optional AI workflow. It contains shared output schemas plus the description,
system prompt, user-prompt template, input schema, output-schema reference,
and version for each stage:

| Skill | Purpose |
|---|---|
| `profile-context` | Identifies material product and tested-policy context without claiming unsupported effects. |
| `module-analysis` | Explains module, technique, coverage, and repeated-run outcome differences. |
| `cross-control-synthesis` | Synthesizes verified trade-offs across all submitted controls. |
| `independent-assessment` | Forms a blinded advisory preference or returns `null`, with categorical confidence, rationale, strengths, concerns, coverage caveats, and deterministic evidence citations. |
| `decision-reconciliation` | Receives both decisions and explains validated agreement, disagreement, or AI inconclusiveness without changing either result. |

The stages run sequentially in that order. They are prompt-and-schema stages,
not independent agents. Calls 1-4 receive scoring context and optional decision
priorities but no ranking object or ranking evidence. Only call 5 receives the
authoritative ranking alongside the already-completed AI preference.

## HTML templates and page flow

The frontend is server-rendered. FastAPI selects a Jinja template, Jinja
escapes dynamic values by default, and the browser receives complete HTML.
There is no React/Vue application, Node.js service, or HTML build step.

### HTML request flow

```text
GET /
  -> web.py home()
  -> templates\index.html
  -> templates\base.html

POST /comparisons/validate
  -> validate and temporarily stage ZIPs
  -> templates\preflight.html replaces #preflight-result through HTMX

POST /comparisons
  -> validate inputs and queue work
  -> HTTP 303 redirect to /jobs/<job-id>
  -> templates\job.html
  -> app.js polls /api/jobs/<job-id>

Job completes
  -> browser redirects to /comparisons/<comparison-id>
  -> templates\comparison.html renders calculated JSON and artifact links
```

### Template responsibilities

| Path | Purpose |
|---|---|
| `src\sct_ai\templates\base.html` | Shared document shell. It defines UTF-8 and viewport metadata, disables HTMX history/evaluation/script injection, loads only local CSS and JavaScript, provides title/content blocks, renders the site header and footer, and displays the shared-mode security warning. Every full page extends this file. |
| `src\sct_ai\templates\index.html` | Home and new-comparison page. Its ordinary multipart form accepts user-uploaded comparison ZIPs through a cumulative, removable file queue and contains dynamically discovered module weights, editable detection/blocking weights, decision thresholds, optional decision priorities, allowlisted independent-AI selection, and comparison ID. It does not expose server-side submission files as checkboxes. The Validate button uses HTMX only to replace the preflight result region; the Run button performs a normal form submission. It also renders server validation errors and recent jobs. |
| `src\sct_ai\templates\preflight.html` | Reusable HTML fragment returned by package preflight. Success output lists control identity, cases, trials, and modules. Failure output uses an alert region. It is intentionally a fragment rather than a complete HTML document because HTMX inserts it into `index.html`. |
| `src\sct_ai\templates\job.html` | Background-job progress page. It exposes the job ID through a `data-job-id` attribute and provides stable progress, status, stage, message, and error elements for `app.js`. Failed or interrupted jobs receive a server-rendered, CSRF-protected rerun form. |
| `src\sct_ai\templates\comparison.html` | Completed-result page. It renders the Python decision, independent AI preference and confidence, validated agreement/disagreement/inconclusive state, AI-unavailable state, weighted coverage, resolved scoring, decision priorities, ranking cards, per-control metrics, per-module technique/subtest and detected/blocked result counts, comparable module scores, pairwise differences, evidence analysis, expandable JSON evidence, a print/PDF action, and allowlisted artifact-download links. It reads already-calculated data and does not calculate scores in the template. |

### HTML and browser security boundary

- `web.py` adds a restrictive Content Security Policy, denies framing, disables
  MIME sniffing, prevents referrer leakage, and marks responses `no-store`.
- Full forms contain a server-issued CSRF token that must match the strict
  same-site CSRF cookie.
- Jinja automatic escaping protects normal template substitutions. Structured
  evidence is serialized through Jinja's `tojson` filter.
- HTMX is configured for same-origin requests only, with history caching,
  script tags, and evaluated expressions disabled.
- No inline application JavaScript is used on server-rendered pages. The
  portable standalone `report.html` contains only a fixed local print-button
  listener. No remote CDN, arbitrary download name, or user-selectable
  provider endpoint is used.
- Browser validation improves feedback, but `web.py`, `packages.py`, and
  `metrics.py` repeat all security and policy validation on the server.

## Browser assets

| Path | Purpose |
|---|---|
| `src\sct_ai\static\app.css` | All repository-owned visual styling for forms, messages, tables, rankings, evidence panels, downloads, responsive layouts, and print-friendly pages. |
| `src\sct_ai\static\app.js` | Configures HTMX, validates module and scoring totals, keeps detection/blocking fields editable, switches an edited preset to Custom, updates scoring help, invokes the browser print dialog for report/PDF saving, polls the job-status API, redirects completed jobs, and displays polling or job errors. |
| `src\sct_ai\static\htmx.min.js` | Vendored and pinned HTMX 2.0.10 library used for partial package-preflight submission. It avoids a CDN dependency and supports air-gapped operation. |
| `src\sct_ai\static\HTMX-LICENSE.txt` | Zero-Clause BSD licence text accompanying the vendored HTMX file. |

## Tests

| Path | Purpose |
|---|---|
| `tests\__init__.py` and `tests\python\__init__.py` | Mark the test directories as importable Python packages. |
| `tests\Run-Tests.ps1` | Runs the dependency-free PowerShell surface checks and complete Python `unittest` suite under the selected Python minor version. |
| `tests\Test-AISystemSurface.ps1` | Checks Python rules, required files, package metadata, console/ASGI entry points, offline installation, vendored HTMX, skill entries, parent SCT integration, and PowerShell syntax. |
| `tests\python\helpers.py` | Creates valid in-memory and on-disk SCT ZIP fixtures with profiles, catalogues, results, cases, and repeated trials. |
| `tests\python\test_comparison_engine.py` | Covers ZIP safety and uniqueness, matching, repeated trials, scoring, legacy normalization, policy validation, coverage/tie decisions, input preservation, deterministic output, and artifacts. |
| `tests\python\test_ai_skills.py` | Uses fake models to verify all five skill contracts, ranking blindness for calls 1-4, independent disagreement/null behavior, reconciliation immutability, and the single correction attempt for invalid evidence. |
| `tests\python\test_runtime.py` | Confirms the supported Python range and hosted web root arguments. |
| `tests\python\test_web.py` | Covers safe binding, interrupted-job recovery, ASGI environment configuration, security headers, CSRF-backed preflight, vendored assets, and form scoring. |

## Generated files and directories

| Path | Contents and lifecycle |
|---|---|
| `.venv\` | Private interpreter environment and installed dependencies. Recreate it when changing Python minor versions; do not review it as source. |
| `.tools\` | Local Python bootstrap downloads used by repository setup. It is generated and gitignored. |
| `src\sct_ai\__pycache__\` | Python bytecode cache generated during imports and tests. It is safe to delete when Python is not running. |
| `comparisons\index.sqlite3` | Web job index. `jobs.py` can repopulate missing completed-run entries from run manifests. |
| `comparisons\.staging\` | Temporary copies of uploaded ZIPs. Preflight copies are deleted immediately; run copies are deleted when their background job finishes. |
| `comparisons\<comparison-id>\` | Persistent output for one comparison. `run-manifest.json` is the run-status source of truth. |
| `offline-bundles\` | Default output location for locally built, version-specific wheel bundles. These may be large and are not source. |

Generated directories can contain thousands of files. Collapse or exclude
them in the editor.

When adding a source module, template, or browser asset, update
`pyproject.toml` if packaging rules change and extend the relevant tests. When
changing a public workflow, update the operator README and example
configuration together.
