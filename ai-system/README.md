# SCT comparison web application

This folder contains the Security Control Testing (SCT) comparison engine,
web application, optional independent AI assessment workflow, and offline-installation
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

To perform a comparison, you also need at least two valid SCT result ZIPs. The
web application accepts them through its upload control; the command-line
interface accepts explicit local package paths.

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

At startup, the application loads `.env` from the repository root when the
file exists. It also discovers `ai-system\config\config.local.ai.json`
automatically. Both files are ignored by Git.

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

### Step 1: Upload result packages

Upload at least two comparison ZIPs from your own files.

The upload control keeps a numbered list beneath the file picker. You can add
ZIPs one at a time or select several together; later selections are appended
to the list. Review filenames and sizes there, remove individual files, or
clear the upload list before validating.

Use only comparison packages produced by
`framework\scripts\review\Build-SCTComparisonPackage.ps1`. A valid package is
named `<control-id>.zip` under `framework\submissions\` and contains a
root-level `control-profile.json` plus matching result/catalogue pairs for the
tested modules. Do not upload a ZIP made directly from `framework\results`;
product-specific profile names, nested workspace folders, and catalogues
without matching results are rejected.

Requirements:

- At least two and no more than twenty ZIPs.
- Each ZIP must be no larger than 100 MB.
- Every package must have a unique control ID.
- Every result module must have a matching test catalogue.
- Unsafe paths, duplicate entries, encrypted entries, unexpected files, and
  unsafe compression ratios are rejected.

Use **Validate packages** before running a comparison. The preflight result
shows each control ID, case count, trial count, submitted module IDs, and the
declared policy mode, and warns when the selection mixes detect-only and
blocking policies.

Uploads are copied to a generated staging directory and removed when the job
finishes. The web page does not expose server-side files from
`framework\submissions\`; those packages remain available to command-line
workflows through explicit paths.

### Step 2: Set module weights

The module display is not fixed to four entries. The page discovers every
valid `framework\scenarios\*\module.json` file and creates one numeric field for each
module. The current repository has:

- Module 01: Malware Delivery
- Module 02: Exploitation
- Module 03: Privilege Escalation
- Module 04: Persistence

If two more module definitions are added, the page displays six module cards
automatically. Initial weights are divided equally across all discovered
modules, with the final value adjusted for rounding so the total remains
exactly 100%. For six modules, that is 16.667% for the first five modules and
16.665% for the last one.

Module weights describe business importance. A module with a 40% weight has
twice the ranking influence of a module with a 20% weight.

The modules contained in the selected ZIPs must have positive weights totaling
100%. In the web form, set modules not present in the selected packages to 0%
so that the on-page total reaches 100%; the server ignores those fields and
validates only the modules that the packages actually contain. This 0% rule
applies to the web form only — a command-line policy file must instead omit
absent modules entirely, because the policy validator rejects any module
weight of 0 (see [Command-line use](#command-line-use)).

Examples:

```text
Equal importance:       25 / 25 / 25 / 25
Delivery emphasized:   40 / 20 / 20 / 20
Modules 01 and 02 only: 60 / 40 /  0 /  0
```

Module weighting occurs after cases have been matched and averaged. It cannot
make a product-only case comparable.

### Step 3: Choose detection and blocking scoring

The detection and blocking percentage fields are editable in every mode.
Selecting a preset fills its standard values; changing either percentage
automatically changes the mode to **Custom** so the server uses the edited
values. Each value may be from 0% to 100%, but together they must total 100%.

The GUI provides four starting modes.

#### Automatic

This is the recommended default when every submission shares one policy mode.

- If every submitted control profile has `default_mode: detect_only`, scoring
  resolves to 100% detection and 0% blocking.
- If every submitted control can block (`detect_and_block` or `custom`),
  scoring resolves to prevention-first: 40% detection and 60% blocking.
- If the submissions mix detect-only with blocking policies, Automatic
  refuses to choose and the comparison stops with a validation error. A
  detect-only control never earns blocking credit under prevention-first
  scoring, so its maximum possible score would be 40 out of 100; that
  trade-off must be chosen deliberately. Select **Detection only**,
  **Prevention first**, or **Custom** instead.

**Validate packages** shows each package's declared policy mode and flags a
mixed selection before the comparison runs. The page then disables Automatic
until an explicit mode is selected.

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

Module 01 uses one `test_stage=write` row for each payload attempt, with its
outcome stored in `execution_status`. A package that repeats the same logical
payload and run as separate write and execution rows is rejected.

### Step 4: Set decision thresholds

**Minimum comparable weight** defaults to 80%.

The ranking uses only cases shared by every submitted control. If the modules
containing shared cases represent less than this threshold, the result is
provisional and the engine does not recommend a product.

Two behaviors matter when coverage is incomplete:

- A module with no shared cases is excluded from the ranking, and the
  remaining module weights are scaled up proportionally. The effective
  weighted comparable coverage appears in the reports.
- A module counts its full weight toward comparable coverage when at least
  one of its cases is shared, even if most of its cases are not. The
  threshold therefore measures module-level coverage, not the share of
  individual cases that are comparable.

**Tie margin** defaults to 2 points.

When the top two scores are within this margin, the result is reported as
`no_clear_winner`.

### Step 5: Describe decision priorities

Optionally state the evaluation priorities that the independent AI assessment
should consider, such as prevention, detection visibility, broad module
coverage, or stable repeated-run outcomes. This text is limited to 2,000
characters. It is stored with the comparison policy but does not change
Python's weights, scores, thresholds, ranking, or recommendation.

Do not paste secrets, raw logs, reviewer notes, or sensitive sample data into
this field.

### Step 6: Optionally enable independent AI assessment

Metrics-only mode is always available and does not contact an AI provider.

When AI is configured:

1. Select **Run independent AI evidence review**.
2. Select an allowlisted provider and model.
3. Run the comparison normally.

The deterministic comparison is completed and saved before any model request.
If AI configuration or output validation fails, the job still completes with
the deterministic result and reports. The AI section is marked unavailable
and records the provider error separately.

### Step 7: Validate and run

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
blinded independent AI assessment and decision reconciliation
```

When complete, the browser displays:

- The resolved scoring mode and weights.
- Comparable coverage.
- The verified ranking or no-winner reason.
- Per-control and per-module metrics.
- A per-control, per-module breakdown of represented techniques and subtests,
  recorded result runs, detected results, and blocked results.
- Pairwise score differences.
- Optional independent AI preference, confidence, and findings.
- An `AGREES`, `DISAGREES`, or `AI INCONCLUSIVE` comparison between the
  Python recommendation and AI preference.
- Expandable evidence records.
- Downloadable output files.
- A **Print / Save as PDF** action that prints the complete current report,
  including deterministic metrics and optional AI findings.

## Choose and configure an AI model

AI is optional. Leave **Run independent AI evidence review** unchecked when deterministic
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

Create the ignored repository-root environment file once:

```powershell
Copy-Item .\.env.example .\.env
```

Open `.env` and set the key issued for the approved API project:

```dotenv
OPENAI_API_KEY=replace-with-the-api-key
```

The application loads this file automatically from the repository root.
An environment variable already set by Windows or PowerShell takes precedence
over the value in `.env`.

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

Then set the matching value in the repository-root `.env` file:

```dotenv
SCT_AI_API_KEY=replace-with-the-compatible-api-key
```

Users cannot submit an arbitrary model URL through the browser.

### 4. Protect the API key

- Put only the environment-variable name in `config.local.ai.json`, never the
  secret value. Store the local secret in the ignored repository-root `.env`.
- Do not commit keys, paste them into comparison policies, or include them in
  command history or screenshots.
- Use a key scoped to the approved project and provider permissions.
- `.env` and `.env.*` are ignored by Git; `.env.example` contains no secret and
  remains tracked as the setup template.
- A process-level environment variable overrides `.env`, which allows managed
  deployments to inject credentials without a local secret file.

### 5. Start and verify

Start the application from the repository root:

```powershell
.\ai-system\.venv\Scripts\python.exe -m sct_ai web
```

Open `http://127.0.0.1:8000`, enable **Run independent AI evidence review**, and confirm
the expected provider/model pair appears in the dropdown. This confirms that
the provider configuration and model allowlist were loaded. Running an
AI-enabled comparison also verifies the API credential from `.env` or the
process environment. Restart the server after changing either file.

## What the AI workflow does

The AI component is an optional explanation layer over the deterministic
comparison. Python finishes and saves `comparison.json`, including every
metric, evidence record, rank, and recommendation decision, before the first
model call. The model may reach a different advisory preference, but it cannot
change the deterministic result.

One selected model client then makes five sequential calls. These are
versioned prompt-and-schema stages, not autonomous agents, and they do not use
tools or modify repository data.

```text
                         deterministic comparison.json
                           /                    \
                          v                      v
             1. profile-context        2. module-analysis
                policy/product            modules/cases
                interpretation             interpretation
                          \                      /
                           validated outputs only
                                    |
                                    v
                       3. cross-control-synthesis
                          correlates calls 1 and 2
                                    |
                         blinded context and outputs 1, 2, 3
                                    |
                                    v
                       4. independent-assessment
                          advisory preference; still blind
                                    |
                 Python ranking + independent AI assessment
                                    |
                                    v
                       5. decision-reconciliation
                          explains agreement/disagreement
                                    |
                                    v
                              ai-analysis.json
```

Calls 1 and 2 run in sequence but are analytically independent: call 2 does
not receive call 1's prose. Call 3 is the first stage that receives and
correlates both earlier validated outputs. Calls 1 through 4 do not receive
Python's winner, rank ordering, or `ranking` evidence, which reduces anchoring.
Call 4 forms an independent advisory preference from the sanitized context,
metrics, decision priorities, and validated earlier analysis. Call 5 is the
only stage that receives both the authoritative Python ranking and the blinded
AI assessment.

### What each call receives and produces

| Call | Question it answers | Deterministic input sent to the model | Output and downstream use |
|---|---|---|---|
| `profile-context` | What product and tested-policy differences matter when interpreting the results? | Control identity and product/version metadata, tested policy context, calculated control metrics, scoring configuration, decision priorities, and only `profile_summary` and `control_metrics` evidence records. | Produces contextual findings. It cannot calculate scores, rank controls, claim unsupported causation, or recommend a product. Its validated output is supplied to calls 3, 4, and 5. |
| `module-analysis` | Where do module, technique, coverage, case-outcome, or repeated-run differences appear? | Control context and metrics, global coverage, case catalogue, scoring configuration, decision priorities, and only `module_metrics` and `case_outcome` evidence records. | Produces module/outcome findings. It cannot recalculate percentages, alter scores, rank, or recommend. Its validated output is supplied to calls 3, 4, and 5. |
| `cross-control-synthesis` | What decision-relevant trade-offs emerge when the profile context and outcome analysis are considered together? | Control context, coverage, pairwise comparisons, scoring configuration, decision priorities, non-ranking deterministic evidence, plus validated outputs from calls 1 and 2. | Produces a synthesis across every submitted control while preserving coverage and policy caveats. It still cannot recommend a product. Its validated output is supplied to calls 4 and 5. |
| `independent-assessment` | Which control, if any, is the AI's advisory preference under the stated priorities and context? | The same blinded context as call 3, plus validated outputs from calls 1 through 3. It does not receive Python's winner, rank order, or ranking evidence. | Produces a known control ID or `null`, categorical confidence, rationale, strengths, concerns, coverage caveats, and evidence IDs. It may disagree with Python or remain inconclusive. |
| `decision-reconciliation` | Why do Python and the independent AI agree, disagree, or produce an inconclusive AI result? | Both decisions, the authoritative full ranking, control context, coverage, pairwise comparisons, decision priorities, full deterministic evidence, and validated outputs from calls 1 through 3. | Produces the report's `AGREES`, `DISAGREES`, or `AI INCONCLUSIVE` explanation. Validation prevents it from changing either decision. |

"Control context" contains each control's identity, submitted product profile,
tested policy, and deterministic metrics. Detailed policy settings are removed
unless the selected server-side provider configuration explicitly sets
`include_policy_details` to `true`.

### How the prompt is assembled

Every call sends exactly two initial chat messages:

1. A system message copied from that skill's `system_prompt`.
2. A user message copied from that skill's `user_prompt`, with
   `{{payload}}` replaced by the JSON input described above.

The five user-message instructions are:

| Call | User instruction surrounding the JSON payload |
|---|---|
| `profile-context` | "Analyze the tested control profiles and policy context in this evidence payload. Separate facts from interpretation and cite every finding." |
| `module-analysis` | "Analyze meaningful module and technique differences, missing coverage, and repeated-run instability. Cite the exact evidence behind each finding." |
| `cross-control-synthesis` | "Synthesize the most decision-relevant tradeoffs across all controls. Preserve coverage and policy caveats, and cite every finding." |
| `independent-assessment` | "Make an independent advisory assessment using the stated decision priorities and supplied evidence. You have not been given the deterministic winner or rank order. Select a control only when the contextual evidence supports it; otherwise return null." |
| `decision-reconciliation` | "Reconcile the deterministic Python result with the blinded independent AI assessment. Preserve both decisions exactly and explain the most important evidence-backed reason for agreement, disagreement, or AI inconclusiveness." |

The full, exact system prompts, user-prompt templates, versions, and JSON
schemas are the runtime source of truth in
[`src/sct_ai/skills.json`](src/sct_ai/skills.json). Prompt assembly and payload
selection are implemented in
[`src/sct_ai/ai_workflow.py`](src/sct_ai/ai_workflow.py).

### Output contract

Calls 1 through 3 must return one JSON object in this shape:

```json
{
  "summary": "Evidence-bounded summary",
  "findings": [
    {
      "title": "Short finding title",
      "analysis": "Explanation supported by the cited records",
      "severity": "strength",
      "controls": ["known-control-id"],
      "evidence_ids": ["EVIDENCE-..."]
    }
  ],
  "recommendation": null
}
```

`severity` must be `strength`, `concern`, `context`, or `gap`. Call 4 returns
the independent advisory assessment:

```json
{
  "preferred_control_id": "known-control-id",
  "confidence": "medium",
  "rationale": "Evidence-bounded advisory explanation",
  "strengths": ["Relevant strength"],
  "concerns": ["Relevant concern"],
  "coverage_caveats": ["Relevant coverage limitation"],
  "evidence_ids": ["EVIDENCE-..."]
}
```

`preferred_control_id` may be `null`, even when Python selected a winner. It
may also contain a known control when Python returned `null` for a tie,
provisional result, or insufficient evidence. This is permitted because the
AI result is explicitly advisory rather than an override.

Call 5 returns the exact comparison of the two decisions:

```json
{
  "status": "disagrees",
  "python_recommended_control_id": null,
  "ai_preferred_control_id": "known-control-id",
  "summary": "Evidence-bounded explanation of the disagreement",
  "evidence_ids": ["EVIDENCE-..."]
}
```

The application calculates the expected status before validating the model:

- `AI INCONCLUSIVE` when the independent AI preference is `null`.
- `AGREES` when both non-null control IDs match.
- `DISAGREES` for every other non-null AI preference.

The stored `ai-analysis.json` wraps all five outputs with the provider/model
identity, generation time, skill name, and skill version. The website and
generated human-readable reports incorporate the validated outputs appropriate
to each view.

### How the stages correlate without changing the result

For example, call 1 may identify that two controls were tested under different
policy modes. Independently, call 2 may identify a module-level detection or
blocking difference and a coverage gap. Call 3 can then describe those facts
as a decision trade-off, but it cannot state that the policy difference caused
the outcome unless the cited deterministic evidence supports that statement.
Call 4 may independently prefer one control, prefer a different control from
Python, or return `null`. Call 5 then explains the relationship between the two
decisions without changing either one.

The chain therefore carries interpretation forward while retaining the
original evidence references:

```text
deterministic evidence IDs
  -> contextual/module findings citing those IDs
  -> synthesis citing deterministic IDs
  -> blinded independent AI preference citing deterministic IDs
  -> reconciliation with the separately calculated Python result
```

Earlier AI text is context for later stages, but it never becomes a new
authoritative metric. Every finding and recommendation must still cite an
evidence ID that exists in the deterministic payload.

### Validation and correction

Before an output can reach the next stage or a report, the application checks
that it:

- Matches the skill's JSON schema and contains no extra fields.
- References only submitted control IDs.
- References only evidence IDs included in that call's payload.
- Uses only supported percentages found in the cited evidence.
- Returns `recommendation: null` for calls 1 through 3.
- Returns only a known control ID or `null` from the blinded call 4.
- Uses only `low`, `medium`, or `high` confidence in call 4.
- Preserves both decision IDs and the calculated agreement status in call 5.

If the first response fails validation, that skill receives the invalid
response plus one correction message describing the validation error. The
model is told to return corrected JSON without adding new claims or evidence
identifiers. If the correction also fails, the AI assessment is marked
unavailable; the job still completes and the already saved deterministic
metrics and reports remain available. A normal run makes five model calls,
while validation corrections can add at most one additional call per stage.

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
ai-analysis.json      optional validated AI output or explicit unavailable state
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
  "scoring_mode": "auto",
  "decision_priorities": "Prioritize prevention, broad coverage, and stable repeated-run outcomes."
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

`module_weights` must list exactly the modules present in the submitted
packages: every listed module needs a positive weight, and absent modules must
be omitted entirely rather than set to 0. The policy is rejected when it names
a module the packages do not contain or gives any module a weight of 0. The
example above assumes both packages contain modules 01 through 04.
`decision_priorities` is optional, limited to 2,000 characters, and influences
only the blinded advisory AI assessment—not deterministic scoring.

Run metrics and ranking:

```powershell
.\ai-system\.venv\Scripts\python.exe -m sct_ai compare `
    --package .\framework\submissions\control-a.zip `
    --package .\framework\submissions\control-b.zip `
    --policy .\ai-system\config\config.local.comparison.json
```

Add local AI analysis:

```powershell
.\ai-system\.venv\Scripts\python.exe -m sct_ai compare `
    --package .\framework\submissions\control-a.zip `
    --package .\framework\submissions\control-b.zip `
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
| `SCT_REPOSITORY_ROOT` | Framework directory containing `scenarios/` and `submissions/` |
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

### An AI run says the API key variable is not set

- Confirm the repository-root `.env` file exists, not only `.env.example`.
- Confirm it contains a non-empty value such as `OPENAI_API_KEY=...`.
- Confirm `api_key_env` in `config.local.ai.json` names that same variable.
- Remove an empty process-level variable because it takes precedence over
  `.env`; in PowerShell, use `Remove-Item Env:OPENAI_API_KEY`.
- Restart the web application after changing `.env`.

### Module weights are rejected

- Use **Validate packages** to see which modules are present.
- Give every present module a positive value.
- In the web form, set absent modules to 0 so the page total reaches 100.
- In a command-line policy file, omit absent modules entirely; a listed
  weight of 0 is rejected.
- Confirm the present-module values total exactly 100.

### Custom scoring is rejected

Detection and blocking weights must each be between 0 and 100 and together
must total exactly 100.

### Automatic scoring is rejected

The submitted packages mix `detect_only` with blocking policy modes, so
Automatic cannot choose a fair detection/blocking split. Use
**Validate packages** to see each package's declared mode, then select
Detection only, Prevention first, or Custom explicitly. The same rule applies
to `"scoring_mode": "auto"` in a command-line policy file.

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

- Source ZIPs under `framework\submissions\` and workspaces under `framework\results\` are treated
  as read-only.
- Uploads receive generated staging names and are deleted after their job.
- Web forms use same-site double-submit CSRF protection.
- Pages use automatic HTML escaping and a restrictive Content Security Policy.
- Browser code makes self-origin requests only and uses no CDN.
- API keys are read from server environment variables. For local source
  checkouts, the ignored repository-root `.env` populates variables that the
  launch environment has not already set.
- Provider names, model names, and endpoints are server-allowlisted.
- Calls 1-4 receive sanitized structured evidence without Python's winner or
  rank order. The AI may give a separate advisory preference but cannot change
  the deterministic ranking.
