# AI-assisted control comparison

This folder is the self-contained SCT comparison and AI subsystem. It
accepts two or more validated ZIPs from `submissions/`, calculates reproducible
metrics, and can ask an allowlisted hosted or local model to explain those
metrics. The model never calculates or changes the official score.

## Workflow

```text
validated product ZIPs
        |
        v
safe package validation and normalization
        |
        v
deterministic coverage, metrics, pairwise deltas, and ranking
        |
        +---------------------> metrics-only reports
        |
        v
versioned LangChain runtime skills
        |
        v
validated evidence citations and qualified narrative
```

Authoritative workspaces under `results/` and source ZIPs under `submissions/`
are read-only inputs. Each generated run is written under
`ai-system/comparisons/<comparison-id>/`. Run every command below from the
repository root.

## Install

The comparison application targets Python 3.11 x64. On a connected development
machine:

```powershell
py -3.11 -m venv .\ai-system\.venv
.\ai-system\.venv\Scripts\python.exe -m pip install -r .\ai-system\requirements\all.txt
```

Generated virtual environments are gitignored. For an air-gapped installation,
use the [offline transfer workflow](#air-gapped-transfer) instead.

## Prepare local configuration

Copy and edit the examples. Both local files are gitignored:

```powershell
Copy-Item .\ai-system\config\comparison-policy.example.json `
    .\ai-system\config\config.local.comparison.json
Copy-Item .\ai-system\config\ai-providers.example.json `
    .\ai-system\config\config.local.ai.json
```

The comparison policy must contain exactly the modules represented by the
selected ZIPs, and its weights must total 100. For example:

```json
{
  "schema_version": "1.0",
  "module_weights": {
    "01": 40,
    "02": 20,
    "03": 20,
    "04": 20
  },
  "minimum_comparable_weight": 80,
  "tie_margin": 2
}
```

An AI provider entry allowlists its models and names the environment variable
that contains its key. It never contains the secret value. Ollama requires no
key. Browser users can select only server-allowlisted provider/model pairs and
cannot supply an arbitrary model URL.

## Start the web application

Local mode is the default and binds only to loopback:

```powershell
.\ai-system\scripts\Start-SCTComparisonWeb.ps1
```

Open `http://127.0.0.1:8000`. The page can select existing ZIPs, upload
additional packages, preflight them, set module weights, choose metrics-only or
AI analysis, show job progress, and reopen completed runs.

Shared proof-of-concept mode must be explicit:

```powershell
.\ai-system\scripts\Start-SCTComparisonWeb.ps1 `
    -Shared `
    -ListenAddress 0.0.0.0 `
    -Port 8000
```

Shared mode has no authentication or built-in TLS. Use it only on a trusted,
isolated lab network. A production deployment needs a separate authentication,
authorization, TLS, and operational-security design.

## Run from PowerShell

Metrics and ranking only:

```powershell
.\ai-system\scripts\Compare-SCTControls.ps1 `
    -PackagePath .\submissions\control-a.zip,.\submissions\control-b.zip `
    -PolicyPath .\ai-system\config\config.local.comparison.json
```

Local Ollama analysis:

```powershell
.\ai-system\scripts\Compare-SCTControls.ps1 `
    -PackagePath .\submissions\control-a.zip,.\submissions\control-b.zip `
    -PolicyPath .\ai-system\config\config.local.comparison.json `
    -Provider local-ollama `
    -Model <allowlisted-model-name> `
    -ProviderConfigPath .\ai-system\config\config.local.ai.json
```

The direct Python interface is:

```text
python -m sct_ai compare --package <zip> --package <zip> \
  --policy <json> --provider <provider-alias> --model <model> \
  --provider-config <json>
```

Use `--provider none` or omit all AI options for a network-free metrics-only
run.

## How matching and scoring work

A comparison case is identified by module, technique, subtest, test stage,
delivery method, and sample hash or opaque input identity. Display names and
free-text notes are not matching keys.

Repeated executions remain separate trials inside one case. SCT first averages
trials within that case, then averages cases within the module. This prevents a
frequently repeated case from silently dominating the module.

The prevention-first score is:

```text
case score = (detection effectiveness * 40%)
           + (action effectiveness * 60%)
```

Action credit is 100% for a block before execution, 50% for a block after
execution, and 0% for no block. Module scores are combined with the explicit
operator weights.

The headline ranking uses only cases shared by every submitted control.
Product-only cases still contribute to coverage and gap reporting. If the
shared modules represent less than the configured minimum weight, scores are
provisional and no product is recommended. Scores within the configured tie
margin also produce no clear winner.

## Runtime skills and evidence

The model workflow is stored under `ai-system/src/sct_ai/skills/`:

- `profile-context`
- `module-analysis`
- `cross-control-synthesis`
- `qualified-recommendation`

Each skill has a versioned manifest, system and user prompts, and input/output
schemas. Outputs must cite evidence IDs from `comparison.json`. Unknown
evidence, unsupported percentages, invalid fields, or a recommendation that
differs from the deterministic decision are rejected. The model receives one
correction attempt before the AI stage fails.

Remote-provider payloads omit raw CSV rows, reviewer notes, source results,
sample names, local-log paths, exclusion values, and detailed settings by
default. A provider may explicitly enable policy-setting details in the local
server configuration.

## Generated artifacts

```text
ai-system/comparisons/<comparison-id>/
|-- comparison.json
|-- ai-analysis.json
|-- technical-report.md
|-- executive-summary.md
|-- report.html
`-- run-manifest.json
```

`comparison.json` is the authoritative calculated output.
`ai-analysis.json` exists only when every AI skill succeeds. If AI fails, the
metrics and deterministic reports remain available and the manifest records
the failure.

The web job index is `ai-system/comparisons/index.sqlite3`. Run manifests remain the
source of truth and are re-imported when the application starts.

## Air-gapped transfer

On an approved connected Windows staging machine with Python 3.11:

```powershell
.\ai-system\scripts\Build-SCTOfflineBundle.ps1 `
    -OutputPath D:\Transfer\sct-comparison-python311 `
    -ModelPath D:\ApprovedModels\model.gguf
```

The command downloads binary wheels for the pinned top-level dependency set
and writes `bundle-manifest.json` containing the exact size and SHA-256 of
every transferred file.

Inside the air gap, verify and install without consulting a package index:

```powershell
.\ai-system\scripts\Install-SCTOfflineBundle.ps1 `
    -BundlePath D:\Transfer\sct-comparison-python311
```

Import an approved GGUF or supported Safetensors model:

```powershell
.\ai-system\scripts\Import-SCTOllamaModel.ps1 `
    -ModelPath D:\Transfer\sct-comparison-python311\models\model.gguf `
    -ModelName sct-approved
```

The import script creates a temporary Ollama `Modelfile`, verifies that Ollama
can show the imported model, and removes the temporary file.

## Security boundary

- ZIP paths, duplicate entries, unexpected files, encrypted entries, excessive
  sizes, schemas, catalogue joins, and result values are validated before use.
- Uploads are given generated staging names and removed after their job.
- Web forms use a same-site double-submit CSRF token.
- Pages use automatic HTML escaping, self-only browser requests, no CDN, and a
  restrictive Content Security Policy.
- API keys are read only from server environment variables.
- Generated comparisons are gitignored because they may contain sensitive
  evaluation context.
