# Project Structure

This guide explains where SCT discovers configuration, where test code belongs, and where generated data is stored.

## Repository layout

```text
security-controls/
├── Start-SCT.ps1
├── core/
│   └── SCT-Core.ps1
├── docs/
├── results/
│   ├── raw/
│   └── analysis/
├── samples/
│   └── README.md
├── sanity_checks/
├── scenarios/
│   ├── 01-malware-introduction/
│   ├── 02-exploitation/
│   ├── 03-privilege-escalation/
│   └── 04-persistence/
└── scripts/
    ├── New-SCTModuleJson.ps1
    ├── collect-results.py
    └── run-scenario.ps1
```

## Where files belong

| Content | Location |
|---|---|
| Launcher changes | `Start-SCT.ps1` |
| Menu, dispatch, marker, or result logic | `core/SCT-Core.ps1` |
| Module metadata | `scenarios/<module>/module.json` |
| Vector scripts and vector-specific guidance | `scenarios/<module>/<vector>/` |
| Local malware archives | `samples/` |
| Pre-test control checks | `sanity_checks/` |
| Generated CSVs | `results/raw/` |
| Reports and analysis | `results/analysis/` |
| Architecture and operator documentation | `docs/` |
| Scaffolding and utility scripts | `scripts/` |

Real malware samples and generated results should not be committed.

## Module layout

A module is a numbered folder with a `module.json` file. Each vector script path is relative to that module folder:

```text
scenarios/04-persistence/
├── module.json
├── v4.1-registry-run-key/
│   ├── README.md
│   └── v4.1-registry-run-key.ps1
├── v4.2-scheduled-task/
└── v4.3-startup-folder/
```

SCT scans these metadata files at startup; no central list needs to be updated.

## Adding a vector

1. Create a descriptive folder inside the target module.
2. Add the vector's PowerShell script and, when setup is non-trivial, a local `README.md`.
3. Add a vector object to the module's `vectors` array.
4. Confirm `script` is relative to the module folder and `type` matches the script's parameters.
5. Restart `Start-SCT.ps1` and verify that the vector appears.

Minimal metadata example:

```json
{
  "id": "4.4",
  "name": "WMI Subscription Persistence",
  "description": "Tests permanent WMI event subscription persistence.",
  "mitre": "T1546.003",
  "script": "v4.4-wmi-subscription/v4.4-wmi-subscription.ps1",
  "type": "technique",
  "techniques": ["EventFilter", "EventConsumer", "All"],
  "individual_techniques": ["EventFilter", "EventConsumer"],
  "marker_file": "C:\\Windows\\Temp\\art-v4.4-{technique}.txt"
}
```

For a `technique` vector:

- Accept `-Technique` and validate every value declared in `techniques`.
- Write one marker per completed sub-technique.
- Keep `individual_techniques` identical to independently evaluated techniques and exclude `All`.
- Ensure `marker_file` exactly matches the script's filenames.
- Implement cleanup for created files, registry values, tasks, or other persistence.

See [Framework Design](framework-design.md#module-metadata) for all metadata fields and vector contracts.

## Adding a module

Run the interactive scaffolder from the repository root:

```powershell
.\scripts\New-SCTModuleJson.ps1
```

Use `-NoWrite` to preview generated metadata. After generation:

1. Place each vector script at its declared `script` path.
2. Leave unfinished vectors as `"type": "not-implemented"`.
3. Restart the launcher; the numbered module appears automatically.

## Adding samples

Put malware archives in `samples/` only for Vector 1.1. Vector 1.2 reads removable media, Vector 1.3 uses the companion server's directory, and the remaining Module 1 vectors are self-contained or in-memory.

See the [Sample Guide](../samples/README.md) for supported ZIP layouts and handling precautions.
