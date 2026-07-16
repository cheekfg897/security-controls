# Project Structure

This guide explains where SCT configuration and technique code belong.

## Repository layout

```text
security-controls/
|-- Start-SCT.ps1
|-- core/
|   `-- SCT-Core.ps1
|-- docs/
|-- results/
|   |-- raw/
|   `-- analysis/
|-- samples/
|-- sanity_checks/
|-- scenarios/
|   |-- 01-malware-introduction/
|   |-- 02-exploitation/
|   |-- 03-privilege-escalation/
|   `-- 04-persistence/
`-- scripts/
    |-- New-SCTModuleJson.ps1
    `-- Test-SCTModuleJson.ps1
```

| Content | Location |
|---|---|
| Launcher parameters and startup | `Start-SCT.ps1` |
| Discovery, validation, execution, markers, and summaries | `core/SCT-Core.ps1` |
| Module metadata | `scenarios/<module>/module.json` |
| Technique scripts and local guidance | Inside the relevant module folder |
| Local malware archives | `samples/` |
| Pre-test control checks | `sanity_checks/` |
| Generated CSV files | `results/raw/` |
| Architecture and operator guidance | `docs/` |
| Manifest generation and validation | `scripts/` |

Real malware samples and generated results should not be committed.

## Module layout

A module is a numbered folder containing one `module.json`. Technique script paths are relative to that folder:

```text
scenarios/04-persistence/
|-- module.json
|-- v4.1-registry-run-key/
|   |-- README.md
|   `-- v4.1-registry-run-key.ps1
|-- v4.2-scheduled-task/
`-- v4.3-startup-folder/
```

Folder and script names can retain existing `v` prefixes; the SCT hierarchy comes from `module.json`, where these entries are techniques.

## Adding a technique

1. Add the PowerShell script and, if setup is non-trivial, a nearby `README.md`.
2. Add one object to the module's `techniques` array.
3. Run `scripts/Test-SCTModuleJson.ps1`.
4. Restart `Start-SCT.ps1` and confirm the technique appears.

Minimal entry:

```json
{
  "id": "4.4",
  "name": "WMI Subscription Persistence",
  "attack_id": "T1546.003",
  "script": "4.4-wmi-subscription/4.4-wmi-subscription.ps1"
}
```

If the technique has selectable variations, add one `subtests` array:

```json
{
  "id": "4.4",
  "name": "WMI Subscription Persistence",
  "description": "Tests permanent WMI event subscription persistence.",
  "attack_id": "T1546.003",
  "script": "4.4-wmi-subscription/4.4-wmi-subscription.ps1",
  "subtests": ["EventFilter", "EventConsumer"]
}
```

Do not list `All`; SCT adds it automatically. The script accepts `-Subtest`, validates both names plus `All`, and writes successful markers as:

```text
C:\Windows\Temp\art-v4.4-EventFilter.txt
C:\Windows\Temp\art-v4.4-EventConsumer.txt
```

If only some subtests need a server VM, list those names once more in `server_subtests`. They must also exist in `subtests`.

Use `"status": "planned"` for an unavailable technique. The script path may be reserved before the file exists; remove `status` when implementation is ready.

## Adding a module

Run the guided generator from the repository root:

```powershell
.\scripts\New-SCTModuleJson.ps1
```

Use `-NoWrite` to preview the JSON. The generator asks only for module details, technique details, optional subtests, and optional server-dependent subtests.

After adding scripts, validate everything:

```powershell
.\scripts\Test-SCTModuleJson.ps1
```

SCT discovers valid modules automatically; no central module list needs updating.

## Adding samples

Put malware archives in `samples/` only for Technique 1.1. Technique 1.2 reads removable media, Technique 1.3 uses a companion server directory, and the remaining Module 01 techniques are self-contained or in-memory.

See the [Sample Guide](../samples/README.md) for ZIP layouts and handling precautions.
