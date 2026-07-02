# Security Controls Testing Framework (SCT)

Run `Start-SCT.ps1` on a Windows lab VM to test how well an EDR or AV product detects and blocks attack techniques, mapped to MITRE ATT&CK.

> **Lab VMs only — never run on a production or networked machine.**

---

## Before you start

- **Isolated Windows 10/11 VM** — snapshot it before running anything
- **PowerShell 5.1+** — built-in on Windows 10/11, no extra modules needed
- **Sysmon installed** — required for fileless vector result detection; useful for everything else. Use the [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) if you don't have one already
- Clone this repo onto the VM

---

## Running a test

```powershell
# From the repo root:
.\Start-SCT.ps1

# Or pre-set the product name to skip the first prompt:
.\Start-SCT.ps1 -Control SentinelOne
```

**On first launch** you'll be asked for the product under test (e.g. `SentinelOne`, `CarbonBlack`). This tags every result row so you can compare products side-by-side later.

**Test flow:**
1. Select a module — e.g. `[4] Persistence`
2. Select a vector — e.g. `[3] Startup Folder / Advanced Logon`
3. Select a sub-technique, or `All` to run them in sequence
4. **Open your EDR/AV console and start monitoring** when the script prompts you
5. Press Enter — the test runs automatically
6. Results appear immediately after the script exits, then get logged to CSV

**Reading results:**
```
  [!]  JSEStartup    EXECUTED    ← technique ran; EDR did NOT block it  (red)
  [+]  LNKShortcut   BLOCKED     ← EDR stopped it                       (green)
```

Press `[V]` from the main menu at any time to see a summary of everything run so far, grouped by product.

All results are saved to `results/raw/technique-results.csv` (technique tests) and `results/raw/results.csv` (malware delivery tests).

---

## What's included

| # | Module | Status | What it tests |
|---|--------|--------|---------------|
| 1 | Malware Introduction | Active (6 vectors) | File delivery, removable media, internet download, fileless PS, DLL sideload |
| 2 | Exploitation | Stubs | Placeholder — not yet implemented |
| 3 | Privilege Escalation | Partial | v3.2 UAC Bypass implemented; v3.1 and v3.3 are stubs |
| 4 | Persistence | Active (3 vectors) | Registry run keys, scheduled tasks, startup folder |

---

## Malware tests (module 1)

Module 1 works differently: it delivers sample files and measures whether the product blocks delivery or execution. Samples live as ZIPs in `samples/`.

```
Start-SCT.ps1 → [1] Malware Introduction → [1] Known Malware → select a ZIP
```

**Password-protected ZIPs** (conventional AV-sharing password: `infected`) require [7-Zip](https://www.7-zip.org). If 7-Zip isn't installed, the launcher will tell you to extract it manually and use `[M]` to point at the folder. Unprotected ZIPs use built-in .NET — no tools needed.

To add a new sample pack, see [samples/README.md](samples/README.md).

---

## Adding a new vector to an existing module

This is the most common task. Here's a worked example adding a WMI persistence vector to module 4.

**Step 1 — Create the folder and write the script**

```
scenarios/04-persistence/
    v4.4-wmi-subscription/
        v4.4-wmi-subscription.ps1     ← your new script
```

The quickest way to start: copy [v4.3-startup-folder.ps1](scenarios/04-persistence/v4.3-startup-folder/v4.3-startup-folder.ps1) and adapt it. It's the most complete example in the repo.

Script conventions for `technique`-type vectors:
- Accept `-Technique` with `[ValidateSet('SubtechA','SubtechB','All')]`
- Write one marker file per sub-technique: `C:\Windows\Temp\art-v4.4-<TechniqueName>.txt` — the launcher reads these to determine EXECUTED / BLOCKED automatically
- Include a cleanup function and offer to clean up at the end

**Step 2 — Register it in `module.json`**

Open `scenarios/04-persistence/module.json` and add to the `vectors` array:

```json
{
  "id": "4.4",
  "name": "WMI Subscription Persistence",
  "description": "Permanent WMI event subscription executes payload on system events.",
  "mitre": "T1546.003",
  "script": "v4.4-wmi-subscription/v4.4-wmi-subscription.ps1",
  "type": "technique",
  "techniques": ["EventFilter", "EventConsumer", "FilterToConsumerBinding", "All"],
  "individual_techniques": ["EventFilter", "EventConsumer", "FilterToConsumerBinding"],
  "marker_file": "C:\\Windows\\Temp\\art-v4.4-{technique}.txt"
}
```

Two fields that are easy to get wrong:

- **`individual_techniques`** — same as `techniques` but **without `"All"`**. The launcher checks one marker file per entry when `All` is selected, so this must match the names your script appends to the marker filename exactly.
- **`marker_file`** — must match what your script actually writes. The `{technique}` placeholder is replaced with each technique name at runtime. If your script writes `art-v4.4-EventFilter.txt`, the template is `C:\\Windows\\Temp\\art-v4.4-{technique}.txt`.

**Step 3 — Restart `Start-SCT.ps1`**

The new vector appears in the menu automatically. No changes to the launcher or core needed.

---

## Adding a new module

1. Create a numbered folder: `scenarios/05-lateral-movement/`
2. Create `module.json` in it (copy any existing one as a starting point):

```json
{
  "id": "05",
  "display_name": "Lateral Movement",
  "description": "Tests detection of techniques used to move between hosts.",
  "mitre_tactics": ["Lateral Movement"],
  "vectors": [
    {
      "id": "5.1",
      "name": "Pass-the-Hash (SMB)",
      "description": "Authenticates to a remote host using a captured NTLM hash. MITRE T1550.002.",
      "mitre": "T1550.002",
      "script": "v5.1-pass-the-hash/v5.1-pth.ps1",
      "type": "not-implemented",
      "supports": []
    }
  ]
}
```

3. Create the script at the `"script"` path (relative to the module folder)
4. Change `"type"` from `"not-implemented"` to the appropriate type when the script is ready
5. Restart — the module appears as a numbered option automatically

---

## Reference

### Vector types

| Type | What the launcher does |
|---|---|
| `technique` | Shows sub-technique menu; calls script with `-Technique <name>`; checks marker files and logs results automatically |
| `fileless` | Like `technique` but only prompts for a server IP when the selected technique is in `remote_techniques` |
| `malware-batch` | Shows ZIPs from `samples/`, extracts the chosen one, calls script with `-SourcePath -Control` |
| `removable-media` | Prompts for a drive letter, calls script with `-DriveLetter -Control` |
| `client-server` | Prompts for server IP/port, calls script with `-ServerIP -Port -Control` |
| `simple` | Runs the script directly with no extra parameters |
| `not-implemented` | Shows a placeholder — update `type` when the script is ready |

### module.json field reference

**Module-level:**

| Field | Required | Description |
|---|---|---|
| `id` | Yes | Two-digit number, e.g. `"05"` |
| `display_name` | Yes | Shown in the main menu |
| `description` | Yes | One-line summary |
| `mitre_tactics` | Yes | Array of tactic names, e.g. `["Persistence"]` |
| `vectors` | Yes | Array of vector objects |

**Vector-level:**

| Field | Required | Description |
|---|---|---|
| `id` | Yes | e.g. `"4.4"` |
| `name` | Yes | Short display name |
| `description` | Yes | One sentence |
| `mitre` | Yes | MITRE technique ID, e.g. `"T1546.003"` |
| `script` | Yes | Path to the PS1 file, relative to the module folder |
| `type` | Yes | One of the types above |
| `techniques` | `technique` / `fileless` only | Sub-technique names passed to `-Technique`. Include `"All"` last if supported. |
| `individual_techniques` | `technique` only | Same as `techniques` minus `"All"`. One marker file is checked per entry. |
| `marker_file` | `technique` only | Marker path template. Use `{technique}` as the placeholder. |
| `remote_techniques` | `fileless` only | Subset that need a server VM — launcher only prompts for IP when one of these is selected. |
| `default_technique` | No | Default shown in the menu (informational only). |

### Repo layout

```
security-controls/
├── Start-SCT.ps1                  # Entry point — run this
├── core/
│   └── SCT-Core.ps1               # Menu, dispatch, and result-writing logic
├── samples/                       # Malware ZIPs (gitignored — never commit real samples)
│   └── README.md
├── scenarios/
│   ├── 01-malware-introduction/
│   ├── 02-exploitation/
│   ├── 03-privilege-escalation/
│   └── 04-persistence/
│       ├── module.json            # Describes vectors; launcher reads this at startup
│       ├── v4.1-registry-run-key/
│       ├── v4.2-scheduled-task/
│       └── v4.3-startup-folder/
├── results/
│   ├── raw/                       # results.csv and technique-results.csv (gitignored)
│   └── analysis/
└── scripts/
    ├── run-scenario.ps1
    └── collect-results.py         # Parses CSVs into a report (Python 3, optional)
```
