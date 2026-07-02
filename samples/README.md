# samples/ — Malware ZIP Archive Store

This folder holds the ZIP archives used by **malware-batch** vectors (v1.1 Disk Drop, v1.2 Removable Media).

The launcher (`Start-SCT.ps1`) reads this folder, lists the available ZIPs, and extracts your chosen archive to `C:\Temp\SCT-Staging\<zip-name>\` before running the test.

---

## Why ZIPs?

Real malware samples should **never** sit uncompressed on disk outside a VM.  
Keeping them zipped:

- Prevents accidental execution
- Reduces AV/EDR false-positives that would kill the samples before you test them intentionally
- Makes it obvious that a file is a deliberate test artifact, not an infection

---

## What to put here

Each ZIP should contain a flat folder of sample executables **and** a `manifest.csv` that describes them.

### manifest.csv schema

| Column | Required | Description |
|---|---|---|
| `sample_id` | Yes | Unique ID (e.g. `S1`). Used as subfolder name under `C:\Temp\`. |
| `name` | Yes | Human-readable name shown in console output. |
| `sha256` | Yes | Expected SHA-256 of the file, verified after delivery. |
| `stage_applicable` | Yes | `write_only` (delivery test only) or `write_execution` (deliver + execute). |
| `exe` | Yes | Filename of the sample inside the ZIP. |
| `classification` | No | `benign`, `dual_use`, or `malware`. Defaults to `unspecified`. |

### Example manifest.csv

```csv
sample_id,name,sha256,stage_applicable,exe,classification
S1,EICAR,275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0,write_only,eicar.com,benign
S2,Mimikatz,<sha256_here>,write_execution,mimikatz.exe,dual_use
S3,MyMalwareSample,<sha256_here>,write_execution,sample.exe,malware
```

### Auto-generating a manifest

Use the helper script to compute SHA-256 hashes and generate a starter manifest from a folder of files:

```powershell
.\scenarios\01-malware-introduction\New-Manifest.ps1 -FolderPath C:\MySamples -OutputPath .\my-manifest.csv
```

Review and adjust `classification` and `stage_applicable` values before running.

---

## ZIP structure

```
my-samples.zip
├── manifest.csv
├── eicar.com
├── mimikatz.exe
└── sample.exe
```

The `manifest.csv` must be at the **root** of the ZIP (same level as the exe files).

---

## Adding a new sample set

1. Prepare your samples on a separate, isolated machine
2. Create a `manifest.csv` (use `New-Manifest.ps1` to auto-generate it)
3. ZIP everything together: `manifest.csv` + all referenced exe files
4. Copy the ZIP into this `samples/` folder
5. Run `Start-SCT.ps1`, choose **Malware Introduction → Vector 1.1**, and select your ZIP

---

## Security notes

- This folder is `.gitignore`d to prevent accidental commits of real malware
- Only copy ZIPs into a running, isolated lab VM
- Never extract on a production machine or networked host
- After testing, extracted files remain at `C:\Temp\SCT-Staging\<name>\` — delete them when review is complete
