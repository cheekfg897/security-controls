# samples/ — Malware ZIP Archive Store

This folder holds ZIP archives used by sample-delivery techniques, primarily Technique 1.1 Disk Drop.

The launcher (`Start-SCT.ps1`) reads this folder, lists the available ZIPs,
and stages the selected archive under `C:\Temp\SCT-Staging\combined-*\` before
running the test.

---

## Why ZIPs?

Real malware samples should **never** sit uncompressed on disk outside a VM.  
Keeping them zipped:

- Prevents accidental execution
- Reduces AV/EDR false-positives that would kill the samples before you test them intentionally
- Makes it obvious that a file is a deliberate test artifact, not an infection

---

## What to put here

Each ZIP is treated as one malware bundle. It may contain its original
subdirectories, supporting DLLs, configuration, resources, and source
material; no hand-written manifest is needed. Before extraction, the launcher
generates an internal inventory in `.sct-bundles.json`, then records which
members remain available afterward. `v1.1-known-malware.ps1` reports recognized
payload files (`.exe .dll .com .bat .cmd .ps1 .vbs .js .hta .jar .py`) even
when a control removes one during extraction, while preserving every available
supporting file in place.

By default the launcher only **copies** each complete bundle to
`C:\Temp\SCT-Bundles\` and does not run it. If execution is enabled, a bundle
opens a file picker rooted at its extracted directory on every run. The
operator browses the nested folders and explicitly selects one or more files
to launch; nothing is selected automatically. Cancelling makes that bundle
delivery-only. DLLs are delivery-only.

---

## ZIP structures

All formats below are supported. Use whichever matches how your samples arrive.

### Option A — All samples in one ZIP

```
my-samples.zip
├── eicar.com
├── mimikatz.exe
└── sample.exe
```

Select the ZIP by number in the launcher.

### Option B — One sample per ZIP

```
samples/
├── eicar.zip           ← contains only eicar.com
├── mimikatz.zip        ← contains only mimikatz.exe
└── custom.zip          ← contains only custom.exe
```

Select **`[A] Combine and run ALL ZIPs as one batch`** in the launcher — it
extracts every ZIP into its own bundle directory. Identical filenames in
different archives do not collide because bundles are never flattened.

### Option C — A ZIP containing malware ZIPs

```text
container.zip
├── eicar.zip
├── mimikatz.zip
└── custom.zip
```

Select `container.zip` by number. After extracting it, the launcher detects
the inner ZIPs and asks whether to extract them and include their samples.
Each inner ZIP becomes a separate bundle with its directory tree intact.
Nested ZIPs are supported to a maximum depth of three, with a safety limit of
100 processed archives per batch. The nested archives must share one password;
press Enter at the nested-password prompt to reuse the outer ZIP password.

---

## Adding a new sample set

**Option A (batch, one ZIP):**
1. Prepare your samples on a separate, isolated machine
2. ZIP them together as-is
3. Copy the ZIP into this `samples/` folder
4. Run `Start-SCT.ps1`, choose **Malware Delivery -> Technique 1.1**, and select the ZIP by number

**Option B (one sample per ZIP):**
1. Create one ZIP per sample
2. Copy all ZIPs into this `samples/` folder
3. Run `Start-SCT.ps1`, choose **Malware Delivery -> Technique 1.1**, and select **`[A] Combine and run ALL ZIPs`**

**Option C (one outer ZIP containing sample ZIPs):**
1. Put the individual sample ZIPs into one outer ZIP
2. Copy the outer ZIP into this `samples/` folder
3. Select the outer ZIP and answer **Y** when the launcher reports nested ZIPs

---

## Security notes

- This folder is `.gitignore`d to prevent accidental commits of real malware
- Only copy ZIPs into a running, isolated lab VM
- Never extract on a production machine or networked host
- The launcher asks **"Execute samples after delivery?"** before running; if enabled, every extracted bundle requires explicit file-picker selection
- After testing, extracted files remain under `C:\Temp\SCT-Staging\combined-*\` — delete the batch folder when review is complete
