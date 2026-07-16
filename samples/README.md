# samples/ — Malware ZIP Archive Store

This folder holds ZIP archives used by sample-delivery techniques, primarily Technique 1.1 Disk Drop.

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

Each ZIP should contain a flat folder of sample executables — that's it, no
manifest or metadata file needed. `v1.1-known-malware.ps1` tests every
recognised file it finds (`.exe .dll .com .bat .cmd .ps1 .vbs .js .hta .jar
.py`).

By default the launcher only **copies** each file to `C:\Temp\` — it doesn't
run any of them. You choose whether to also execute the batch (Y/N prompt)
each time you run the technique, so a colleague picking a ZIP from the launcher
sees that choice explicitly rather than it being decided by a file they
haven't looked at.

---

## ZIP structures

Both formats are supported. Use whichever matches how your samples arrive.

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
extracts every ZIP and copies all the files into a single combined staging
folder. Filenames that collide across ZIPs are prefixed with the ZIP's name
to keep them distinct.

---

## Adding a new sample set

**Option A (batch, one ZIP):**
1. Prepare your samples on a separate, isolated machine
2. ZIP them together as-is
3. Copy the ZIP into this `samples/` folder
4. Run `Start-SCT.ps1`, choose **Malware Introduction -> Technique 1.1**, and select the ZIP by number

**Option B (one sample per ZIP):**
1. Create one ZIP per sample
2. Copy all ZIPs into this `samples/` folder
3. Run `Start-SCT.ps1`, choose **Malware Introduction -> Technique 1.1**, and select **`[A] Combine and run ALL ZIPs`**

---

## Security notes

- This folder is `.gitignore`d to prevent accidental commits of real malware
- Only copy ZIPs into a running, isolated lab VM
- Never extract on a production machine or networked host
- The launcher will ask **"Execute samples after delivery?"** before running — every file in the batch is either delivery-only or delivery-and-execution for that run, so check what's in the ZIP before answering yes
- After testing, extracted files remain at `C:\Temp\SCT-Staging\<name>\` — delete them when review is complete
