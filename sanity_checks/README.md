# Sanity Checks

This folder contains simple tests to verify that security solutions (EDR/AV) are working properly **before** running actual security control tests.

## Purpose

Use these scripts to confirm that your security tools are:
- Actively monitoring file creation
- Detecting known malware signatures
- Quarantining/blocking threats
- Logging detections properly

## Tests Included

### 1. SentinelOne Sanity Check
**File:** `sentinelone-sanity-check.ps1`

**What it does:**
- Creates the EICAR test file (a harmless file that all AV solutions recognize as "malware")
- Saves it to an obvious location (Desktop, Downloads, or Temp)
- Expects SentinelOne to immediately quarantine/delete the file
- Verifies if SentinelOne is actively protecting the system

**Expected result:**
- File should be quarantined/deleted within seconds
- SentinelOne should log a detection event
- File should NOT persist on disk

**Usage:**
```powershell
.\sentinelone-sanity-check.ps1
```

### 2. Carbon Black Sanity Check
**Status:** Coming soon

### 3. Morphisec Sanity Check
**Status:** Coming soon

## Why This Matters

If sanity checks fail:
- Your security solution may not be active
- Detection rules may be disabled
- Logging may be turned off
- You should fix these BEFORE running actual tests

If all sanity checks pass:
- You can be confident your security tools are working
- Negative results on actual tests are meaningful
- You know the system is properly protected

## Notes

- EICAR file is **completely harmless** — it's a standard test file used by all security vendors
- These tests should pass on any properly configured security solution
- If a test fails, investigate before proceeding with actual tests
