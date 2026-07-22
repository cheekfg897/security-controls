# Threat Scenarios

SCT groups techniques into modules by security objective. Use the launcher to select a module, technique, and optional subtest.

## Module 01 - Malware Delivery

Tests common ways malware reaches or executes on an endpoint.

| Technique | Purpose | Preparation |
|---|---|---|
| 1.1 Disk Drop | Copy samples to disk and optionally execute them. | Put ZIPs in `samples/`; see the [technique guide](../../scenarios/01-malware-delivery/v1.1-known-malware/README.md). |
| 1.2 Removable Media | Deliver samples from USB media. | Use an authorised endpoint with physical USB passthrough; see the [technique guide](../../scenarios/01-malware-delivery/v1.2-removable-media/README.md). |
| 1.3 Internet Download | Download samples over HTTP. | Start the companion server on a second VM; see the [two-VM guide](../../scenarios/01-malware-delivery/v1.3-download-internet/README.md). |
| 1.4 Trojanised COTS | Exercise a decoy application and hidden payload chain. | Self-contained; see the [technique guide](../../scenarios/01-malware-delivery/v1.4-trojanised-cots/README.md). |
| 1.5 Fileless PowerShell | Exercise local or remotely fetched in-memory subtests. | Sysmon is required for result collection; remote subtests need a second VM. |
| 1.6 DLL Sideloading | Load an unsigned DLL through a trusted process. | Self-contained; see the [technique guide](../../scenarios/01-malware-delivery/v1.6-dll-sideloading/README.md). |

> Technique 1.2 has not been validated in the current environment. A virtual disk can exercise file-copy detection, but it does not validate USB device-control monitoring.

## Module 02 - Exploitation

Tests exploit-like delivery and execution behavior.

| Technique | Purpose | Status |
|---|---|---|
| 2.1 Malicious Macro | Exercise an Office VBA delivery chain. | Planned |
| 2.2 CVE Simulation | Exercise behavior associated with a known-vulnerability proof of concept. | Available; follow the [technique guide](../../scenarios/02-exploitation/v2.2-cve-simulation/README.md). |

## Module 03 - Privilege Escalation

Tests elevation and signed-binary proxy execution.

| Technique | Purpose | Status |
|---|---|---|
| 3.1 Process Hollowing | Exercise memory-resident code replacement. | Planned |
| 3.2 UAC Bypass | Run Fodhelper, Eventvwr, ComputerDefaults, and SilentCleanup subtests. | Available |
| 3.3 LOLBin Signed Binary | Run Mshta, Regsvr32, Rundll32, and InfDefaultInstall subtests. | Available; see the [technique guide](../../scenarios/03-privilege-escalation/v3.3-lotl-signed-binary/README.md). |

## Module 04 - Persistence

Tests mechanisms that can survive logon, reboot, or credential changes.

| Technique | Purpose | Guide |
|---|---|---|
| 4.1 Registry Run Keys / Startup Folder | HKCU/HKLM Run and RunOnce, VBS/BAT startup, and hidden PowerShell patterns. | [Technique 4.1](../../scenarios/04-persistence/v4.1-registry-run-key/README.md) |
| 4.2 Scheduled Task / Job | User, cmdlet, registry-loader, SYSTEM, and hidden XML task patterns. | [Technique 4.2](../../scenarios/04-persistence/v4.2-scheduled-task/README.md) |
| 4.3 Startup Folder (Advanced) | JSE, LNK, all-users BAT, shell-folder redirect, and Winlogon patterns. | [Technique 4.3](../../scenarios/04-persistence/v4.3-startup-folder/README.md) |
| 4.4 WMI Event Subscription | Permanent command-line and active-script WMI consumers with immediate benign triggers. | [Technique 4.4](../../scenarios/04-persistence/v4.4-wmi-event-subscription/README.md) |

Module 04 can run all 19 subtests without prompts from an Administrator PowerShell session:

```powershell
.\Start-SCT.ps1 `
    -ControlProfilePath .\results\sentinelone\control-profile.json `
    -RunModule 04 -NonInteractive
```

## General operating guidance

- Snapshot the isolated VM before each test series.
- Confirm the EDR/AV is active with a [sanity check](../../sanity_checks/README.md).
- Monitor the product console while the technique runs.
- Review the generated `results/<control-id>/results.csv`.
- Complete the technique's cleanup before restoring or reusing the VM.
