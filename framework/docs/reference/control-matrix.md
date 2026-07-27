# Control Matrix

This matrix reflects the current `module.json` definitions. "Available" means SCT has an executable script path; it does not claim validation against every security product.

| Module | Technique | ATT&CK | Subtests | Status |
|---|---|---|---:|---|
| Malware Delivery | 1.1 Known Malware - Disk Drop | T1105 | - | Available |
| Malware Delivery | 1.2 Removable Media (USB) | T1091 | - | Available; environment validation pending |
| Malware Delivery | 1.3 Download from Internet (HTTP) | T1105 | - | Available |
| Malware Delivery | 1.4 Trojanised COTS Application | T1036.005 | 2 | Available |
| Malware Delivery | 1.5 Fileless PowerShell | T1059.001 | 9 | Available |
| Malware Delivery | 1.6 DLL Sideloading | T1574.002 | - | Available |
| Exploitation | 2.1 Malicious Macro (Office VBA) | T1566.001 | 1 | Available; requires desktop Word and manual document preparation |
| Exploitation | 2.2 CVE Simulation | T1203 | - | Available |
| Privilege Escalation | 3.1 Process Hollowing | T1055.012 | - | Planned |
| Privilege Escalation | 3.2 UAC Bypass | T1548.002 | 4 | Available |
| Privilege Escalation | 3.3 LOLBin Signed Binary | T1218 | 4 | Available |
| Persistence | 4.1 Registry Run Keys / Startup Folder | T1547.001 | 7 | Available; HKLM subtests require Administrator |
| Persistence | 4.2 Scheduled Task / Job | T1053.005 | 5 | Available |
| Persistence | 4.3 Startup Folder (Advanced) | T1547.001 | 5 | Available |
| Persistence | 4.4 WMI Event Subscription | T1546.003 | 2 | Available; requires Administrator |

See [Framework Design](../architecture/framework-design.md#execution-inference) for how launch behavior is inferred without a metadata type field, and [Threat Scenarios](threat-scenarios.md) for preparation requirements.
