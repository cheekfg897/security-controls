# Control Matrix

This matrix reflects the current `module.json` definitions. “Available” means the launcher has an executable dispatch path; it does not claim validation against every security product.

| Module | Vector | MITRE ATT&CK | Type | Status |
|---|---|---|---|---|
| Malware Introduction | 1.1 Known Malware — Disk Drop | T1105 | `malware-batch` | Available |
| Malware Introduction | 1.2 Removable Media (USB) | T1091 | `removable-media` | Available; environment validation pending |
| Malware Introduction | 1.3 Download from Internet (HTTP) | T1105 | `client-server` | Available |
| Malware Introduction | 1.4 Trojanised COTS Application | T1036.005 | `simple` | Available |
| Malware Introduction | 1.5 Fileless PowerShell | T1059.001 | `fileless` | Available |
| Malware Introduction | 1.6 DLL Sideloading | T1574.002 | `simple` | Available |
| Exploitation | 2.1 Malicious Macro (Office VBA) | T1566.001 | `not-implemented` | Planned |
| Exploitation | 2.2 CVE Simulation | T1203 | `simple` | Available |
| Privilege Escalation | 3.1 Process Hollowing | T1055.012 | `not-implemented` | Planned |
| Privilege Escalation | 3.2 UAC Bypass | T1548.002 | `technique` | Available |
| Privilege Escalation | 3.3 LOLBin Signed Binary | T1218 | `technique` | Available |
| Persistence | 4.1 Registry Run Keys / Startup Folder | T1547.001 | `technique` | Available |
| Persistence | 4.2 Scheduled Task / Job | T1053.005 | `technique` | Available |
| Persistence | 4.3 Startup Folder (Advanced) | T1547.001 | `technique` | Available |

See [Framework Design](framework-design.md#vector-dispatch) for vector-type behaviour and [Threat Scenarios](threat-scenarios.md) for execution requirements.
