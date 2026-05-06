# Endpoint Security Control Evaluation

A structured framework for evaluating the detection and prevention capabilities of endpoint security controls — **Morphisec**, **Carbon Black EDR**, and **Antivirus** — across 7 threat scenarios mapped to the MITRE ATT&CK framework.

---

## Project Overview

This project simulates realistic attack techniques in an isolated lab environment and measures how effectively each security control detects, prevents, or misses them. Results are captured in a structured format to produce a comparative control matrix.

**Duration:** 12 weeks  
**Environment:** Isolated Windows VM (lab only)  
**Controls evaluated:** Morphisec · Carbon Black EDR · Antivirus  

---

## Threat Scenarios

| # | Scenario | MITRE Tactics |
|---|----------|---------------|
| 1 | Introduce Malware to Endpoints | Execution |
| 2 | Gain Unauthorised Access to Classified Data | Credential Access, Privilege Escalation |
| 3 | Exfiltrate Classified Data Through Endpoints | Exfiltration |
| 4 | Establish Persistence on an Endpoint | Persistence |
| 5 | Escalate Privileges on an Endpoint | Privilege Escalation |
| 6 | Move Laterally Across the Network | Lateral Movement |
| 7 | Evade Detection and Disable Security Controls | Defense Evasion |

---

## Repo Structure

```
endpoint-security-evaluation/
│
├── README.md
│
├── docs/
│   ├── framework-design.md        # Framework architecture & data schema
│   ├── threat-scenarios.md        # Full scenario write-ups with MITRE mapping
│   └── control-matrix.md          # Comparative results across all controls
│
├── scenarios/
│   ├── 01-malware-introduction/
│   │   ├── fileless-powershell.ps1
│   │   ├── process-hollowing.ps1
│   │   └── dll-sideloading.ps1
│   ├── 02-unauthorised-access/
│   │   ├── lsass-credential-dumping.ps1
│   │   └── uac-bypass-fodhelper.ps1
│   ├── 03-data-exfiltration/
│   │   ├── http-exfiltration.ps1
│   │   └── dns-exfiltration.ps1
│   ├── 04-persistence/
│   │   ├── registry-run-key.ps1
│   │   ├── scheduled-task.ps1
│   │   └── startup-folder.ps1
│   ├── 05-privilege-escalation/
│   │   ├── uac-bypass-fodhelper.ps1
│   │   └── token-impersonation.ps1
│   ├── 06-lateral-movement/
│   │   ├── pass-the-hash-smb.ps1
│   │   └── remote-exec-psexec.ps1
│   └── 07-defense-evasion/
│       ├── disable-defender.ps1
│       ├── clear-event-logs.ps1
│       └── living-off-the-land.ps1
│
├── results/
│   ├── raw/                       # Raw JSON/CSV output from each test run
│   └── analysis/                  # Processed findings and notes per scenario
│
├── scripts/
│   ├── run-scenario.ps1           # Wrapper to execute a scenario and log output
│   └── collect-results.py         # Parses logs into structured data
│
└── .gitignore
```

---

## How to Use

> **All tests must be run inside the isolated lab VM only. Never run these scripts on a production or networked machine.**

1. Clone the repo into your lab environment
2. Navigate to the relevant scenario folder
3. Run the test script via PowerShell
4. Results are logged automatically to `results/raw/`
5. Run `collect-results.py` to parse output into structured format

---

## Lab Environment

- **OS:** Windows (isolated VM — no network access to production)
- **Logging:** Windows Event Log + Sysmon (SwiftOnSecurity config)
- **Tooling:** PowerShell, Python 3

---

## Results Summary

> To be updated upon completion of Phase 2 (test execution).

A full control comparison matrix will be published in `docs/control-matrix.md` once all scenarios have been executed and results analysed.

---

## Project Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Foundation & Scenario Design | ✅ Complete |
| 2 | Build & Execute | 🔄 In Progress |
| 3 | Analysis | ⏳ Pending |
| 4 | Reporting | ⏳ Pending |

---



