# Technique 4.4: WMI Event Subscription Persistence (T1546.003)

## Contents

- [How to run](#how-to-run)
- [Subtests](#subtests)
- [Interpreting results](#interpreting-results)

This technique creates real permanent WMI event subscriptions in `root\subscription`, triggers them once with a benign `ping.exe` process, and verifies execution through marker files. It is adapted from the Atomic Red Team T1546.003 CommandLineEventConsumer and ActiveScriptEventConsumer tests.

> Run this technique from an Administrator PowerShell session on an isolated Windows 10/11 lab VM.

Use `Start-SCT.ps1` when the outcome should be appended to the active product's `results/<control-id>/results-module-04.csv`. The direct commands below are useful for focused testing, but they only produce console output and marker files.

## How to run

```powershell
# Run both subtests in sequence
.\v4.4-wmi-event-subscription.ps1 -Subtest All

# Run one consumer type
.\v4.4-wmi-event-subscription.ps1 -Subtest CommandLineConsumer
.\v4.4-wmi-event-subscription.ps1 -Subtest ActiveScriptConsumer

# Remove SCT marker files and any WMI objects left by an interrupted run
.\v4.4-wmi-event-subscription.ps1 -CleanupOnly
```

Each subtest creates three WMI objects:

1. An `__EventFilter` that detects a new `PING.EXE` process.
2. A command-line or active-script event consumer.
3. An `__FilterToConsumerBinding` joining the filter and consumer.

After creating the subscription, the script starts `ping.exe` briefly. The consumer runs as SYSTEM and writes one of these benign markers:

```text
C:\Windows\Temp\art-v4.4-CommandLineConsumer.txt
C:\Windows\Temp\art-v4.4-ActiveScriptConsumer.txt
```

The WMI binding, consumer, and filter are removed in a `finally` block immediately after each subtest. The marker remains long enough for SCT to record the outcome. `-CleanupOnly` also removes any SCT WMI objects left by a terminated or interrupted run.

## Subtests

### CommandLineConsumer

Creates a `CommandLineEventConsumer` that launches `cmd.exe` to write the marker. Relevant telemetry includes Sysmon events 19, 20, and 21 and a `WmiPrvSE.exe` to `cmd.exe` process relationship.

### ActiveScriptConsumer

Creates an `ActiveScriptEventConsumer` containing VBScript that writes the marker through `Scripting.FileSystemObject`. Relevant telemetry includes Sysmon events 19, 20, and 21 and `scrcons.exe` execution.

## Interpreting results

- `EXECUTED`: the WMI consumer created its expected marker.
- `NOT EXECUTED`: the marker was absent. Review the script output and control telemetry to distinguish a block from a failed prerequisite or unsupported behavior.

Review the endpoint-control console even when the result is `EXECUTED`; a product can detect the behavior without blocking it.
