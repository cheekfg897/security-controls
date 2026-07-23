# Documentation

Use this page as the entry point for SCT documentation. The root [README](../README.md) covers installation and the normal operator workflow.

## Architecture

- [Framework design](architecture/framework-design.md) explains module discovery, execution inference, markers, and result storage.

## Guides

- [Project structure](guides/project-structure.md) explains where code and metadata belong and how to add modules or techniques.
- [AI-assisted control comparison](../ai-system/README.md) explains deterministic scoring, runtime skills, the local/shared web app, providers, and offline installation.

## Reference

- [Control matrix](reference/control-matrix.md) lists implementation status and MITRE ATT&CK mappings.
- [Threat scenarios](reference/threat-scenarios.md) lists purposes, prerequisites, and operating notes for each module.

Documentation that belongs to one technique stays beside that technique under `scenarios/`. Sample handling and endpoint sanity-check instructions stay beside their respective assets in `samples/` and `sanity_checks/`.
