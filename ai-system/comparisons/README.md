# SCT comparisons

The comparison CLI and web application write generated runs here:

```text
comparisons/<comparison-id>/
|-- comparison.json
|-- ai-analysis.json
|-- technical-report.md
|-- executive-summary.md
|-- report.html
`-- run-manifest.json
```

`comparison.json` contains the authoritative deterministic evidence and
Python recommendation. When AI was requested, `ai-analysis.json` contains the
blinded independent preference, categorical confidence, the fifth-stage
agreement/disagreement reconciliation, or an explicit `unavailable` state.
The AI result is advisory and never replaces `comparison.json`.

`index.sqlite3` stores the web application's job index. Run manifests remain
the source of truth and can be used to rebuild the index.

Generated comparison data is gitignored because profiles and results may
contain environment-sensitive information. Source packages under
`framework/submissions/` and authoritative workspaces under
`framework/results/` are never
modified by the comparison workflow.
