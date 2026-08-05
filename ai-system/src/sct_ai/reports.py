"""Deterministic Markdown and standalone HTML renderers."""

from __future__ import annotations

import html
from typing import Any


def _fmt(value: Any, suffix: str = "") -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.2f}{suffix}"
    return f"{value}{suffix}"


def _status_label(value: str) -> str:
    return value.replace("_", " ").upper()


def _module_breakdown_rows(comparison: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for control in comparison["controls"]:
        for module_id, metrics in sorted(control["metrics"]["modules"].items()):
            rows.append(
                [
                    control["display_name"],
                    f"{module_id} - {metrics['module_name']}",
                    metrics["technique_count"],
                    metrics["subtest_count"],
                    metrics["trial_count"],
                    f"{metrics['detected_count']} / {metrics['trial_count']}",
                    f"{metrics['blocked_count']} / {metrics['trial_count']}",
                ]
            )
    return rows


def _control_label(comparison: dict[str, Any], control_id: str | None) -> str:
    if control_id is None:
        return "No control selected"
    for control in comparison["controls"]:
        if control["control_id"] == control_id:
            return f"{control['display_name']} ({control_id})"
    return control_id


def _analysis_skills_with_findings(
    analysis: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        skill
        for skill in analysis.get("skills", [])
        if isinstance(skill.get("output"), dict)
        and "summary" in skill["output"]
        and "findings" in skill["output"]
    ]


def render_technical_markdown(
    comparison: dict[str, Any],
    analysis: dict[str, Any] | None = None,
) -> str:
    scoring = comparison["scoring"]
    priorities = (comparison.get("policy") or {}).get("decision_priorities")
    lines = [
        "# SCT technical comparison report",
        "",
        f"Comparison ID: `{comparison.get('comparison_id') or 'not-set'}`",
        "",
        "## Scoring configuration",
        "",
        f"- Requested mode: `{scoring['requested_mode']}`",
        f"- Resolved mode: `{scoring['resolved_mode']}`",
        (
            "- Detection weight: "
            f"{_fmt(100 * scoring['detection_weight'], '%')}"
        ),
        (
            "- Blocking weight: "
            f"{_fmt(100 * scoring['blocking_weight'], '%')}"
        ),
        f"- Decision priorities: {priorities or 'None supplied'}",
        "",
        "## Comparable evidence",
        "",
        "| Controls | Union cases | Shared cases | Global comparability |",
        "|---:|---:|---:|---:|",
        (
            f"| {comparison['coverage']['control_count']} "
            f"| {comparison['coverage']['union_case_count']} "
            f"| {comparison['coverage']['globally_comparable_case_count']} "
            f"| {_fmt(comparison['coverage']['global_comparability_rate'], '%')} |"
        ),
        "",
        "## Ranking",
        "",
    ]
    ranking = comparison["ranking"]
    if ranking["entries"]:
        lines.extend(
            [
                "| Rank | Control | Score |",
                "|---:|---|---:|",
            ]
        )
        for entry in ranking["entries"]:
            lines.append(
                f"| {entry['rank']} | {entry['display_name']} "
                f"| {_fmt(entry['score'])} |"
            )
        lines.extend(
            [
                "",
                f"Status: **{ranking['status']}**",
                "",
                ranking["reason"],
                "",
                (
                    "Weighted comparable coverage: "
                    f"{_fmt(ranking['weighted_comparable_coverage'], '%')}"
                ),
            ]
        )
    else:
        lines.append(ranking["reason"])

    lines.extend(["", "## Per-control metrics", ""])
    lines.extend(
        [
            "| Control | Cases | Detection | Blocked | Score | Coverage |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for control in comparison["controls"]:
        metrics = control["metrics"]["all_cases"]
        coverage = control["metrics"]["coverage"]
        lines.append(
            f"| {control['display_name']} | {metrics['case_count']} "
            f"| {_fmt(metrics['detection_rate'], '%')} "
            f"| {_fmt(metrics['blocked_rate'], '%')} "
            f"| {_fmt(metrics['score'])} "
            f"| {_fmt(coverage['coverage_rate'], '%')} |"
        )

    lines.extend(
        [
            "",
            "## Module technique and subtest breakdown",
            "",
            (
                "Subtests are distinct technique/subtest definitions represented "
                "in the submitted results; a technique without a named subtest "
                "counts once. Detected and blocked counts use recorded result "
                "runs, shown against the result total."
            ),
            "",
            (
                "| Control | Module | Techniques | Subtests | Results | "
                "Detected | Blocked |"
            ),
            "|---|---|---:|---:|---:|---:|---:|",
        ]
    )
    for row in _module_breakdown_rows(comparison):
        lines.append("| " + " | ".join(str(item) for item in row) + " |")

    module_ids = sorted(
        {
            module_id
            for control in comparison["controls"]
            for module_id in control["metrics"]["comparable_modules"]
        }
    )
    if module_ids:
        lines.extend(["", "## Globally comparable module scores", ""])
        headers = ["Module"] + [
            control["display_name"] for control in comparison["controls"]
        ]
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("|---" * len(headers) + "|")
        for module_id in module_ids:
            row = [module_id]
            for control in comparison["controls"]:
                metrics = control["metrics"]["comparable_modules"].get(module_id)
                row.append(_fmt(metrics["score"]) if metrics else "n/a")
            lines.append("| " + " | ".join(row) + " |")

    if comparison["pairwise"]:
        lines.extend(["", "## Pairwise comparison", ""])
        lines.extend(
            [
                "| Left | Right | Shared cases | Score delta (left - right) |",
                "|---|---|---:|---:|",
            ]
        )
        names = {
            item["control_id"]: item["display_name"]
            for item in comparison["controls"]
        }
        for item in comparison["pairwise"]:
            lines.append(
                f"| {names[item['left_control_id']]} "
                f"| {names[item['right_control_id']]} "
                f"| {item['comparable_case_count']} "
                f"| {_fmt(item['score_delta'])} |"
            )

    inconsistent = [
        evidence
        for evidence in comparison["evidence"]
        if evidence["type"] == "case_outcome"
        and evidence["metrics"]["inconsistent"]
    ]
    lines.extend(["", "## Repeated-run consistency", ""])
    if inconsistent:
        for item in inconsistent:
            case = item["case"]
            lines.append(
                f"- `{item['evidence_id']}`: {item['control_id']} "
                f"{case['technique_id']}/{case['subtest'] or '(no subtest)'} "
                f"at stage `{case['test_stage']}` produced inconsistent outcomes."
            )
    else:
        lines.append("No inconsistent repeated comparison cases were found.")

    if analysis:
        if analysis.get("status") == "unavailable":
            lines.extend(
                [
                    "",
                    "## Independent AI assessment",
                    "",
                    "**AI assessment unavailable.**",
                    "",
                    analysis["decision_comparison"]["summary"],
                    "",
                    f"Provider error: `{analysis.get('error', 'unknown error')}`",
                ]
            )
        elif analysis.get("decision_comparison"):
            decision = analysis["decision_comparison"]
            assessment = analysis["independent_assessment"]
            lines.extend(
                [
                    "",
                    "## Python and independent AI decision review",
                    "",
                    f"- Agreement status: **{_status_label(decision['status'])}**",
                    "- Python recommendation: "
                    + _control_label(
                        comparison,
                        decision["python_recommended_control_id"],
                    ),
                    "- Independent AI preference: "
                    + _control_label(
                        comparison,
                        decision["ai_preferred_control_id"],
                    ),
                    f"- AI confidence: **{assessment['confidence']}**",
                    "",
                    f"AI rationale: {assessment['rationale']}",
                    "",
                    f"Reconciliation: {decision['summary']}",
                ]
            )
            for heading, values in (
                ("Strengths", assessment["strengths"]),
                ("Concerns", assessment["concerns"]),
                ("Coverage caveats", assessment["coverage_caveats"]),
            ):
                if values:
                    lines.extend(["", f"### {heading}", ""])
                    lines.extend(f"- {value}" for value in values)

        finding_skills = _analysis_skills_with_findings(analysis)
        if finding_skills:
            lines.extend(["", "## AI-assisted evidence analysis", ""])
        for skill in finding_skills:
            output = skill["output"]
            lines.extend(
                [
                    f"### {skill['name']} (v{skill['version']})",
                    "",
                    output["summary"],
                    "",
                ]
            )
            for finding in output["findings"]:
                refs = ", ".join(f"`{item}`" for item in finding["evidence_ids"])
                lines.append(
                    f"- **{finding['title']}** [{finding['severity']}]: "
                    f"{finding['analysis']} Evidence: {refs}."
                )

    lines.extend(
        [
            "",
            "## Provenance",
            "",
            "All percentages and rankings in this report are calculated by the "
            "deterministic SCT comparison engine. AI output may explain these "
            "values but cannot alter them.",
            "",
        ]
    )
    return "\n".join(lines)


def render_executive_markdown(
    comparison: dict[str, Any],
    analysis: dict[str, Any] | None = None,
) -> str:
    ranking = comparison["ranking"]
    scoring = comparison["scoring"]
    priorities = (comparison.get("policy") or {}).get("decision_priorities")
    lines = [
        "# SCT executive summary",
        "",
        (
            f"{comparison['coverage']['control_count']} controls were compared "
            f"across {comparison['coverage']['union_case_count']} unique cases; "
            f"{comparison['coverage']['globally_comparable_case_count']} were "
            "shared by every control."
        ),
        "",
        f"**Decision status:** {ranking['status']}",
        "",
        ranking["reason"],
        "",
        (
            f"Scoring mode: **{scoring['resolved_mode']}** "
            f"({_fmt(100 * scoring['detection_weight'], '%')} detection, "
            f"{_fmt(100 * scoring['blocking_weight'], '%')} blocking)."
        ),
    ]
    if priorities:
        lines.extend(["", f"Decision priorities: {priorities}"])
    if ranking["entries"]:
        lines.extend(["", "## Verified ranking", ""])
        for entry in ranking["entries"]:
            lines.append(
                f"{entry['rank']}. {entry['display_name']} — "
                f"{_fmt(entry['score'])}/100"
            )
    if analysis:
        if analysis.get("status") == "unavailable":
            lines.extend(
                [
                    "",
                    "## Independent AI assessment",
                    "",
                    "The independent AI assessment was unavailable. The "
                    "deterministic result above remains complete.",
                ]
            )
        elif analysis.get("decision_comparison"):
            decision = analysis["decision_comparison"]
            assessment = analysis["independent_assessment"]
            lines.extend(
                [
                    "",
                    "## Python and independent AI review",
                    "",
                    f"**{_status_label(decision['status'])}**",
                    "",
                    "Python: "
                    + _control_label(
                        comparison,
                        decision["python_recommended_control_id"],
                    ),
                    "",
                    "Independent AI: "
                    + _control_label(
                        comparison,
                        decision["ai_preferred_control_id"],
                    ),
                    "",
                    f"AI confidence: {assessment['confidence']}",
                    "",
                    assessment["rationale"],
                    "",
                    decision["summary"],
                ]
            )
    lines.extend(
        [
            "",
            "The ranking uses only globally comparable evidence. Review the "
            "technical report for policy differences, missing coverage, and "
            "case-level evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def _html_table(headers: list[str], rows: list[list[Any]]) -> str:
    head = "".join(f"<th>{html.escape(str(item))}</th>" for item in headers)
    body = "".join(
        "<tr>"
        + "".join(f"<td>{html.escape(str(item))}</td>" for item in row)
        + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render_standalone_html(
    comparison: dict[str, Any],
    analysis: dict[str, Any] | None = None,
) -> str:
    ranking = comparison["ranking"]
    scoring = comparison["scoring"]
    priorities = (comparison.get("policy") or {}).get("decision_priorities")
    rank_rows = [
        [entry["rank"], entry["display_name"], _fmt(entry["score"])]
        for entry in ranking["entries"]
    ]
    metric_rows = []
    for control in comparison["controls"]:
        metrics = control["metrics"]["all_cases"]
        metric_rows.append(
            [
                control["display_name"],
                metrics["case_count"],
                _fmt(metrics["detection_rate"], "%"),
                _fmt(metrics["blocked_rate"], "%"),
                _fmt(metrics["score"]),
                _fmt(control["metrics"]["coverage"]["coverage_rate"], "%"),
            ]
        )
    module_rows = _module_breakdown_rows(comparison)
    findings = ""
    if analysis and analysis.get("status") == "unavailable":
        findings = (
            "<h2>Independent AI assessment</h2>"
            '<div class="status"><strong>AI UNAVAILABLE</strong><br>'
            + html.escape(analysis["decision_comparison"]["summary"])
            + "</div>"
        )
    elif analysis and analysis.get("decision_comparison"):
        decision = analysis["decision_comparison"]
        assessment = analysis["independent_assessment"]
        list_sections = ""
        for heading, values in (
            ("Strengths", assessment["strengths"]),
            ("Concerns", assessment["concerns"]),
            ("Coverage caveats", assessment["coverage_caveats"]),
        ):
            if values:
                list_sections += (
                    f"<h3>{html.escape(heading)}</h3><ul>"
                    + "".join(
                        f"<li>{html.escape(value)}</li>" for value in values
                    )
                    + "</ul>"
                )
        findings = (
            "<h2>Python and independent AI decision review</h2>"
            '<div class="status"><strong>'
            + html.escape(_status_label(decision["status"]))
            + "</strong><br>Python: "
            + html.escape(
                _control_label(
                    comparison,
                    decision["python_recommended_control_id"],
                )
            )
            + "<br>Independent AI: "
            + html.escape(
                _control_label(
                    comparison,
                    decision["ai_preferred_control_id"],
                )
            )
            + "<br>AI confidence: "
            + html.escape(assessment["confidence"])
            + "</div><p><strong>AI rationale:</strong> "
            + html.escape(assessment["rationale"])
            + "</p><p><strong>Reconciliation:</strong> "
            + html.escape(decision["summary"])
            + "</p>"
            + list_sections
        )

    if analysis:
        blocks = []
        for skill in _analysis_skills_with_findings(analysis):
            items = "".join(
                "<li><strong>"
                + html.escape(finding["title"])
                + "</strong>: "
                + html.escape(finding["analysis"])
                + "</li>"
                for finding in skill["output"]["findings"]
            )
            blocks.append(
                f"<section><h3>{html.escape(skill['name'])}</h3>"
                f"<p>{html.escape(skill['output']['summary'])}</p>"
                f"<ul>{items}</ul></section>"
            )
        if blocks:
            findings += "<h2>AI-assisted evidence analysis</h2>" + "".join(blocks)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SCT comparison report</title>
<style>
body{{font:16px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#172033}}
h1,h2,h3{{color:#162a54}}table{{width:100%;border-collapse:collapse;margin:1rem 0 2rem}}
th,td{{border:1px solid #cbd3e1;padding:.55rem;text-align:left}}th{{background:#edf2fb}}
.status{{padding:1rem;border-left:5px solid #3767b1;background:#eef5ff}}code{{background:#eef1f5;padding:.1rem .25rem}}
.report-actions{{display:flex;align-items:center;gap:1rem;margin:1rem 0}}
button{{border:0;border-radius:8px;background:#274f9e;color:white;padding:.75rem 1.1rem;font:inherit;font-weight:700;cursor:pointer}}
.muted{{color:#61708d}}
section,table{{break-inside:avoid}}
@page{{margin:14mm}}
@media print{{body{{max-width:none;margin:0;padding:0;font-size:10pt}}.report-actions{{display:none}}a{{color:inherit;text-decoration:none}}}}
</style>
</head>
<body>
<h1>SCT comparison report</h1>
<p>Comparison <code>{html.escape(str(comparison.get("comparison_id") or "not-set"))}</code></p>
<div class="report-actions">
<button type="button" data-print-report>Print / Save as PDF</button>
<span class="muted">Uses your browser's print dialog.</span>
</div>
<div class="status"><strong>{html.escape(ranking["status"])}</strong><br>{html.escape(ranking["reason"])}</div>
<p><strong>Scoring:</strong> {html.escape(scoring["resolved_mode"])};
{_fmt(100 * scoring["detection_weight"], "%")} detection and
{_fmt(100 * scoring["blocking_weight"], "%")} blocking.</p>
{f'<p><strong>Decision priorities:</strong> {html.escape(priorities)}</p>' if priorities else ''}
<h2>Ranking</h2>
{_html_table(["Rank", "Control", "Score"], rank_rows) if rank_rows else "<p>No ranking was calculated.</p>"}
<h2>Per-control metrics</h2>
{_html_table(["Control", "Cases", "Detection", "Blocked", "Score", "Coverage"], metric_rows)}
<h2>Module technique and subtest breakdown</h2>
<p>Subtests are distinct technique/subtest definitions represented in the submitted results; a technique without a named subtest counts once. Detected and blocked counts are recorded result runs.</p>
{_html_table(["Control", "Module", "Techniques", "Subtests", "Results", "Detected", "Blocked"], module_rows)}
{findings}
<h2>Provenance</h2>
<p>Metrics and rankings are deterministic. AI output cannot alter them. See <code>comparison.json</code> and <code>run-manifest.json</code> for machine-readable evidence.</p>
<script>
document.querySelector('[data-print-report]').addEventListener('click', function () {{
  window.print();
}});
</script>
</body>
</html>
"""
