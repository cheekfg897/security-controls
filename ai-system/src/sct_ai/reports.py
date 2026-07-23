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


def render_technical_markdown(
    comparison: dict[str, Any],
    analysis: dict[str, Any] | None = None,
) -> str:
    lines = [
        "# SCT technical comparison report",
        "",
        f"Comparison ID: `{comparison.get('comparison_id') or 'not-set'}`",
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
            "| Control | Cases | Detection | Blocked before | Blocked after | Score | Coverage |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for control in comparison["controls"]:
        metrics = control["metrics"]["all_cases"]
        coverage = control["metrics"]["coverage"]
        lines.append(
            f"| {control['display_name']} | {metrics['case_count']} "
            f"| {_fmt(metrics['detection_rate'], '%')} "
            f"| {_fmt(metrics['blocked_before_rate'], '%')} "
            f"| {_fmt(metrics['blocked_after_rate'], '%')} "
            f"| {_fmt(metrics['score'])} "
            f"| {_fmt(coverage['coverage_rate'], '%')} |"
        )

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
        lines.extend(["", "## AI-assisted evidence analysis", ""])
        for skill in analysis.get("skills", []):
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
            recommendation = output.get("recommendation")
            if recommendation:
                refs = ", ".join(
                    f"`{item}`" for item in recommendation["evidence_ids"]
                )
                lines.extend(
                    [
                        "",
                        f"Recommendation: {recommendation['rationale']}",
                        f"Evidence: {refs}.",
                    ]
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
    ]
    if ranking["entries"]:
        lines.extend(["", "## Verified ranking", ""])
        for entry in ranking["entries"]:
            lines.append(
                f"{entry['rank']}. {entry['display_name']} — "
                f"{_fmt(entry['score'])}/100"
            )
    if analysis:
        final_skill = next(
            (
                skill
                for skill in analysis.get("skills", [])
                if skill["name"] == "qualified-recommendation"
            ),
            None,
        )
        if final_skill:
            lines.extend(
                [
                    "",
                    "## Qualified interpretation",
                    "",
                    final_skill["output"]["summary"],
                ]
            )
            recommendation = final_skill["output"].get("recommendation")
            if recommendation:
                lines.extend(["", recommendation["rationale"]])
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
                _fmt(metrics["blocked_before_rate"], "%"),
                _fmt(metrics["blocked_after_rate"], "%"),
                _fmt(metrics["score"]),
                _fmt(control["metrics"]["coverage"]["coverage_rate"], "%"),
            ]
        )
    findings = ""
    if analysis:
        blocks = []
        for skill in analysis.get("skills", []):
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
        findings = "<h2>AI-assisted evidence analysis</h2>" + "".join(blocks)

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
@media print{{body{{max-width:none}}}}
</style>
</head>
<body>
<h1>SCT comparison report</h1>
<p>Comparison <code>{html.escape(str(comparison.get("comparison_id") or "not-set"))}</code></p>
<div class="status"><strong>{html.escape(ranking["status"])}</strong><br>{html.escape(ranking["reason"])}</div>
<h2>Ranking</h2>
{_html_table(["Rank", "Control", "Score"], rank_rows) if rank_rows else "<p>No ranking was calculated.</p>"}
<h2>Per-control metrics</h2>
{_html_table(["Control", "Cases", "Detection", "Blocked before", "Blocked after", "Score", "Coverage"], metric_rows)}
{findings}
<h2>Provenance</h2>
<p>Metrics and rankings are deterministic. AI output cannot alter them. See <code>comparison.json</code> and <code>run-manifest.json</code> for machine-readable evidence.</p>
</body>
</html>
"""

