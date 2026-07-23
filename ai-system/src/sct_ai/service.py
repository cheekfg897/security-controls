"""Application service shared by the CLI and web layer."""

from __future__ import annotations

import re
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .errors import AIOutputError, SCTComparisonError
from .metrics import compare_packages, load_policy
from .packages import load_packages
from .reports import (
    render_executive_markdown,
    render_standalone_html,
    render_technical_markdown,
)
from .util import dump_json, utc_now, validate_comparison_id


ProgressCallback = Callable[[str, int, str], None]


def _progress(
    callback: ProgressCallback | None,
    stage: str,
    percent: int,
    message: str,
) -> None:
    if callback:
        callback(stage, percent, message)


def default_comparison_id(control_ids: list[str]) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    suffix = "-".join(sorted(control_ids))
    value = re.sub(r"[^a-z0-9._-]+", "-", f"{stamp}-{suffix}".lower()).strip("-")
    if len(value) > 80:
        from .util import stable_id

        value = f"{stamp}-{stable_id('set', *sorted(control_ids), length=16).lower()}"
    return validate_comparison_id(value)


def _prepare_output(
    output_root: Path,
    comparison_id: str,
    force: bool,
) -> Path:
    output_root.mkdir(parents=True, exist_ok=True)
    output_dir = (output_root / comparison_id).resolve()
    if output_dir.parent != output_root.resolve():
        raise SCTComparisonError("Comparison output must stay under comparisons/.")
    if output_dir.exists():
        if not force:
            raise SCTComparisonError(
                f"Comparison output already exists: {output_dir}. Use --force to replace it."
            )
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=False)
    return output_dir


def _write_reports(
    output_dir: Path,
    comparison: dict[str, Any],
    analysis: dict[str, Any] | None,
) -> None:
    (output_dir / "technical-report.md").write_text(
        render_technical_markdown(comparison, analysis),
        encoding="utf-8",
    )
    (output_dir / "executive-summary.md").write_text(
        render_executive_markdown(comparison, analysis),
        encoding="utf-8",
    )
    (output_dir / "report.html").write_text(
        render_standalone_html(comparison, analysis),
        encoding="utf-8",
    )


def run_comparison(
    package_paths: list[str | Path],
    *,
    policy_path: str | Path | None,
    policy: dict[str, Any] | None = None,
    output_root: str | Path,
    comparison_id: str | None = None,
    force: bool = False,
    provider_name: str | None = None,
    model_name: str | None = None,
    provider_config_path: str | Path | None = None,
    progress_callback: ProgressCallback | None = None,
) -> dict[str, Any]:
    _progress(progress_callback, "validation", 5, "Validating comparison packages")
    packages = load_packages(package_paths)
    selected_id = (
        validate_comparison_id(comparison_id)
        if comparison_id
        else default_comparison_id([package.control_id for package in packages])
    )
    output_dir = _prepare_output(Path(output_root).resolve(), selected_id, force)
    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "comparison_id": selected_id,
        "engine_version": __version__,
        "status": "running",
        "started_at": utc_now(),
        "completed_at": None,
        "mode": "ai" if provider_name else "metrics-only",
        "provider": provider_name,
        "model": model_name,
        "inputs": [package.preflight_summary() for package in packages],
        "artifacts": [],
        "error": None,
    }
    dump_json(output_dir / "run-manifest.json", manifest)

    try:
        if policy is not None and policy_path is not None:
            raise SCTComparisonError(
                "Specify a policy object or policy path, not both."
            )
        selected_policy = load_policy(policy_path) if policy_path else policy
        _progress(progress_callback, "metrics", 25, "Calculating deterministic metrics")
        comparison = compare_packages(
            packages,
            policy=selected_policy,
            comparison_id=selected_id,
        )
        dump_json(output_dir / "comparison.json", comparison)
        _write_reports(output_dir, comparison, None)
        manifest["status"] = "metrics_complete"
        manifest["artifacts"] = [
            "comparison.json",
            "technical-report.md",
            "executive-summary.md",
            "report.html",
            "run-manifest.json",
        ]
        dump_json(output_dir / "run-manifest.json", manifest)

        analysis = None
        if provider_name:
            if not model_name or not provider_config_path:
                raise SCTComparisonError(
                    "AI mode requires a model and provider configuration path."
                )
            _progress(progress_callback, "ai", 50, "Running evidence-analysis skills")
            from .ai_workflow import run_ai_workflow

            analysis = run_ai_workflow(
                comparison,
                provider_name=provider_name,
                model_name=model_name,
                provider_config_path=Path(provider_config_path),
                progress_callback=progress_callback,
            )
            dump_json(output_dir / "ai-analysis.json", analysis)
            manifest["artifacts"].append("ai-analysis.json")
            _write_reports(output_dir, comparison, analysis)

        manifest["status"] = "completed"
        manifest["completed_at"] = utc_now()
        dump_json(output_dir / "run-manifest.json", manifest)
        _progress(progress_callback, "complete", 100, "Comparison completed")
        return {
            "comparison_id": selected_id,
            "output_dir": str(output_dir),
            "comparison": comparison,
            "analysis": analysis,
            "manifest": manifest,
        }
    except Exception as exc:
        manifest["status"] = (
            "ai_failed"
            if (output_dir / "comparison.json").is_file()
            else "failed"
        )
        manifest["completed_at"] = utc_now()
        manifest["error"] = str(exc)
        dump_json(output_dir / "run-manifest.json", manifest)
        if isinstance(exc, SCTComparisonError):
            raise
        raise AIOutputError(str(exc)) from exc
