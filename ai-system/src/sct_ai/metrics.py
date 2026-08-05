"""Deterministic SCT metrics, coverage, pairwise deltas, and ranking."""

from __future__ import annotations

import itertools
import math
from collections import defaultdict
from pathlib import Path
from statistics import fmean
from typing import Any, Callable, Iterable

from . import __version__
from .errors import PolicyValidationError
from .packages import NormalizedCase, PackageData
from .util import load_json_no_duplicates, stable_id


DEFAULT_DETECTION_WEIGHT = 0.40
DEFAULT_BLOCKING_WEIGHT = 0.60
# Backwards-compatible names for callers that imported the original constants.
DETECTION_WEIGHT = DEFAULT_DETECTION_WEIGHT
ACTION_WEIGHT = DEFAULT_BLOCKING_WEIGHT
BLOCKING_CREDIT = {
    "blocked": 1.0,
    "not_blocked": 0.0,
}


def load_policy(path: str | Path) -> dict[str, Any]:
    policy_path = Path(path).resolve()
    if not policy_path.is_file():
        raise PolicyValidationError(f"Comparison policy does not exist: {policy_path}")
    try:
        policy = load_json_no_duplicates(
            policy_path.read_text(encoding="utf-8-sig"),
            "comparison policy",
        )
    except (OSError, ValueError) as exc:
        raise PolicyValidationError(str(exc)) from exc
    return policy


def validate_policy(
    policy: dict[str, Any],
    required_modules: set[str],
    policy_modes: set[str] | None = None,
) -> dict[str, Any]:
    allowed = {
        "schema_version",
        "module_weights",
        "minimum_comparable_weight",
        "tie_margin",
        "scoring_mode",
        "detection_weight",
        "blocking_weight",
        "decision_priorities",
    }
    unknown = set(policy) - allowed
    if unknown:
        raise PolicyValidationError(
            f"Comparison policy has unknown fields: {sorted(unknown)}"
        )
    if policy.get("schema_version") != "1.0":
        raise PolicyValidationError("Comparison policy schema_version must be '1.0'.")
    weights = policy.get("module_weights")
    if not isinstance(weights, dict):
        raise PolicyValidationError("module_weights must be an object.")
    if set(weights) != required_modules:
        missing = sorted(required_modules - set(weights))
        extra = sorted(set(weights) - required_modules)
        details = []
        if missing:
            details.append(f"missing {missing}")
        if extra:
            details.append(f"unexpected {extra}")
        raise PolicyValidationError(
            "module_weights must contain exactly the submitted modules ("
            + "; ".join(details)
            + ")."
        )
    normalized_weights: dict[str, float] = {}
    for module_id, value in weights.items():
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or float(value) <= 0
        ):
            raise PolicyValidationError(
                f"module_weights.{module_id} must be a positive number."
            )
        normalized_weights[module_id] = float(value)
    if not math.isclose(sum(normalized_weights.values()), 100.0, abs_tol=0.001):
        raise PolicyValidationError("module_weights must total 100.")

    minimum = policy.get("minimum_comparable_weight", 80)
    tie_margin = policy.get("tie_margin", 2)
    for name, value, lower, upper in (
        ("minimum_comparable_weight", minimum, 0, 100),
        ("tie_margin", tie_margin, 0, 100),
    ):
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or not lower <= float(value) <= upper
        ):
            raise PolicyValidationError(f"{name} must be between {lower} and {upper}.")

    scoring = resolve_scoring(policy, policy_modes or set())
    normalized_policy = {
        "schema_version": "1.0",
        "module_weights": normalized_weights,
        "minimum_comparable_weight": float(minimum),
        "tie_margin": float(tie_margin),
        "scoring_mode": scoring["scoring_mode"],
    }
    if "decision_priorities" in policy:
        priorities = policy["decision_priorities"]
        if not isinstance(priorities, str) or not priorities.strip():
            raise PolicyValidationError(
                "decision_priorities must be a non-empty string when supplied."
            )
        if len(priorities.strip()) > 2000:
            raise PolicyValidationError(
                "decision_priorities must not exceed 2000 characters."
            )
        normalized_policy["decision_priorities"] = priorities.strip()
    if scoring["scoring_mode"] == "custom":
        normalized_policy["detection_weight"] = scoring["detection_weight"]
        normalized_policy["blocking_weight"] = scoring["blocking_weight"]
    return normalized_policy


def resolve_scoring(
    policy: dict[str, Any] | None,
    policy_modes: set[str],
) -> dict[str, Any]:
    policy = policy or {}
    requested_mode = policy.get("scoring_mode", "auto")
    allowed_modes = {"auto", "detect_only", "prevention_first", "custom"}
    if requested_mode not in allowed_modes:
        raise PolicyValidationError(
            "scoring_mode must be auto, detect_only, prevention_first, or custom."
        )

    supplied_weights = {
        name: policy.get(name)
        for name in ("detection_weight", "blocking_weight")
        if name in policy
    }
    if requested_mode != "custom" and supplied_weights:
        raise PolicyValidationError(
            "detection_weight and blocking_weight are used only when "
            "scoring_mode is custom."
        )

    if requested_mode == "auto":
        if "detect_only" in policy_modes and len(policy_modes) > 1:
            raise PolicyValidationError(
                "Automatic scoring cannot resolve mixed policy modes ("
                + ", ".join(sorted(policy_modes))
                + "): a detect-only control never earns blocking credit under "
                "prevention-first scoring. Set scoring_mode to detect_only, "
                "prevention_first, or custom explicitly."
            )
        resolved_mode = (
            "detect_only"
            if policy_modes and policy_modes == {"detect_only"}
            else "prevention_first"
        )
    else:
        resolved_mode = requested_mode

    if resolved_mode == "detect_only":
        detection = 100.0
        blocking = 0.0
    elif resolved_mode == "prevention_first":
        detection = 40.0
        blocking = 60.0
    else:
        if set(supplied_weights) != {"detection_weight", "blocking_weight"}:
            raise PolicyValidationError(
                "Custom scoring requires detection_weight and blocking_weight."
            )
        normalized: dict[str, float] = {}
        for name, value in supplied_weights.items():
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(float(value))
                or not 0 <= float(value) <= 100
            ):
                raise PolicyValidationError(f"{name} must be between 0 and 100.")
            normalized[name] = float(value)
        detection = normalized["detection_weight"]
        blocking = normalized["blocking_weight"]
        if not math.isclose(detection + blocking, 100.0, abs_tol=0.001):
            raise PolicyValidationError(
                "detection_weight and blocking_weight must total 100."
            )

    return {
        "scoring_mode": requested_mode,
        "resolved_scoring_mode": resolved_mode,
        "detection_weight": detection,
        "blocking_weight": blocking,
    }


def _rounded(value: float) -> float:
    return round(value, 4)


def case_metrics(
    case: NormalizedCase,
    detection_weight: float = DEFAULT_DETECTION_WEIGHT,
    blocking_weight: float = DEFAULT_BLOCKING_WEIGHT,
) -> dict[str, Any]:
    trial_count = len(case.trials)
    detected = sum(
        trial.detection_status == "detected" for trial in case.trials
    )
    blocked = sum(
        trial.action_status == "blocked" for trial in case.trials
    )
    not_blocked = sum(
        trial.action_status == "not_blocked" for trial in case.trials
    )
    detection_rate = 100.0 * detected / trial_count
    blocking_rate = 100.0 * blocked / trial_count
    score = (
        detection_weight * detection_rate
        + blocking_weight * blocking_rate
    )
    outcome_signatures = {
        (
            trial.execution_status,
            trial.detection_status,
            trial.action_status,
        )
        for trial in case.trials
    }
    return {
        "case_id": case.case_id,
        "trial_count": trial_count,
        "detection_rate": _rounded(detection_rate),
        "blocked_rate": _rounded(blocking_rate),
        "not_blocked_rate": _rounded(100.0 * not_blocked / trial_count),
        "score": _rounded(score),
        "inconsistent": len(outcome_signatures) > 1,
    }


def aggregate_cases(
    cases: Iterable[NormalizedCase],
    detection_weight: float = DEFAULT_DETECTION_WEIGHT,
    blocking_weight: float = DEFAULT_BLOCKING_WEIGHT,
) -> dict[str, Any]:
    materialized = list(cases)
    if not materialized:
        return {
            "case_count": 0,
            "trial_count": 0,
            "detection_rate": None,
            "blocked_rate": None,
            "not_blocked_rate": None,
            "score": None,
            "inconsistent_case_count": 0,
        }
    values = [
        case_metrics(case, detection_weight, blocking_weight)
        for case in materialized
    ]

    def mean(name: str) -> float:
        return _rounded(fmean(float(value[name]) for value in values))

    return {
        "case_count": len(values),
        "trial_count": sum(value["trial_count"] for value in values),
        "detection_rate": mean("detection_rate"),
        "blocked_rate": mean("blocked_rate"),
        "not_blocked_rate": mean("not_blocked_rate"),
        "score": mean("score"),
        "inconsistent_case_count": sum(value["inconsistent"] for value in values),
    }


def _breakdown(
    cases: Iterable[NormalizedCase],
    key_fn: Callable[[NormalizedCase], str],
    detection_weight: float = DEFAULT_DETECTION_WEIGHT,
    blocking_weight: float = DEFAULT_BLOCKING_WEIGHT,
) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[NormalizedCase]] = defaultdict(list)
    for case in cases:
        groups[key_fn(case)].append(case)
    return {
        key: aggregate_cases(
            groups[key],
            detection_weight,
            blocking_weight,
        )
        for key in sorted(groups)
    }


def _module_breakdown(
    cases: Iterable[NormalizedCase],
    detection_weight: float = DEFAULT_DETECTION_WEIGHT,
    blocking_weight: float = DEFAULT_BLOCKING_WEIGHT,
) -> dict[str, dict[str, Any]]:
    """Summarize represented test definitions and their recorded outcomes."""
    groups: dict[str, list[NormalizedCase]] = defaultdict(list)
    for case in cases:
        groups[case.module_id].append(case)

    result: dict[str, dict[str, Any]] = {}
    for module_id in sorted(groups):
        module_cases = groups[module_id]
        metrics = aggregate_cases(
            module_cases,
            detection_weight,
            blocking_weight,
        )
        trials = [trial for case in module_cases for trial in case.trials]
        metrics.update(
            {
                "module_name": module_cases[0].module_name,
                "technique_count": len(
                    {case.technique_id for case in module_cases}
                ),
                # An empty subtest is the technique-level test definition, so
                # it still contributes one represented subtest to the report.
                "subtest_count": len(
                    {
                        (case.technique_id, case.subtest)
                        for case in module_cases
                    }
                ),
                "detected_count": sum(
                    trial.detection_status == "detected" for trial in trials
                ),
                "not_detected_count": sum(
                    trial.detection_status == "not_detected" for trial in trials
                ),
                "blocked_count": sum(
                    trial.action_status == "blocked" for trial in trials
                ),
                "not_blocked_count": sum(
                    trial.action_status == "not_blocked" for trial in trials
                ),
            }
        )
        result[module_id] = metrics
    return result


def _case_metadata(case: NormalizedCase) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "module_id": case.module_id,
        "module_name": case.module_name,
        "technique_id": case.technique_id,
        "technique_name": case.technique_name,
        "subtest": case.subtest,
        "test_stage": case.test_stage,
        "delivery_method": case.delivery_method,
        "input_identity": case.input_identity,
        "attack_id": case.attack_id,
        "objective": case.objective,
        "what_it_does": case.what_it_does,
        "success_indicator": case.success_indicator,
    }


def _metric_evidence(
    evidence: list[dict[str, Any]],
    evidence_ids: set[str],
    evidence_type: str,
    identity: str,
    payload: dict[str, Any],
) -> str:
    evidence_id = stable_id("EVIDENCE", evidence_type, identity)
    if evidence_id not in evidence_ids:
        evidence.append(
            {
                "evidence_id": evidence_id,
                "type": evidence_type,
                **payload,
            }
        )
        evidence_ids.add(evidence_id)
    return evidence_id


def compare_packages(
    packages: list[PackageData],
    policy: dict[str, Any] | None = None,
    comparison_id: str | None = None,
) -> dict[str, Any]:
    packages = sorted(packages, key=lambda item: item.control_id)
    package_by_control = {package.control_id: package for package in packages}
    case_key_sets = [set(package.cases) for package in packages]
    union_keys = set().union(*case_key_sets)
    shared_keys = set.intersection(*case_key_sets) if case_key_sets else set()
    union_modules = {
        case.module_id
        for package in packages
        for case in package.cases.values()
    }
    control_policy_modes = {
        package.control_id: package.profile_summary["policy"]["default_mode"]
        for package in packages
    }
    policy_modes = set(control_policy_modes.values())
    normalized_policy = (
        validate_policy(policy, union_modules, policy_modes)
        if policy is not None
        else None
    )
    scoring_policy = resolve_scoring(normalized_policy, policy_modes)
    detection_weight = scoring_policy["detection_weight"] / 100.0
    blocking_weight = scoring_policy["blocking_weight"] / 100.0

    representative: dict[str, NormalizedCase] = {}
    for package in packages:
        for key, case in package.cases.items():
            representative.setdefault(key, case)

    evidence: list[dict[str, Any]] = []
    evidence_ids: set[str] = set()
    controls: list[dict[str, Any]] = []
    product_metrics: dict[str, dict[str, Any]] = {}

    for package in packages:
        all_cases = list(package.cases.values())
        comparable_cases = [
            package.cases[key] for key in sorted(shared_keys)
        ]
        modules = _module_breakdown(
            all_cases,
            detection_weight,
            blocking_weight,
        )
        comparable_modules = _breakdown(
            comparable_cases,
            lambda case: case.module_id,
            detection_weight,
            blocking_weight,
        )
        control_metrics = {
            "all_cases": aggregate_cases(
                all_cases,
                detection_weight,
                blocking_weight,
            ),
            "comparable_cases": aggregate_cases(
                comparable_cases,
                detection_weight,
                blocking_weight,
            ),
            "coverage": {
                "union_case_count": len(union_keys),
                "present_case_count": len(package.cases),
                "coverage_rate": _rounded(
                    100.0 * len(package.cases) / len(union_keys)
                )
                if union_keys
                else 0.0,
                "globally_comparable_case_count": len(shared_keys),
                "missing_case_ids": [
                    representative[key].case_id
                    for key in sorted(union_keys - set(package.cases))
                ],
            },
            "modules": modules,
            "comparable_modules": comparable_modules,
            "techniques": _breakdown(
                all_cases,
                lambda case: f"{case.module_id}:{case.technique_id}",
                detection_weight,
                blocking_weight,
            ),
            "stages": _breakdown(
                all_cases,
                lambda case: case.test_stage,
                detection_weight,
                blocking_weight,
            ),
            "samples": _breakdown(
                (
                    case
                    for case in all_cases
                    if case.input_identity != "none"
                ),
                lambda case: case.input_identity,
                detection_weight,
                blocking_weight,
            ),
        }
        product_metrics[package.control_id] = control_metrics
        controls.append(
            {
                "control_id": package.control_id,
                "display_name": package.display_name,
                "package_sha256": package.package_sha256,
                "profile": package.profile_summary,
                "metrics": control_metrics,
            }
        )

        _metric_evidence(
            evidence,
            evidence_ids,
            "profile_summary",
            package.control_id,
            {
                "control_id": package.control_id,
                "display_name": package.display_name,
                "profile": package.profile_summary,
            },
        )
        _metric_evidence(
            evidence,
            evidence_ids,
            "control_metrics",
            package.control_id,
            {
                "control_id": package.control_id,
                "scope": "all_cases",
                "metrics": control_metrics["all_cases"],
                "coverage": control_metrics["coverage"],
            },
        )
        for module_id, metrics in comparable_modules.items():
            _metric_evidence(
                evidence,
                evidence_ids,
                "module_metrics",
                f"{package.control_id}|{module_id}",
                {
                    "control_id": package.control_id,
                    "module_id": module_id,
                    "module_name": package.module_names.get(module_id, module_id),
                    "scope": "globally_comparable_cases",
                    "metrics": metrics,
                },
            )
        for key, case in sorted(package.cases.items()):
            metrics = case_metrics(
                case,
                detection_weight,
                blocking_weight,
            )
            _metric_evidence(
                evidence,
                evidence_ids,
                "case_outcome",
                f"{package.control_id}|{key}",
                {
                    "control_id": package.control_id,
                    "case": _case_metadata(case),
                    "metrics": metrics,
                },
            )

    pairwise: list[dict[str, Any]] = []
    for left_id, right_id in itertools.combinations(sorted(package_by_control), 2):
        left = package_by_control[left_id]
        right = package_by_control[right_id]
        pair_keys = set(left.cases) & set(right.cases)
        left_metrics = aggregate_cases(
            (left.cases[key] for key in sorted(pair_keys)),
            detection_weight,
            blocking_weight,
        )
        right_metrics = aggregate_cases(
            (right.cases[key] for key in sorted(pair_keys)),
            detection_weight,
            blocking_weight,
        )
        score_delta = (
            _rounded(left_metrics["score"] - right_metrics["score"])
            if pair_keys
            else None
        )
        item = {
            "left_control_id": left_id,
            "right_control_id": right_id,
            "comparable_case_count": len(pair_keys),
            "left_metrics": left_metrics,
            "right_metrics": right_metrics,
            "score_delta": score_delta,
        }
        evidence_id = _metric_evidence(
            evidence,
            evidence_ids,
            "pairwise_metrics",
            f"{left_id}|{right_id}",
            item,
        )
        item["evidence_id"] = evidence_id
        pairwise.append(item)

    ranking: dict[str, Any] = {
        "status": "not_requested",
        "recommended_control_id": None,
        "reason": "A comparison policy is required to calculate a ranking.",
        "weighted_comparable_coverage": None,
        "provisional": None,
        "entries": [],
    }
    if normalized_policy is not None:
        weights = normalized_policy["module_weights"]
        comparable_modules = {
            representative[key].module_id for key in shared_keys
        }
        available_weight = sum(
            weights[module_id] for module_id in comparable_modules
        )
        provisional = (
            available_weight
            < normalized_policy["minimum_comparable_weight"]
        )
        entries: list[dict[str, Any]] = []
        if available_weight > 0:
            for package in packages:
                module_scores: dict[str, float] = {}
                weighted_total = 0.0
                for module_id in sorted(comparable_modules):
                    metrics = product_metrics[package.control_id][
                        "comparable_modules"
                    ][module_id]
                    score = float(metrics["score"])
                    module_scores[module_id] = score
                    weighted_total += score * weights[module_id]
                overall = _rounded(weighted_total / available_weight)
                entries.append(
                    {
                        "control_id": package.control_id,
                        "display_name": package.display_name,
                        "score": overall,
                        "module_scores": module_scores,
                    }
                )
            entries.sort(key=lambda item: (-item["score"], item["control_id"]))
            for index, entry in enumerate(entries, start=1):
                entry["rank"] = index

            top_gap = (
                _rounded(entries[0]["score"] - entries[1]["score"])
                if len(entries) > 1
                else None
            )
            if provisional:
                status = "provisional"
                recommended = None
                reason = (
                    "Insufficient comparable evidence: weighted comparable "
                    f"coverage is {_rounded(available_weight)}%."
                )
            elif top_gap is not None and top_gap <= normalized_policy["tie_margin"]:
                status = "no_clear_winner"
                recommended = None
                reason = (
                    f"The top scores are within the "
                    f"{normalized_policy['tie_margin']}-point tie margin."
                )
            else:
                status = "recommended"
                recommended = entries[0]["control_id"]
                reason = (
                    f"{entries[0]['display_name']} has the highest verified "
                    "weighted score on globally comparable cases."
                )
        else:
            status = "unavailable"
            recommended = None
            reason = "The submitted controls have no globally comparable cases."
            top_gap = None
        ranking = {
            "status": status,
            "recommended_control_id": recommended,
            "reason": reason,
            "weighted_comparable_coverage": _rounded(available_weight),
            "provisional": provisional if available_weight > 0 else None,
            "top_score_gap": top_gap,
            "entries": entries,
        }
        ranking["evidence_id"] = _metric_evidence(
            evidence,
            evidence_ids,
            "ranking",
            "overall",
            {
                "ranking": ranking.copy(),
                "policy": normalized_policy,
            },
        )

    case_catalog = [
        {
            **_case_metadata(representative[key]),
            "globally_comparable": key in shared_keys,
            "present_control_ids": [
                package.control_id for package in packages if key in package.cases
            ],
        }
        for key in sorted(union_keys)
    ]

    result = {
        "schema_version": "1.1",
        "engine_version": __version__,
        "comparison_id": comparison_id,
        "scoring": {
            "requested_mode": scoring_policy["scoring_mode"],
            "resolved_mode": scoring_policy["resolved_scoring_mode"],
            "detection_weight": detection_weight,
            "blocking_weight": blocking_weight,
            "blocking_credit": BLOCKING_CREDIT,
            "aggregation": "trials_within_case_then_cases_within_module",
            "control_policy_modes": control_policy_modes,
        },
        "policy": normalized_policy,
        "coverage": {
            "control_count": len(packages),
            "union_case_count": len(union_keys),
            "globally_comparable_case_count": len(shared_keys),
            "global_comparability_rate": _rounded(
                100.0 * len(shared_keys) / len(union_keys)
            )
            if union_keys
            else 0.0,
        },
        "controls": controls,
        "case_catalog": case_catalog,
        "pairwise": pairwise,
        "ranking": ranking,
        "evidence": sorted(evidence, key=lambda item: item["evidence_id"]),
    }
    return result
