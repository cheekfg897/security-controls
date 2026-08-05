from __future__ import annotations

import io
import json
import platform
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from sct_ai.errors import PackageValidationError, PolicyValidationError
from sct_ai.metrics import compare_packages
from sct_ai.packages import load_package, load_packages
from sct_ai.reports import render_standalone_html
from sct_ai.service import run_comparison

from .helpers import package_bytes, write_package


class ComparisonEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_legacy_generated_notes_column_remains_readable(self) -> None:
        path = write_package(
            self.root / "legacy-notes.zip",
            "legacy-notes",
            [{"sha256": "A" * 64}],
            legacy_notes_column=True,
        )
        package = load_package(path)
        self.assertEqual(1, len(package.cases))

    def test_previous_result_column_order_remains_readable(self) -> None:
        path = write_package(
            self.root / "previous-layout.zip",
            "previous-layout",
            [{"sha256": "B" * 64}],
            previous_result_layout=True,
        )
        package = load_package(path)
        case = next(iter(package.cases.values()))
        self.assertEqual("sha256:" + ("B" * 64), case.input_identity)
        self.assertEqual("1.1", case.technique_id)

    def test_compact_malware_label_aligns_when_one_member_hash_is_missing(self) -> None:
        compact_label = "payload.exe [A1B2C3D4]"
        present = load_package(
            write_package(
                self.root / "present.zip",
                "present",
                [{"test_input": compact_label, "sha256": "A" * 64}],
            )
        )
        quarantined = load_package(
            write_package(
                self.root / "quarantined.zip",
                "quarantined",
                [{"test_input": compact_label, "sha256": ""}],
            )
        )

        self.assertEqual(set(present.cases), set(quarantined.cases))
        self.assertEqual(
            next(iter(present.cases.values())).input_identity,
            next(iter(quarantined.cases.values())).input_identity,
        )

    def test_stage_is_evidence_not_case_identity(self) -> None:
        path = write_package(
            self.root / "stage-evidence.zip",
            "stage-evidence",
            [
                {"sha256": "A" * 64, "stage": "write"},
                {"sha256": "A" * 64, "stage": "execution"},
            ],
        )
        package = load_package(path)
        case = next(iter(package.cases.values()))
        self.assertEqual(1, len(package.cases))
        self.assertEqual(2, len(case.trials))
        self.assertEqual("write", case.test_stage)

    def test_duplicate_stage_rows_in_one_run_are_rejected(self) -> None:
        content = package_bytes(
            "duplicate-stages",
            [
                {"sha256": "A" * 64, "stage": "write"},
                {"sha256": "A" * 64, "stage": "execution"},
            ],
        )
        with zipfile.ZipFile(io.BytesIO(content), "r") as source:
            entries = {item.filename: source.read(item) for item in source.infolist()}
        results_name = "results-module-01.csv"
        entries[results_name] = entries[results_name].replace(
            b"fixture-2",
            b"fixture-1",
        )
        path = self.root / "duplicate-stages.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, value in entries.items():
                archive.writestr(name, value)

        with self.assertRaisesRegex(
            PackageValidationError,
            "one row with its outcome in execution_status",
        ):
            load_package(path)

    def test_removed_payload_remains_one_non_executed_case(self) -> None:
        package = load_package(
            write_package(
                self.root / "removed.zip",
                "removed",
                [
                    {
                        "sha256": "A" * 64,
                        "stage": "write",
                        "execution": "not_executed",
                        "source_result": (
                            "delivery_success=False; "
                            "execution_reason=payload_unavailable_after_delivery"
                        ),
                    }
                ],
            )
        )
        case = next(iter(package.cases.values()))
        trial = case.trials[0]
        self.assertEqual(1, len(package.cases))
        self.assertEqual("write", case.test_stage)
        self.assertEqual("not_executed", trial.execution_status)

    def test_prevention_first_ranking_uses_shared_cases(self) -> None:
        cases_a = [
            {"sha256": "A" * 64, "detection": "detected", "action": "blocked"},
            {"sha256": "B" * 64, "detection": "detected", "action": "not_blocked"},
        ]
        cases_b = [
            {"sha256": "A" * 64, "detection": "detected", "action": "blocked"},
            {"sha256": "B" * 64, "detection": "not_detected", "action": "blocked"},
        ]
        package_a = load_package(write_package(self.root / "a.zip", "control-a", cases_a))
        package_b = load_package(write_package(self.root / "b.zip", "control-b", cases_b))
        policy = {
            "schema_version": "1.0",
            "module_weights": {"01": 100},
            "minimum_comparable_weight": 80,
            "tie_margin": 2,
        }
        result = compare_packages([package_a, package_b], policy, "fixture")
        entries = {item["control_id"]: item for item in result["ranking"]["entries"]}
        self.assertEqual(70.0, entries["control-a"]["score"])
        self.assertEqual(80.0, entries["control-b"]["score"])
        self.assertEqual("recommended", result["ranking"]["status"])
        self.assertEqual("control-b", result["ranking"]["recommended_control_id"])
        self.assertEqual(2, result["coverage"]["globally_comparable_case_count"])

    def test_repeated_trials_are_averaged_within_one_case(self) -> None:
        repeated = [
            {
                "sha256": "A" * 64,
                "trials": [
                    {"detection": "detected", "action": "blocked"},
                    {"detection": "not_detected", "action": "not_blocked"},
                ],
            }
        ]
        package_a = load_package(write_package(self.root / "a.zip", "control-a", repeated))
        package_b = load_package(write_package(self.root / "b.zip", "control-b", repeated))
        result = compare_packages([package_a, package_b])
        metrics = result["controls"][0]["metrics"]["all_cases"]
        self.assertEqual(1, metrics["case_count"])
        self.assertEqual(2, metrics["trial_count"])
        self.assertEqual(50.0, metrics["detection_rate"])
        self.assertEqual(1, metrics["inconsistent_case_count"])

    def test_module_breakdown_counts_techniques_subtests_and_outcomes(self) -> None:
        cases = [
            {
                "module_id": "01",
                "technique_id": "1.1",
                "subtest": "One",
                "sha256": "A" * 64,
                "trials": [
                    {"detection": "detected", "action": "blocked"},
                    {"detection": "not_detected", "action": "not_blocked"},
                ],
            },
            {
                "module_id": "01",
                "technique_id": "1.1",
                "subtest": "Two",
                "sha256": "B" * 64,
                "detection": "detected",
                "action": "not_blocked",
            },
            {
                "module_id": "01",
                "technique_id": "1.2",
                "subtest": "",
                "sha256": "C" * 64,
                "detection": "not_detected",
                "action": "blocked",
            },
            {
                "module_id": "02",
                "technique_id": "2.1",
                "subtest": "Macro",
                "sha256": "D" * 64,
                "detection": "detected",
                "action": "blocked",
            },
        ]
        package = load_package(
            write_package(self.root / "breakdown.zip", "control-a", cases)
        )

        result = compare_packages([package])
        breakdown = result["controls"][0]["metrics"]["modules"]
        module_one = breakdown["01"]
        self.assertEqual("Malware Delivery", module_one["module_name"])
        self.assertEqual(2, module_one["technique_count"])
        self.assertEqual(3, module_one["subtest_count"])
        self.assertEqual(4, module_one["trial_count"])
        self.assertEqual(2, module_one["detected_count"])
        self.assertEqual(2, module_one["not_detected_count"])
        self.assertEqual(2, module_one["blocked_count"])
        self.assertEqual(2, module_one["not_blocked_count"])
        self.assertEqual(1, breakdown["02"]["technique_count"])
        self.assertEqual(1, breakdown["02"]["subtest_count"])

    def test_standalone_report_prints_metrics_and_optional_ai_analysis(self) -> None:
        package = load_package(
            write_package(
                self.root / "report.zip",
                "control-a",
                [
                    {
                        "module_id": "01",
                        "technique_id": "1.1",
                        "subtest": "FixtureSubtest",
                        "sha256": "A" * 64,
                        "detection": "detected",
                        "action": "blocked",
                    }
                ],
            )
        )
        comparison = compare_packages([package], comparison_id="report-fixture")
        analysis = {
            "status": "completed",
            "independent_assessment": {
                "preferred_control_id": "control-a",
                "confidence": "medium",
                "rationale": "AI fixture rationale",
                "strengths": ["Fixture strength"],
                "concerns": ["Fixture concern"],
                "coverage_caveats": ["Fixture caveat"],
                "evidence_ids": ["EVIDENCE-FIXTURE"],
            },
            "decision_comparison": {
                "status": "disagrees",
                "python_recommended_control_id": None,
                "ai_preferred_control_id": "control-a",
                "ai_confidence": "medium",
                "summary": "AI differs from the deterministic no-winner result.",
                "evidence_ids": ["EVIDENCE-FIXTURE"],
            },
            "skills": [
                {
                    "name": "module-analysis",
                    "version": "1.0",
                    "output": {
                        "summary": "AI fixture summary",
                        "findings": [
                            {
                                "title": "Fixture finding",
                                "analysis": "AI fixture analysis",
                            }
                        ],
                    },
                }
            ]
        }

        report = render_standalone_html(comparison, analysis)
        self.assertIn("Print / Save as PDF", report)
        self.assertIn("window.print()", report)
        self.assertIn("Module technique and subtest breakdown", report)
        self.assertIn("01 - Malware Delivery", report)
        self.assertIn("1 / 1", report)
        self.assertIn("AI-assisted evidence analysis", report)
        self.assertIn("AI fixture analysis", report)
        self.assertIn("Python and independent AI decision review", report)
        self.assertIn("DISAGREES", report)
        self.assertIn("AI fixture rationale", report)

    def test_auto_scoring_uses_detection_only_for_detect_only_profiles(self) -> None:
        cases_a = [
            {
                "sha256": "A" * 64,
                "detection": "detected",
                "action": "not_blocked",
            }
        ]
        cases_b = [
            {
                "sha256": "A" * 64,
                "detection": "not_detected",
                "action": "blocked",
            }
        ]
        package_a = load_package(
            write_package(
                self.root / "a.zip",
                "control-a",
                cases_a,
                default_mode="detect_only",
            )
        )
        package_b = load_package(
            write_package(
                self.root / "b.zip",
                "control-b",
                cases_b,
                default_mode="detect_only",
            )
        )
        policy = {
            "schema_version": "1.0",
            "module_weights": {"01": 100},
            "minimum_comparable_weight": 80,
            "tie_margin": 2,
            "scoring_mode": "auto",
        }
        result = compare_packages([package_a, package_b], policy)
        entries = {
            item["control_id"]: item
            for item in result["ranking"]["entries"]
        }
        self.assertEqual("detect_only", result["scoring"]["resolved_mode"])
        self.assertEqual(1.0, result["scoring"]["detection_weight"])
        self.assertEqual(0.0, result["scoring"]["blocking_weight"])
        self.assertEqual(100.0, entries["control-a"]["score"])
        self.assertEqual(0.0, entries["control-b"]["score"])

    def test_auto_scoring_rejects_mixed_policy_modes(self) -> None:
        case = [{"sha256": "A" * 64}]
        package_a = load_package(
            write_package(
                self.root / "a.zip",
                "control-a",
                case,
                default_mode="detect_only",
            )
        )
        package_b = load_package(
            write_package(self.root / "b.zip", "control-b", case)
        )
        policy = {
            "schema_version": "1.0",
            "module_weights": {"01": 100},
            "minimum_comparable_weight": 80,
            "tie_margin": 2,
            "scoring_mode": "auto",
        }
        with self.assertRaises(PolicyValidationError) as context:
            compare_packages([package_a, package_b], policy)
        self.assertIn("mixed policy modes", str(context.exception))

        explicit = dict(policy, scoring_mode="prevention_first")
        result = compare_packages([package_a, package_b], explicit)
        self.assertEqual("prevention_first", result["scoring"]["resolved_mode"])

    def test_custom_scoring_weights_are_applied(self) -> None:
        cases_a = [
            {
                "sha256": "A" * 64,
                "detection": "detected",
                "action": "not_blocked",
            }
        ]
        cases_b = [
            {
                "sha256": "A" * 64,
                "detection": "not_detected",
                "action": "blocked",
            }
        ]
        packages = [
            load_package(write_package(self.root / "a.zip", "control-a", cases_a)),
            load_package(write_package(self.root / "b.zip", "control-b", cases_b)),
        ]
        policy = {
            "schema_version": "1.0",
            "module_weights": {"01": 100},
            "minimum_comparable_weight": 80,
            "tie_margin": 2,
            "scoring_mode": "custom",
            "detection_weight": 75,
            "blocking_weight": 25,
        }
        result = compare_packages(packages, policy)
        entries = {
            item["control_id"]: item
            for item in result["ranking"]["entries"]
        }
        self.assertEqual("custom", result["scoring"]["resolved_mode"])
        self.assertEqual(75.0, entries["control-a"]["score"])
        self.assertEqual(25.0, entries["control-b"]["score"])

    def test_custom_scoring_weights_must_total_100(self) -> None:
        case = [{"sha256": "A" * 64}]
        packages = [
            load_package(write_package(self.root / f"{name}.zip", name, case))
            for name in ("control-a", "control-b")
        ]
        with self.assertRaises(PolicyValidationError):
            compare_packages(
                packages,
                {
                    "schema_version": "1.0",
                    "module_weights": {"01": 100},
                    "minimum_comparable_weight": 80,
                    "tie_margin": 2,
                    "scoring_mode": "custom",
                    "detection_weight": 70,
                    "blocking_weight": 20,
                },
            )

    def test_legacy_block_timing_values_normalize_to_blocked(self) -> None:
        legacy_cases = [
            {
                "sha256": "A" * 64,
                "action": "blocked_before_execution",
            },
            {
                "sha256": "B" * 64,
                "action": "blocked_after_execution",
            },
        ]
        canonical_cases = [
            {"sha256": "A" * 64, "action": "blocked"},
            {"sha256": "B" * 64, "action": "blocked"},
        ]
        legacy = load_package(
            write_package(self.root / "legacy.zip", "legacy", legacy_cases)
        )
        canonical = load_package(
            write_package(
                self.root / "canonical.zip",
                "canonical",
                canonical_cases,
            )
        )
        self.assertEqual(
            {"blocked"},
            {
                trial.action_status
                for case in legacy.cases.values()
                for trial in case.trials
            },
        )
        result = compare_packages(
            [legacy, canonical],
            {
                "schema_version": "1.0",
                "module_weights": {"01": 100},
                "minimum_comparable_weight": 80,
                "tie_margin": 2,
            },
        )
        self.assertEqual(
            {"blocked": 1.0, "not_blocked": 0.0},
            result["scoring"]["blocking_credit"],
        )
        for control in result["controls"]:
            metrics = control["metrics"]["all_cases"]
            self.assertEqual(100.0, metrics["blocked_rate"])
            self.assertNotIn("blocked_before_rate", metrics)
            self.assertNotIn("blocked_after_rate", metrics)

    def test_low_weighted_coverage_is_provisional(self) -> None:
        common = {"module_id": "01", "sha256": "A" * 64}
        a_only = {"module_id": "02", "sha256": "B" * 64}
        b_only = {"module_id": "02", "sha256": "C" * 64}
        package_a = load_package(
            write_package(self.root / "a.zip", "control-a", [common, a_only])
        )
        package_b = load_package(
            write_package(self.root / "b.zip", "control-b", [common, b_only])
        )
        policy = {
            "schema_version": "1.0",
            "module_weights": {"01": 50, "02": 50},
            "minimum_comparable_weight": 80,
            "tie_margin": 2,
        }
        result = compare_packages([package_a, package_b], policy)
        self.assertEqual("provisional", result["ranking"]["status"])
        self.assertEqual(50.0, result["ranking"]["weighted_comparable_coverage"])
        self.assertIsNone(result["ranking"]["recommended_control_id"])

    def test_tie_margin_prevents_winner(self) -> None:
        case = [{"sha256": "A" * 64, "detection": "detected", "action": "not_blocked"}]
        package_a = load_package(write_package(self.root / "a.zip", "control-a", case))
        package_b = load_package(write_package(self.root / "b.zip", "control-b", case))
        policy = {
            "schema_version": "1.0",
            "module_weights": {"01": 100},
            "minimum_comparable_weight": 80,
            "tie_margin": 2,
        }
        result = compare_packages([package_a, package_b], policy)
        self.assertEqual("no_clear_winner", result["ranking"]["status"])
        self.assertIsNone(result["ranking"]["recommended_control_id"])

    def test_policy_requires_exact_submitted_modules_and_total(self) -> None:
        case = [{"sha256": "A" * 64}]
        packages = [
            load_package(write_package(self.root / f"{name}.zip", name, case))
            for name in ("control-a", "control-b")
        ]
        with self.assertRaises(PolicyValidationError):
            compare_packages(
                packages,
                {
                    "schema_version": "1.0",
                    "module_weights": {"01": 90},
                    "minimum_comparable_weight": 80,
                    "tie_margin": 2,
                },
            )

    def test_decision_priorities_are_preserved_but_do_not_change_scores(self) -> None:
        case = [{"sha256": "A" * 64}]
        packages = [
            load_package(write_package(self.root / f"{name}.zip", name, case))
            for name in ("control-a", "control-b")
        ]
        policy = {
            "schema_version": "1.0",
            "module_weights": {"01": 100},
            "minimum_comparable_weight": 80,
            "tie_margin": 2,
            "decision_priorities": (
                "Prioritize prevention and stable repeated-run outcomes."
            ),
        }
        with_priorities = compare_packages(packages, policy)
        without_priorities = compare_packages(
            packages,
            {key: value for key, value in policy.items() if key != "decision_priorities"},
        )
        self.assertEqual(
            policy["decision_priorities"],
            with_priorities["policy"]["decision_priorities"],
        )
        self.assertEqual(
            without_priorities["ranking"],
            with_priorities["ranking"],
        )

        with self.assertRaises(PolicyValidationError):
            compare_packages(
                packages,
                {**policy, "decision_priorities": "x" * 2001},
            )

    def test_duplicate_control_ids_are_rejected(self) -> None:
        case = [{"sha256": "A" * 64}]
        write_package(self.root / "a.zip", "same-control", case)
        write_package(self.root / "b.zip", "same-control", case)
        with self.assertRaises(PackageValidationError):
            load_packages([self.root / "a.zip", self.root / "b.zip"])

    def test_traversal_and_unexpected_entries_are_rejected(self) -> None:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("../control-profile.json", "{}")
        path = self.root / "traversal.zip"
        path.write_bytes(output.getvalue())
        with self.assertRaises(PackageValidationError):
            load_package(path)

        path = self.root / "unexpected.zip"
        content = package_bytes("control-a", [{"sha256": "A" * 64}])
        with zipfile.ZipFile(io.BytesIO(content), "r") as source:
            entries = {item.filename: source.read(item) for item in source.infolist()}
        with zipfile.ZipFile(path, "w") as archive:
            for name, value in entries.items():
                archive.writestr(name, value)
            archive.writestr("unexpected.txt", "not allowed")
        with self.assertRaises(PackageValidationError):
            load_package(path)

    def test_catalogue_without_results_is_ignored(self) -> None:
        content = package_bytes("control-a", [{"sha256": "A" * 64}])
        catalogue_source = package_bytes(
            "catalogue-source",
            [{"module_id": "02", "sha256": "B" * 64}],
        )
        with zipfile.ZipFile(io.BytesIO(content), "r") as source:
            entries = {item.filename: source.read(item) for item in source.infolist()}
        with zipfile.ZipFile(io.BytesIO(catalogue_source), "r") as source:
            entries["test-catalog-module-02.csv"] = source.read(
                "test-catalog-module-02.csv"
            )

        path = self.root / "catalogue-only-module.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, value in entries.items():
                archive.writestr(name, value)

        package = load_package(path)
        self.assertEqual({"01"}, set(package.module_names))

    def test_result_without_catalogue_is_rejected(self) -> None:
        content = package_bytes("control-a", [{"sha256": "A" * 64}])
        with zipfile.ZipFile(io.BytesIO(content), "r") as source:
            entries = {
                item.filename: source.read(item)
                for item in source.infolist()
                if item.filename != "test-catalog-module-01.csv"
            }

        path = self.root / "missing-catalogue.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, value in entries.items():
                archive.writestr(name, value)

        with self.assertRaisesRegex(
            PackageValidationError,
            r"missing matching catalogues: \['01'\]",
        ):
            load_package(path)

    def test_workspace_review_prompts_are_normalized(self) -> None:
        content = package_bytes(
            "control-a",
            [
                {
                    "sha256": "A" * 64,
                    "detection": "not_detected",
                    "action": "not_blocked",
                }
            ],
        )
        with zipfile.ZipFile(io.BytesIO(content), "r") as source:
            entries = {item.filename: source.read(item) for item in source.infolist()}
        results_name = "results-module-01.csv"
        results = entries[results_name].decode("utf-8")
        results = results.replace("not_detected", "detection=NOT_DETECTED")
        results = results.replace("not_blocked", "action=NOT_BLOCKED")
        results = results.replace("Fixture reviewer note", "notes=Reviewed")
        entries[results_name] = results.encode("utf-8")

        path = self.root / "review-prompts.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, value in entries.items():
                archive.writestr(name, value)

        package = load_package(path)
        trial = next(iter(package.cases.values())).trials[0]
        self.assertEqual("not_detected", trial.detection_status)
        self.assertEqual("not_blocked", trial.action_status)

    def test_service_preserves_inputs_and_writes_metrics_only_artifacts(self) -> None:
        case = [{"sha256": "A" * 64}]
        left = write_package(self.root / "a.zip", "control-a", case)
        right = write_package(self.root / "b.zip", "control-b", case)
        before = (left.read_bytes(), right.read_bytes())
        policy_path = self.root / "policy.json"
        policy_path.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "module_weights": {"01": 100},
                    "minimum_comparable_weight": 80,
                    "tie_margin": 2,
                }
            ),
            encoding="utf-8",
        )
        result = run_comparison(
            [left, right],
            policy_path=policy_path,
            output_root=self.root / "comparisons",
            comparison_id="fixture-run",
        )
        output = Path(result["output_dir"])
        for name in (
            "comparison.json",
            "technical-report.md",
            "executive-summary.md",
            "report.html",
            "run-manifest.json",
        ):
            self.assertTrue((output / name).is_file(), name)
        technical_report = (output / "technical-report.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "## Module technique and subtest breakdown",
            technical_report,
        )
        standalone_report = (output / "report.html").read_text(encoding="utf-8")
        self.assertIn("Print / Save as PDF", standalone_report)
        self.assertFalse((output / "ai-analysis.json").exists())
        self.assertEqual(before, (left.read_bytes(), right.read_bytes()))
        manifest = json.loads(
            (output / "run-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(platform.python_version(), manifest["python_version"])
        first = json.loads((output / "comparison.json").read_text(encoding="utf-8"))
        second = compare_packages(
            load_packages([left, right]),
            json.loads(policy_path.read_text(encoding="utf-8")),
            "fixture-run",
        )
        self.assertEqual(first, second)

    def test_service_completes_when_ai_assessment_is_unavailable(self) -> None:
        case = [{"sha256": "A" * 64}]
        left = write_package(self.root / "ai-left.zip", "control-a", case)
        right = write_package(self.root / "ai-right.zip", "control-b", case)
        policy = {
            "schema_version": "1.0",
            "module_weights": {"01": 100},
            "minimum_comparable_weight": 80,
            "tie_margin": 2,
        }

        with patch(
            "sct_ai.ai_workflow.run_ai_workflow",
            side_effect=RuntimeError("fixture provider unavailable"),
        ):
            result = run_comparison(
                [left, right],
                policy_path=None,
                policy=policy,
                output_root=self.root / "ai-comparisons",
                comparison_id="ai-unavailable",
                provider_name="fixture",
                model_name="fixture-model",
                provider_config_path=self.root / "provider.json",
            )

        output = Path(result["output_dir"])
        self.assertEqual("completed", result["manifest"]["status"])
        self.assertEqual("unavailable", result["manifest"]["ai_status"])
        self.assertEqual("unavailable", result["analysis"]["status"])
        self.assertEqual(
            "ai_unavailable",
            result["analysis"]["decision_comparison"]["status"],
        )
        self.assertTrue((output / "comparison.json").is_file())
        self.assertTrue((output / "ai-analysis.json").is_file())
        self.assertIn(
            "AI assessment unavailable",
            (output / "technical-report.md").read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
