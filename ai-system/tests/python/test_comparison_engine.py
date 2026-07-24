from __future__ import annotations

import io
import json
import platform
import tempfile
import unittest
import zipfile
from pathlib import Path

from sct_ai.errors import PackageValidationError, PolicyValidationError
from sct_ai.metrics import compare_packages
from sct_ai.packages import load_package, load_packages
from sct_ai.service import run_comparison

from .helpers import package_bytes, write_package


class ComparisonEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

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


if __name__ == "__main__":
    unittest.main()
