from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from sct_ai.metrics import compare_packages
from sct_ai.packages import load_package

from .helpers import write_package


HAS_AI_DEPS = bool(
    importlib.util.find_spec("pydantic")
    and importlib.util.find_spec("langchain_core")
)


@unittest.skipUnless(HAS_AI_DEPS, "AI test dependencies are not installed")
class AISkillTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        cases = [{"sha256": "A" * 64}]
        packages = [
            load_package(write_package(root / f"{name}.zip", name, cases))
            for name in ("control-a", "control-b")
        ]
        self.comparison = compare_packages(
            packages,
            {
                "schema_version": "1.0",
                "module_weights": {"01": 100},
                "minimum_comparable_weight": 80,
                "tie_margin": 2,
                "decision_priorities": (
                    "Prioritize prevention and stable repeated-run outcomes."
                ),
            },
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_every_runtime_skill_accepts_valid_fake_model_output(self) -> None:
        from sct_ai.ai_workflow import (
            SKILL_ORDER,
            _invoke_skill,
            _load_skill,
            _skill_payload,
        )

        previous = []
        payloads = {}
        for skill_name in SKILL_ORDER:
            skill = _load_skill(skill_name)
            payload = _skill_payload(skill_name, self.comparison, previous, False)
            payloads[skill_name] = payload
            evidence_id = payload["evidence"][0]["evidence_id"]
            if skill_name == "independent-assessment":
                response = {
                    "preferred_control_id": "control-a",
                    "confidence": "medium",
                    "rationale": "Control A is the advisory preference.",
                    "strengths": ["Supported strength."],
                    "concerns": ["Supported concern."],
                    "coverage_caveats": ["Coverage remains limited."],
                    "evidence_ids": [evidence_id],
                }
            elif skill_name == "decision-reconciliation":
                response = {
                    "status": "disagrees",
                    "python_recommended_control_id": None,
                    "ai_preferred_control_id": "control-a",
                    "summary": "The advisory AI preference differs from the tie.",
                    "evidence_ids": [evidence_id],
                }
            else:
                response = {
                    "summary": "The supplied evidence was reviewed.",
                    "findings": [
                        {
                            "title": "Evidence-backed context",
                            "analysis": "The finding is limited to supplied evidence.",
                            "severity": "context",
                            "controls": ["control-a"],
                            "evidence_ids": [evidence_id],
                        }
                    ],
                    "recommendation": None,
                }

            class FakeModel:
                def invoke(self, messages: object) -> object:
                    return type("Response", (), {"content": json.dumps(response)})()

            output = _invoke_skill(FakeModel(), skill, payload, self.comparison)
            previous.append(
                {"name": skill_name, "version": skill["version"], "output": output}
            )
        self.assertEqual(5, len(previous))
        for skill_name in SKILL_ORDER[:4]:
            self.assertNotIn("ranking", payloads[skill_name])
            self.assertNotIn(
                "ranking",
                {item["type"] for item in payloads[skill_name]["evidence"]},
            )
        self.assertIn("ranking", payloads["decision-reconciliation"])
        self.assertEqual(
            "control-a",
            payloads["decision-reconciliation"]["independent_assessment"][
                "preferred_control_id"
            ],
        )
        profile_payload = payloads["profile-context"]
        self.assertEqual(
            "1.0",
            profile_payload["controls"][0]["control"]["product_version"],
        )
        self.assertEqual(
            [],
            profile_payload["controls"][0]["policy"]["settings"],
        )
        self.assertEqual(
            "Prioritize prevention and stable repeated-run outcomes.",
            profile_payload["decision_context"]["decision_priorities"],
        )
        serialized = json.dumps(payloads["independent-assessment"])
        self.assertNotIn("Fixture reviewer note", serialized)
        self.assertNotIn("source_result", serialized)

    def test_unknown_evidence_triggers_one_correction(self) -> None:
        from sct_ai.ai_workflow import _invoke_skill, _load_skill, _skill_payload

        skill = _load_skill("profile-context")
        payload = _skill_payload("profile-context", self.comparison, [], False)
        evidence_id = payload["evidence"][0]["evidence_id"]
        valid = {
            "summary": "Evidence reviewed.",
            "findings": [
                {
                    "title": "Context",
                    "analysis": "Supported context.",
                    "severity": "context",
                    "controls": ["control-a"],
                    "evidence_ids": [evidence_id],
                }
            ],
            "recommendation": None,
        }
        invalid = json.loads(json.dumps(valid))
        invalid["findings"][0]["evidence_ids"] = ["UNKNOWN"]

        class CorrectingModel:
            calls = 0

            def invoke(self, messages: object) -> object:
                self.calls += 1
                content = invalid if self.calls == 1 else valid
                return type("Response", (), {"content": json.dumps(content)})()

        model = CorrectingModel()
        _invoke_skill(model, skill, payload, self.comparison)
        self.assertEqual(2, model.calls)

    def test_control_ids_alias_is_normalized_to_controls(self) -> None:
        from sct_ai.ai_workflow import _invoke_skill, _load_skill, _skill_payload

        skill = _load_skill("profile-context")
        payload = _skill_payload("profile-context", self.comparison, [], False)
        evidence_id = payload["evidence"][0]["evidence_id"]
        response = {
            "summary": "Evidence reviewed.",
            "findings": [
                {
                    "title": "Context",
                    "analysis": "Supported context.",
                    "severity": "context",
                    "controls": ["control-a"],
                    "control_ids": ["control-a"],
                    "evidence_ids": [evidence_id],
                }
            ],
            "recommendation": None,
        }

        class AliasModel:
            calls = 0

            def invoke(self, messages: object) -> object:
                self.calls += 1
                return type("Response", (), {"content": json.dumps(response)})()

        model = AliasModel()
        output = _invoke_skill(model, skill, payload, self.comparison)
        self.assertEqual(1, model.calls)
        self.assertEqual(["control-a"], output["findings"][0]["controls"])
        self.assertNotIn("control_ids", output["findings"][0])

    def test_independent_assessment_may_disagree_with_no_winner(self) -> None:
        from sct_ai.ai_workflow import _invoke_skill, _load_skill, _skill_payload

        skill = _load_skill("independent-assessment")
        payload = _skill_payload(
            "independent-assessment",
            self.comparison,
            [],
            False,
        )
        evidence_id = payload["evidence"][0]["evidence_id"]
        response = {
            "preferred_control_id": "control-b",
            "confidence": "low",
            "rationale": "The advisory assessment can prefer a known control.",
            "strengths": [],
            "concerns": ["Python found no clear winner."],
            "coverage_caveats": [],
            "evidence_ids": [evidence_id],
        }

        class FakeModel:
            def invoke(self, messages: object) -> object:
                return type("Response", (), {"content": json.dumps(response)})()

        output = _invoke_skill(FakeModel(), skill, payload, self.comparison)
        self.assertIsNone(self.comparison["ranking"]["recommended_control_id"])
        self.assertEqual("control-b", output["preferred_control_id"])

    def test_reconciliation_cannot_change_either_decision(self) -> None:
        from sct_ai.ai_workflow import _invoke_skill, _load_skill, _skill_payload

        evidence_id = self.comparison["evidence"][0]["evidence_id"]
        previous = [
            {
                "name": "independent-assessment",
                "version": "1.0.0",
                "output": {
                    "preferred_control_id": "control-a",
                    "confidence": "medium",
                    "rationale": "Advisory preference.",
                    "strengths": [],
                    "concerns": [],
                    "coverage_caveats": [],
                    "evidence_ids": [evidence_id],
                },
            }
        ]
        skill = _load_skill("decision-reconciliation")
        payload = _skill_payload(
            "decision-reconciliation",
            self.comparison,
            previous,
            False,
        )
        invalid = {
            "status": "agrees",
            "python_recommended_control_id": "control-a",
            "ai_preferred_control_id": "control-a",
            "summary": "Invalid changed decision.",
            "evidence_ids": [evidence_id],
        }

        class InvalidModel:
            def invoke(self, messages: object) -> object:
                return type("Response", (), {"content": json.dumps(invalid)})()

        with self.assertRaisesRegex(
            Exception,
            "failed validation after one correction",
        ):
            _invoke_skill(InvalidModel(), skill, payload, self.comparison)


if __name__ == "__main__":
    unittest.main()
