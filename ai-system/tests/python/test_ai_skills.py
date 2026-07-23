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
        for skill_name in SKILL_ORDER:
            skill = _load_skill(skill_name)
            payload = _skill_payload(skill_name, self.comparison, previous, False)
            evidence_id = payload["evidence"][0]["evidence_id"]
            recommendation = None
            if skill_name == "qualified-recommendation":
                recommendation = {
                    "control_id": self.comparison["ranking"]["recommended_control_id"],
                    "rationale": "The deterministic decision and its caveats are preserved.",
                    "evidence_ids": [evidence_id],
                }
            response = {
                "summary": "The supplied evidence was reviewed.",
                "findings": [
                    {
                        "title": "Evidence-backed context",
                        "analysis": "The finding is limited to the supplied evidence.",
                        "severity": "context",
                        "controls": ["control-a"],
                        "evidence_ids": [evidence_id],
                    }
                ],
                "recommendation": recommendation,
            }

            class FakeModel:
                def invoke(self, messages: object) -> object:
                    return type("Response", (), {"content": json.dumps(response)})()

            output = _invoke_skill(FakeModel(), skill, payload, self.comparison)
            previous.append(
                {"name": skill_name, "version": skill["version"], "output": output}
            )
        self.assertEqual(4, len(previous))

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


if __name__ == "__main__":
    unittest.main()
