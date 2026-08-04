from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sct_ai.cli import _parser
from sct_ai.environment import load_environment_file
from sct_ai.errors import SCTComparisonError


class RuntimeCompatibilityTests(unittest.TestCase):
    def test_supported_python_runtime(self) -> None:
        self.assertGreaterEqual(sys.version_info, (3, 11))
        self.assertLess(sys.version_info, (4, 0))

    def test_python_web_command_accepts_host_paths(self) -> None:
        arguments = _parser().parse_args(
            [
                "web",
                "--repository-root",
                "repository",
                "--system-root",
                "runtime-data",
            ]
        )
        self.assertEqual("repository", arguments.repository_root)
        self.assertEqual("runtime-data", arguments.system_root)

    def test_python_web_accepts_provider_config_from_environment(self) -> None:
        with patch.dict(
            os.environ,
            {"SCT_PROVIDER_CONFIG": "provider-config.json"},
            clear=False,
        ):
            arguments = _parser().parse_args(["web"])
        self.assertEqual("provider-config.json", arguments.provider_config)

    def test_environment_file_loads_values_without_overriding_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment_path = Path(directory) / ".env"
            environment_path.write_text(
                "# test values\n"
                "OPENAI_API_KEY='file-key'\n"
                "SCT_EXISTING_VALUE=file-value\n",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"SCT_EXISTING_VALUE": "process-value"},
                clear=True,
            ):
                loaded = load_environment_file(environment_path)
                self.assertEqual("file-key", os.environ["OPENAI_API_KEY"])
                self.assertEqual("process-value", os.environ["SCT_EXISTING_VALUE"])
                self.assertEqual(["OPENAI_API_KEY"], loaded)

    def test_environment_file_rejects_invalid_assignment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment_path = Path(directory) / ".env"
            environment_path.write_text("not an assignment\n", encoding="utf-8")
            with self.assertRaises(SCTComparisonError):
                load_environment_file(environment_path)


if __name__ == "__main__":
    unittest.main()
