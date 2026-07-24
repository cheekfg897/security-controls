from __future__ import annotations

import sys
import unittest

from sct_ai.cli import _parser


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


if __name__ == "__main__":
    unittest.main()
