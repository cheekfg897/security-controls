from __future__ import annotations

import importlib.util
import re
import tempfile
import unittest
from pathlib import Path

from sct_ai.jobs import JobStore
from sct_ai.web import validate_web_binding

from .helpers import package_bytes


HAS_WEB_DEPS = bool(
    importlib.util.find_spec("fastapi")
    and importlib.util.find_spec("httpx")
)


class WebSurfaceTests(unittest.TestCase):
    def test_non_loopback_requires_shared_mode(self) -> None:
        validate_web_binding("127.0.0.1", 8000, False)
        validate_web_binding("0.0.0.0", 8000, True)
        with self.assertRaises(RuntimeError):
            validate_web_binding("0.0.0.0", 8000, False)

    def test_queued_jobs_become_interrupted_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            database = Path(value) / "index.sqlite3"
            store = JobStore(database)
            job_id = store.create({"fixture": True})
            restarted = JobStore(database)
            self.assertEqual("interrupted", restarted.get(job_id)["status"])

    @unittest.skipUnless(HAS_WEB_DEPS, "Web test dependencies are not installed")
    def test_home_security_headers_and_package_preflight(self) -> None:
        from fastapi.testclient import TestClient
        from sct_ai.web import create_app

        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            system_root = root / "ai-system"
            system_root.mkdir()
            (root / "submissions").mkdir()
            module = root / "scenarios" / "01-fixture"
            module.mkdir(parents=True)
            (module / "module.json").write_text(
                '{"id":"01","name":"Fixture","techniques":[]}',
                encoding="utf-8",
            )
            app = create_app(
                repository_root=root,
                system_root=system_root,
            )
            with TestClient(app) as client:
                response = client.get("/")
                self.assertEqual(200, response.status_code)
                self.assertIn("default-src 'self'", response.headers["content-security-policy"])
                self.assertNotIn("https://", response.text)
                token_match = re.search(
                    r'name="csrf_token" value="([^"]+)"',
                    response.text,
                )
                self.assertIsNotNone(token_match)
                token = token_match.group(1)
                response = client.post(
                    "/comparisons/validate",
                    data={"csrf_token": token},
                    files=[
                        (
                            "uploads",
                            ("a.zip", package_bytes("control-a", [{"sha256": "A" * 64}]), "application/zip"),
                        ),
                        (
                            "uploads",
                            ("b.zip", package_bytes("control-b", [{"sha256": "A" * 64}]), "application/zip"),
                        ),
                    ],
                )
                self.assertEqual(200, response.status_code, response.text)
                self.assertTrue(response.json()["valid"])
                self.assertEqual(2, len(response.json()["packages"]))
                htmx = client.get("/static/htmx.min.js")
                self.assertEqual(200, htmx.status_code)
                self.assertIn("2.0.10", htmx.text)


if __name__ == "__main__":
    unittest.main()
