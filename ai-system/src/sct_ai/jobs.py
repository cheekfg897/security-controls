"""SQLite-backed job metadata and a small in-process comparison queue."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

from .service import run_comparison
from .util import utc_now


class JobStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    comparison_id TEXT,
                    status TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    progress INTEGER NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    error TEXT
                )
                """
            )
            connection.execute(
                """
                UPDATE jobs
                SET status = 'interrupted',
                    stage = 'interrupted',
                    message = 'The application stopped before this job completed.',
                    updated_at = ?
                WHERE status IN ('queued', 'running')
                """,
                (utc_now(),),
            )

    def create(self, request_data: dict[str, Any]) -> str:
        job_id = uuid.uuid4().hex
        now = utc_now()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                    job_id, comparison_id, status, stage, progress, message,
                    created_at, updated_at, request_json, error
                ) VALUES (?, NULL, 'queued', 'queued', 0, ?, ?, ?, ?, NULL)
                """,
                (
                    job_id,
                    "Waiting for an available comparison worker.",
                    now,
                    now,
                    json.dumps(request_data, sort_keys=True),
                ),
            )
        return job_id

    def update(
        self,
        job_id: str,
        *,
        comparison_id: str | None = None,
        status: str | None = None,
        stage: str | None = None,
        progress: int | None = None,
        message: str | None = None,
        error: str | None = None,
    ) -> None:
        assignments = ["updated_at = ?"]
        values: list[Any] = [utc_now()]
        for name, value in (
            ("comparison_id", comparison_id),
            ("status", status),
            ("stage", stage),
            ("progress", progress),
            ("message", message),
            ("error", error),
        ):
            if value is not None:
                assignments.append(f"{name} = ?")
                values.append(value)
        values.append(job_id)
        with self._lock, self._connect() as connection:
            connection.execute(
                f"UPDATE jobs SET {', '.join(assignments)} WHERE job_id = ?",
                values,
            )

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_by_comparison(self, comparison_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM jobs WHERE comparison_id = ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (comparison_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def sync_manifests(self, output_root: Path) -> None:
        for manifest_path in sorted(output_root.glob("*/run-manifest.json")):
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                comparison_id = str(manifest["comparison_id"])
                status = str(manifest["status"])
            except (OSError, ValueError, KeyError, TypeError):
                continue
            if self.get_by_comparison(comparison_id):
                continue
            timestamp = str(manifest.get("completed_at") or manifest.get("started_at") or utc_now())
            job_id = f"manifest-{comparison_id}"
            with self._lock, self._connect() as connection:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO jobs (
                        job_id, comparison_id, status, stage, progress, message,
                        created_at, updated_at, request_json, error
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}', ?)
                    """,
                    (
                        job_id,
                        comparison_id,
                        status,
                        "complete" if status == "completed" else status,
                        100,
                        "Imported from run-manifest.json.",
                        timestamp,
                        timestamp,
                        manifest.get("error"),
                    ),
                )


class ComparisonJobManager:
    def __init__(
        self,
        store: JobStore,
        output_root: Path,
        max_workers: int = 1,
    ) -> None:
        self.store = store
        self.output_root = output_root
        self.executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="sct-comparison",
        )

    def submit(
        self,
        request_data: dict[str, Any],
        *,
        cleanup: Callable[[], None] | None = None,
    ) -> str:
        job_id = self.store.create(request_data)
        self.executor.submit(self._run, job_id, request_data, cleanup)
        return job_id

    def _run(
        self,
        job_id: str,
        request_data: dict[str, Any],
        cleanup: Callable[[], None] | None,
    ) -> None:
        self.store.update(
            job_id,
            status="running",
            stage="validation",
            progress=1,
            message="Starting comparison.",
        )

        def progress(stage: str, percent: int, message: str) -> None:
            self.store.update(
                job_id,
                status="running",
                stage=stage,
                progress=percent,
                message=message,
            )

        try:
            result = run_comparison(
                request_data["package_paths"],
                policy_path=None,
                policy=request_data["policy"],
                output_root=self.output_root,
                comparison_id=request_data.get("comparison_id"),
                provider_name=request_data.get("provider_name"),
                model_name=request_data.get("model_name"),
                provider_config_path=request_data.get("provider_config_path"),
                progress_callback=progress,
            )
            self.store.update(
                job_id,
                comparison_id=result["comparison_id"],
                status="completed",
                stage="complete",
                progress=100,
                message=(
                    "Comparison completed; the independent AI assessment "
                    "was unavailable."
                    if result["manifest"].get("ai_status") == "unavailable"
                    else "Comparison completed."
                ),
                error=result["manifest"].get("ai_error"),
            )
        except Exception as exc:
            self.store.update(
                job_id,
                status="failed",
                stage="failed",
                progress=100,
                message="Comparison failed.",
                error=str(exc),
            )
        finally:
            if cleanup:
                cleanup()
