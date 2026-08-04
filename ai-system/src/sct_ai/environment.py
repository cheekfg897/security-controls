"""Strict loading of repository-local environment variables."""

from __future__ import annotations

import os
import re
from pathlib import Path

from .errors import SCTComparisonError


_ASSIGNMENT = re.compile(
    r"(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>.*)"
)


def load_environment_file(path: Path, *, override: bool = False) -> list[str]:
    """Load a small, strict dotenv file without exposing any values."""
    if not path.is_file():
        return []

    loaded: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        raise SCTComparisonError(f"Environment file could not be read: {path}") from exc

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        match = _ASSIGNMENT.fullmatch(line)
        if match is None:
            raise SCTComparisonError(
                f"Environment file has an invalid assignment on line {line_number}: {path}"
            )

        name = match.group("name")
        value = match.group("value").strip()
        if value.startswith(("'", '"')):
            quote = value[0]
            if len(value) < 2 or not value.endswith(quote):
                raise SCTComparisonError(
                    f"Environment file has an unterminated quoted value on line "
                    f"{line_number}: {path}"
                )
            value = value[1:-1]

        if override or name not in os.environ:
            os.environ[name] = value
            loaded.append(name)

    return loaded


def load_repository_environment() -> Path | None:
    """Find the source checkout and load its root .env file when present."""
    candidates: list[Path] = []
    current = Path.cwd().resolve()
    candidates.extend((current, *current.parents))

    source_root = Path(__file__).resolve().parents[3]
    if source_root not in candidates:
        candidates.append(source_root)

    for candidate in candidates:
        if (candidate / "ai-system" / "pyproject.toml").is_file():
            environment_path = candidate / ".env"
            load_environment_file(environment_path)
            return environment_path if environment_path.is_file() else None
    return None
