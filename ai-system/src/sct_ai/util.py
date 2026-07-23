"""Small deterministic helpers shared by the comparison engine."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


COMPARISON_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def stable_id(prefix: str, *parts: str, length: int = 20) -> str:
    payload = "\x1f".join(parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(payload).hexdigest()[:length].upper()}"


def dump_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )


def load_json_no_duplicates(text: str, context: str) -> dict[str, Any]:
    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{context} contains duplicate JSON key '{key}'.")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"{context} contains invalid numeric constant '{value}'.")

    value = json.loads(
        text,
        object_pairs_hook=pairs_hook,
        parse_constant=reject_constant,
    )
    if not isinstance(value, dict):
        raise ValueError(f"{context} must contain a JSON object.")
    return value


def validate_comparison_id(value: str) -> str:
    normalized = value.strip().lower()
    if not COMPARISON_ID_PATTERN.fullmatch(normalized):
        raise ValueError(
            "Comparison id must start with a lowercase letter or digit and use "
            "only lowercase letters, digits, dots, underscores, or hyphens "
            "(maximum 80 characters)."
        )
    return normalized
