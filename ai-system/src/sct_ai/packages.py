"""Safe loading and normalization of validated SCT comparison ZIPs."""

from __future__ import annotations

import csv
import io
import json
import re
import stat
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import PackageValidationError
from .util import load_json_no_duplicates, sha256_file, stable_id


MAX_PACKAGE_BYTES = 100 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 250 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1000

RESULT_COLUMNS = (
    "timestamp",
    "run_id",
    "technique_id",
    "technique_name",
    "subtest",
    "test_script",
    "test_input",
    "test_input_sha256",
    "delivery_method",
    "test_stage",
    "source_result",
    "execution_status",
    "detection_status",
    "action_status",
    "reviewer_notes",
    "notes",
)

CATALOG_COLUMNS = (
    "module_id",
    "module_name",
    "technique_id",
    "technique_name",
    "subtest",
    "attack_id",
    "test_script",
    "objective",
    "what_it_does",
    "success_indicator",
    "status",
)

RESULT_NAME = re.compile(r"^results-module-(\d{2})\.csv$")
CATALOG_NAME = re.compile(r"^test-catalog-module-(\d{2})\.csv$")
SHA256_PATTERN = re.compile(r"^[0-9A-Fa-f]{64}$")
CONTROL_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


@dataclass(frozen=True)
class Trial:
    trial_id: str
    timestamp: str
    run_id: str
    execution_status: str
    detection_status: str
    action_status: str


@dataclass
class NormalizedCase:
    case_id: str
    case_key: str
    module_id: str
    module_name: str
    technique_id: str
    technique_name: str
    subtest: str
    test_stage: str
    delivery_method: str
    input_identity: str
    attack_id: str
    objective: str
    what_it_does: str
    success_indicator: str
    trials: list[Trial] = field(default_factory=list)


@dataclass
class PackageData:
    path: Path
    package_sha256: str
    control_id: str
    display_name: str
    profile_summary: dict[str, Any]
    cases: dict[str, NormalizedCase]
    module_names: dict[str, str]

    def preflight_summary(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "package_sha256": self.package_sha256,
            "control_id": self.control_id,
            "display_name": self.display_name,
            "modules": [
                {"module_id": module_id, "module_name": self.module_names[module_id]}
                for module_id in sorted(self.module_names)
            ],
            "case_count": len(self.cases),
            "trial_count": sum(len(case.trials) for case in self.cases.values()),
        }


def _fail(package: Path, message: str) -> PackageValidationError:
    return PackageValidationError(f"{package.name}: {message}")


def _validate_archive_entry(package: Path, info: zipfile.ZipInfo) -> None:
    name = info.filename
    if not name or "\\" in name:
        raise _fail(package, f"archive entry has an invalid path: {name!r}")
    pure = PurePosixPath(name)
    if (
        pure.is_absolute()
        or len(pure.parts) != 1
        or any(part in ("", ".", "..") for part in pure.parts)
        or ":" in name
    ):
        raise _fail(package, f"archive entry must be a root-level file: {name!r}")
    if info.is_dir():
        raise _fail(package, f"archive directories are not allowed: {name!r}")
    mode = info.external_attr >> 16
    if mode and stat.S_ISLNK(mode):
        raise _fail(package, f"archive symbolic links are not allowed: {name!r}")
    if info.flag_bits & 0x1:
        raise _fail(package, f"encrypted archive entries are not supported: {name!r}")
    if info.file_size > MAX_UNCOMPRESSED_BYTES:
        raise _fail(package, f"archive entry is too large: {name!r}")
    if (
        info.file_size > 0
        and info.compress_size > 0
        and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO
    ):
        raise _fail(package, f"archive entry has an unsafe compression ratio: {name!r}")


def _read_text(package: Path, archive: zipfile.ZipFile, name: str) -> str:
    try:
        with archive.open(name, "r") as handle:
            return handle.read(MAX_UNCOMPRESSED_BYTES + 1).decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise _fail(package, f"{name} is not valid UTF-8") from exc


def _require_text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} must be a non-empty string.")
    return value.strip()


def _validate_profile(profile: dict[str, Any]) -> dict[str, Any]:
    allowed_root = {"schema_version", "control", "policy", "local_logs", "notes"}
    unknown = set(profile) - allowed_root
    if unknown:
        raise ValueError(f"control-profile.json has unknown fields: {sorted(unknown)}")
    if profile.get("schema_version") != "1.0":
        raise ValueError("control-profile.json schema_version must be '1.0'.")

    control = profile.get("control")
    if not isinstance(control, dict):
        raise ValueError("control-profile.json control must be an object.")
    allowed_control = {
        "id",
        "display_name",
        "vendor",
        "product",
        "product_version",
        "agent_version",
    }
    unknown = set(control) - allowed_control
    if unknown:
        raise ValueError(f"control has unknown fields: {sorted(unknown)}")
    normalized_control = {
        name: _require_text(control.get(name), f"control.{name}")
        for name in allowed_control
    }
    if not CONTROL_ID_PATTERN.fullmatch(normalized_control["id"]):
        raise ValueError("control.id has an invalid format.")

    policy = profile.get("policy")
    if not isinstance(policy, dict):
        raise ValueError("control-profile.json policy must be an object.")
    allowed_policy = {"name", "default_mode", "settings", "exclusions"}
    unknown = set(policy) - allowed_policy
    if unknown:
        raise ValueError(f"policy has unknown fields: {sorted(unknown)}")
    policy_name = _require_text(policy.get("name"), "policy.name")
    default_mode = policy.get("default_mode")
    if default_mode not in {"detect_only", "detect_and_block", "custom"}:
        raise ValueError("policy.default_mode is invalid.")

    settings_value = policy.get("settings", [])
    if not isinstance(settings_value, list):
        raise ValueError("policy.settings must be an array.")
    settings: list[dict[str, Any]] = []
    for index, setting in enumerate(settings_value):
        if not isinstance(setting, dict):
            raise ValueError(f"policy.settings[{index}] must be an object.")
        unknown = set(setting) - {"name", "value", "scope", "notes"}
        if unknown:
            raise ValueError(
                f"policy.settings[{index}] has unknown fields: {sorted(unknown)}"
            )
        if "value" not in setting:
            raise ValueError(f"policy.settings[{index}] is missing value.")
        if "notes" in setting and not isinstance(setting["notes"], str):
            raise ValueError(f"policy.settings[{index}].notes must be a string.")
        settings.append(
            {
                "name": _require_text(setting.get("name"), f"policy.settings[{index}].name"),
                "value": setting.get("value"),
                "scope": _require_text(
                    setting.get("scope"), f"policy.settings[{index}].scope"
                ),
            }
        )

    exclusions = policy.get("exclusions", [])
    if not isinstance(exclusions, list) or any(
        not isinstance(item, str) or not item.strip() for item in exclusions
    ):
        raise ValueError("policy.exclusions must contain only non-empty strings.")

    local_logs = profile.get("local_logs", [])
    if not isinstance(local_logs, list):
        raise ValueError("local_logs must be an array.")
    for index, local_log in enumerate(local_logs):
        if not isinstance(local_log, dict):
            raise ValueError(f"local_logs[{index}] must be an object.")
        unknown = set(local_log) - {"name", "path", "format"}
        if unknown:
            raise ValueError(
                f"local_logs[{index}] has unknown fields: {sorted(unknown)}"
            )
        _require_text(local_log.get("name"), f"local_logs[{index}].name")
        _require_text(local_log.get("path"), f"local_logs[{index}].path")
        if local_log.get("format") not in {
            "text",
            "csv",
            "json",
            "jsonl",
            "xml",
            "evtx",
        }:
            raise ValueError(f"local_logs[{index}].format is invalid.")
    if "notes" in profile and not isinstance(profile["notes"], str):
        raise ValueError("control-profile.json notes must be a string.")

    return {
        "control": normalized_control,
        "policy": {
            "name": policy_name,
            "default_mode": default_mode,
            "settings": settings,
            "exclusion_count": len(exclusions),
        },
    }


def _parse_csv(
    package: Path,
    name: str,
    text: str,
    expected_columns: tuple[str, ...],
) -> list[dict[str, str]]:
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if tuple(reader.fieldnames or ()) != expected_columns:
        raise _fail(
            package,
            f"{name} has an unexpected schema; expected: {', '.join(expected_columns)}",
        )
    rows: list[dict[str, str]] = []
    for line_number, row in enumerate(reader, start=2):
        if None in row or any(value is None for value in row.values()):
            raise _fail(package, f"{name} line {line_number} is malformed")
        rows.append({key: value.strip() for key, value in row.items()})
    if not rows:
        raise _fail(package, f"{name} contains no rows")
    return rows


def _validate_result_row(
    package: Path,
    filename: str,
    line_number: int,
    module_id: str,
    row: dict[str, str],
) -> None:
    context = f"{filename} line {line_number}"
    for name in (
        "timestamp",
        "run_id",
        "technique_id",
        "technique_name",
        "test_script",
        "test_stage",
    ):
        if not row[name]:
            raise _fail(package, f"{context} is missing '{name}'")
    try:
        datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise _fail(package, f"{context} has an invalid timestamp") from exc
    try:
        technique_module = f"{int(row['technique_id'].split('.')[0]):02d}"
    except (ValueError, IndexError) as exc:
        raise _fail(package, f"{context} has an invalid technique_id") from exc
    if technique_module != module_id:
        raise _fail(package, f"{context} does not belong to Module {module_id}")
    if row["execution_status"] not in {"", "executed", "not_executed"}:
        raise _fail(package, f"{context} has an invalid execution_status")
    if row["detection_status"] not in {"detected", "not_detected"}:
        raise _fail(package, f"{context} has an invalid detection_status")
    if row["action_status"] not in {
        "blocked_before_execution",
        "blocked_after_execution",
        "not_blocked",
    }:
        raise _fail(package, f"{context} has an invalid action_status")
    if (
        row["execution_status"] == "executed"
        and row["action_status"] == "blocked_before_execution"
    ):
        raise _fail(package, f"{context} cannot be executed and blocked before execution")
    if row["action_status"] == "blocked_after_execution" and row[
        "execution_status"
    ] != "executed":
        raise _fail(
            package,
            f"{context} can be blocked after execution only when execution occurred",
        )
    if row["test_input_sha256"] and not SHA256_PATTERN.fullmatch(
        row["test_input_sha256"]
    ):
        raise _fail(package, f"{context} has an invalid test_input_sha256")


def _input_identity(row: dict[str, str]) -> str:
    if row["test_input_sha256"]:
        return f"sha256:{row['test_input_sha256'].upper()}"
    if row["test_input"]:
        return stable_id("opaque-input", row["test_input"].strip().casefold())
    return "none"


def _make_case_key(
    module_id: str,
    row: dict[str, str],
    input_identity: str,
) -> str:
    return "|".join(
        (
            module_id,
            row["technique_id"].strip().casefold(),
            row["subtest"].strip().casefold(),
            row["test_stage"].strip().casefold(),
            row["delivery_method"].strip().casefold(),
            input_identity,
        )
    )


def load_package(path: str | Path) -> PackageData:
    package = Path(path).resolve()
    if not package.is_file():
        raise PackageValidationError(f"Comparison package does not exist: {package}")
    if package.suffix.lower() != ".zip":
        raise _fail(package, "comparison package must be a ZIP file")
    if package.stat().st_size > MAX_PACKAGE_BYTES:
        raise _fail(package, "comparison package exceeds the 100 MB limit")

    package_hash = sha256_file(package)
    try:
        archive = zipfile.ZipFile(package, "r")
    except (zipfile.BadZipFile, OSError) as exc:
        raise _fail(package, "comparison package is not a readable ZIP") from exc

    with archive:
        infos = archive.infolist()
        if not infos:
            raise _fail(package, "comparison package is empty")
        if sum(info.file_size for info in infos) > MAX_UNCOMPRESSED_BYTES:
            raise _fail(package, "uncompressed package exceeds the 250 MB limit")
        seen: set[str] = set()
        for info in infos:
            _validate_archive_entry(package, info)
            folded = info.filename.casefold()
            if folded in seen:
                raise _fail(package, f"archive contains duplicate entry '{info.filename}'")
            seen.add(folded)

        names = {info.filename for info in infos}
        result_modules = {
            match.group(1): name
            for name in names
            if (match := RESULT_NAME.fullmatch(name))
        }
        catalog_modules = {
            match.group(1): name
            for name in names
            if (match := CATALOG_NAME.fullmatch(name))
        }
        expected = {"control-profile.json"} | set(result_modules.values()) | set(
            catalog_modules.values()
        )
        unexpected = names - expected
        if unexpected:
            raise _fail(
                package, f"archive contains unexpected entries: {sorted(unexpected)}"
            )
        if "control-profile.json" not in names:
            raise _fail(package, "archive is missing control-profile.json")
        if not result_modules:
            raise _fail(package, "archive contains no module result files")
        if set(result_modules) != set(catalog_modules):
            raise _fail(
                package,
                "every module result file must have exactly one matching catalogue",
            )

        try:
            profile = load_json_no_duplicates(
                _read_text(package, archive, "control-profile.json"),
                "control-profile.json",
            )
            profile_summary = _validate_profile(profile)
        except (json.JSONDecodeError, ValueError) as exc:
            raise _fail(package, str(exc)) from exc

        cases: dict[str, NormalizedCase] = {}
        module_names: dict[str, str] = {}
        for module_id in sorted(result_modules):
            catalog_name = catalog_modules[module_id]
            catalog_rows = _parse_csv(
                package,
                catalog_name,
                _read_text(package, archive, catalog_name),
                CATALOG_COLUMNS,
            )
            catalog: dict[tuple[str, str], dict[str, str]] = {}
            for line_number, row in enumerate(catalog_rows, start=2):
                context = f"{catalog_name} line {line_number}"
                for field_name in (
                    "module_id",
                    "module_name",
                    "technique_id",
                    "technique_name",
                    "attack_id",
                    "test_script",
                    "objective",
                    "what_it_does",
                    "success_indicator",
                ):
                    if not row[field_name]:
                        raise _fail(package, f"{context} is missing '{field_name}'")
                if row["module_id"] != module_id:
                    raise _fail(package, f"{context} has the wrong module_id")
                key = (row["technique_id"], row["subtest"])
                if key in catalog:
                    raise _fail(package, f"{catalog_name} has duplicate row {key!r}")
                catalog[key] = row
                previous_name = module_names.setdefault(module_id, row["module_name"])
                if previous_name != row["module_name"]:
                    raise _fail(package, f"{catalog_name} has inconsistent module names")

            results_name = result_modules[module_id]
            result_rows = _parse_csv(
                package,
                results_name,
                _read_text(package, archive, results_name),
                RESULT_COLUMNS,
            )
            for line_number, row in enumerate(result_rows, start=2):
                _validate_result_row(
                    package, results_name, line_number, module_id, row
                )
                catalog_key = (row["technique_id"], row["subtest"])
                catalog_row = catalog.get(catalog_key)
                if catalog_row is None:
                    raise _fail(
                        package,
                        f"{results_name} line {line_number} has no matching catalogue row",
                    )
                input_identity = _input_identity(row)
                case_key = _make_case_key(module_id, row, input_identity)
                case = cases.get(case_key)
                if case is None:
                    case = NormalizedCase(
                        case_id=stable_id("CASE", case_key),
                        case_key=case_key,
                        module_id=module_id,
                        module_name=catalog_row["module_name"],
                        technique_id=row["technique_id"],
                        technique_name=catalog_row["technique_name"],
                        subtest=row["subtest"],
                        test_stage=row["test_stage"],
                        delivery_method=row["delivery_method"],
                        input_identity=input_identity,
                        attack_id=catalog_row["attack_id"],
                        objective=catalog_row["objective"],
                        what_it_does=catalog_row["what_it_does"],
                        success_indicator=catalog_row["success_indicator"],
                    )
                    cases[case_key] = case
                case.trials.append(
                    Trial(
                        trial_id=stable_id(
                            "TRIAL",
                            package_hash,
                            row["run_id"],
                            row["timestamp"],
                            case_key,
                            str(line_number),
                        ),
                        timestamp=row["timestamp"],
                        run_id=row["run_id"],
                        execution_status=row["execution_status"],
                        detection_status=row["detection_status"],
                        action_status=row["action_status"],
                    )
                )

    control = profile_summary["control"]
    return PackageData(
        path=package,
        package_sha256=package_hash,
        control_id=control["id"],
        display_name=control["display_name"],
        profile_summary=profile_summary,
        cases=cases,
        module_names=module_names,
    )


def load_packages(paths: list[str | Path]) -> list[PackageData]:
    if len(paths) < 2:
        raise PackageValidationError("At least two comparison ZIPs are required.")
    if len(paths) > 20:
        raise PackageValidationError("No more than 20 comparison ZIPs are allowed.")
    packages = [load_package(path) for path in paths]
    seen: set[str] = set()
    duplicates: set[str] = set()
    for package in packages:
        if package.control_id in seen:
            duplicates.add(package.control_id)
        seen.add(package.control_id)
    if duplicates:
        raise PackageValidationError(
            f"Control IDs must be unique across packages: {sorted(duplicates)}"
        )
    return packages
