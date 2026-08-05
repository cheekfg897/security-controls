from __future__ import annotations

import csv
import io
import json
import zipfile
from pathlib import Path
from typing import Any

from sct_ai.packages import (
    CATALOG_COLUMNS,
    LEGACY_RESULT_COLUMNS,
    PREVIOUS_LEGACY_RESULT_COLUMNS,
    PREVIOUS_RESULT_COLUMNS,
    RESULT_COLUMNS,
)


MODULE_NAMES = {
    "01": "Malware Delivery",
    "02": "Exploitation",
    "03": "Privilege Escalation",
    "04": "Persistence",
}


def _csv_bytes(columns: tuple[str, ...], rows: list[dict[str, str]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream,
        fieldnames=columns,
        lineterminator="\n",
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def package_bytes(
    control_id: str,
    cases: list[dict[str, Any]],
    *,
    display_name: str | None = None,
    default_mode: str = "detect_and_block",
    legacy_notes_column: bool = False,
    previous_result_layout: bool = False,
) -> bytes:
    profile = {
        "schema_version": "1.0",
        "control": {
            "id": control_id,
            "display_name": display_name or control_id.upper(),
            "vendor": "Fixture Vendor",
            "product": "Fixture Endpoint",
            "product_version": "1.0",
            "agent_version": "2.0",
        },
        "policy": {
            "name": "Fixture policy",
            "default_mode": default_mode,
            "settings": [
                {
                    "name": "Protection",
                    "value": "enabled",
                    "scope": "global",
                }
            ],
            "exclusions": [],
        },
    }
    result_by_module: dict[str, list[dict[str, str]]] = {}
    catalog_by_module: dict[str, dict[tuple[str, str], dict[str, str]]] = {}
    row_index = 0
    for specification in cases:
        module_id = specification.get("module_id", "01")
        technique_id = specification.get(
            "technique_id",
            f"{int(module_id)}.1",
        )
        subtest = specification.get("subtest", "")
        module_name = MODULE_NAMES[module_id]
        technique_name = specification.get("technique_name", f"Technique {technique_id}")
        catalog_by_module.setdefault(module_id, {})[(technique_id, subtest)] = {
            "module_id": module_id,
            "module_name": module_name,
            "technique_id": technique_id,
            "technique_name": technique_name,
            "subtest": subtest,
            "attack_id": specification.get("attack_id", "T0001"),
            "test_script": f"scenarios/{module_id}/fixture.ps1",
            "objective": f"Exercise {technique_id}",
            "what_it_does": "Runs a benign fixture behavior",
            "success_indicator": "The fixture marker is created",
            "status": "",
        }
        repeats = specification.get("trials")
        if repeats is None:
            repeats = [
                {
                    "detection": specification.get("detection", "detected"),
                    "action": specification.get("action", "not_blocked"),
                    "execution": specification.get("execution"),
                }
            ]
        for trial in repeats:
            row_index += 1
            action = trial["action"]
            execution = trial.get("execution")
            if execution is None:
                execution = "executed"
            stage = specification.get("stage", "execution")
            result_row = {
                "timestamp": f"2026-07-23T01:00:{row_index:02d}+00:00",
                "run_id": f"fixture-{row_index}",
                "technique_id": technique_id,
                "technique_name": technique_name,
                "subtest": subtest,
                "test_script": f"fixture-{technique_id}.ps1",
                "test_input": specification.get("test_input", "fixture.bin"),
                "test_input_sha256": specification.get(
                    "sha256",
                    f"{row_index:064X}",
                ),
                "delivery_method": specification.get("delivery_method", "Fixture"),
                "test_stage": stage,
                "source_result": specification.get("source_result", "fixture=true"),
                "execution_status": execution,
                "detection_status": trial["detection"],
                "action_status": action,
                "reviewer_notes": "Fixture reviewer note",
            }
            if legacy_notes_column:
                result_row["notes"] = "Legacy generated note"
            result_by_module.setdefault(module_id, []).append(result_row)

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "control-profile.json",
            json.dumps(profile, indent=2).encode("utf-8"),
        )
        for module_id in sorted(result_by_module):
            if previous_result_layout:
                result_columns = (
                    PREVIOUS_LEGACY_RESULT_COLUMNS
                    if legacy_notes_column
                    else PREVIOUS_RESULT_COLUMNS
                )
            else:
                result_columns = (
                    LEGACY_RESULT_COLUMNS if legacy_notes_column else RESULT_COLUMNS
                )
            archive.writestr(
                f"results-module-{module_id}.csv",
                _csv_bytes(result_columns, result_by_module[module_id]),
            )
            archive.writestr(
                f"test-catalog-module-{module_id}.csv",
                _csv_bytes(
                    CATALOG_COLUMNS,
                    list(catalog_by_module[module_id].values()),
                ),
            )
    return output.getvalue()


def write_package(
    path: Path,
    control_id: str,
    cases: list[dict[str, Any]],
    *,
    display_name: str | None = None,
    default_mode: str = "detect_and_block",
    legacy_notes_column: bool = False,
    previous_result_layout: bool = False,
) -> Path:
    path.write_bytes(
        package_bytes(
            control_id,
            cases,
            display_name=display_name,
            default_mode=default_mode,
            legacy_notes_column=legacy_notes_column,
            previous_result_layout=previous_result_layout,
        )
    )
    return path
