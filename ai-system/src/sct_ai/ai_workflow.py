"""LangChain-backed execution of versioned, evidence-bound runtime skills."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Literal

from .errors import AIConfigurationError, AIOutputError
from .util import load_json_no_duplicates, utc_now


SKILL_ORDER = (
    "profile-context",
    "module-analysis",
    "cross-control-synthesis",
    "independent-assessment",
    "decision-reconciliation",
)
ANALYSIS_SKILLS = {
    "profile-context",
    "module-analysis",
    "cross-control-synthesis",
}
PERCENT_PATTERN = re.compile(r"(?<![\w.])(\d+(?:\.\d+)?)\s*%")


def load_provider_config(
    path: Path,
    provider_name: str,
    model_name: str,
) -> dict[str, Any]:
    if not path.is_file():
        raise AIConfigurationError(f"AI provider configuration does not exist: {path}")
    try:
        config = load_json_no_duplicates(
            path.read_text(encoding="utf-8-sig"),
            "AI provider configuration",
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise AIConfigurationError(str(exc)) from exc
    if config.get("schema_version") != "1.0":
        raise AIConfigurationError(
            "AI provider configuration schema_version must be '1.0'."
        )
    if set(config) != {"schema_version", "providers"}:
        raise AIConfigurationError("AI provider configuration has unknown fields.")
    providers = config.get("providers")
    if not isinstance(providers, dict) or not providers:
        raise AIConfigurationError("AI provider configuration has no providers.")
    provider = providers.get(provider_name)
    if not isinstance(provider, dict):
        raise AIConfigurationError(
            f"Provider '{provider_name}' is not allowlisted by the server configuration."
        )
    allowed = {
        "type",
        "base_url",
        "models",
        "api_key_env",
        "timeout_seconds",
        "max_retries",
        "include_policy_details",
    }
    unknown = set(provider) - allowed
    if unknown:
        raise AIConfigurationError(
            f"Provider '{provider_name}' has unknown fields: {sorted(unknown)}"
        )
    provider_type = provider.get("type")
    if provider_type not in {"openai", "openai-compatible", "ollama"}:
        raise AIConfigurationError(
            f"Provider '{provider_name}' has unsupported type '{provider_type}'."
        )
    models = provider.get("models")
    if (
        not isinstance(models, list)
        or not models
        or any(not isinstance(item, str) or not item.strip() for item in models)
    ):
        raise AIConfigurationError(
            f"Provider '{provider_name}' must allowlist at least one model."
        )
    if model_name not in models:
        raise AIConfigurationError(
            f"Model '{model_name}' is not allowlisted for provider '{provider_name}'."
        )
    base_url = provider.get("base_url")
    if provider_type in {"openai-compatible", "ollama"} and (
        not isinstance(base_url, str) or not base_url.strip()
    ):
        raise AIConfigurationError(
            f"Provider '{provider_name}' requires a base_url."
        )
    if base_url and not base_url.startswith(("http://", "https://")):
        raise AIConfigurationError(
            f"Provider '{provider_name}' base_url must use HTTP or HTTPS."
        )
    api_key_env = provider.get("api_key_env")
    if provider_type != "ollama":
        if not isinstance(api_key_env, str) or not api_key_env.strip():
            raise AIConfigurationError(
                f"Provider '{provider_name}' requires api_key_env."
            )
        if not os.environ.get(api_key_env):
            raise AIConfigurationError(
                f"Required API key environment variable '{api_key_env}' is not set."
            )

    timeout = provider.get("timeout_seconds", 120)
    retries = provider.get("max_retries", 2)
    if not isinstance(timeout, int) or not 1 <= timeout <= 1800:
        raise AIConfigurationError("timeout_seconds must be between 1 and 1800.")
    if not isinstance(retries, int) or not 0 <= retries <= 10:
        raise AIConfigurationError("max_retries must be between 0 and 10.")
    return {
        "name": provider_name,
        "type": provider_type,
        "base_url": base_url,
        "model": model_name,
        "api_key_env": api_key_env,
        "timeout_seconds": timeout,
        "max_retries": retries,
        "include_policy_details": bool(
            provider.get("include_policy_details", False)
        ),
    }


def create_chat_model(provider: dict[str, Any]) -> Any:
    provider_type = provider["type"]
    try:
        if provider_type == "ollama":
            from langchain_ollama import ChatOllama

            return ChatOllama(
                model=provider["model"],
                base_url=provider["base_url"],
                temperature=0,
                client_kwargs={"timeout": provider["timeout_seconds"]},
            )
        from langchain_openai import ChatOpenAI

        kwargs: dict[str, Any] = {
            "model": provider["model"],
            "api_key": os.environ[provider["api_key_env"]],
            "temperature": 0,
            "timeout": provider["timeout_seconds"],
            "max_retries": provider["max_retries"],
        }
        if provider_type == "openai-compatible":
            kwargs["base_url"] = provider["base_url"]
        return ChatOpenAI(**kwargs)
    except ImportError as exc:
        raise AIConfigurationError(
            "LangChain provider packages are not installed. Install the 'ai' "
            "or 'all' dependency set from the approved offline wheelhouse."
        ) from exc


def _response_text(response: Any) -> str:
    content = getattr(response, "content", response)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "\n".join(parts)
    return str(content)


def _extract_json(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, count=1)
        cleaned = re.sub(r"\s*```$", "", cleaned, count=1)
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        if start < 0:
            raise AIOutputError("Model response contains no JSON object.")
        try:
            value, _ = json.JSONDecoder().raw_decode(cleaned[start:])
        except json.JSONDecodeError as exc:
            raise AIOutputError("Model response is not valid JSON.") from exc
    if not isinstance(value, dict):
        raise AIOutputError("Model response must be a JSON object.")
    return value


def _pydantic_models() -> dict[str, type[Any]]:
    try:
        from pydantic import BaseModel, ConfigDict, Field
    except ImportError as exc:
        raise AIConfigurationError(
            "Pydantic is required for AI output validation."
        ) from exc

    class Finding(BaseModel):
        model_config = ConfigDict(extra="forbid")
        title: str = Field(min_length=1, max_length=160)
        analysis: str = Field(min_length=1, max_length=2000)
        severity: Literal["strength", "concern", "context", "gap"]
        controls: list[str] = Field(min_length=1)
        evidence_ids: list[str] = Field(min_length=1)

    class AnalysisOutput(BaseModel):
        model_config = ConfigDict(extra="forbid")
        summary: str = Field(min_length=1, max_length=3000)
        findings: list[Finding]
        recommendation: None = None

    class IndependentAssessment(BaseModel):
        model_config = ConfigDict(extra="forbid")
        preferred_control_id: str | None
        confidence: Literal["low", "medium", "high"]
        rationale: str = Field(min_length=1, max_length=2000)
        strengths: list[str]
        concerns: list[str]
        coverage_caveats: list[str]
        evidence_ids: list[str] = Field(min_length=1)

    class Reconciliation(BaseModel):
        model_config = ConfigDict(extra="forbid")
        status: Literal["agrees", "disagrees", "ai_inconclusive"]
        python_recommended_control_id: str | None
        ai_preferred_control_id: str | None
        summary: str = Field(min_length=1, max_length=3000)
        evidence_ids: list[str] = Field(min_length=1)

    return {
        "analysis": AnalysisOutput,
        "independent_assessment": IndependentAssessment,
        "reconciliation": Reconciliation,
    }


def _validate_json_contract(value: Any, schema: dict[str, Any], context: str) -> None:
    expected_type = schema.get("type")
    if isinstance(expected_type, list):
        if value is None and "null" in expected_type:
            return
        non_null = [item for item in expected_type if item != "null"]
        if non_null:
            _validate_json_contract(
                value,
                {**schema, "type": non_null[0]},
                context,
            )
        return
    type_checks = {
        "object": dict,
        "array": list,
        "string": str,
        "null": type(None),
    }
    if expected_type in type_checks and not isinstance(value, type_checks[expected_type]):
        raise AIOutputError(f"{context} must be of type {expected_type}.")
    if "enum" in schema and value not in schema["enum"]:
        raise AIOutputError(f"{context} is not an allowed value.")
    if isinstance(value, str) and len(value) < schema.get("minLength", 0):
        raise AIOutputError(f"{context} is too short.")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise AIOutputError(f"{context} has too few items.")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate_json_contract(item, item_schema, f"{context}[{index}]")
    if isinstance(value, dict):
        required = schema.get("required", [])
        missing = [name for name in required if name not in value]
        if missing:
            raise AIOutputError(f"{context} is missing fields: {missing}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unknown = set(value) - set(properties)
            if unknown:
                raise AIOutputError(
                    f"{context} has unknown fields: {sorted(unknown)}"
                )
        for name, child_schema in properties.items():
            if name in value and isinstance(child_schema, dict):
                _validate_json_contract(
                    value[name],
                    child_schema,
                    f"{context}.{name}",
                )


def _numbers(value: Any) -> set[float]:
    result: set[float] = set()
    if isinstance(value, bool) or value is None:
        return result
    if isinstance(value, (int, float)):
        result.add(round(float(value), 4))
    elif isinstance(value, dict):
        for child in value.values():
            result.update(_numbers(child))
    elif isinstance(value, list):
        for child in value:
            result.update(_numbers(child))
    return result


def _validate_numeric_claims(
    text: str,
    evidence_ids: list[str],
    evidence_index: dict[str, dict[str, Any]],
) -> None:
    claims = {round(float(match), 4) for match in PERCENT_PATTERN.findall(text)}
    if not claims:
        return
    allowed: set[float] = set()
    for evidence_id in evidence_ids:
        allowed.update(_numbers(evidence_index[evidence_id]))
    unsupported = sorted(
        claim
        for claim in claims
        if not any(math_isclose(claim, candidate) for candidate in allowed)
    )
    if unsupported:
        raise AIOutputError(
            f"Response contains unsupported percentage claims: {unsupported}"
        )


def math_isclose(left: float, right: float) -> bool:
    return abs(left - right) <= 0.01


def _validate_output(
    raw: dict[str, Any],
    *,
    skill_name: str,
    comparison: dict[str, Any],
    evidence_index: dict[str, dict[str, Any]],
    payload: dict[str, Any],
) -> dict[str, Any]:
    try:
        skill = _load_skill(skill_name)
        _validate_json_contract(raw, skill["output_schema"], "model output")
        output_type = _pydantic_models()[skill["output_schema_name"]]
        output = output_type.model_validate(raw)
    except Exception as exc:
        raise AIOutputError(f"Output schema validation failed: {exc}") from exc
    known_controls = {
        control["control_id"] for control in comparison["controls"]
    }
    if skill_name in ANALYSIS_SKILLS:
        all_refs: list[str] = []
        for finding in output.findings:
            unknown_controls = set(finding.controls) - known_controls
            if unknown_controls:
                raise AIOutputError(
                    "Finding references unknown controls: "
                    f"{sorted(unknown_controls)}"
                )
            _validate_evidence_ids(
                finding.evidence_ids,
                evidence_index,
                "Finding",
            )
            _validate_numeric_claims(
                f"{finding.title} {finding.analysis}",
                finding.evidence_ids,
                evidence_index,
            )
            all_refs.extend(finding.evidence_ids)
        _validate_numeric_claims(output.summary, all_refs, evidence_index)
    elif skill_name == "independent-assessment":
        if (
            output.preferred_control_id is not None
            and output.preferred_control_id not in known_controls
        ):
            raise AIOutputError(
                "Independent assessment references an unknown preferred control."
            )
        _validate_non_empty_text_items(
            output.strengths + output.concerns + output.coverage_caveats
        )
        _validate_evidence_ids(
            output.evidence_ids,
            evidence_index,
            "Independent assessment",
        )
        _validate_numeric_claims(
            " ".join(
                [
                    output.rationale,
                    *output.strengths,
                    *output.concerns,
                    *output.coverage_caveats,
                ]
            ),
            output.evidence_ids,
            evidence_index,
        )
    elif skill_name == "decision-reconciliation":
        assessment = payload["independent_assessment"]
        expected_python = comparison["ranking"]["recommended_control_id"]
        expected_ai = assessment["preferred_control_id"]
        expected_status = _agreement_status(expected_python, expected_ai)
        if output.python_recommended_control_id != expected_python:
            raise AIOutputError(
                "Reconciliation changed the deterministic recommendation."
            )
        if output.ai_preferred_control_id != expected_ai:
            raise AIOutputError(
                "Reconciliation changed the independent AI preference."
            )
        if output.status != expected_status:
            raise AIOutputError(
                "Reconciliation returned the wrong agreement status."
            )
        _validate_evidence_ids(
            output.evidence_ids,
            evidence_index,
            "Reconciliation",
        )
        _validate_numeric_claims(
            output.summary,
            output.evidence_ids,
            evidence_index,
        )
    return output.model_dump(mode="json")


def _validate_evidence_ids(
    evidence_ids: list[str],
    evidence_index: dict[str, dict[str, Any]],
    label: str,
) -> None:
    unknown = set(evidence_ids) - set(evidence_index)
    if unknown:
        raise AIOutputError(
            f"{label} references unknown evidence: {sorted(unknown)}"
        )


def _validate_non_empty_text_items(values: list[str]) -> None:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise AIOutputError(
            "Assessment strengths, concerns, and coverage caveats must be "
            "non-empty strings."
        )


def _agreement_status(
    python_control_id: str | None,
    ai_control_id: str | None,
) -> str:
    if ai_control_id is None:
        return "ai_inconclusive"
    if ai_control_id == python_control_id:
        return "agrees"
    return "disagrees"


def _load_skill(skill_name: str) -> dict[str, Any]:
    catalog_path = Path(__file__).resolve().parent / "skills.json"
    if not catalog_path.is_file():
        raise AIConfigurationError("Runtime skill catalog is missing.")
    try:
        catalog = load_json_no_duplicates(
            catalog_path.read_text(encoding="utf-8"),
            "skills.json",
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise AIConfigurationError(str(exc)) from exc
    if (
        set(catalog) != {"schema_version", "output_schemas", "skills"}
        or catalog.get("schema_version") != "1.0"
        or not isinstance(catalog.get("output_schemas"), dict)
        or not isinstance(catalog.get("skills"), dict)
    ):
        raise AIConfigurationError("Runtime skill catalog is invalid.")
    manifest = catalog["skills"].get(skill_name)
    if not isinstance(manifest, dict):
        raise AIConfigurationError(f"Runtime skill is missing: {skill_name}")
    required = {
        "version",
        "description",
        "system_prompt",
        "user_prompt",
        "input_schema",
        "output_schema",
    }
    if set(manifest) != required:
        raise AIConfigurationError(f"Runtime skill manifest is invalid: {skill_name}")
    if (
        not isinstance(manifest["version"], str)
        or not isinstance(manifest["description"], str)
        or not isinstance(manifest["system_prompt"], str)
        or not isinstance(manifest["user_prompt"], str)
        or not isinstance(manifest["input_schema"], dict)
        or not isinstance(manifest["output_schema"], str)
    ):
        raise AIConfigurationError(f"Runtime skill manifest is invalid: {skill_name}")
    output_schema = catalog["output_schemas"].get(manifest["output_schema"])
    if not isinstance(output_schema, dict):
        raise AIConfigurationError(
            f"Runtime skill '{skill_name}' references an unknown output schema."
        )
    loaded = {
        "name": skill_name,
        **manifest,
        "output_schema": output_schema,
        "output_schema_name": manifest["output_schema"],
    }
    return loaded


def _control_context(
    control: dict[str, Any],
    include_policy_details: bool,
) -> dict[str, Any]:
    profile = control["profile"]
    policy = dict(profile["policy"])
    if not include_policy_details:
        policy["settings"] = []
    return {
        "control_id": control["control_id"],
        "display_name": control["display_name"],
        "control": profile["control"],
        "policy": policy,
        "metrics": control["metrics"],
    }


def _skill_payload(
    skill_name: str,
    comparison: dict[str, Any],
    previous_outputs: list[dict[str, Any]],
    include_policy_details: bool,
) -> dict[str, Any]:
    controls = [
        _control_context(control, include_policy_details)
        for control in comparison["controls"]
    ]
    policy = comparison.get("policy") or {}
    decision_context = {
        "scoring": comparison["scoring"],
        "module_weights": policy.get("module_weights", {}),
        "minimum_comparable_weight": policy.get("minimum_comparable_weight"),
        "tie_margin": policy.get("tie_margin"),
        "decision_priorities": policy.get(
            "decision_priorities",
            "No additional decision priorities were supplied.",
        ),
    }
    blinded_evidence = [
        item
        for item in comparison["evidence"]
        if item["type"] != "ranking"
    ]
    if skill_name == "profile-context":
        evidence_types = {"profile_summary", "control_metrics"}
        return {
            "controls": controls,
            "decision_context": decision_context,
            "evidence": [
                item
                for item in blinded_evidence
                if item["type"] in evidence_types
            ],
        }
    if skill_name == "module-analysis":
        evidence_types = {"module_metrics", "case_outcome"}
        return {
            "controls": controls,
            "coverage": comparison["coverage"],
            "case_catalog": comparison["case_catalog"],
            "decision_context": decision_context,
            "evidence": [
                item
                for item in blinded_evidence
                if item["type"] in evidence_types
            ],
        }
    if skill_name == "decision-reconciliation":
        independent = next(
            item["output"]
            for item in previous_outputs
            if item["name"] == "independent-assessment"
        )
        return {
            "controls": controls,
            "coverage": comparison["coverage"],
            "pairwise": comparison["pairwise"],
            "decision_context": decision_context,
            "ranking": comparison["ranking"],
            "previous_analysis_outputs": [
                item for item in previous_outputs if item["name"] in ANALYSIS_SKILLS
            ],
            "independent_assessment": independent,
            "evidence": comparison["evidence"],
        }
    return {
        "controls": controls,
        "coverage": comparison["coverage"],
        "pairwise": comparison["pairwise"],
        "decision_context": decision_context,
        "previous_skill_outputs": previous_outputs,
        "evidence": blinded_evidence,
    }


def _invoke_skill(
    model: Any,
    skill: dict[str, Any],
    payload: dict[str, Any],
    comparison: dict[str, Any],
) -> dict[str, Any]:
    try:
        from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
    except ImportError as exc:
        raise AIConfigurationError("langchain-core is not installed.") from exc
    evidence_index = {
        item["evidence_id"]: item for item in payload.get("evidence", [])
    }
    _validate_json_contract(payload, skill["input_schema"], "skill input")
    user_prompt = skill["user_prompt"].replace(
        "{{payload}}",
        json.dumps(payload, sort_keys=True, ensure_ascii=False),
    )
    messages: list[Any] = [
        SystemMessage(content=skill["system_prompt"]),
        HumanMessage(content=user_prompt),
    ]
    last_error: Exception | None = None
    for attempt in range(2):
        response = model.invoke(messages)
        raw_text = _response_text(response)
        try:
            parsed = _extract_json(raw_text)
            return _validate_output(
                parsed,
                skill_name=skill["name"],
                comparison=comparison,
                evidence_index=evidence_index,
                payload=payload,
            )
        except AIOutputError as exc:
            last_error = exc
            if attempt == 0:
                messages.append(AIMessage(content=raw_text))
                messages.append(
                    HumanMessage(
                        content=(
                            "Your previous response failed validation: "
                            f"{exc}. Return one corrected JSON object only. "
                            "Do not add new claims or evidence identifiers."
                        )
                    )
                )
    raise AIOutputError(
        f"Skill '{skill['name']}' failed validation after one correction: {last_error}"
    )


def run_ai_workflow(
    comparison: dict[str, Any],
    *,
    provider_name: str,
    model_name: str,
    provider_config_path: Path,
    progress_callback: Callable[[str, int, str], None] | None = None,
) -> dict[str, Any]:
    provider = load_provider_config(
        provider_config_path,
        provider_name,
        model_name,
    )
    model = create_chat_model(provider)
    outputs: list[dict[str, Any]] = []
    for index, skill_name in enumerate(SKILL_ORDER):
        skill = _load_skill(skill_name)
        if progress_callback:
            progress_callback(
                "ai",
                52 + (index * 8),
                f"Running {skill_name} skill",
            )
        payload = _skill_payload(
            skill_name,
            comparison,
            outputs,
            provider["include_policy_details"],
        )
        output = _invoke_skill(model, skill, payload, comparison)
        outputs.append(
            {
                "name": skill_name,
                "version": skill["version"],
                "output": output,
            }
        )
    independent = next(
        item["output"]
        for item in outputs
        if item["name"] == "independent-assessment"
    )
    reconciliation = next(
        item["output"]
        for item in outputs
        if item["name"] == "decision-reconciliation"
    )
    return {
        "schema_version": "1.1",
        "status": "completed",
        "generated_at": utc_now(),
        "provider": {
            "name": provider["name"],
            "type": provider["type"],
            "model": provider["model"],
            "policy_details_included": provider["include_policy_details"],
        },
        "skills": outputs,
        "independent_assessment": independent,
        "decision_comparison": {
            "status": reconciliation["status"],
            "python_recommended_control_id": reconciliation[
                "python_recommended_control_id"
            ],
            "ai_preferred_control_id": reconciliation[
                "ai_preferred_control_id"
            ],
            "ai_confidence": independent["confidence"],
            "summary": reconciliation["summary"],
            "evidence_ids": reconciliation["evidence_ids"],
        },
    }
