"""FastAPI web interface for local and trusted-network SCT comparisons."""

from __future__ import annotations

import hmac
import json
import secrets
import shutil
import sys
import uuid
from pathlib import Path
from typing import Any

from .jobs import ComparisonJobManager, JobStore
from .packages import MAX_PACKAGE_BYTES, load_packages
from .util import load_json_no_duplicates, validate_comparison_id


DOWNLOAD_ARTIFACTS = {
    "comparison.json",
    "ai-analysis.json",
    "technical-report.md",
    "executive-summary.md",
    "report.html",
    "run-manifest.json",
}


def validate_web_binding(host: str, port: int, shared: bool) -> None:
    if not shared and host not in {"127.0.0.1", "::1", "localhost"}:
        raise RuntimeError(
            "Non-loopback binding requires the explicit --shared option."
        )
    if not 1 <= port <= 65535:
        raise RuntimeError("Port must be between 1 and 65535.")


def _system_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _provider_options(path: Path | None) -> list[dict[str, str]]:
    if path is None or not path.is_file():
        return []
    try:
        config = load_json_no_duplicates(
            path.read_text(encoding="utf-8-sig"),
            "AI provider configuration",
        )
    except Exception:
        return []
    options: list[dict[str, str]] = []
    providers = config.get("providers", {})
    if not isinstance(providers, dict):
        return []
    for provider_name, provider in sorted(providers.items()):
        if not isinstance(provider, dict) or not isinstance(provider.get("models"), list):
            continue
        for model in provider["models"]:
            if isinstance(model, str) and model.strip() and "<" not in model:
                options.append(
                    {
                        "value": f"{provider_name}::{model}",
                        "label": f"{provider_name} — {model}",
                    }
                )
    return options


def _default_weights(repo_root: Path) -> dict[str, float]:
    module_ids: list[str] = []
    for path in sorted((repo_root / "scenarios").glob("*/module.json")):
        try:
            metadata = json.loads(path.read_text(encoding="utf-8-sig"))
            module_id = str(metadata["id"])
            if len(module_id) == 2 and module_id.isdigit():
                module_ids.append(module_id)
        except (OSError, ValueError, KeyError, TypeError):
            continue
    if not module_ids:
        return {}
    base = round(100.0 / len(module_ids), 4)
    weights = {module_id: base for module_id in module_ids}
    weights[module_ids[-1]] = round(
        100.0 - sum(weights[module_id] for module_id in module_ids[:-1]),
        4,
    )
    return weights


def create_app(
    *,
    repository_root: Path | None = None,
    system_root: Path | None = None,
    shared_mode: bool = False,
    provider_config_path: Path | None = None,
    job_workers: int = 1,
) -> Any:
    try:
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
        from fastapi.staticfiles import StaticFiles
        from fastapi.templating import Jinja2Templates
    except ImportError as exc:
        raise RuntimeError(
            "FastAPI web dependencies are not installed. Install the 'web' "
            "or 'all' dependency set from the approved offline wheelhouse."
        ) from exc

    repository = (repository_root or _repository_root()).resolve()
    system = (system_root or _system_root()).resolve()
    output_root = system / "comparisons"
    submissions_root = repository / "submissions"
    staging_root = output_root / ".staging"
    output_root.mkdir(parents=True, exist_ok=True)
    staging_root.mkdir(parents=True, exist_ok=True)

    package_root = Path(__file__).resolve().parent
    templates = Jinja2Templates(directory=package_root / "templates")
    store = JobStore(output_root / "index.sqlite3")
    store.sync_manifests(output_root)
    manager = ComparisonJobManager(
        store,
        output_root,
        max_workers=max(1, min(job_workers, 8)),
    )
    app = FastAPI(
        title="SCT comparison",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.repository_root = repository
    app.state.system_root = system
    app.state.output_root = output_root
    app.state.store = store
    app.state.manager = manager
    app.state.shared_mode = shared_mode
    app.state.provider_config_path = provider_config_path
    app.add_event_handler(
        "shutdown",
        lambda: manager.executor.shutdown(wait=False, cancel_futures=True),
    )
    app.mount(
        "/static",
        StaticFiles(directory=package_root / "static"),
        name="static",
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    def render(
        request: Request,
        template_name: str,
        context: dict[str, Any],
        status_code: int = 200,
    ) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request,
            name=template_name,
            context={
                "shared_mode": shared_mode,
                **context,
            },
            status_code=status_code,
        )

    def csrf_token(request: Request) -> tuple[str, bool]:
        existing = request.cookies.get("sct_csrf")
        if existing and len(existing) >= 32:
            return existing, False
        return secrets.token_urlsafe(32), True

    def set_csrf_cookie(response: Any, token: str, is_new: bool) -> None:
        if is_new:
            response.set_cookie(
                "sct_csrf",
                token,
                httponly=True,
                samesite="strict",
                secure=False,
            )

    def check_csrf(request: Request, form: Any) -> None:
        cookie = request.cookies.get("sct_csrf", "")
        submitted = str(form.get("csrf_token", ""))
        if not cookie or not submitted or not hmac.compare_digest(cookie, submitted):
            raise HTTPException(status_code=403, detail="CSRF validation failed.")

    def existing_packages() -> list[str]:
        return [
            path.name
            for path in sorted(submissions_root.glob("*.zip"))
            if path.is_file()
        ]

    async def stage_inputs(form: Any, stage_dir: Path) -> list[str]:
        selected = [str(value) for value in form.getlist("existing_packages")]
        uploads = [
            value
            for value in form.getlist("uploads")
            if getattr(value, "filename", "")
        ]
        if len(selected) + len(uploads) < 2:
            raise ValueError("Select or upload at least two comparison ZIPs.")
        if len(selected) + len(uploads) > 20:
            raise ValueError("No more than 20 comparison ZIPs are allowed.")
        paths: list[str] = []
        for name in selected:
            if Path(name).name != name:
                raise ValueError("Existing package selection is invalid.")
            path = (submissions_root / name).resolve()
            if path.parent != submissions_root.resolve() or not path.is_file():
                raise ValueError(f"Selected package does not exist: {name}")
            paths.append(str(path))

        stage_dir.mkdir(parents=True, exist_ok=False)
        for upload in uploads:
            if not str(upload.filename).lower().endswith(".zip"):
                raise ValueError(f"Uploaded file must be a ZIP: {upload.filename}")
            target = stage_dir / f"{uuid.uuid4().hex}.zip"
            total = 0
            with target.open("xb") as handle:
                while True:
                    chunk = await upload.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_PACKAGE_BYTES:
                        raise ValueError(
                            f"Uploaded package exceeds 100 MB: {upload.filename}"
                        )
                    handle.write(chunk)
            paths.append(str(target))
        return paths

    def parse_policy(form: Any) -> dict[str, Any]:
        raw = str(form.get("module_weights", "")).strip()
        try:
            weights = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("Module weights must be a valid JSON object.") from exc
        if not isinstance(weights, dict):
            raise ValueError("Module weights must be a JSON object.")
        return {
            "schema_version": "1.0",
            "module_weights": weights,
            "minimum_comparable_weight": 80,
            "tie_margin": 2,
        }

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> Any:
        token, is_new = csrf_token(request)
        response = render(
            request,
            "index.html",
            {
                "csrf_token": token,
                "packages": existing_packages(),
                "provider_options": _provider_options(provider_config_path),
                "default_weights": json.dumps(
                    _default_weights(repository),
                    indent=2,
                    sort_keys=True,
                ),
                "jobs": store.list_recent(),
                "error": None,
            },
        )
        set_csrf_cookie(response, token, is_new)
        return response

    @app.post("/comparisons/validate")
    async def validate_inputs(request: Request) -> Any:
        form = await request.form()
        check_csrf(request, form)
        stage_dir = staging_root / f"preflight-{uuid.uuid4().hex}"
        try:
            paths = await stage_inputs(form, stage_dir)
            packages = load_packages(paths)
            summaries = [package.preflight_summary() for package in packages]
            if request.headers.get("HX-Request") == "true":
                return render(
                    request,
                    "preflight.html",
                    {"valid": True, "packages": summaries, "error": None},
                )
            return JSONResponse(
                {
                    "valid": True,
                    "packages": summaries,
                }
            )
        except Exception as exc:
            if request.headers.get("HX-Request") == "true":
                return render(
                    request,
                    "preflight.html",
                    {"valid": False, "packages": [], "error": str(exc)},
                )
            return JSONResponse(
                {"valid": False, "error": str(exc)},
                status_code=400,
            )
        finally:
            shutil.rmtree(stage_dir, ignore_errors=True)

    @app.post("/comparisons")
    async def create_comparison(request: Request) -> Any:
        form = await request.form()
        check_csrf(request, form)
        stage_dir = staging_root / uuid.uuid4().hex
        try:
            paths = await stage_inputs(form, stage_dir)
            policy = parse_policy(form)
            comparison_id_value = str(form.get("comparison_id", "")).strip()
            comparison_id = (
                validate_comparison_id(comparison_id_value)
                if comparison_id_value
                else None
            )
            provider_name = None
            model_name = None
            if form.get("enable_ai"):
                selection = str(form.get("provider_model", ""))
                if "::" not in selection:
                    raise ValueError("Select an allowlisted AI provider and model.")
                provider_name, model_name = selection.split("::", 1)
                allowed = {
                    option["value"]
                    for option in _provider_options(provider_config_path)
                }
                if selection not in allowed:
                    raise ValueError("The selected provider/model is not allowlisted.")
            request_data = {
                "package_paths": paths,
                "policy": policy,
                "comparison_id": comparison_id,
                "provider_name": provider_name,
                "model_name": model_name,
                "provider_config_path": str(provider_config_path)
                if provider_name and provider_config_path
                else None,
            }
            job_id = manager.submit(
                request_data,
                cleanup=lambda: shutil.rmtree(stage_dir, ignore_errors=True),
            )
            return RedirectResponse(f"/jobs/{job_id}", status_code=303)
        except Exception as exc:
            shutil.rmtree(stage_dir, ignore_errors=True)
            token, is_new = csrf_token(request)
            response = render(
                request,
                "index.html",
                {
                    "csrf_token": token,
                    "packages": existing_packages(),
                    "provider_options": _provider_options(provider_config_path),
                    "default_weights": str(form.get("module_weights", "")),
                    "jobs": store.list_recent(),
                    "error": str(exc),
                },
                status_code=400,
            )
            set_csrf_cookie(response, token, is_new)
            return response

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    async def job_page(request: Request, job_id: str) -> Any:
        job = store.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found.")
        token, is_new = csrf_token(request)
        response = render(
            request,
            "job.html",
            {"job": job, "csrf_token": token},
        )
        set_csrf_cookie(response, token, is_new)
        return response

    @app.post("/jobs/{job_id}/rerun")
    async def rerun_job(request: Request, job_id: str) -> Any:
        form = await request.form()
        check_csrf(request, form)
        job = store.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found.")
        if job["status"] not in {"failed", "interrupted"}:
            raise HTTPException(
                status_code=409,
                detail="Only failed or interrupted jobs can be rerun.",
            )
        try:
            request_data = json.loads(job["request_json"])
            paths = [Path(path) for path in request_data["package_paths"]]
        except (ValueError, KeyError, TypeError) as exc:
            raise HTTPException(
                status_code=409,
                detail="The saved job request is invalid.",
            ) from exc
        if any(not path.is_file() for path in paths):
            raise HTTPException(
                status_code=409,
                detail="One or more staged inputs are no longer available; create a new run.",
            )
        cleanup_roots = {
            path.parent
            for path in paths
            if path.parent.parent == staging_root
        }
        new_job_id = manager.submit(
            request_data,
            cleanup=lambda: [
                shutil.rmtree(path, ignore_errors=True)
                for path in cleanup_roots
            ],
        )
        return RedirectResponse(f"/jobs/{new_job_id}", status_code=303)

    @app.get("/api/jobs/{job_id}")
    async def job_status(job_id: str) -> JSONResponse:
        job = store.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found.")
        return JSONResponse(
            {
                key: job[key]
                for key in (
                    "job_id",
                    "comparison_id",
                    "status",
                    "stage",
                    "progress",
                    "message",
                    "created_at",
                    "updated_at",
                    "error",
                )
            }
        )

    @app.get("/comparisons/{comparison_id}", response_class=HTMLResponse)
    async def comparison_page(request: Request, comparison_id: str) -> Any:
        try:
            comparison_id = validate_comparison_id(comparison_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        directory = (output_root / comparison_id).resolve()
        if directory.parent != output_root.resolve():
            raise HTTPException(status_code=404, detail="Comparison not found.")
        comparison_path = directory / "comparison.json"
        manifest_path = directory / "run-manifest.json"
        if not comparison_path.is_file() or not manifest_path.is_file():
            raise HTTPException(status_code=404, detail="Comparison not found.")
        comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        analysis_path = directory / "ai-analysis.json"
        analysis = (
            json.loads(analysis_path.read_text(encoding="utf-8"))
            if analysis_path.is_file()
            else None
        )
        return render(
            request,
            "comparison.html",
            {
                "comparison": comparison,
                "analysis": analysis,
                "manifest": manifest,
                "downloads": [
                    name
                    for name in sorted(DOWNLOAD_ARTIFACTS)
                    if (directory / name).is_file()
                ],
            },
        )

    @app.get("/comparisons/{comparison_id}/download/{artifact}")
    async def download(comparison_id: str, artifact: str) -> Any:
        if artifact not in DOWNLOAD_ARTIFACTS:
            raise HTTPException(status_code=404, detail="Artifact not found.")
        try:
            comparison_id = validate_comparison_id(comparison_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        directory = (output_root / comparison_id).resolve()
        path = (directory / artifact).resolve()
        if (
            directory.parent != output_root.resolve()
            or path.parent != directory
            or not path.is_file()
        ):
            raise HTTPException(status_code=404, detail="Artifact not found.")
        return FileResponse(path, filename=artifact)

    return app


def run_web(
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    shared: bool = False,
    provider_config_path: str | Path | None = None,
    workers: int = 1,
) -> None:
    validate_web_binding(host, port, shared)
    if shared:
        print(
            "WARNING: SCT shared proof-of-concept mode has no authentication or "
            "built-in TLS. Use only on a trusted isolated network.",
            file=sys.stderr,
        )
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError(
            "Uvicorn is not installed. Install the approved web dependency set."
        ) from exc
    config_path = (
        Path(provider_config_path).resolve() if provider_config_path else None
    )
    app = create_app(
        shared_mode=shared,
        provider_config_path=config_path,
        job_workers=workers,
    )
    uvicorn.run(app, host=host, port=port, workers=1)


def main() -> int:
    run_web()
    return 0
