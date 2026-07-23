"""Command-line interface for SCT comparison validation and execution."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .errors import AIOutputError, PackageValidationError, SCTComparisonError
from .packages import load_packages
from .service import run_comparison


def _system_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sct-compare",
        description="Compare two or more validated SCT result packages.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="Validate package inputs")
    validate.add_argument("--package", action="append", required=True)

    compare = subparsers.add_parser("compare", help="Run a comparison")
    compare.add_argument("--package", action="append", required=True)
    compare.add_argument("--policy")
    compare.add_argument("--provider", default="none")
    compare.add_argument("--model")
    compare.add_argument("--provider-config")
    compare.add_argument("--comparison-id")
    compare.add_argument(
        "--output-root",
        default=str(_system_root() / "comparisons"),
    )
    compare.add_argument("--force", action="store_true")

    web = subparsers.add_parser("web", help="Start the local/shared web application")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8000)
    web.add_argument("--shared", action="store_true")
    web.add_argument("--provider-config")
    web.add_argument("--workers", type=int, default=1)
    return parser


def _print_progress(stage: str, percent: int, message: str) -> None:
    print(f"[{percent:3d}%] {stage}: {message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            packages = load_packages(args.package)
            print(
                json.dumps(
                    [package.preflight_summary() for package in packages],
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        if args.command == "web":
            from .web import run_web

            run_web(
                host=args.host,
                port=args.port,
                shared=args.shared,
                provider_config_path=args.provider_config,
                workers=args.workers,
            )
            return 0

        provider = None if args.provider.casefold() == "none" else args.provider
        result = run_comparison(
            args.package,
            policy_path=args.policy,
            output_root=args.output_root,
            comparison_id=args.comparison_id,
            force=args.force,
            provider_name=provider,
            model_name=args.model,
            provider_config_path=args.provider_config,
            progress_callback=_print_progress,
        )
        print(result["output_dir"])
        return 0
    except PackageValidationError as exc:
        print(f"Input validation failed: {exc}", file=sys.stderr)
        return 2
    except AIOutputError as exc:
        print(f"AI analysis failed after metrics were preserved: {exc}", file=sys.stderr)
        return 4
    except SCTComparisonError as exc:
        print(f"Comparison failed: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
