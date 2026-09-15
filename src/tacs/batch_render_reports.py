# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Render findings JSON or a batch run directory to text/HTML (``tacs render``)."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal

from report_renderer.core import (
    FindingsLoadError,
    apply_filters,
    load_findings_json,
    normalize_findings,
    sort_findings,
)
from report_renderer.renderers import render_html, render_text, write_html_file

RenderMode = Literal["single", "batch"]


def _repo_dirs(batch_run_dir: Path) -> list[Path]:
    repos_dir = batch_run_dir / "repos"
    if not repos_dir.exists():
        return []
    dirs = [p for p in repos_dir.iterdir() if p.is_dir()]
    dirs.sort(key=lambda p: p.name)
    return dirs


def _findings_path(repo_dir: Path) -> Path:
    return repo_dir / "scan" / "findings.json"


def _resolve_input_path(args: argparse.Namespace) -> Path:
    positional = getattr(args, "input", None)
    batch_alias = getattr(args, "batch_run_dir", None)
    if positional and batch_alias:
        raise SystemExit(
            "error: pass either a positional path or --batch-run-dir, not both"
        )
    raw = positional or batch_alias
    if not raw:
        raise SystemExit(
            "error: provide a findings JSON path or a batch run directory "
            "(see tacs render --help)"
        )
    return Path(raw).expanduser().resolve()


def detect_render_mode(path: Path) -> tuple[RenderMode, Path]:
    """
    Decide single vs batch render target.

    Returns ``(mode, findings_or_batch_path)`` where single mode's path is the
    findings JSON file to load.
    """
    if path.is_file():
        return "single", path
    if not path.is_dir():
        raise SystemExit(f"error: path not found: {path}")

    if (path / "repos").is_dir():
        return "batch", path

    for candidate in (
        path / "scan" / "findings.json",
        path / "findings" / "findings.json",
        path / "findings.json",
    ):
        if candidate.is_file():
            return "single", candidate

    raise SystemExit(
        "error: not a findings JSON file or batch run directory "
        f"(expected a .json file, or a directory with repos/): {path}"
    )


def _render_one(
    findings_path: Path,
    *,
    fmt: str,
    out_path: Path | None,
    only: str | None,
    min_confidence: float | None,
    file_globs: list[str],
    rules: list[str],
    sort_mode: str,
    strict: bool,
    list_mode: bool,
    group_by: str,
    title: str,
    finding_index: int | None = None,
) -> tuple[bool, str]:
    try:
        _meta, raw_findings = load_findings_json(str(findings_path))
        norm = normalize_findings(raw_findings, strict=strict)
    except FindingsLoadError as exc:
        return False, f"load error: {exc}"

    findings = apply_filters(
        norm.findings,
        only=only,
        min_confidence=min_confidence,
        file_globs=file_globs,
        rules=rules,
    )
    findings = sort_findings(findings, sort_mode)
    if not findings:
        return False, "no findings matched filters"

    if finding_index is not None:
        if finding_index < 1 or finding_index > len(findings):
            return False, f"--finding must be between 1 and {len(findings)}"
        findings = [findings[finding_index - 1]]

    if fmt == "text":
        payload = render_text(findings, list_mode=list_mode and finding_index is None)
        if out_path is None:
            return True, payload
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload + "\n", encoding="utf-8")
        return True, str(out_path)

    html = render_html(findings, title=title, group_by=group_by)
    if out_path is None:
        return False, "html requires --out (or --out-dir in batch mode)"
    rendered_path = write_html_file(html, str(out_path))
    return True, str(rendered_path)


def _best_effort_open(path: Path) -> None:
    path_str = str(path.resolve())
    try:
        if sys.platform.startswith("darwin"):
            subprocess.run(["open", path_str], check=False)
            return
        if os.name == "nt":
            os.startfile(path_str)  # type: ignore[attr-defined]
            return
        subprocess.run(["xdg-open", path_str], check=False)
    except Exception as exc:  # pragma: no cover - non-deterministic env
        print(f"warning: failed to open report automatically: {exc}", file=sys.stderr)


def _run_batch(args: argparse.Namespace, batch_run_dir: Path) -> int:
    from tacs.core.logging_config import get_logger
    from tacs.core.status_logger import StatusLogger

    log = get_logger("tacs.batch_render_reports")

    if args.out is not None:
        raise SystemExit("error: --out is only valid for a single findings JSON")
    if args.finding is not None:
        raise SystemExit("error: --finding is only valid for a single findings JSON")
    if args.open:
        raise SystemExit("error: --open is only valid for a single findings JSON")

    repos = _repo_dirs(batch_run_dir)
    if not repos:
        raise SystemExit(f"error: no repo directories found under: {batch_run_dir / 'repos'}")

    out_dir = (
        Path(args.out_dir).resolve()
        if args.out_dir
        else (batch_run_dir / "reports" / args.format)
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    rendered: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    failed = 0

    log.info("Rendering %d repo report(s) from %s", len(repos), batch_run_dir)

    for idx, repo_dir in enumerate(repos, start=1):
        repo_key = repo_dir.name
        # Essential progress: visible at every log level.
        StatusLogger.always(f"[{idx}/{len(repos)}] {repo_key}")
        findings = _findings_path(repo_dir)
        if not findings.exists():
            skipped.append({"repo_key": repo_key, "reason": "missing findings.json"})
            log.debug("skip %s: missing findings.json", repo_key)
            continue

        if args.format == "html":
            target = out_dir / f"{repo_key}.html"
        else:
            target = out_dir / f"{repo_key}.txt"

        ok, msg = _render_one(
            findings,
            fmt=args.format,
            out_path=target,
            only=args.only,
            min_confidence=args.min_confidence,
            file_globs=args.file_glob,
            rules=args.rule,
            sort_mode=args.sort,
            strict=args.strict,
            list_mode=args.list,
            group_by=args.group_by,
            title=args.title,
        )
        if ok:
            rendered.append({"repo_key": repo_key, "output": msg})
            log.debug("rendered %s -> %s", repo_key, msg)
        else:
            failed += 1
            skipped.append({"repo_key": repo_key, "reason": msg})
            log.warning("skip %s: %s", repo_key, msg)

    index = {
        "batch_run_dir": str(batch_run_dir),
        "format": args.format,
        "output_dir": str(out_dir),
        "counts": {
            "repos_total": len(repos),
            "rendered": len(rendered),
            "skipped_or_failed": len(skipped),
            "failed": failed,
        },
        "rendered": rendered,
        "skipped_or_failed": skipped,
    }
    index_path = out_dir / "index.json"
    index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")
    # Primary command result on stdout (not mixed into diagnostics).
    print(f"Rendered {len(rendered)} report(s). Index: {index_path}")
    return 0 if failed == 0 else 1


def _run_single(args: argparse.Namespace, findings_path: Path) -> int:
    from tacs.core.logging_config import get_logger

    log = get_logger("tacs.batch_render_reports")

    if args.out_dir is not None:
        raise SystemExit("error: --out-dir is only valid for a batch run directory")
    if args.format == "html" and args.finding is not None:
        raise SystemExit("error: --finding is only valid with --format text")
    if args.format == "html" and args.list:
        raise SystemExit("error: --list is only valid with --format text")
    if args.open and args.format != "html":
        raise SystemExit("error: --open is only valid with --format html")

    out_path: Path | None = None
    if args.out is not None:
        out_path = Path(args.out).expanduser().resolve()
    elif args.format == "html":
        out_path = findings_path.with_name(f"{findings_path.stem}_report.html")

    log.info("Rendering single findings file: %s", findings_path)
    ok, msg = _render_one(
        findings_path,
        fmt=args.format,
        out_path=out_path,
        only=args.only,
        min_confidence=args.min_confidence,
        file_globs=args.file_glob,
        rules=args.rule,
        sort_mode=args.sort,
        strict=args.strict,
        list_mode=args.list,
        group_by=args.group_by,
        title=args.title,
        finding_index=args.finding,
    )
    if not ok:
        raise SystemExit(f"error: {msg}")

    if args.format == "text" and out_path is None:
        # Primary machine-oriented report on stdout.
        print(msg)
        return 0

    print(f"Report written to: {msg}")
    if args.open and args.format == "html":
        _best_effort_open(Path(msg))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tacs render",
        description=(
            "Render scanner findings as text or HTML. "
            "Accepts a findings JSON file or a batch run directory "
            "(e.g. results/batch_runs/<run_id>)."
        ),
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Findings JSON file, or a batch run directory (e.g. results/batch_runs/<run_id>)",
    )
    parser.add_argument(
        "--batch-run-dir",
        help="Deprecated alias for a batch run directory (prefer the positional path)",
    )
    parser.add_argument("--format", required=True, choices=["text", "html"], help="Output format")
    parser.add_argument(
        "--out",
        help="Single-file mode: output path (text optional; HTML defaults beside the findings file)",
    )
    parser.add_argument(
        "--out-dir",
        help="Batch mode: output directory (default: <batch-run-dir>/reports/<format>)",
    )
    parser.add_argument("--only", choices=["yes", "no", "abstain"], help="Filter issue class")
    parser.add_argument("--min-confidence", type=float, help="Minimum confidence [0.0, 1.0]")
    parser.add_argument("--file-glob", action="append", default=[], help="File path glob filter (repeatable)")
    parser.add_argument("--rule", action="append", default=[], help="Rule ID filter (repeatable)")
    parser.add_argument("--sort", choices=["file", "line", "risk", "confidence"], default="file")
    parser.add_argument("--strict", action="store_true", help="Fail on malformed finding entries")
    parser.add_argument("--list", action="store_true", help="Text mode: compact list")
    parser.add_argument(
        "--finding",
        type=int,
        help="Single-file text mode: show one finding by 1-based index",
    )
    parser.add_argument("--group-by", choices=["file", "rule", "none"], default="file", help="HTML grouping")
    parser.add_argument("--title", default="Y2038 Scan Report", help="HTML title")
    parser.add_argument(
        "--open",
        action="store_true",
        help="Single-file HTML mode: best-effort open the report",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "debug", "info", "warning", "error"],
        help="Console diagnostic log level (default: INFO)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    from tacs.core.logging_config import configure_logging, resolve_log_level

    configure_logging(resolve_log_level(log_level=args.log_level))

    if args.min_confidence is not None and not (0.0 <= args.min_confidence <= 1.0):
        raise SystemExit("error: --min-confidence must be between 0.0 and 1.0")

    path = _resolve_input_path(args)
    if not path.exists():
        raise SystemExit(f"error: path not found: {path}")

    # Explicit --batch-run-dir must be a batch directory.
    if args.batch_run_dir and not args.input:
        if not path.is_dir() or not (path / "repos").is_dir():
            raise SystemExit(
                f"error: --batch-run-dir must be a batch run directory with repos/: {path}"
            )
        mode, target = "batch", path
    else:
        mode, target = detect_render_mode(path)

    if mode == "batch":
        return _run_batch(args, target)
    return _run_single(args, target)


if __name__ == "__main__":
    raise SystemExit(main())
