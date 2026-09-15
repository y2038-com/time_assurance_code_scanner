# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from report_renderer.core import (
    FindingsLoadError,
    apply_filters,
    load_findings_json,
    normalize_findings,
    sort_findings,
)
from report_renderer.renderers import render_html, render_text, write_html_file


def _repo_dirs(batch_run_dir: Path) -> list[Path]:
    repos_dir = batch_run_dir / "repos"
    if not repos_dir.exists():
        return []
    dirs = [p for p in repos_dir.iterdir() if p.is_dir()]
    dirs.sort(key=lambda p: p.name)
    return dirs


def _findings_path(repo_dir: Path) -> Path:
    return repo_dir / "scan" / "findings.json"


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

    if fmt == "text":
        payload = render_text(findings, list_mode=list_mode)
        if out_path is None:
            return True, payload
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload + "\n", encoding="utf-8")
        return True, str(out_path)

    html = render_html(findings, title=title, group_by=group_by)
    if out_path is None:
        return False, "html requires output path"
    rendered_path = write_html_file(html, str(out_path))
    return True, str(rendered_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="batch-render-reports",
        description="Render report_renderer outputs for all repos in a batch run.",
    )
    parser.add_argument("--batch-run-dir", required=True, help="Path to one batch_runs/<run_id> directory")
    parser.add_argument("--format", required=True, choices=["text", "html"], help="Output format")
    parser.add_argument("--out-dir", help="Output dir (default: <batch-run-dir>/reports/<format>)")
    parser.add_argument("--only", choices=["yes", "no", "abstain"], help="Filter issue class")
    parser.add_argument("--min-confidence", type=float, help="Minimum confidence [0.0, 1.0]")
    parser.add_argument("--file-glob", action="append", default=[], help="File path glob filter (repeatable)")
    parser.add_argument("--rule", action="append", default=[], help="Rule ID filter (repeatable)")
    parser.add_argument("--sort", choices=["file", "line", "risk", "confidence"], default="file")
    parser.add_argument("--strict", action="store_true", help="Fail on malformed finding entries")
    parser.add_argument("--list", action="store_true", help="Text mode: compact list")
    parser.add_argument("--group-by", choices=["file", "rule", "none"], default="file", help="HTML grouping")
    parser.add_argument("--title", default="Y2038 Scan Report", help="HTML title")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "debug", "info", "warning", "error"],
        help="Console diagnostic log level (default: INFO)",
    )
    args = parser.parse_args(argv)

    from tacs.core.logging_config import configure_logging, get_logger, resolve_log_level

    configure_logging(resolve_log_level(log_level=args.log_level))
    log = get_logger("tacs.batch_render_reports")

    if args.min_confidence is not None and not (0.0 <= args.min_confidence <= 1.0):
        raise SystemExit("--min-confidence must be between 0.0 and 1.0")

    batch_run_dir = Path(args.batch_run_dir).resolve()
    if not batch_run_dir.exists():
        raise SystemExit(f"batch run dir not found: {batch_run_dir}")

    repos = _repo_dirs(batch_run_dir)
    if not repos:
        raise SystemExit(f"no repo directories found under: {batch_run_dir / 'repos'}")

    out_dir = Path(args.out_dir).resolve() if args.out_dir else (batch_run_dir / "reports" / args.format)
    out_dir.mkdir(parents=True, exist_ok=True)

    rendered: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    failed = 0

    log.info("Rendering %d repo report(s) from %s", len(repos), batch_run_dir)

    for repo_dir in repos:
        repo_key = repo_dir.name
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


if __name__ == "__main__":
    raise SystemExit(main())
