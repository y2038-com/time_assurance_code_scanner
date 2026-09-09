"""CLI entrypoint for report_renderer."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from report_renderer.core import FindingsLoadError, apply_filters, load_findings_json, normalize_findings, sort_findings
from report_renderer.renderers import render_html, render_text, write_html_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan-report",
        description="Render scanner findings JSON as text or HTML.",
    )
    parser.add_argument("input", help="Path to findings JSON")
    parser.add_argument("--format", required=True, choices=["text", "html"], help="Output format")
    parser.add_argument("--only", choices=["yes", "no", "abstain"], help="Filter by issue class")
    parser.add_argument("--min-confidence", type=float, help="Minimum confidence threshold [0.0, 1.0]")
    parser.add_argument("--file-glob", action="append", default=[], help="File path glob filter (repeatable)")
    parser.add_argument("--rule", action="append", default=[], help="Rule ID filter (repeatable)")
    parser.add_argument(
        "--sort",
        choices=["file", "line", "risk", "confidence"],
        default="file",
        help="Sorting mode (default: file)",
    )
    parser.add_argument("--strict", action="store_true", help="Fail on malformed finding entries")
    parser.add_argument("--context", type=int, default=3, help="Reserved for v2 source-context expansion")

    parser.add_argument("--finding", type=int, help="Text mode: show one finding by 1-based index")
    parser.add_argument("--list", action="store_true", help="Text mode: compact list output")

    parser.add_argument("--out", default="report.html", help="HTML mode output path")
    parser.add_argument("--group-by", choices=["file", "rule", "none"], default="file", help="HTML grouping")
    parser.add_argument("--title", default="Y2038 Scan Report", help="HTML title")
    parser.add_argument("--open", action="store_true", help="HTML mode: open generated report")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.min_confidence is not None and not (0.0 <= args.min_confidence <= 1.0):
        print("error: --min-confidence must be between 0.0 and 1.0", file=sys.stderr)
        return 2
    if args.context < 0:
        print("error: --context must be >= 0", file=sys.stderr)
        return 2
    if args.format == "html" and args.finding is not None:
        print("error: --finding is only valid with --format text", file=sys.stderr)
        return 2
    if args.format == "html" and args.list:
        print("error: --list is only valid with --format text", file=sys.stderr)
        return 2

    try:
        _meta, raw_findings = load_findings_json(args.input)
        norm = normalize_findings(raw_findings, strict=args.strict)
    except FindingsLoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    findings = apply_filters(
        norm.findings,
        only=args.only,
        min_confidence=args.min_confidence,
        file_globs=args.file_glob,
        rules=args.rule,
    )
    findings = sort_findings(findings, args.sort)

    if norm.warnings:
        print(f"warning: {len(norm.warnings)} findings skipped or corrected during normalization", file=sys.stderr)
    if not findings:
        print("No findings matched filters.", file=sys.stderr)
        return 4

    if args.format == "text":
        if args.finding is not None:
            if args.finding < 1 or args.finding > len(findings):
                print(f"error: --finding must be between 1 and {len(findings)}", file=sys.stderr)
                return 2
            payload = render_text([findings[args.finding - 1]], list_mode=False)
        else:
            payload = render_text(findings, list_mode=args.list)
        print(payload)
        return 0

    html = render_html(findings, title=args.title, group_by=args.group_by)
    out_path = write_html_file(html, args.out)
    print(f"HTML report written to: {out_path}")
    if args.open:
        _best_effort_open(out_path)
    return 0


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


if __name__ == "__main__":
    raise SystemExit(main())
