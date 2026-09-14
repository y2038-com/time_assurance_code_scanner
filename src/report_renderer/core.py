# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Shared core for loading, normalizing, filtering, and sorting findings."""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class FindingsLoadError(Exception):
    """Raised when input JSON cannot be loaded."""


@dataclass
class SnippetLine:
    line_no: int | None
    text: str
    is_affected: bool


@dataclass
class NormalizedFinding:
    finding_id: str
    index: int
    file_path: str
    start_line: int | None
    end_line: int | None
    affected_lines: list[int]
    symbol: str | None
    rule_id: str
    issue_type: str | None
    issue_class: str
    risk: str
    risk_source: str
    confidence: float | None
    reason_short: str
    why_flagged: str
    snippet_lines: list[SnippetLine]
    raw: dict[str, Any]


@dataclass
class NormalizationResult:
    findings: list[NormalizedFinding]
    warnings: list[str]
    meta: dict[str, Any]


def load_findings_json(path: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load findings JSON from scanner output variants."""
    in_path = Path(path)
    if not in_path.exists():
        raise FindingsLoadError(f"Input not found: {path}")

    try:
        payload = json.loads(in_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FindingsLoadError(f"Invalid JSON: {exc}") from exc

    if isinstance(payload, dict):
        findings = payload.get("findings")
        if not isinstance(findings, list):
            raise FindingsLoadError("Expected object with 'findings' array.")
        meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
        return meta, findings

    if isinstance(payload, list):
        return {}, payload

    raise FindingsLoadError("Expected top-level JSON object or array.")


def normalize_findings(
    raw_findings: list[dict[str, Any]],
    *,
    strict: bool = False,
) -> NormalizationResult:
    warnings: list[str] = []
    out: list[NormalizedFinding] = []

    for i, item in enumerate(raw_findings, start=1):
        if not isinstance(item, dict):
            msg = f"Finding #{i}: not an object; skipped."
            if strict:
                raise FindingsLoadError(msg)
            warnings.append(msg)
            continue
        try:
            out.append(_normalize_one(item, i))
        except Exception as exc:  # pragma: no cover - defensive
            msg = f"Finding #{i}: normalization error: {exc}"
            if strict:
                raise FindingsLoadError(msg) from exc
            warnings.append(msg)

    _reindex(out)
    return NormalizationResult(findings=out, warnings=warnings, meta={})


def apply_filters(
    findings: list[NormalizedFinding],
    *,
    only: str | None,
    min_confidence: float | None,
    file_globs: list[str],
    rules: list[str],
) -> list[NormalizedFinding]:
    results = findings
    if only:
        if only == "yes":
            results = [f for f in results if _is_positive_issue(f)]
        else:
            results = [f for f in results if f.issue_class == only]
    if min_confidence is not None:
        results = [f for f in results if f.confidence is not None and f.confidence >= min_confidence]
    if file_globs:
        results = [
            f
            for f in results
            if any(fnmatch.fnmatch(f.file_path, pattern) for pattern in file_globs)
        ]
    if rules:
        allowed = {r.strip().upper() for r in rules if r.strip()}
        results = [f for f in results if f.rule_id.upper() in allowed]
    _reindex(results)
    return results


def sort_findings(findings: list[NormalizedFinding], sort_key: str) -> list[NormalizedFinding]:
    if sort_key == "line":
        ordered = sorted(findings, key=lambda f: (f.start_line is None, f.start_line or 10**9, f.file_path))
    elif sort_key == "risk":
        ranking = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        ordered = sorted(
            findings,
            key=lambda f: (ranking.get(f.risk, 99), -(f.confidence or -1.0), f.file_path),
        )
    elif sort_key == "confidence":
        ordered = sorted(findings, key=lambda f: (f.confidence is None, -(f.confidence or -1.0), f.file_path))
    else:
        ordered = sorted(findings, key=lambda f: (f.file_path, f.start_line or 10**9))
    _reindex(ordered)
    return ordered


def _normalize_one(item: dict[str, Any], i: int) -> NormalizedFinding:
    file_path = str(item.get("file") or "<unknown-file>")
    start_line, end_line = _extract_region(item)
    affected_lines = _extract_affected_lines(item, start_line, end_line)
    # Snippet text is usually the full function body; anchor line numbers at
    # function_id start, not at the focus/affected line.
    snippet_base_line = (
        _parse_function_id_start(item.get("function_id"))
        or start_line
        or (min(affected_lines) if affected_lines else None)
    )
    issue_class = _normalize_issue_class(item.get("y2038_issue"))
    confidence = _coerce_confidence(item.get("confidence"))
    risk, risk_source = _normalize_risk(item.get("severity"), confidence)
    rule_id = _normalize_rule_id(item)
    issue_type = _clean_opt_str(item.get("issue_type"))
    reason = _clean_opt_str(item.get("reason")) or "No reason provided."
    snippet_lines = _build_snippet_lines(
        _clean_opt_str(item.get("source_snippet")) or "",
        snippet_base_line=snippet_base_line,
        affected_lines=affected_lines,
    )
    finding_id = f"{file_path}:{start_line or '?'}-{end_line or '?'}:{i}"

    return NormalizedFinding(
        finding_id=finding_id,
        index=i,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        affected_lines=affected_lines,
        symbol=_clean_opt_str(item.get("symbol")),
        rule_id=rule_id,
        issue_type=issue_type,
        issue_class=issue_class,
        risk=risk,
        risk_source=risk_source,
        confidence=confidence,
        reason_short=reason,
        why_flagged=reason,
        snippet_lines=snippet_lines,
        raw=item,
    )


def _extract_region(item: dict[str, Any]) -> tuple[int | None, int | None]:
    region = item.get("region")
    if isinstance(region, dict):
        s = _coerce_int(region.get("start_line"))
        e = _coerce_int(region.get("end_line"))
        if s is not None and e is not None:
            return s, e
    lines = item.get("lines")
    if isinstance(lines, list):
        ints = [_coerce_int(v) for v in lines]
        ints = [v for v in ints if v is not None]
        if ints:
            return min(ints), max(ints)
    return None, None


def _extract_affected_lines(
    item: dict[str, Any], start_line: int | None, end_line: int | None
) -> list[int]:
    issue_lines: list[int] = []
    issues = item.get("issues")
    if isinstance(issues, list):
        for issue in issues:
            if isinstance(issue, dict):
                line = _coerce_int(issue.get("line"))
                if line is not None:
                    issue_lines.append(line)
    if issue_lines:
        return sorted(set(issue_lines))

    if start_line is not None and end_line is not None:
        return list(range(start_line, end_line + 1))
    lines = item.get("lines")
    if isinstance(lines, list):
        ints = sorted({v for raw in lines if (v := _coerce_int(raw)) is not None})
        return ints
    return []


def _normalize_issue_class(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    v = value.strip().lower()
    if v in {"yes", "no", "abstain"}:
        return v
    return "unknown"


def _is_positive_issue(finding: NormalizedFinding) -> bool:
    """Treat either y2038=yes or y2106=yes as a positive issue."""
    if finding.issue_class == "yes":
        return True
    y2106_issue = finding.raw.get("y2106_issue")
    return isinstance(y2106_issue, str) and y2106_issue.strip().lower() == "yes"


def _coerce_confidence(value: Any) -> float | None:
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    if out < 0.0 or out > 1.0:
        return None
    return out


def _normalize_risk(severity: Any, confidence: float | None) -> tuple[str, str]:
    if isinstance(severity, str):
        s = severity.strip().lower()
        if s in {"critical", "high", "medium", "low"}:
            return s, "severity"
    if confidence is None:
        return "unknown", "none"
    if confidence >= 0.90:
        return "high", "derived"
    if confidence >= 0.75:
        return "medium", "derived"
    return "low", "derived"


def _normalize_rule_id(item: dict[str, Any]) -> str:
    for key in ("rule_id", "rule", "check_id", "issue_type"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return _canonical_rule_name(value)

    issues = item.get("issues")
    if isinstance(issues, list):
        for issue in issues:
            if isinstance(issue, dict):
                issue_type = issue.get("type")
                if isinstance(issue_type, str) and issue_type.strip():
                    return _canonical_rule_name(issue_type)

    for key in ("symbol", "migration_risk_type"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return _canonical_rule_name(value)

    return "UNSPECIFIED_RULE"


def _canonical_rule_name(value: str) -> str:
    out = value.strip().upper().replace("-", "_").replace(" ", "_")
    cleaned = "".join(ch for ch in out if ch.isalnum() or ch == "_")
    return cleaned or "UNSPECIFIED_RULE"


def _build_snippet_lines(
    snippet: str,
    *,
    snippet_base_line: int | None,
    affected_lines: list[int],
) -> list[SnippetLine]:
    if "\\n" in snippet and "\n" not in snippet:
        # Some pipelines store snippets with escaped newlines. Normalize for rendering.
        snippet = snippet.replace("\\n", "\n")
    if not snippet:
        return [SnippetLine(line_no=snippet_base_line, text="<no snippet>", is_affected=False)]
    raw_lines = snippet.splitlines()
    affected = set(affected_lines)
    out: list[SnippetLine] = []
    for idx, text in enumerate(raw_lines):
        line_no = snippet_base_line + idx if snippet_base_line is not None else None
        out.append(
            SnippetLine(
                line_no=line_no,
                text=text,
                is_affected=(line_no in affected) if line_no is not None else False,
            )
        )
    return out


def _parse_function_id_start(function_id: Any) -> int | None:
    """Extract `<start>` from function_id like `<path>@<sym>:<start>-<end>`."""
    if not isinstance(function_id, str):
        return None
    # Take the last `:<num>-<num>` tail.
    import re

    m = re.search(r":(\d+)-\d+\Z", function_id.strip())
    if not m:
        return None
    try:
        return int(m.group(1))
    except (TypeError, ValueError):
        return None


def _coerce_int(value: Any) -> int | None:
    try:
        out = int(value)
    except (TypeError, ValueError):
        return None
    return out if out > 0 else None


def _clean_opt_str(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped if stripped else None


def _reindex(findings: list[NormalizedFinding]) -> None:
    for i, finding in enumerate(findings, start=1):
        finding.index = i
