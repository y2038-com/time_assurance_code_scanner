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


@dataclass
class LoadedScanDocument:
    """Scanner result JSON (versioned schema or legacy findings-only)."""

    meta: dict[str, Any]
    findings: list[dict[str, Any]]
    candidates: list[dict[str, Any]]
    assessments: list[dict[str, Any]]
    schema_version: str | None

    @property
    def is_versioned(self) -> bool:
        return bool(self.schema_version) or bool(self.candidates) or bool(self.assessments)

    @property
    def has_assessment_section(self) -> bool:
        """True when the document is schema 1.1+ (assessments array is meaningful)."""
        if self.assessments:
            return True
        from tacs.core.model_assessment import schema_supports_assessments

        return schema_supports_assessments(self.schema_version)


def load_scan_document(path: str) -> LoadedScanDocument:
    """Load a scanner result JSON (schema 1.x or legacy findings-only / bare array)."""
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
        raw_candidates = payload.get("candidates")
        candidates: list[dict[str, Any]] = []
        if isinstance(raw_candidates, list):
            candidates = [c for c in raw_candidates if isinstance(c, dict)]
        raw_assessments = payload.get("assessments")
        assessments: list[dict[str, Any]] = []
        if isinstance(raw_assessments, list):
            assessments = [a for a in raw_assessments if isinstance(a, dict)]
        schema_version = payload.get("schema_version")
        if schema_version is not None and not isinstance(schema_version, str):
            schema_version = str(schema_version)
        return LoadedScanDocument(
            meta=meta,
            findings=findings,
            candidates=candidates,
            assessments=assessments,
            schema_version=schema_version,
        )

    if isinstance(payload, list):
        return LoadedScanDocument(
            meta={},
            findings=payload,
            candidates=[],
            assessments=[],
            schema_version=None,
        )

    raise FindingsLoadError("Expected top-level JSON object or array.")


def load_findings_json(path: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load findings JSON from scanner output variants.

    Prefer :func:`load_scan_document` when candidate evidence is needed.
    """
    doc = load_scan_document(path)
    return doc.meta, doc.findings


def candidate_counts_from_document(
    doc: LoadedScanDocument,
) -> dict[str, int]:
    """Derive deterministic-candidate counts from meta.candidate_summary or candidates[]."""
    summary = doc.meta.get("candidate_summary") if isinstance(doc.meta, dict) else None
    if isinstance(summary, dict):
        total = int(summary.get("total") or 0)
        grouped = int(summary.get("grouped") or 0)
        ungrouped = int(summary.get("ungrouped") or 0)
        functions = int(summary.get("functions_with_candidates") or 0)
        findings = int(summary.get("findings") if summary.get("findings") is not None else len(doc.findings))
        return {
            "total": total,
            "grouped": grouped,
            "ungrouped": ungrouped,
            "functions_with_candidates": functions,
            "findings": findings,
        }

    total = len(doc.candidates)
    grouped = sum(1 for c in doc.candidates if c.get("function_id") or c.get("analysis_coverage") == "grouped")
    ungrouped = total - grouped
    function_ids = {c.get("function_id") for c in doc.candidates if c.get("function_id")}
    return {
        "total": total,
        "grouped": grouped,
        "ungrouped": ungrouped,
        "functions_with_candidates": len(function_ids),
        "findings": len(doc.findings),
    }


def assessment_counts_from_document(
    doc: LoadedScanDocument,
) -> dict[str, int | str | None]:
    """Derive assessment counts / analysis_status from meta or assessments[]."""
    status = None
    if isinstance(doc.meta, dict):
        status = doc.meta.get("analysis_status")
    summary = doc.meta.get("assessment_summary") if isinstance(doc.meta, dict) else None
    if isinstance(summary, dict):
        return {
            "total": int(summary.get("total") or 0),
            "completed": int(summary.get("completed") or 0),
            "yes": int(summary.get("yes") or 0),
            "no": int(summary.get("no") or 0),
            "abstain": int(summary.get("abstain") or 0),
            "analysis_errors": int(summary.get("analysis_errors") or 0),
            "not_requested": int(summary.get("not_requested") or 0),
            "analysis_status": status,
        }
    completed = yes = no = abstain = errors = not_requested = 0
    for row in doc.assessments:
        exec_status = row.get("execution_status")
        verdict = row.get("verdict")
        if exec_status == "completed":
            completed += 1
            if verdict == "yes":
                yes += 1
            elif verdict == "no":
                no += 1
            elif verdict == "abstain":
                abstain += 1
        elif exec_status == "analysis_error":
            errors += 1
        elif exec_status == "not_requested":
            not_requested += 1
    return {
        "total": len(doc.assessments),
        "completed": completed,
        "yes": yes,
        "no": no,
        "abstain": abstain,
        "analysis_errors": errors,
        "not_requested": not_requested,
        "analysis_status": status,
    }


def format_candidate_preservation_message(
    *,
    candidate_total: int,
    ungrouped: int,
    findings_shown: int,
    has_candidate_section: bool,
) -> str:
    """Honest empty-findings / zero-candidate wording for reports."""
    if not has_candidate_section:
        # Legacy findings-only JSON: do not invent candidate counts.
        if findings_shown == 0:
            return "No findings match the selected filters."
        return ""

    if candidate_total == 0 and findings_shown == 0:
        return "No deterministic candidates were found."

    parts: list[str] = []
    if findings_shown == 0 and candidate_total > 0:
        parts.append(
            f"No model-retained findings were produced; {candidate_total} "
            "deterministic candidates were recorded for review."
        )
    elif candidate_total > 0:
        parts.append(
            f"{candidate_total} deterministic candidates were recorded"
            + (
                f", including {ungrouped} candidates not grouped into a recognized function."
                if ungrouped
                else "."
            )
        )
    elif findings_shown == 0:
        parts.append("No deterministic candidates were found.")
    return " ".join(parts)


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
