# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Build public ModelAssessment records from function analyses."""

from __future__ import annotations

import math
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from tacs.core.function_schemas import FunctionAnalysis, FunctionBody, Y2038Summary
from tacs.core.schema import (
    ASSESSMENT_REASON_MAX_CHARS,
    PUBLIC_ASSESSMENT_KEYS,
    AssessmentExecutionStatus,
    AssessmentSummary,
    ModelAssessment,
    ModelVerdict,
    RunAnalysisStatus,
)

# Controlled public reasons for operational stubs. Full exception text and host
# paths stay out of assessments[]; compatibility findings may still carry the
# richer internal description as a legacy projection.
_OPERATIONAL_REASON_BY_ISSUE_TYPE = {
    "parse_gap": "No usable model output for this function",
    "duplicate_conflict": "Conflicting model outputs for this function",
    "analysis_error": "Model analysis failed for this function",
}
_DEFAULT_OPERATIONAL_REASON = "Model analysis could not be completed for this function"

# Absolute / home-style path fragments that must not appear in public reasons.
_ABS_PATH_RE = re.compile(
    r"(?:(?<![A-Za-z0-9_])(?:/[^\s\"']+|[A-Za-z]:\\[^\s\"']+)|(?:^|[\s\"'(])~/[^\s\"']+)"
)


def _summary_to_verdict(summary: Y2038Summary) -> ModelVerdict:
    if summary == Y2038Summary.YES:
        return ModelVerdict.YES
    if summary == Y2038Summary.NO:
        return ModelVerdict.NO
    return ModelVerdict.ABSTAIN


def _bound_reason(text: str, max_chars: int = ASSESSMENT_REASON_MAX_CHARS) -> str:
    collapsed = " ".join((text or "").split())
    if len(collapsed) <= max_chars:
        return collapsed
    if max_chars <= 3:
        return collapsed[:max_chars]
    return collapsed[: max_chars - 3] + "..."


def _redact_absolute_paths(text: str) -> str:
    """Replace absolute / home path tokens in reason text with a placeholder."""
    return _ABS_PATH_RE.sub("<path>", text)


def _first_issue_type(analysis: FunctionAnalysis) -> Optional[str]:
    for issue in analysis.issues or []:
        if isinstance(issue, dict):
            itype = issue.get("type")
            if isinstance(itype, str) and itype.strip():
                return itype.strip()
    return None


def _first_issue_description(analysis: FunctionAnalysis) -> Optional[str]:
    for issue in analysis.issues or []:
        if isinstance(issue, dict):
            desc = issue.get("description")
            if isinstance(desc, str) and desc.strip():
                return desc.strip()
    return None


def _reason_from_analysis(
    analysis: FunctionAnalysis,
    status: AssessmentExecutionStatus,
) -> Optional[str]:
    """Public reason only — never prompts, bodies, or raw exception dumps."""
    if status == AssessmentExecutionStatus.ANALYSIS_ERROR:
        itype = _first_issue_type(analysis)
        controlled = _OPERATIONAL_REASON_BY_ISSUE_TYPE.get(
            itype or "", _DEFAULT_OPERATIONAL_REASON
        )
        return _bound_reason(controlled)

    desc = _first_issue_description(analysis)
    if not desc:
        return None
    return _bound_reason(_redact_absolute_paths(desc))


def _clamp_confidence(value: Any) -> Optional[float]:
    try:
        conf = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(conf):
        return None
    if conf < 0.0:
        return 0.0
    if conf > 1.0:
        return 1.0
    return conf


def build_model_assessment(
    analysis: FunctionAnalysis,
    function: FunctionBody,
    *,
    analysis_mode: str = "function_first",
) -> ModelAssessment:
    """Convert one aligned FunctionAnalysis into a public ModelAssessment."""
    status = getattr(
        analysis, "execution_status", AssessmentExecutionStatus.COMPLETED
    )
    if isinstance(status, str):
        status = AssessmentExecutionStatus(status)

    verdict: Optional[ModelVerdict] = None
    confidence: Optional[float] = None
    if status == AssessmentExecutionStatus.COMPLETED:
        verdict = _summary_to_verdict(analysis.y2038_summary)
        confidence = _clamp_confidence(analysis.confidence)

    # Copy ids so later filtering cannot mutate FunctionBody.candidate_ids.
    candidate_ids = list(getattr(function, "candidate_ids", None) or [])
    return ModelAssessment(
        assessment_id=f"assessment:{function.function_id}",
        function_id=function.function_id,
        candidate_ids=candidate_ids,
        execution_status=status,
        verdict=verdict,
        confidence=confidence,
        reason=_reason_from_analysis(analysis, status),
        analysis_mode=analysis_mode,
    )


def record_assessments(
    store: Dict[str, ModelAssessment],
    analyses: Sequence[FunctionAnalysis],
    functions: Sequence[FunctionBody],
    *,
    analysis_mode: str = "function_first",
) -> None:
    """Upsert assessments keyed by function_id (later passes replace earlier)."""
    for analysis, function in zip(analyses, functions):
        store[function.function_id] = build_model_assessment(
            analysis, function, analysis_mode=analysis_mode
        )


def finalize_assessments(store: Dict[str, ModelAssessment]) -> List[ModelAssessment]:
    """Stable order by assessment_id for deterministic serialization."""
    return sorted(store.values(), key=lambda a: a.assessment_id)


def derive_run_analysis_status(
    *,
    llm_requested: bool,
    assessments: Sequence[ModelAssessment],
) -> RunAnalysisStatus:
    """Compute run-level analysis_status from finalized assessments."""
    if not llm_requested:
        return RunAnalysisStatus.NOT_REQUESTED
    if not assessments:
        # Requested analysis with zero eligible units and no operational error.
        return RunAnalysisStatus.COMPLETE

    completed = 0
    errors = 0
    for a in assessments:
        if a.execution_status == AssessmentExecutionStatus.COMPLETED:
            completed += 1
        elif a.execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR:
            errors += 1

    if errors and completed:
        return RunAnalysisStatus.PARTIAL
    if errors and not completed:
        return RunAnalysisStatus.FAILED
    return RunAnalysisStatus.COMPLETE


def summarize_assessments(
    assessments: Sequence[ModelAssessment],
    *,
    findings_count: int,
) -> AssessmentSummary:
    completed = yes = no = abstain = errors = not_requested = 0
    for a in assessments:
        if a.execution_status == AssessmentExecutionStatus.COMPLETED:
            completed += 1
            if a.verdict == ModelVerdict.YES:
                yes += 1
            elif a.verdict == ModelVerdict.NO:
                no += 1
            elif a.verdict == ModelVerdict.ABSTAIN:
                abstain += 1
        elif a.execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR:
            errors += 1
        elif a.execution_status == AssessmentExecutionStatus.NOT_REQUESTED:
            not_requested += 1
    return AssessmentSummary(
        total=len(assessments),
        completed=completed,
        yes=yes,
        no=no,
        abstain=abstain,
        analysis_errors=errors,
        not_requested=not_requested,
        findings=findings_count,
    )


def summarize_serialized_assessments(
    assessments: Sequence[dict],
    *,
    findings_count: int,
) -> AssessmentSummary:
    """Reconcile assessment_summary from final serialized assessment rows."""
    completed = yes = no = abstain = errors = not_requested = 0
    for row in assessments:
        status = row.get("execution_status")
        verdict = row.get("verdict")
        if status == AssessmentExecutionStatus.COMPLETED.value or status == "completed":
            completed += 1
            if verdict in (ModelVerdict.YES.value, "yes"):
                yes += 1
            elif verdict in (ModelVerdict.NO.value, "no"):
                no += 1
            elif verdict in (ModelVerdict.ABSTAIN.value, "abstain"):
                abstain += 1
        elif status in (AssessmentExecutionStatus.ANALYSIS_ERROR.value, "analysis_error"):
            errors += 1
        elif status in (AssessmentExecutionStatus.NOT_REQUESTED.value, "not_requested"):
            not_requested += 1
    return AssessmentSummary(
        total=len(assessments),
        completed=completed,
        yes=yes,
        no=no,
        abstain=abstain,
        analysis_errors=errors,
        not_requested=not_requested,
        findings=int(findings_count),
    )


def filter_candidate_ids(
    assessments: Iterable[ModelAssessment],
    valid_ids: set[str],
) -> List[ModelAssessment]:
    """Drop unknown candidate_ids so assessments cannot invent linkage.

    Returns new assessment objects when ids change; never mutates inputs.
    """
    out: List[ModelAssessment] = []
    for a in assessments:
        ids = [cid for cid in a.candidate_ids if cid in valid_ids]
        if ids != list(a.candidate_ids):
            if hasattr(a, "model_copy"):
                out.append(a.model_copy(update={"candidate_ids": ids}))
            else:
                out.append(a.copy(update={"candidate_ids": ids}))
        else:
            out.append(a)
    return out


def assessment_to_public_dict(assessment: Any) -> Dict[str, Any]:
    """Serialize one assessment with an allowlist (no bodies/prompts/extras)."""
    raw: Dict[str, Any]
    try:
        if hasattr(assessment, "model_dump"):
            raw = assessment.model_dump(mode="json")
        elif hasattr(assessment, "dict"):
            raw = assessment.dict()
        elif isinstance(assessment, dict):
            raw = dict(assessment)
        else:
            raw = {}
            for key in PUBLIC_ASSESSMENT_KEYS:
                if hasattr(assessment, key):
                    raw[key] = getattr(assessment, key)
    except Exception:
        raw = {}
        for key in PUBLIC_ASSESSMENT_KEYS:
            try:
                if hasattr(assessment, key):
                    raw[key] = getattr(assessment, key)
            except Exception:
                continue

    out: Dict[str, Any] = {}
    for key in PUBLIC_ASSESSMENT_KEYS:
        if key not in raw:
            continue
        value = raw[key]
        if hasattr(value, "value") and not isinstance(value, (str, bytes, bool, int, float)):
            value = value.value
        if key == "candidate_ids":
            if isinstance(value, list):
                value = [str(x) for x in value]
            else:
                value = []
        if key == "reason" and isinstance(value, str):
            value = _bound_reason(_redact_absolute_paths(value))
        if key == "confidence":
            value = _clamp_confidence(value)
        out[key] = value
    # Required identity fields with safe defaults if missing after failure.
    out.setdefault("assessment_id", "assessment:unknown")
    out.setdefault("function_id", "unknown")
    out.setdefault("candidate_ids", [])
    out.setdefault("execution_status", AssessmentExecutionStatus.ANALYSIS_ERROR.value)
    out.setdefault("analysis_mode", "function_first")
    if "verdict" not in out:
        out["verdict"] = None
    return out


def parse_schema_version(version: Optional[str]) -> Optional[Tuple[int, int]]:
    """Parse ``major.minor`` integers from a schema_version string.

    Ignores pre-release / build suffixes. Returns None when unparsable.
    Does not use lexicographic string comparison.
    """
    if not version or not isinstance(version, str):
        return None
    core = version.strip().split("+", 1)[0].split("-", 1)[0]
    parts = core.split(".")
    if not parts or not parts[0]:
        return None
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 and parts[1] != "" else 0
    except ValueError:
        return None
    return major, minor


def schema_supports_assessments(version: Optional[str]) -> bool:
    """True when the public schema includes assessments[] (1.1 and later)."""
    parsed = parse_schema_version(version)
    if parsed is None:
        return False
    major, minor = parsed
    return major > 1 or (major == 1 and minor >= 1)
