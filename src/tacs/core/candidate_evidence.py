# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Build public CandidateEvidence from the canonical prepared candidate set.

Function association for evidence uses the full canonical set so Stage 7
filtering cannot relabel an in-function candidate as ungrouped. Analysis may
still run on a Stage-7-filtered subset without changing these evidence records.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from tacs.core.candidate_utils import candidate_id_for
from tacs.core.function_schemas import FunctionBody
from tacs.core.path_utils import repo_relative_path
from tacs.core.schema import (
    CANDIDATE_SNIPPET_MAX_CHARS,
    DISCOVERY_METHODS,
    AnalysisCoverage,
    Candidate,
    CandidateEvidence,
    DeterministicCandidateSummary,
)


def bound_candidate_snippet(snippet: str, max_chars: int = CANDIDATE_SNIPPET_MAX_CHARS) -> str:
    """Truncate a one-line snippet for public evidence (no function bodies)."""
    text = (snippet or "").replace("\n", " ").replace("\r", " ")
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return text[: max_chars - 3] + "..."


def normalize_discovery_method(method: Optional[str]) -> str:
    """Return a controlled discovery_method from the producing detector.

    Producers must set a ``DISCOVERY_METHODS`` value at emission time. Missing
    or empty values become ``unknown`` (not a fabricated catalog match). A
    non-empty unrecognized value raises ``ValueError`` rather than inventing a
    label from risk, description, or symbol text.
    """
    if method is None or (isinstance(method, str) and not method.strip()):
        return "unknown"
    if method in DISCOVERY_METHODS:
        return method
    raise ValueError(
        f"Unrecognized discovery_method {method!r}; expected one of "
        f"{sorted(DISCOVERY_METHODS)}"
    )


def map_candidates_to_function_ids(
    candidates: Sequence[Candidate],
    functions: Sequence[FunctionBody],
    root_path: str,
) -> Dict[str, str]:
    """Map candidate_id → function_id for candidates covered by extracted functions.

    A candidate appears in at most one function under current extraction. When
    ``FunctionBody.candidate_ids`` is populated, those ids win; otherwise a
    candidate whose line falls in a function span and file matches is linked.
    """
    mapping: Dict[str, str] = {}

    # Prefer explicit candidate_ids when present (split parts, exact identity).
    for func in functions:
        for cid in getattr(func, "candidate_ids", None) or []:
            if cid and cid not in mapping:
                mapping[cid] = func.function_id

    # Fallback: line-in-span matching for bodies without candidate_ids.
    by_file_funcs: Dict[str, List[FunctionBody]] = {}
    for func in functions:
        key = repo_relative_path(func.file_path, root_path)
        by_file_funcs.setdefault(key, []).append(func)

    for candidate in candidates:
        rel = repo_relative_path(candidate.file, root_path)
        cid = candidate_id_for(candidate, rel)
        if cid in mapping:
            continue
        for func in by_file_funcs.get(rel, []):
            lines = set(func.candidate_lines or [])
            if candidate.line in lines:
                mapping[cid] = func.function_id
                break
            start = int(func.start_line or 0)
            end = int(func.end_line or 0)
            if start and end and start <= candidate.line <= end:
                # Prefer candidate_lines membership; span is last resort when
                # the line was not recorded on the body (should be rare).
                if not lines:
                    mapping[cid] = func.function_id
                    break
    return mapping


def build_candidate_evidence(
    candidates: Sequence[Candidate],
    *,
    root_path: str,
    functions: Sequence[FunctionBody] = (),
) -> List[CandidateEvidence]:
    """Build one CandidateEvidence row per prepared candidate (order preserved)."""
    id_to_function = map_candidates_to_function_ids(candidates, functions, root_path)
    out: List[CandidateEvidence] = []
    for candidate in candidates:
        rel = repo_relative_path(candidate.file, root_path)
        cid = candidate_id_for(candidate, rel)
        function_id = id_to_function.get(cid)
        coverage = (
            AnalysisCoverage.GROUPED if function_id else AnalysisCoverage.UNGROUPED
        )
        out.append(
            CandidateEvidence(
                candidate_id=cid,
                file=rel,
                line=int(candidate.line or 0),
                col_start=candidate.col_start,
                col_end=candidate.col_end,
                symbol=candidate.symbol or "",
                symbol_role=candidate.symbol_role,
                risk=candidate.risk or "",
                description=candidate.description or "",
                one_line_snippet=bound_candidate_snippet(candidate.one_line_snippet or ""),
                discovery_method=normalize_discovery_method(candidate.discovery_method),
                rule_id=(
                    candidate.rule_id
                    if isinstance(getattr(candidate, "rule_id", None), str)
                    and candidate.rule_id.strip()
                    else None
                ),
                function_id=function_id,
                analysis_coverage=coverage,
            )
        )
    return out


def summarize_candidate_evidence(
    evidence: Sequence[CandidateEvidence],
    *,
    findings_count: int,
) -> DeterministicCandidateSummary:
    """Compute public candidate_summary counts."""
    grouped = sum(1 for e in evidence if e.analysis_coverage == AnalysisCoverage.GROUPED)
    ungrouped = len(evidence) - grouped
    function_ids = {e.function_id for e in evidence if e.function_id}
    return DeterministicCandidateSummary(
        total=len(evidence),
        grouped=grouped,
        ungrouped=ungrouped,
        functions_with_candidates=len(function_ids),
        findings=findings_count,
    )


def summarize_serialized_candidates(
    candidates: Sequence[dict],
    *,
    findings_count: int,
) -> DeterministicCandidateSummary:
    """Reconcile candidate_summary from final serialized candidate/finding arrays."""
    grouped = 0
    function_ids = set()
    for row in candidates:
        coverage = row.get("analysis_coverage")
        function_id = row.get("function_id")
        if coverage == AnalysisCoverage.GROUPED.value or coverage == AnalysisCoverage.GROUPED:
            grouped += 1
        elif function_id and coverage is None:
            grouped += 1
        if function_id:
            function_ids.add(function_id)
    total = len(candidates)
    return DeterministicCandidateSummary(
        total=total,
        grouped=grouped,
        ungrouped=total - grouped,
        functions_with_candidates=len(function_ids),
        findings=int(findings_count),
    )


def attach_candidate_ids_to_functions(
    functions: Sequence[FunctionBody],
    candidates: Sequence[Candidate],
    root_path: str,
) -> List[FunctionBody]:
    """Return FunctionBody copies with ``candidate_ids`` filled from the candidate set.

    Split parts receive only candidates whose lines fall in that part's
    ``candidate_lines`` (or span when lines are empty).
    """
    # Index candidates by (relpath, line) → list (multi-symbol same line).
    by_file_line: Dict[Tuple[str, int], List[Candidate]] = {}
    for candidate in candidates:
        rel = repo_relative_path(candidate.file, root_path)
        by_file_line.setdefault((rel, int(candidate.line or 0)), []).append(candidate)

    updated: List[FunctionBody] = []
    for func in functions:
        rel = repo_relative_path(func.file_path, root_path)
        ids: List[str] = []
        seen = set()
        line_set = set(func.candidate_lines or [])
        if not line_set and func.start_line and func.end_line:
            line_set = set(range(int(func.start_line), int(func.end_line) + 1))
        for line in sorted(line_set):
            for candidate in by_file_line.get((rel, line), []):
                cid = candidate_id_for(candidate, rel)
                if cid not in seen:
                    seen.add(cid)
                    ids.append(cid)
        updated.append(func.model_copy(update={"candidate_ids": ids}))
    return updated
