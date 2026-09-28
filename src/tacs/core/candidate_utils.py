# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Deterministic candidate identity, ordering, and deduplication."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from tacs.core.path_utils import canonical_source_path
from tacs.core.schema import Candidate

CandidateRuleIdConflictError = type("CandidateRuleIdConflictError", (ValueError,), {})
CandidateProvenanceConflictError = type(
    "CandidateProvenanceConflictError", (ValueError,), {}
)


def normalize_candidate_file(candidate: Candidate) -> Candidate:
    """Point ``candidate.file`` at the resolved absolute source path."""
    canonical = canonical_source_path(candidate.file)
    if not canonical or canonical == candidate.file:
        return candidate
    return candidate.model_copy(update={"file": canonical})


def candidate_identity_key(candidate: Candidate) -> Tuple[str, int, int, int, str, str]:
    """
    Semantic identity for a candidate discovery.

    Tuple: ``(canonical_file, line, col_start, col_end, symbol, risk)``.

    Why ``risk`` (not description / a synthetic rule id):
    * ``risk`` is the stable severity tag supplied by rules JSON and by the
      define/arithmetic detectors.
    * Catalog ``rule_id`` is a separate attribution field on ``Candidate`` /
      ``CandidateEvidence``; it is not part of this identity tuple.
    * It is deterministic for a given ruleset/detector (not model output or a
      timestamp). Distinct severity at the same site stays distinct.
    * ``description`` is deliberately omitted: wording is unstable.
    * On the sample ruleset every symbol maps to one risk, so risk rarely
      splits IR hits by itself; columns + symbol already separate sites. Risk
      still belongs in the key for detector severity differences and for
      future multi-risk rules.

    Symlink aliases of one file collapse through ``canonical_source_path``.

    Contract: this id/key is a **weak in-report foreign key** for linking
    assessments and findings within an equivalent scan. It is not a
    suppression key or long-term baseline identity across catalog severity
    edits or unrelated source changes.
    """
    return (
        canonical_source_path(candidate.file),
        int(candidate.line or 0),
        int(candidate.col_start or 0),
        int(candidate.col_end or 0),
        candidate.symbol or "",
        candidate.risk or "",
    )


def candidate_sort_key(candidate: Candidate) -> Tuple[str, int, int, int, str, str]:
    """Stable ordering used before persistence and functionization."""
    return candidate_identity_key(candidate)


def make_candidate_id(
    relpath: str,
    line: int,
    symbol: str = "",
    col_start: int | None = 0,
    col_end: int | None = 0,
    risk: str = "",
) -> str:
    """
    Persisted candidate id:

        ``<relpath>:<line>:<col_start>:<col_end>:<risk>:<symbol>``

    The tuple matches ``candidate_identity_key`` so two distinct semantic
    candidates cannot share an id after exact duplicates are removed. See
    that helper for why ``risk`` is the severity discriminator (and why
    ``description`` / ``rule_id`` are not part of the id). This remains a weak
    in-report foreign key, not a suppression or long-term baseline identity.
    """
    return (
        f"{relpath}:{int(line)}:{int(col_start or 0)}:{int(col_end or 0)}"
        f":{risk or ''}:{symbol or ''}"
    )


def candidate_id_for(candidate: Candidate, relpath: str) -> str:
    """Build a persisted id from a Candidate and its repo-relative path."""
    return make_candidate_id(
        relpath,
        candidate.line,
        candidate.symbol,
        candidate.col_start,
        candidate.col_end,
        candidate.risk,
    )


def _normalized_rule_id(candidate: Candidate) -> Optional[str]:
    rid = getattr(candidate, "rule_id", None)
    if isinstance(rid, str) and rid.strip():
        return rid.strip()
    return None


def _normalized_discovery_method(candidate: Candidate) -> Optional[str]:
    method = getattr(candidate, "discovery_method", None)
    if isinstance(method, str) and method.strip():
        return method.strip()
    return None


def normalize_description_text(description: Optional[str]) -> str:
    """Harmless description normalization for equality (line endings only)."""
    if not description:
        return ""
    return description.replace("\r\n", "\n").replace("\r", "\n")


def _merge_rule_attribution(existing: Candidate, incoming: Candidate) -> Candidate:
    """Reconcile rule_id when two candidates share the same identity key.

    * Equal non-null IDs → keep ``existing`` (first-seen).
    * Conflicting non-null IDs → raise ``CandidateRuleIdConflictError``.
    * One null and one non-null → keep the non-null ID (truthful attribution)
      without changing the identity key.
    * Both null → keep ``existing``.
    """
    a = _normalized_rule_id(existing)
    b = _normalized_rule_id(incoming)
    if a is not None and b is not None and a != b:
        raise CandidateRuleIdConflictError(
            f"Conflicting rule_id values for identical candidate "
            f"{candidate_identity_key(existing)!r}: {a!r} vs {b!r}"
        )
    if a is None and b is not None:
        return existing.model_copy(update={"rule_id": b})
    return existing


def _merge_description(existing: Candidate, incoming: Candidate) -> Candidate:
    """Reconcile descriptions without producer-order bias.

    After line-ending normalization:
    * Equal text → keep the normalized form.
    * One empty, one non-empty → keep the non-empty text (normalized).
    * Materially different non-empty text → raise
      :class:`CandidateProvenanceConflictError` (no silent first-seen choice).
    """
    a = normalize_description_text(existing.description)
    b = normalize_description_text(incoming.description)
    if a and b and a != b:
        raise CandidateProvenanceConflictError(
            f"Conflicting description for identical candidate "
            f"{candidate_identity_key(existing)!r}"
        )
    chosen = a or b
    if chosen != (existing.description or ""):
        return existing.model_copy(update={"description": chosen})
    return existing


def _assert_compatible_provenance(existing: Candidate, incoming: Candidate) -> None:
    """Fail closed when same identity carries conflicting detector provenance."""
    method_a = _normalized_discovery_method(existing)
    method_b = _normalized_discovery_method(incoming)
    if method_a is not None and method_b is not None and method_a != method_b:
        raise CandidateProvenanceConflictError(
            f"Conflicting discovery_method for identical candidate "
            f"{candidate_identity_key(existing)!r}: {method_a!r} vs {method_b!r}"
        )


def dedupe_candidates(candidates: Sequence[Candidate]) -> List[Candidate]:
    """Drop exact semantic duplicates, preserving first-seen order.

    Conflicting non-null ``rule_id`` values for the same identity raise
    :class:`CandidateRuleIdConflictError`. Conflicting discovery_method or
    materially different descriptions (after line-ending normalization) for
    the same identity raise :class:`CandidateProvenanceConflictError` rather
    than silently keeping a producer-order-dependent description.
    """
    seen: Dict[Tuple[str, int, int, int, str, str], int] = {}
    out: List[Candidate] = []
    for candidate in candidates:
        normalized = normalize_candidate_file(candidate)
        # Canonicalize harmless description line endings up front.
        norm_desc = normalize_description_text(normalized.description)
        if norm_desc != (normalized.description or ""):
            normalized = normalized.model_copy(update={"description": norm_desc})
        key = candidate_identity_key(normalized)
        if key not in seen:
            seen[key] = len(out)
            out.append(normalized)
            continue
        idx = seen[key]
        _assert_compatible_provenance(out[idx], normalized)
        merged = _merge_rule_attribution(out[idx], normalized)
        out[idx] = _merge_description(merged, normalized)
    return out


def sort_candidates(candidates: Iterable[Candidate]) -> List[Candidate]:
    """Return candidates in deterministic order."""
    return sorted(
        (normalize_candidate_file(c) for c in candidates),
        key=candidate_sort_key,
    )


def prepare_candidates(candidates: Sequence[Candidate]) -> List[Candidate]:
    """Normalize paths, drop exact duplicates, then sort stably."""
    return sort_candidates(dedupe_candidates(candidates))


def function_sort_key(function_id: str, file_path: str = "", start_line: int = 0) -> Tuple:
    """Stable ordering for extracted functions."""
    return (canonical_source_path(file_path) or file_path, int(start_line or 0), function_id)


def summary_value(summary: object) -> str:
    """Normalize a Y2038 summary enum or string to lowercase text."""
    if hasattr(summary, "value"):
        return str(getattr(summary, "value")).lower()
    return str(summary or "").lower()


def analyses_conflict(left: object, right: object) -> bool:
    """True when two analyses disagree on the Y2038 summary verdict."""
    return summary_value(getattr(left, "y2038_summary", left)) != summary_value(
        getattr(right, "y2038_summary", right)
    )
