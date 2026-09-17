# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Deterministic candidate identity, ordering, and deduplication."""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Tuple

from tacs.core.path_utils import canonical_source_path
from tacs.core.schema import Candidate


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
    * ``Candidate`` has no ``rule_id`` or ``category`` field; ``risk`` is the
      stable severity tag supplied by rules JSON and by the define/arithmetic
      detectors.
    * It is deterministic for a given ruleset/detector (not model output or a
      timestamp). Distinct severity at the same site stays distinct.
    * ``description`` is deliberately omitted: wording is unstable, and the
      bundled ruleset has several same-symbol/same-risk entries that differ
      only in prose (OS/header variants). Collapsing those is correct.
    * On the sample ruleset every symbol maps to one risk, so risk rarely
      splits IR hits by itself; columns + symbol already separate sites. Risk
      still belongs in the key for detector severity differences and for
      future multi-risk rules.

    Symlink aliases of one file collapse through ``canonical_source_path``.
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
    ``description`` is not part of the id).
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


def dedupe_candidates(candidates: Sequence[Candidate]) -> List[Candidate]:
    """Drop exact semantic duplicates, preserving first-seen order."""
    seen = set()
    out: List[Candidate] = []
    for candidate in candidates:
        normalized = normalize_candidate_file(candidate)
        key = candidate_identity_key(normalized)
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
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
