# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Structured IR match records for deterministic candidate attribution.

``matches[]`` is authoritative. Optional line-level aggregates such as
``line_max_risk`` and ``match_count`` are summaries only and must never feed
``Candidate`` construction, identity, deduplication, or public evidence.
Summary fields are always *derived* from ``matches[]`` on write; on read they
are re-derived and any supplied values must agree or the record is rejected.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# Mirror scanner risk ordering for aggregate summaries only.
_RANK = {"low": 0, "medium": 1, "high": 2}


class IRMatchError(ValueError):
    """Unsupported, ambiguous, or inconsistent IR match record.

    Messages are controlled diagnostics and must not embed source line text.
    """


def _norm_rule_id(value: Any) -> Optional[str]:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _norm_method(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_description(description: Any) -> str:
    text = str(description or "")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _validate_columns(col_start: Any, col_end: Any) -> Tuple[Optional[int], Optional[int]]:
    """Return normalized columns or raise if the range is invalid."""
    if col_start is None and col_end is None:
        return None, None
    if col_start is None or col_end is None:
        raise IRMatchError(
            "Unsupported IR record: columns must both be absent or both present"
        )
    try:
        start = int(col_start)
        end = int(col_end)
    except (TypeError, ValueError) as exc:
        raise IRMatchError(
            "Unsupported IR record: columns must be integers when present"
        ) from exc
    if start < 0 or end < 0:
        raise IRMatchError(
            "Unsupported IR record: columns must be nonnegative"
        )
    if start > end:
        raise IRMatchError(
            "Unsupported IR record: col_start must be <= col_end"
        )
    return start, end


def match_equality_key(match: Dict[str, Any]) -> Tuple[Any, ...]:
    """Equality key for collapsing true duplicate observations only.

    Matches that differ by discovery method, rule ID, risk, description, or
    columns remain distinct even when the symbol text is identical.
    """
    return (
        str(match.get("symbol") or ""),
        str(match.get("risk") or ""),
        _normalize_description(match.get("description")),
        _norm_method(match.get("discovery_method")),
        _norm_rule_id(match.get("rule_id")),
        match.get("col_start"),
        match.get("col_end"),
        int(match.get("line") or 0),
    )


def _match_sort_key(match: Dict[str, Any]) -> Tuple[Any, ...]:
    """Stable ordering for matches within a line record."""
    return (
        str(match.get("symbol") or ""),
        _norm_method(match.get("discovery_method")) or "",
        _norm_rule_id(match.get("rule_id")) or "",
        str(match.get("risk") or ""),
        _normalize_description(match.get("description")),
        -1 if match.get("col_start") is None else int(match["col_start"]),
        -1 if match.get("col_end") is None else int(match["col_end"]),
    )


def raw_hit_to_match(hit: Dict[str, Any]) -> Dict[str, Any]:
    """Build one authoritative match dict from a scanner per-hit record."""
    col_start, col_end = _validate_columns(hit.get("col_start"), hit.get("col_end"))
    return {
        "symbol": str(hit.get("symbol") or ""),
        "risk": str(hit.get("risk") or ""),
        "description": _normalize_description(hit.get("description")),
        "discovery_method": hit.get("discovery_method"),
        "rule_id": _norm_rule_id(hit.get("rule_id")),
        "line": int(hit.get("line") or 0),
        "col_start": col_start,
        "col_end": col_end,
    }


def compute_line_max_risk(matches: Sequence[Dict[str, Any]]) -> str:
    """Summary-only hottest risk among matches; empty when there are none."""
    best = ""
    best_rank = -1
    for match in matches:
        risk = str(match.get("risk") or "")
        rank = _RANK.get(risk, -1)
        if rank > best_rank:
            best_rank = rank
            best = risk
    return best


def group_by_line(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group raw per-hit results into line records with authoritative matches[].

    Duplicate observations (identical equality keys) collapse to one match.
    Distinct provenance for the same symbol is preserved. ``match_count`` and
    ``line_max_risk`` are always derived from ``matches[]``.
    """
    grouped_map: Dict[Tuple[str, int], Dict[str, Any]] = {}
    order: List[Tuple[str, int]] = []

    for hit in results:
        key = (hit["file"], int(hit["line"]))
        match = raw_hit_to_match(hit)
        bucket = grouped_map.get(key)
        if bucket is None:
            grouped_map[key] = {
                "file": hit["file"],
                "line": int(hit["line"]),
                "lineText": hit.get("lineText", ""),
                "matches": [match],
            }
            order.append(key)
            continue

        eq = match_equality_key(match)
        existing_keys = {match_equality_key(m) for m in bucket["matches"]}
        if eq not in existing_keys:
            bucket["matches"].append(match)
        if not bucket.get("lineText") and hit.get("lineText"):
            bucket["lineText"] = hit.get("lineText", "")

    out: List[Dict[str, Any]] = []
    for key in sorted(order, key=lambda k: (k[0], k[1])):
        bucket = grouped_map[key]
        matches = sorted(bucket["matches"], key=_match_sort_key)
        out.append(
            {
                "file": bucket["file"],
                "line": bucket["line"],
                "lineText": bucket.get("lineText", ""),
                "matches": matches,
                "match_count": len(matches),
                "line_max_risk": compute_line_max_risk(matches),
            }
        )
    return out


def _legacy_parallel_lists(item: Dict[str, Any]) -> Optional[Tuple[List[str], List[Any], List[Any]]]:
    """Return (symbols, methods, rule_ids) when legacy parallel arrays are present."""
    if "symbols" not in item and "symbol" not in item:
        return None
    if "symbols" in item:
        symbols = item.get("symbols") or []
        if isinstance(symbols, str):
            symbols = [symbols]
        symbols = [str(s or "") for s in symbols]
        methods = item.get("discovery_methods")
        if not isinstance(methods, list):
            methods = []
        rule_ids = item.get("rule_ids")
        if not isinstance(rule_ids, list):
            rule_ids = []
        return symbols, methods, rule_ids
    symbol = str(item.get("symbol") or "")
    method = item.get("discovery_method")
    rule_id = item.get("rule_id")
    return [symbol], [method], [rule_id]


def _reject_unequal_parallel(symbols: List[str], methods: List[Any], rule_ids: List[Any]) -> None:
    if len(methods) not in (0, len(symbols)):
        raise IRMatchError(
            "Unsupported IR record: discovery_methods length does not match symbols"
        )
    if len(rule_ids) not in (0, len(symbols)):
        raise IRMatchError(
            "Unsupported IR record: rule_ids length does not match symbols"
        )
    if methods and len(methods) != len(symbols):
        raise IRMatchError(
            "Unsupported IR record: unequal discovery_methods and symbols lengths"
        )
    if rule_ids and len(rule_ids) != len(symbols):
        raise IRMatchError(
            "Unsupported IR record: unequal rule_ids and symbols lengths"
        )


def _legacy_matches_unambiguous(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Accept only unambiguous legacy records (single symbol with aligned metadata)."""
    parallel = _legacy_parallel_lists(item)
    if parallel is None:
        raise IRMatchError("Unsupported IR record: no matches[] and no legacy symbol fields")
    symbols, methods, rule_ids = parallel
    _reject_unequal_parallel(symbols, methods, rule_ids)

    if len(symbols) == 0:
        raise IRMatchError("Unsupported IR record: empty legacy symbol list")

    if len(symbols) > 1:
        raise IRMatchError(
            "Unsupported IR record: ambiguous legacy multi-symbol group without matches[]"
        )

    risk = str(item.get("risk") or "")
    if not risk:
        raise IRMatchError(
            "Unsupported IR record: legacy single-symbol record missing risk"
        )

    method = methods[0] if methods else item.get("discovery_method")
    rule_id = rule_ids[0] if rule_ids else item.get("rule_id")
    col_start, col_end = _validate_columns(item.get("col_start"), item.get("col_end"))
    return [
        {
            "symbol": symbols[0],
            "risk": risk,
            "description": _normalize_description(item.get("description")),
            "discovery_method": method,
            "rule_id": _norm_rule_id(rule_id),
            "line": int(item.get("line") or 0),
            "col_start": col_start,
            "col_end": col_end,
        }
    ]


def _matches_from_new_field(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw_matches = item.get("matches")
    if not isinstance(raw_matches, list):
        raise IRMatchError("Unsupported IR record: matches must be a list")
    if len(raw_matches) == 0:
        raise IRMatchError("Unsupported IR record: empty matches[]")

    parent_line = int(item.get("line") or 0)
    out: List[Dict[str, Any]] = []
    for entry in raw_matches:
        if not isinstance(entry, dict):
            raise IRMatchError("Unsupported IR record: match entry must be an object")
        match_line = int(entry.get("line") or parent_line or 0)
        if match_line != parent_line:
            raise IRMatchError(
                "Unsupported IR record: match line disagrees with parent line"
            )
        col_start, col_end = _validate_columns(
            entry.get("col_start"), entry.get("col_end")
        )
        out.append(
            {
                "symbol": str(entry.get("symbol") or ""),
                "risk": str(entry.get("risk") or ""),
                "description": _normalize_description(entry.get("description")),
                "discovery_method": entry.get("discovery_method"),
                "rule_id": _norm_rule_id(entry.get("rule_id")),
                "line": match_line,
                "col_start": col_start,
                "col_end": col_end,
            }
        )
    return sorted(out, key=_match_sort_key)


def _validate_summaries_against_matches(
    item: Dict[str, Any], matches: List[Dict[str, Any]]
) -> None:
    """Fail closed when supplied summary fields disagree with derived values."""
    derived_count = len(matches)
    derived_risk = compute_line_max_risk(matches)

    if "match_count" in item and item.get("match_count") is not None:
        try:
            count = int(item.get("match_count"))
        except (TypeError, ValueError) as exc:
            raise IRMatchError(
                "Unsupported IR record: invalid match_count"
            ) from exc
        if count != derived_count:
            raise IRMatchError(
                "Unsupported IR record: match_count conflicts with matches[]"
            )

    if "line_max_risk" in item and item.get("line_max_risk") is not None:
        if str(item.get("line_max_risk") or "") != derived_risk:
            raise IRMatchError(
                "Unsupported IR record: line_max_risk conflicts with matches[]"
            )


def _validate_legacy_consistent_with_matches(
    item: Dict[str, Any], matches: List[Dict[str, Any]]
) -> None:
    """Fail closed when legacy fields conflict with authoritative matches[]."""
    parallel = _legacy_parallel_lists(item)
    if parallel is not None:
        symbols, methods, rule_ids = parallel
        if symbols:
            _reject_unequal_parallel(symbols, methods, rule_ids)
            match_symbols = [m["symbol"] for m in matches]
            if symbols != match_symbols:
                raise IRMatchError(
                    "Unsupported IR record: legacy symbols conflict with matches[]"
                )
            if methods and [
                _norm_method(m) for m in methods
            ] != [_norm_method(m.get("discovery_method")) for m in matches]:
                raise IRMatchError(
                    "Unsupported IR record: legacy discovery_methods conflict with matches[]"
                )
            if rule_ids and [
                _norm_rule_id(r) for r in rule_ids
            ] != [_norm_rule_id(m.get("rule_id")) for m in matches]:
                raise IRMatchError(
                    "Unsupported IR record: legacy rule_ids conflict with matches[]"
                )

    if "risk" in item and item.get("risk") is not None:
        if len(matches) > 1:
            raise IRMatchError(
                "Unsupported IR record: scalar risk with multi-match matches[] is ambiguous"
            )
        if len(matches) == 1 and str(item.get("risk") or "") != str(matches[0].get("risk") or ""):
            raise IRMatchError(
                "Unsupported IR record: scalar risk conflicts with matches[]"
            )

    if "description" in item and item.get("description") not in (None, ""):
        if len(matches) > 1:
            raise IRMatchError(
                "Unsupported IR record: scalar description with multi-match matches[] "
                "is ambiguous"
            )
        if len(matches) == 1 and _normalize_description(item.get("description")) != (
            matches[0].get("description") or ""
        ):
            raise IRMatchError(
                "Unsupported IR record: scalar description conflicts with matches[]"
            )


def extract_matches_from_ir_item(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return authoritative match dicts from a new or unambiguous legacy IR row.

    Raises :class:`IRMatchError` with a controlled diagnostic (no source dump).
    ``match_count`` / ``line_max_risk`` are never trusted from input; when
    supplied they must equal values derived from ``matches[]``.
    """
    if not isinstance(item, dict):
        raise IRMatchError("Unsupported IR record: expected an object")

    has_matches = isinstance(item.get("matches"), list)
    has_legacy = "symbols" in item or "symbol" in item

    if has_matches:
        matches = _matches_from_new_field(item)
        _validate_summaries_against_matches(item, matches)
        if has_legacy or "risk" in item or "description" in item:
            _validate_legacy_consistent_with_matches(item, matches)
        return matches

    return _legacy_matches_unambiguous(item)


def iter_match_field_sets(item: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    """Yield per-match field dicts suitable for ``Candidate`` construction."""
    line_text = item.get("lineText") or item.get("one_line_snippet") or ""
    file_path = item.get("file")
    for match in extract_matches_from_ir_item(item):
        yield {
            "file": file_path,
            "line": int(match.get("line") or item.get("line") or 0),
            "symbol": match.get("symbol") or "",
            "one_line_snippet": line_text,
            "risk": match.get("risk") or "",
            "description": match.get("description") or "",
            "discovery_method": match.get("discovery_method"),
            "rule_id": _norm_rule_id(match.get("rule_id")),
            "col_start": match.get("col_start"),
            "col_end": match.get("col_end"),
        }
