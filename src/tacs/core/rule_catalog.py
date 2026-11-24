# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Catalog rule_id format, loading helpers, validation, and classification.

Packaged catalogs must carry explicit stable ``rule_id`` values. External or
legacy catalogs may omit IDs (propagated as null). Non-null IDs are always
validated; malformed IDs are never silently coerced to null.

Two separate policies (issue #62):

* **General callability** (``needs_paren`` / ``is_callable_catalog_rule``) —
  whether a catalog symbol is syntactically invoked as a function. Used by IR
  token matching. Descriptive categories do not have to equal ``"function"``.
* **Time-value producers** (``TIME_VALUE_PRODUCER_SYMBOLS`` /
  ``extract_time_value_producer_symbols``) — whether a call's *return value* is
  a deterministic absolute / epoch ``time_t`` (or equivalent). Only this set
  populates Stage 3 ``time_functions`` for line-local cast detection. Being
  callable, time-related, or ``needs_paren`` alone is not enough.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

#: Opaque packaged rule id: TACS-RULE-0001 … (fixed width, ASCII, case-stable).
RULE_ID_PATTERN = re.compile(r"^TACS-RULE-\d{4}$")
RULE_ID_PREFIX = "TACS-RULE-"
RULE_ID_WIDTH = 4

#: Lowercased descriptive categories that are not function-call symbols.
#: Shared with IR rule loading (``needs_paren`` derivation). Unknown categories
#: fail open as *callable* for token matching only — never as time-value
#: producers.
NON_CALLABLE_CATEGORIES = frozenset(
    {
        "constant/definition",
        "env variable",
        "global variable",
        "macro",
        "simple type",
        "structure",
    }
)

#: Exact identifiers whose *return value* is Unix-epoch / absolute ``time_t``
#: (or an equivalent calendar→``time_t`` conversion). Aligned with issue #52
#: ``_DEFAULT_TIME_FUNCTIONS``. Out-parameter / status / ``struct tm*`` APIs
#: from the historical Stage 3 eight-name list (``gmtime``, ``localtime``,
#: ``clock_gettime``, ``gettimeofday``, ``timespec_get``, ``timespec_getres``)
#: are intentionally excluded.
TIME_VALUE_PRODUCER_SYMBOLS = frozenset(
    {
        "time",
        "mktime",
        "timegm",
        "timelocal",
    }
)

#: C identifier shape for a callable catalog symbol (no ``struct``/spaces).
_CALLABLE_SYMBOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

PackagedCatalogError = type("PackagedCatalogError", (ValueError,), {})
CatalogRuleIdError = type("CatalogRuleIdError", (ValueError,), {})


def format_rule_id(n: int) -> str:
    """Format a 1-based sequence number as a stable rule id."""
    if n < 1 or n > 10**RULE_ID_WIDTH - 1:
        raise ValueError(f"rule id sequence out of range: {n}")
    return f"{RULE_ID_PREFIX}{n:0{RULE_ID_WIDTH}d}"


def is_valid_rule_id(value: Any) -> bool:
    return isinstance(value, str) and bool(RULE_ID_PATTERN.fullmatch(value))


def packaged_rules_path() -> Path:
    """Filesystem path of the packaged primary catalog."""
    return Path(__file__).resolve().parent.parent / "rules" / "y2038_sample_rules.json"


def retired_rule_ids_path() -> Path:
    """Deny-list of retired packaged IDs (never reassign)."""
    return Path(__file__).resolve().parent.parent / "rules" / "retired_rule_ids.json"


def is_packaged_rules_path(path: Union[str, Path]) -> bool:
    """True when ``path`` resolves to the packaged primary catalog file."""
    try:
        return Path(path).resolve() == packaged_rules_path().resolve()
    except OSError:
        return False


def load_retired_rule_ids(path: Optional[Union[str, Path]] = None) -> List[str]:
    p = Path(path) if path is not None else retired_rule_ids_path()
    if not p.exists():
        return []
    raw = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise PackagedCatalogError(
            f"retired_rule_ids file must be a JSON array: {p}"
        )
    out: List[str] = []
    for item in raw:
        if not is_valid_rule_id(item):
            raise PackagedCatalogError(
                f"Malformed retired rule_id {item!r} in {p}"
            )
        out.append(item)
    return out


def unwrap_rules_document(raw: Any) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Accept a bare rules array or ``{rules, retired_rule_ids?}`` object."""
    if isinstance(raw, list):
        rules = raw
        retired: List[str] = []
    elif isinstance(raw, dict):
        rules = raw.get("rules")
        if not isinstance(rules, list):
            raise CatalogRuleIdError(
                "Rules document object must contain a 'rules' array"
            )
        retired_raw = raw.get("retired_rule_ids") or []
        if not isinstance(retired_raw, list):
            raise CatalogRuleIdError("'retired_rule_ids' must be an array when present")
        retired = list(retired_raw)
    else:
        raise CatalogRuleIdError("Rules document must be a JSON array or object")

    out: List[Dict[str, Any]] = []
    for i, entry in enumerate(rules):
        if not isinstance(entry, dict):
            raise CatalogRuleIdError(f"Rules entry #{i + 1} is not an object")
        out.append(entry)
    return out, retired


def load_rules_document(path: Union[str, Path]) -> Tuple[List[Dict[str, Any]], List[str]]:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return unwrap_rules_document(raw)


def validate_rule_id_value(value: Any, *, context: str) -> str:
    """Validate a non-null rule_id; raise on malformed or non-string values."""
    if not isinstance(value, str):
        raise CatalogRuleIdError(
            f"{context}: rule_id must be a string, got {type(value).__name__}"
        )
    if not value.strip():
        raise CatalogRuleIdError(f"{context}: rule_id must not be empty")
    if not is_valid_rule_id(value):
        raise CatalogRuleIdError(
            f"{context}: malformed rule_id {value!r}; expected "
            f"{RULE_ID_PREFIX} plus {RULE_ID_WIDTH} digits"
        )
    return value


def validate_catalog_entries(
    entries: Sequence[Dict[str, Any]],
    *,
    strict: bool,
    retired_ids: Optional[Iterable[str]] = None,
    context: str = "catalog",
) -> None:
    """Validate rule_id presence/uniqueness according to ``strict`` policy.

    * ``strict=True`` (packaged): every candidate-producing entry must have a
      valid unique ``rule_id``; retired IDs must not appear; independently
      matchable symbols must be unique.
    * ``strict=False`` (external/legacy): missing/null IDs allowed; any
      supplied non-null ID must be well-formed and unique within the document.
      Duplicate symbols with different non-null rule IDs fail closed. Legacy
      duplicate symbols with no IDs are allowed (null attribution).
    """
    retired = set(retired_ids or [])
    seen_ids: Dict[str, int] = {}
    # symbol -> list of (entry_index_1based, rule_id_or_None)
    by_symbol: Dict[str, List[Tuple[int, Optional[str]]]] = {}

    for i, entry in enumerate(entries):
        loc = f"{context} entry #{i + 1} (symbol={entry.get('symbol')!r})"
        sym = entry.get("symbol")
        if not isinstance(sym, str) or not sym.strip():
            if strict:
                raise PackagedCatalogError(f"{loc}: missing symbol")
            continue

        rid = entry.get("rule_id")
        normalized_rid: Optional[str] = None
        if rid is None or (isinstance(rid, str) and not rid.strip()):
            if strict:
                raise PackagedCatalogError(f"{loc}: missing required rule_id")
        else:
            normalized_rid = validate_rule_id_value(rid, context=loc)
            if normalized_rid in retired:
                raise PackagedCatalogError(
                    f"{loc}: rule_id {normalized_rid} is retired and must not be reused"
                )
            if normalized_rid in seen_ids:
                raise (PackagedCatalogError if strict else CatalogRuleIdError)(
                    f"{loc}: duplicate rule_id {normalized_rid} "
                    f"(also at entry #{seen_ids[normalized_rid]})"
                )
            seen_ids[normalized_rid] = i + 1

        by_symbol.setdefault(sym, []).append((i + 1, normalized_rid))

    for sym, rows in by_symbol.items():
        if len(rows) < 2:
            continue
        non_null = sorted({rid for _idx, rid in rows if rid is not None})
        if strict:
            idxs = [idx for idx, _rid in rows]
            raise PackagedCatalogError(
                f"{context}: duplicate independently matchable symbol {sym!r} "
                f"at entries {idxs}"
            )
        if len(non_null) > 1:
            raise CatalogRuleIdError(
                f"{context}: symbol {sym!r} has conflicting non-null rule_ids "
                f"{non_null}; fail closed (no first-wins)"
            )


def validate_packaged_catalog(
    path: Optional[Union[str, Path]] = None,
) -> List[Dict[str, Any]]:
    """Fail-closed validation of the packaged primary catalog."""
    catalog_path = Path(path) if path is not None else packaged_rules_path()
    entries, embedded_retired = load_rules_document(catalog_path)
    retired = load_retired_rule_ids()
    for rid in embedded_retired:
        validate_rule_id_value(rid, context=f"embedded retired list in {catalog_path}")
        retired.append(rid)
    validate_catalog_entries(
        entries,
        strict=True,
        retired_ids=retired,
        context=str(catalog_path),
    )
    return entries


def rule_needs_paren(entry: Dict[str, Any]) -> bool:
    """Return whether ``entry`` is treated as a syntactically callable symbol.

    Precedence:
    1. Explicit boolean ``needs_paren`` on the rule (custom catalogs).
    2. Otherwise ``category`` lowercased is **not** in
       ``NON_CALLABLE_CATEGORIES`` (descriptive labels like ``Current Time``
       remain callable for IR matching).

    Does **not** assert that the call's return value is time-bearing.
    """
    explicit = entry.get("needs_paren")
    if explicit is not None:
        return bool(explicit)
    category = entry.get("category") or ""
    category_l = category.lower() if isinstance(category, str) else ""
    return category_l not in NON_CALLABLE_CATEGORIES


def is_callable_catalog_rule(
    entry: Dict[str, Any],
    *,
    retired_ids: Optional[Iterable[str]] = None,
) -> bool:
    """True when ``entry`` is a syntactically callable catalog symbol.

    Used for IR ``needs_paren`` / call-site matching. Fail closed for:
    missing/blank symbol, non-identifier symbols (types like ``struct tm``),
    retired ``rule_id`` values, ``type_use_only`` collision rules, and rules
    whose ``needs_paren`` classification is false. Dynamically discovered
    typedef / macro rules use non-callable categories and are excluded without
    special-casing ``discovered``.

    This is **not** the Stage 3 cast-detection producer predicate.
    """
    if not isinstance(entry, dict):
        return False
    symbol = entry.get("symbol")
    if not isinstance(symbol, str) or not symbol.strip():
        return False
    if not _CALLABLE_SYMBOL_RE.fullmatch(symbol):
        return False
    if entry.get("type_use_only"):
        return False
    rid = entry.get("rule_id")
    if isinstance(rid, str) and rid.strip():
        retired = set(retired_ids or ())
        if rid in retired:
            return False
    return rule_needs_paren(entry)


def is_time_value_producer_rule(
    entry: Dict[str, Any],
    *,
    retired_ids: Optional[Iterable[str]] = None,
) -> bool:
    """True when ``entry``'s return value is a verified epoch / ``time_t`` producer.

    Fail closed unless the symbol is in ``TIME_VALUE_PRODUCER_SYMBOLS`` and the
    rule is otherwise an active callable catalog entry. ``needs_paren``,
    descriptive categories, and unknown custom symbols do not qualify.
    """
    if not is_callable_catalog_rule(entry, retired_ids=retired_ids):
        return False
    symbol = entry.get("symbol")
    return isinstance(symbol, str) and symbol in TIME_VALUE_PRODUCER_SYMBOLS


def extract_time_value_producer_symbols(
    entries: Sequence[Dict[str, Any]],
    *,
    retired_ids: Optional[Iterable[str]] = None,
) -> List[str]:
    """Deterministic unique time-value producer symbols for Stage 3 casts.

    Intersects active catalog entries with ``TIME_VALUE_PRODUCER_SYMBOLS``.
    Sorted ascending. Descriptive categories are irrelevant beyond callable
    filtering. Unknown / ambiguous / status-returning callables are excluded.
    """
    retired = set(retired_ids or ())
    names: Set[str] = set()
    for entry in entries:
        if is_time_value_producer_rule(entry, retired_ids=retired):
            names.add(str(entry["symbol"]))
    return sorted(names)


def extract_time_function_symbols(
    entries: Sequence[Dict[str, Any]],
    *,
    retired_ids: Optional[Iterable[str]] = None,
) -> List[str]:
    """Alias for ``extract_time_value_producer_symbols`` (Stage 3 ``time_functions``)."""
    return extract_time_value_producer_symbols(entries, retired_ids=retired_ids)


def extract_callable_catalog_symbols(
    entries: Sequence[Dict[str, Any]],
    *,
    retired_ids: Optional[Iterable[str]] = None,
) -> List[str]:
    """Deterministic unique syntactically callable catalog symbols (not producers)."""
    retired = set(retired_ids or ())
    names: Set[str] = set()
    for entry in entries:
        if is_callable_catalog_rule(entry, retired_ids=retired):
            names.add(str(entry["symbol"]))
    return sorted(names)
