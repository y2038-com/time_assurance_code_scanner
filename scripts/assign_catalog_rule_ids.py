#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""One-time / maintenance tool: consolidate duplicate catalog symbols and
assign stable ``rule_id`` values.

This is NOT a runtime dependency. It:

* preserves existing well-formed ``rule_id`` values;
* never renumbers or overwrites existing IDs;
* refuses duplicate or malformed IDs already present;
* assigns the next unused ``TACS-RULE-NNNN`` only to entries missing an ID;
* writes a bare JSON array (packaged catalog shape).

Usage (from repo root)::

    python scripts/assign_catalog_rule_ids.py \\
        --in src/tacs/rules/y2038_sample_rules.json \\
        --out src/tacs/rules/y2038_sample_rules.json \\
        --consolidate-duplicates
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from tacs.core.rule_catalog import (  # noqa: E402
    RULE_ID_PREFIX,
    RULE_ID_WIDTH,
    format_rule_id,
    is_valid_rule_id,
    load_retired_rule_ids,
    unwrap_rules_document,
    validate_rule_id_value,
)


def _os_union(rows: Sequence[Dict[str, Any]]) -> Optional[Dict[str, bool]]:
    keys = set()
    for row in rows:
        os_s = row.get("os_support")
        if isinstance(os_s, dict):
            keys.update(os_s.keys())
    if not keys:
        return None
    out: Dict[str, bool] = {}
    for k in sorted(keys):
        out[k] = any(
            bool((row.get("os_support") or {}).get(k))
            for row in rows
            if isinstance(row.get("os_support"), dict)
        )
    return out


def _variant_from_row(row: Dict[str, Any], *, label: str) -> Dict[str, Any]:
    v: Dict[str, Any] = {"label": label}
    for key in ("category", "header", "description", "comments", "os_support", "risk"):
        if key in row and row[key] is not None:
            v[key] = copy.deepcopy(row[key])
    return v


def _merge_getfiletime(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    assert len(rows) == 2
    # Prefer more specific CreateFile wording as primary description; keep both.
    primary = rows[0]
    merged = {
        "symbol": "GetFileTime",
        "category": "File System",
        "risk": "high",
        "header": "Windows.h",
        "os_support": _os_union(rows),
        "description": (
            "Windows GetFileTime: returns creation, last-access, and last-write "
            "times for a file or folder (including handles from CreateFile). "
            "Catalog variants differ in wording only; the scanner matches the "
            "symbol and does not distinguish API-usage context."
        ),
        "comments": "",
        "variants": [
            _variant_from_row(rows[0], label="current_time_api"),
            _variant_from_row(rows[1], label="file_system_createfile"),
        ],
    }
    # Preserve first-row category in variant; top-level uses File System as broader.
    _ = primary
    return merged


def _merge_localtime(symbol: str, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    assert len(rows) == 2
    # Prefer the more specific convert-to-tm description as umbrella lead-in.
    lead = rows[0].get("description") or rows[1].get("description") or symbol
    return {
        "symbol": symbol,
        "category": "Format Conversion",
        "risk": "high",
        "header": "time.h",
        "os_support": _os_union(rows),
        "description": (
            f"{lead}. Alternate catalog wording also documents this as a "
            f"Windows localtime variant for the corresponding time width. "
            "The scanner matches the symbol only and does not distinguish "
            "which researched description applies."
        ),
        "comments": "",
        "variants": [
            _variant_from_row(rows[0], label="convert_to_tm"),
            _variant_from_row(rows[1], label="localtime_width_variant"),
        ],
    }


def _merge_sleep(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    assert len(rows) == 3
    # Order: Windows thr/thread, FreeRTOS posix/unistd.h, other unistd.h
    by_header = {r.get("header"): r for r in rows}
    windows = by_header.get("thr/thread") or rows[0]
    freertos = by_header.get("posix/unistd.h") or rows[1]
    other = by_header.get("unistd.h") or rows[2]
    return {
        "symbol": "sleep",
        "category": "Sleep Func",
        "risk": "high",
        "header": None,
        "os_support": _os_union(rows),
        "description": (
            "Sleep-related symbol. Interpretation depends on environment and "
            "usage context (Windows thr/thread, FreeRTOS posix/unistd.h, or "
            "unistd.h on other researched operating systems). The scanner "
            "matches the symbol only and does not determine which "
            "environment-specific form applies."
        ),
        "comments": (
            "Merged from environment-specific research rows; see variants. "
            "Windows note: sleep in thr/thread (likely Boost integration)."
        ),
        "variants": [
            _variant_from_row(windows, label="windows_thr_thread"),
            _variant_from_row(freertos, label="freertos_posix_unistd"),
            _variant_from_row(other, label="other_unistd"),
        ],
    }


def _merge_timezone(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    assert len(rows) == 2
    global_var = next(
        (r for r in rows if (r.get("category") or "") == "Global Variable"),
        rows[0],
    )
    function_like = next(
        (r for r in rows if r is not global_var),
        rows[1],
    )
    return {
        "symbol": "timezone",
        "category": "Timezone",
        "risk": "high",
        "header": "time.h",
        "os_support": _os_union(rows),
        "description": (
            "Timezone-related symbol in time.h. Interpretation depends on "
            "environment and usage context: it may refer to a global variable "
            "(UTC vs local standard-time offset on most applicable operating "
            "systems other than VxWorks) or a function-like form that returns "
            "a timezone abbreviation. The scanner matches the symbol only and "
            "does not determine which variant applies."
        ),
        "comments": (
            "Merged umbrella rule. Global-variable row noted undocumented "
            "usage on Windows & Mac; function-like row preserves researched "
            "os_support (Windows not asserted in source)."
        ),
        "variants": [
            _variant_from_row(
                global_var,
                label="global_variable_time_h",
            ),
            _variant_from_row(
                function_like,
                label="function_timezone_abbreviation_time_h",
            ),
        ],
    }


_MERGERS = {
    "GetFileTime": _merge_getfiletime,
    "_localtime32": lambda rows: _merge_localtime("_localtime32", rows),
    "_localtime64": lambda rows: _merge_localtime("_localtime64", rows),
    "sleep": _merge_sleep,
    "timezone": _merge_timezone,
}


def consolidate_duplicates(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Replace multi-row symbols with one umbrella entry; preserve order."""
    buckets: Dict[str, List[Tuple[int, Dict[str, Any]]]] = {}
    for i, e in enumerate(entries):
        sym = e.get("symbol")
        if isinstance(sym, str) and sym in _MERGERS:
            buckets.setdefault(sym, []).append((i, e))

    skip_indices = set()
    replacements: Dict[int, Dict[str, Any]] = {}
    for sym, indexed in buckets.items():
        if len(indexed) < 2:
            continue
        indices = [i for i, _ in indexed]
        rows = [e for _, e in indexed]
        merged = _MERGERS[sym](rows)
        # Preserve an existing rule_id if exactly one unique id is present.
        ids = [e.get("rule_id") for e in rows if e.get("rule_id")]
        unique_ids = {i for i in ids if i}
        if len(unique_ids) == 1:
            merged["rule_id"] = next(iter(unique_ids))
        elif len(unique_ids) > 1:
            raise SystemExit(
                f"Cannot consolidate {sym!r}: conflicting rule_ids {sorted(unique_ids)}"
            )
        first_idx = indices[0]
        replacements[first_idx] = merged
        for idx in indices[1:]:
            skip_indices.add(idx)

    out: List[Dict[str, Any]] = []
    for i, e in enumerate(entries):
        if i in skip_indices:
            continue
        if i in replacements:
            out.append(replacements[i])
        else:
            out.append(e)
    return out


def _collect_existing_ids(entries: Sequence[Dict[str, Any]]) -> List[str]:
    ids: List[str] = []
    for i, e in enumerate(entries):
        rid = e.get("rule_id")
        if rid is None or (isinstance(rid, str) and not rid.strip()):
            continue
        validate_rule_id_value(rid, context=f"input entry #{i + 1}")
        ids.append(rid)
    return ids


def _next_sequence(existing: Sequence[str], retired: Sequence[str]) -> int:
    used = set(existing) | set(retired)
    n = 1
    while format_rule_id(n) in used:
        n += 1
        if n > 10**RULE_ID_WIDTH - 1:
            raise SystemExit("rule id space exhausted")
    return n


def assign_missing_ids(
    entries: List[Dict[str, Any]],
    retired: Sequence[str],
) -> List[Dict[str, Any]]:
    existing = _collect_existing_ids(entries)
    if len(existing) != len(set(existing)):
        raise SystemExit("duplicate rule_id values present in input; refusing to continue")
    for rid in existing:
        if rid in retired:
            raise SystemExit(f"input reuses retired rule_id {rid}")
    next_n = _next_sequence(existing, retired)
    out: List[Dict[str, Any]] = []
    for e in entries:
        row = copy.deepcopy(e)
        rid = row.get("rule_id")
        if rid is None or (isinstance(rid, str) and not rid.strip()):
            while format_rule_id(next_n) in retired or format_rule_id(next_n) in existing:
                next_n += 1
            new_id = format_rule_id(next_n)
            row["rule_id"] = new_id
            existing.append(new_id)
            next_n += 1
        else:
            validate_rule_id_value(rid, context=f"symbol={row.get('symbol')!r}")
        # Ensure rule_id is the first key for readability.
        ordered = {"rule_id": row["rule_id"]}
        for k, v in row.items():
            if k == "rule_id":
                continue
            ordered[k] = v
        out.append(ordered)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="inp", required=True, help="Input rules JSON")
    ap.add_argument("--out", dest="out", required=True, help="Output rules JSON")
    ap.add_argument(
        "--consolidate-duplicates",
        action="store_true",
        help="Merge known same-symbol research rows into umbrella entries",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Print summary only; do not write",
    )
    args = ap.parse_args()

    in_path = Path(args.inp)
    out_path = Path(args.out)
    raw = json.loads(in_path.read_text(encoding="utf-8"))
    entries, embedded_retired = unwrap_rules_document(raw)
    retired = list(embedded_retired)
    try:
        retired.extend(load_retired_rule_ids())
    except Exception as exc:
        raise SystemExit(f"Failed to load retired_rule_ids deny-list: {exc}") from exc

    # Refuse malformed / duplicate / retired IDs before any mutation or write.
    from tacs.core.rule_catalog import validate_catalog_entries

    try:
        # External-style check on the input first (allows missing IDs).
        validate_catalog_entries(
            entries,
            strict=False,
            retired_ids=retired,
            context=str(in_path),
        )
    except Exception as exc:
        raise SystemExit(f"Input catalog validation failed; refusing to write: {exc}") from exc

    existing_before = {
        e.get("symbol"): e.get("rule_id")
        for e in entries
        if isinstance(e.get("symbol"), str)
        and isinstance(e.get("rule_id"), str)
        and e.get("rule_id").strip()
    }

    if args.consolidate_duplicates:
        before = len(entries)
        entries = consolidate_duplicates(entries)
        print(f"consolidated: {before} -> {len(entries)} entries")

    try:
        entries = assign_missing_ids(entries, retired)
    except SystemExit:
        raise
    except Exception as exc:
        raise SystemExit(f"ID assignment failed; refusing to write: {exc}") from exc

    symbols = [e.get("symbol") for e in entries]
    if len(symbols) != len(set(symbols)):
        dups = sorted({s for s in symbols if symbols.count(s) > 1})
        raise SystemExit(
            f"duplicate symbols remain after consolidate: {dups}; refusing to write"
        )

    # Never renumber: every pre-existing symbol→id mapping must be unchanged.
    for sym, rid in existing_before.items():
        match = next((e for e in entries if e.get("symbol") == sym), None)
        if match is None:
            # Consolidated away — OK only when consolidate flag merged it.
            continue
        if match.get("rule_id") != rid:
            raise SystemExit(
                f"Refusing to renumber {sym!r}: had {rid}, would become "
                f"{match.get('rule_id')}"
            )

    try:
        validate_catalog_entries(
            entries,
            strict=True,
            retired_ids=retired,
            context="assigned output",
        )
    except Exception as exc:
        raise SystemExit(
            f"Output catalog validation failed; refusing to write: {exc}"
        ) from exc

    print(f"entries={len(entries)} ids={len({e['rule_id'] for e in entries})}")
    print(f"id_range={entries[0]['rule_id']} .. {entries[-1]['rule_id']}")

    text = json.dumps(entries, indent=2, ensure_ascii=False) + "\n"
    if args.dry_run:
        return 0

    # Idempotent: skip rewrite when content is unchanged.
    if out_path.exists():
        try:
            if out_path.read_text(encoding="utf-8") == text:
                print(f"unchanged {out_path} (idempotent)")
                return 0
        except OSError:
            pass

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
