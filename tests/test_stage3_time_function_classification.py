# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Stage 3 time-value producers vs general callability (issue #62)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tacs.core.ir_adapter import IRAdapter
from tacs.core.pipeline import ScanningPipeline
from tacs.core.rule_catalog import (
    NON_CALLABLE_CATEGORIES,
    TIME_VALUE_PRODUCER_SYMBOLS,
    extract_callable_catalog_symbols,
    extract_time_value_producer_symbols,
    is_callable_catalog_rule,
    is_time_value_producer_rule,
    load_retired_rule_ids,
    packaged_rules_path,
    rule_needs_paren,
)
from tacs.core.schema import PUBLIC_RESULT_SCHEMA_VERSION

REPO = Path(__file__).resolve().parents[1]
RULES = REPO / "src" / "tacs" / "rules" / "y2038_sample_rules.json"
SCANNER = REPO / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"

LP64 = {
    "config_id": "lp64_signed_64bit",
    "hardware_model": "LP64",
    "time_t_size_bits": 64,
    "time_t_signed": "signed",
}

CURRENT_TIME_SYMBOL = "time"  # category: Current Time; returns time_t
FORMAT_CONV_SYMBOL = "mktime"  # category: Format Conversion; returns time_t


def _packaged_rules() -> list[dict]:
    return json.loads(RULES.read_text(encoding="utf-8"))


def _adapter() -> IRAdapter:
    return IRAdapter(str(SCANNER))


def _producers() -> list[str]:
    return extract_time_value_producer_symbols(
        _packaged_rules(), retired_ids=load_retired_rule_ids()
    )


def test_packaged_catalog_has_no_category_function() -> None:
    assert not any(r.get("category") == "function" for r in _packaged_rules())


def test_old_category_function_equality_yields_empty() -> None:
    tf = [
        r["symbol"]
        for r in _packaged_rules()
        if r.get("category") == "function" and r.get("symbol")
    ]
    assert tf == []


def test_producer_allowlist_is_small_and_reviewed() -> None:
    assert TIME_VALUE_PRODUCER_SYMBOLS == frozenset(
        {"time", "mktime", "timegm", "timelocal"}
    )
    # Original Stage 3 eight-name list minus non-return / pointer APIs.
    excluded_from_historical_eight = {
        "gmtime",
        "localtime",
        "clock_gettime",
        "gettimeofday",
        "timespec_get",
        "timespec_getres",
    }
    assert not (excluded_from_historical_eight & TIME_VALUE_PRODUCER_SYMBOLS)


def test_producers_include_descriptive_categories_not_all_callables() -> None:
    rules = _packaged_rules()
    by_sym = {r["symbol"]: r for r in rules}
    assert by_sym[CURRENT_TIME_SYMBOL]["category"] == "Current Time"
    assert by_sym[FORMAT_CONV_SYMBOL]["category"] == "Format Conversion"
    producers = _producers()
    callables = extract_callable_catalog_symbols(
        rules, retired_ids=load_retired_rule_ids()
    )
    assert set(producers) <= TIME_VALUE_PRODUCER_SYMBOLS
    assert CURRENT_TIME_SYMBOL in producers
    assert FORMAT_CONV_SYMBOL in producers
    assert "timegm" in producers
    assert "timelocal" in producers
    assert len(callables) > len(producers)
    assert "clock_gettime" in callables and "clock_gettime" not in producers
    assert "gettimeofday" in callables and "gettimeofday" not in producers
    assert "gmtime" in callables and "gmtime" not in producers
    assert "strftime" in callables and "strftime" not in producers
    assert "nanosleep" in callables and "nanosleep" not in producers
    assert producers == sorted(set(producers))


def test_needs_paren_is_syntax_only() -> None:
    assert "simple type" in NON_CALLABLE_CATEGORIES
    assert rule_needs_paren({"symbol": "time", "category": "Current Time"}) is True
    assert rule_needs_paren({"symbol": "clock_gettime", "category": "System Clock"}) is True
    assert rule_needs_paren({"symbol": "time_t", "category": "Simple Type"}) is False
    assert (
        rule_needs_paren(
            {"symbol": "forced_call", "category": "Simple Type", "needs_paren": True}
        )
        is True
    )
    # needs_paren alone never makes a time-value producer.
    assert (
        is_time_value_producer_rule(
            {"symbol": "forced_call", "category": "Simple Type", "needs_paren": True}
        )
        is False
    )


def test_type_structure_constant_macro_not_callable_or_producer() -> None:
    rules = _packaged_rules()
    samples = {
        "time_t": "Simple Type",
        "FILETIME": "Structure",
        "CLK_TCK": "Constant/Definition",
        "__DATE__": "Macro",
        "TZ": "Env Variable",
    }
    by_sym = {r["symbol"]: r for r in rules}
    for sym, cat in samples.items():
        assert by_sym[sym]["category"] == cat
        assert is_callable_catalog_rule(by_sym[sym]) is False
        assert is_time_value_producer_rule(by_sym[sym]) is False


def test_retired_and_type_use_only_excluded_from_producers() -> None:
    entry = {
        "symbol": "time",
        "category": "Current Time",
        "rule_id": "TACS-RULE-0040",
    }
    assert is_time_value_producer_rule(entry) is True
    assert is_time_value_producer_rule(entry, retired_ids={"TACS-RULE-0040"}) is False
    assert (
        extract_time_value_producer_symbols([entry], retired_ids={"TACS-RULE-0040"})
        == []
    )
    assert (
        is_time_value_producer_rule(
            {"symbol": "time", "category": "Current Time", "type_use_only": True}
        )
        is False
    )


def test_duplicate_producers_deduped() -> None:
    entries = [
        {"symbol": "mktime", "category": "Format Conversion"},
        {"symbol": "time", "category": "Current Time"},
        {"symbol": "mktime", "category": "Format Conversion"},
        {"symbol": "clock_gettime", "category": "System Clock"},
    ]
    assert extract_time_value_producer_symbols(entries) == ["mktime", "time"]


def test_discovered_typedef_not_producer() -> None:
    discovered = {
        "symbol": "epoch_t",
        "category": "simple type",
        "discovered": True,
    }
    assert is_callable_catalog_rule(discovered) is False
    assert is_time_value_producer_rule(discovered) is False


def test_cast_detection_without_typedef_aliases_for_producers(tmp_path: Path) -> None:
    src = tmp_path / "cast_no_alias.c"
    src.write_text(
        """\
#include <stdint.h>
#include <time.h>

int32_t sample_current_time(void)
{
    return (int32_t)time(NULL);
}

int32_t sample_from_mktime(struct tm *tm)
{
    return (int32_t)mktime(tm);
}
""",
        encoding="utf-8",
    )
    cands = _adapter().discover_candidates(
        root_path=str(tmp_path),
        rules_path=str(RULES),
        include_patterns=["**/*.c"],
        exclude_patterns=[],
        time_t_aliases={},
        time_functions=_producers(),
        environment_config=LP64,
    )
    casts = [c for c in cands if c.discovery_method == "time_t_cast"]
    assert sorted(c.symbol for c in casts) == ["cast_from_mktime", "cast_from_time"]
    assert all(c.rule_id is None for c in casts)


@pytest.mark.parametrize(
    "symbol,source",
    [
        (
            "clock_gettime",
            "int32_t sample_clock_gettime(struct timespec *ts) {\n"
            "    return (int32_t)clock_gettime(CLOCK_REALTIME, ts);\n}\n",
        ),
        (
            "gettimeofday",
            "int32_t sample_gettimeofday(struct timeval *tv) {\n"
            "    return (int32_t)gettimeofday(tv, NULL);\n}\n",
        ),
        (
            "timespec_get",
            "int32_t sample_timespec_get(struct timespec *ts) {\n"
            "    return (int32_t)timespec_get(ts, TIME_UTC);\n}\n",
        ),
        (
            "nanosleep",
            "int32_t sample_nanosleep(const struct timespec *req) {\n"
            "    return (int32_t)nanosleep(req, NULL);\n}\n",
        ),
        (
            "strftime",
            "size_t sample_strftime(char *buf, size_t n, const struct tm *tm) {\n"
            '    return (size_t)strftime(buf, n, "%Y", tm);\n}\n',
        ),
        (
            "stat",
            "int32_t sample_stat(const char *path, struct stat *st) {\n"
            "    return (int32_t)stat(path, st);\n}\n",
        ),
        (
            "KillTimer",
            "int32_t sample_kill_timer(void *hwnd, uint32_t id) {\n"
            "    return (int32_t)KillTimer(hwnd, id);\n}\n",
        ),
    ],
)
def test_status_or_non_time_return_not_time_t_cast(
    tmp_path: Path, symbol: str, source: str
) -> None:
    """Callable / time-related APIs must not seed cast_from_* via return value."""
    src = tmp_path / f"neg_{symbol}.c"
    src.write_text("#include <stdint.h>\n" + source, encoding="utf-8")
    producers = _producers()
    assert symbol not in producers
    cands = _adapter().discover_candidates(
        root_path=str(tmp_path),
        rules_path=str(RULES),
        include_patterns=["**/*.c"],
        exclude_patterns=[],
        time_t_aliases={},
        time_functions=producers,
        environment_config=LP64,
    )
    assert not any(
        c.discovery_method == "time_t_cast" and symbol in (c.symbol or "")
        for c in cands
    )


def test_gmtime_pointer_return_not_producer_cast(tmp_path: Path) -> None:
    src = tmp_path / "gmtime_cast.c"
    src.write_text(
        "void *sample_gmtime(const time_t *t) { return (void *)gmtime(t); }\n",
        encoding="utf-8",
    )
    cands = _adapter().discover_candidates(
        root_path=str(tmp_path),
        rules_path=str(RULES),
        include_patterns=["**/*.c"],
        exclude_patterns=[],
        time_t_aliases={},
        time_functions=_producers(),
        environment_config=LP64,
    )
    assert not any(
        c.discovery_method == "time_t_cast" and "gmtime" in (c.symbol or "")
        for c in cands
    )


def test_cast_detection_still_works_with_typedef_aliases(tmp_path: Path) -> None:
    src = tmp_path / "cast_alias.c"
    src.write_text(
        """\
#include <stdint.h>
typedef time_t epoch_t;
int32_t store(epoch_t t) { return (int32_t)t; }
""",
        encoding="utf-8",
    )
    cands = _adapter().discover_candidates(
        root_path=str(tmp_path),
        rules_path=str(RULES),
        include_patterns=["**/*.c"],
        exclude_patterns=[],
        time_t_aliases={"epoch_t": [f"{src}:2: typedef time_t epoch_t;"]},
        time_functions=[],
        environment_config=LP64,
    )
    casts = [c for c in cands if c.discovery_method == "time_t_cast"]
    assert any("cast" in (c.symbol or "") for c in casts)


def test_pipeline_end_to_end_no_aliases_emits_producer_casts(tmp_path: Path) -> None:
    (tmp_path / "cast.c").write_text(
        """\
#include <stdint.h>
#include <time.h>
int32_t sample_current_time(void) { return (int32_t)time(NULL); }
int32_t sample_from_mktime(struct tm *tm) { return (int32_t)mktime(tm); }
""",
        encoding="utf-8",
    )
    env = tmp_path / "env.json"
    env.write_text(json.dumps(LP64), encoding="utf-8")
    pipe = ScanningPipeline(
        scanner_path=str(SCANNER),
        llm_type="none",
        model="none",
        function_first=True,
        enable_pass1=False,
        enable_io_analysis=False,
        enable_discovery=True,
        environment_config_path=str(env),
    )
    result = pipe.scan(
        root_path=str(tmp_path),
        rules_path=str(RULES),
        include_patterns=["**/*.c"],
        exclude_patterns=[],
        min_risk="low",
        session_dir=str(tmp_path / "session"),
    )
    casts = [c for c in result.candidates if c.discovery_method == "time_t_cast"]
    assert {c.symbol for c in casts} >= {"cast_from_time", "cast_from_mktime"}
    assert result.schema_version == PUBLIC_RESULT_SCHEMA_VERSION == "1.3"
    ids = [
        (c.file, c.line, c.symbol, c.discovery_method, c.rule_id)
        for c in result.candidates
    ]
    assert ids == sorted(ids)


def test_custom_catalog_needs_paren_does_not_imply_producer() -> None:
    rules = [
        {
            "symbol": "my_epoch_now",
            "category": "Simple Type",
            "needs_paren": True,
            "risk": "high",
        },
        {
            "symbol": "time",
            "category": "Current Time",
            "risk": "high",
        },
    ]
    assert extract_callable_catalog_symbols(rules) == ["my_epoch_now", "time"]
    assert extract_time_value_producer_symbols(rules) == ["time"]


def test_unknown_custom_symbol_fails_closed_as_producer() -> None:
    assert (
        is_time_value_producer_rule(
            {"symbol": "mystery_time_api", "category": "Current Time"}
        )
        is False
    )


def test_empty_time_functions_skips_cast_gate_without_aliases(tmp_path: Path) -> None:
    (tmp_path / "cast.c").write_text(
        "int32_t f(void) { return (int32_t)time(NULL); }\n",
        encoding="utf-8",
    )
    cands = _adapter().discover_candidates(
        root_path=str(tmp_path),
        rules_path=str(RULES),
        include_patterns=["**/*.c"],
        exclude_patterns=[],
        time_t_aliases={},
        time_functions=[],
        environment_config=LP64,
    )
    assert not any(c.discovery_method == "time_t_cast" for c in cands)


def test_issue52_local_narrowing_unaffected(tmp_path: Path) -> None:
    from tacs.core.local_narrowing_scanner import LocalNarrowingScanner

    src = """\
#include <stdint.h>
#include <time.h>
void save(int32_t *dst) {
    time_t now = time(NULL);
    *dst = (int32_t)now;
}
"""
    scanner = LocalNarrowingScanner(
        time_t_aliases=[], time_functions=[], environment_config=LP64
    )
    matches = scanner.scan_source(src, "x.c")
    assert matches
    assert any(m.symbol == "cast_from_time_var" for m in matches)


def test_issue57_propagation_still_emits_paths(tmp_path: Path) -> None:
    from tacs.core.callee_propagation import propagate_direct_callee_time

    src = tmp_path / "prop.c"
    src.write_text(
        """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void record_current_event(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
""",
        encoding="utf-8",
    )
    out = propagate_direct_callee_time(
        root_path=str(tmp_path),
        files=[src],
        existing_candidates=[],
        time_t_aliases={},
        time_functions=[],
        environment_config=LP64,
    )
    assert len(out) == 1
    assert out[0].discovery_method == "direct_callee_time_propagation"
    assert out[0].propagation_paths


def test_schema_version_unchanged() -> None:
    assert PUBLIC_RESULT_SCHEMA_VERSION == "1.3"
    assert packaged_rules_path().name == "y2038_sample_rules.json"


def test_name_heuristics_not_enabled_by_producers_alone(tmp_path: Path) -> None:
    src = tmp_path / "name_only.c"
    src.write_text(
        "int f(int timestamp) { return (int)timestamp; }\n",
        encoding="utf-8",
    )
    cands = _adapter().discover_candidates(
        root_path=str(tmp_path),
        rules_path=str(RULES),
        include_patterns=["**/*.c"],
        exclude_patterns=[],
        time_t_aliases={},
        time_functions=_producers(),
        environment_config=LP64,
    )
    assert not any(c.discovery_method == "time_t_cast" for c in cands)
