# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for function-local time-derived narrowing (issue #52)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from report_renderer.core import normalize_findings
from report_renderer.renderers import render_html, render_text
from tacs.core.candidate_utils import candidate_id_for, prepare_candidates
from tacs.core.include_patterns import DEFAULT_EXCLUDE_PATTERNS
from tacs.core.ir_adapter import IRAdapter
from tacs.core.local_narrowing_scanner import (
    LocalNarrowingScanner,
    classify_conversion,
    resolve_type_repr,
)
from tacs.core.pipeline import ScanningPipeline
from tacs.core.schema import Candidate

REPO = Path(__file__).resolve().parents[1]
RULES = REPO / "src" / "tacs" / "rules" / "y2038_sample_rules.json"
SCANNER = REPO / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"
UBXLIB = REPO / ".repo_cache" / "github.com" / "u-blox" / "ubxlib.gitwork"
UBXLIB_SHA = "0237d5d3706ccb17419a8b9eac14bb568e80ad4c"

LP64 = {
    "hardware_model": "LP64",
    "time_t_size_bits": 64,
    "time_t_signed": "signed",
}


def _scanner(**kwargs) -> LocalNarrowingScanner:
    env = kwargs.pop("environment_config", LP64)
    return LocalNarrowingScanner(environment_config=env, **kwargs)


def _match_symbols(source: str, **kwargs):
    return _scanner(**kwargs).scan_source(source, "sample.c")


def test_ubxlib_style_int64_cast_to_int32() -> None:
    source = """\
#include <stdint.h>
static int32_t posDecode(int64_t *pTimeUtc, int printIt)
{
    int64_t t = -1;
    int32_t months = 0;
    t = 0;
    t += uTimeMonthsToSecondsUtc(months);
    t += ((int64_t)1) * 3600 * 24;
    t += ((int64_t)2) * 3600;
    t += ((int64_t)3) * 60;
    t += 4;
    if (printIt) {
        uPortLog("U_GNSS_POS: UTC time = %d.\\n", (int32_t) t);
    }
    if (pTimeUtc != NULL) {
        *pTimeUtc = t;
    }
    return 0;
}
"""
    matches = _match_symbols(source)
    assert len(matches) == 1
    m = matches[0]
    assert m.symbol == "cast_from_time_var"
    assert m.source_var == "t"
    assert m.source_type == "int64_t"
    assert m.source_bits == 64
    assert m.dest_type == "int32_t"
    assert m.dest_bits == 32
    assert m.conversion_kind == "width_reduction"
    assert m.risk == "high"
    assert not m.guarded
    assert "uTimeMonthsToSecondsUtc" in m.provenance
    assert "Unix-epoch" in m.provenance or "absolute-time" in m.provenance
    assert "review candidate" in m.description.lower()
    assert "returned" not in m.description.lower() or "ubxlib" not in m.description.lower()


def test_time_derived_int64_explicit_cast_to_int32() -> None:
    source = """\
#include <time.h>
#include <stdint.h>
void f(void) {
    time_t now = time(NULL);
    int64_t seconds = (int64_t)now;
    log_value((int32_t)seconds);
}
"""
    matches = _match_symbols(source)
    assert len(matches) == 1
    assert matches[0].source_var == "seconds"
    assert matches[0].dest_type == "int32_t"
    assert matches[0].source_bits == 64


def test_time_derived_uint64_cast_to_uint32() -> None:
    source = """\
#include <stdint.h>
uint64_t get_unix_seconds(void);
void f(void) {
    uint64_t t = get_unix_seconds();
    uint32_t narrow = (uint32_t)t;
    (void)narrow;
}
"""
    matches = _match_symbols(source)
    assert len(matches) == 1
    assert matches[0].source_type == "uint64_t"
    assert matches[0].dest_type == "uint32_t"
    assert matches[0].conversion_kind == "width_reduction"


def test_implicit_assignment_to_narrower_local() -> None:
    source = """\
#include <time.h>
#include <stdint.h>
void f(void) {
    time_t now = time(NULL);
    int32_t narrow = now;
    (void)narrow;
}
"""
    matches = _match_symbols(source)
    assert len(matches) == 1
    assert matches[0].symbol == "implicit_cast_from_time"
    assert matches[0].dest_type == "int32_t"


def test_assignment_to_narrower_struct_field() -> None:
    source = """\
#include <time.h>
#include <stdint.h>
void f(void) {
    struct rec {
        int32_t stamp;
    } r;
    time_t now = time(NULL);
    r.stamp = now;
}
"""
    matches = _match_symbols(source)
    assert len(matches) == 1
    assert matches[0].symbol == "implicit_cast_from_time"
    assert "stamp" in matches[0].destination


def test_narrowing_inside_formatted_output_argument() -> None:
    source = """\
#include <time.h>
#include <stdint.h>
#include <stdio.h>
void f(void) {
    time_t now = time(NULL);
    int64_t seconds = (int64_t)now;
    printf("UTC=%d\\n", (int32_t)seconds);
}
"""
    matches = _match_symbols(source)
    assert len(matches) == 1
    assert "printf" in matches[0].full_line or "(int32_t)" in matches[0].full_line


def test_simple_local_assignment_chain() -> None:
    source = """\
#include <time.h>
#include <stdint.h>
void f(void) {
    time_t now = time(NULL);
    int64_t a = (int64_t)now;
    int64_t b = a;
    sink((int32_t)b);
}
"""
    matches = _match_symbols(source)
    assert len(matches) == 1
    assert matches[0].source_var == "b"
    assert "a" in matches[0].provenance or "now" in matches[0].provenance


def test_visible_lower_and_upper_bound_range_check() -> None:
    source = """\
#include <stdint.h>
#include <limits.h>
int64_t seconds_since_epoch(void);
void f(void) {
    int64_t t = seconds_since_epoch();
    if (t < INT32_MIN || t > INT32_MAX) {
        return;
    }
    sink((int32_t)t);
}
"""
    matches = _match_symbols(source)
    assert len(matches) == 1
    assert matches[0].guarded is True
    assert matches[0].risk == "medium"
    assert "INT32" in matches[0].guard_evidence


def test_one_sided_or_insufficient_range_check() -> None:
    source = """\
#include <stdint.h>
#include <limits.h>
int64_t seconds_since_epoch(void);
void f(void) {
    int64_t t = seconds_since_epoch();
    if (t > INT32_MAX) {
        return;
    }
    sink((int32_t)t);
}
"""
    matches = _match_symbols(source)
    assert len(matches) == 1
    assert matches[0].guarded is False
    assert matches[0].risk == "high"
    assert "insufficient" in matches[0].guard_evidence


def test_signedness_change_without_width_reduction() -> None:
    source = """\
#include <stdint.h>
int32_t get_unix_seconds(void);
void f(void) {
    int32_t t = get_unix_seconds();
    uint32_t u = (uint32_t)t;
    (void)u;
}
"""
    matches = _match_symbols(source)
    assert len(matches) == 1
    assert matches[0].conversion_kind == "signedness_change"
    assert matches[0].source_bits == 32
    assert matches[0].dest_bits == 32


def test_unknown_source_or_destination_width_fails_closed() -> None:
    source = """\
#include <time.h>
void f(void) {
    time_t now = time(NULL);
    long narrow = (long)now;
    (void)narrow;
}
"""
    # No hardware_model => long width unresolved => omit claim.
    matches = _match_symbols(
        source, environment_config={"time_t_size_bits": 64, "time_t_signed": "signed"}
    )
    assert matches == []


def test_unrelated_integer_narrowing_negative_control() -> None:
    source = """\
#include <stdint.h>
int64_t get_packet_count(void);
void f(void) {
    int64_t packet_count = get_packet_count();
    log_value((int32_t)packet_count);
}
"""
    assert _match_symbols(source) == []


def test_time_like_name_without_deterministic_provenance() -> None:
    source = """\
#include <stdint.h>
int64_t get_packet_count(void);
void f(void) {
    int64_t timestamp = get_packet_count();
    int64_t epoch = 42;
    log_value((int32_t)timestamp);
    log_value((int32_t)epoch);
}
"""
    assert _match_symbols(source) == []


def test_multiple_locals_with_similar_names() -> None:
    source = """\
#include <stdint.h>
int64_t seconds_since_epoch(void);
int64_t get_packet_count(void);
void f(void) {
    int64_t t = seconds_since_epoch();
    int64_t t2 = get_packet_count();
    sink((int32_t)t);
    sink((int32_t)t2);
}
"""
    matches = _match_symbols(source)
    assert len(matches) == 1
    assert matches[0].source_var == "t"


def test_comments_and_string_literals_do_not_seed_provenance() -> None:
    source = """\
#include <stdint.h>
/* int64_t timestamp = time(NULL); (int32_t)timestamp */
void f(void) {
    int64_t packet_count = 1;
    const char *msg = "time_t; (int32_t)t; uTimeMonthsToSecondsUtc";
    sink((int32_t)packet_count);
    (void)msg;
}
"""
    assert _match_symbols(source) == []


def test_candidate_identity_rule_attribution_and_ordering() -> None:
    source = """\
#include <time.h>
#include <stdint.h>
void f(void) {
    time_t now = time(NULL);
    int64_t a = (int64_t)now;
    int64_t b = (int64_t)now;
    sink((int32_t)b);
    sink((int32_t)a);
}
"""
    matches = _match_symbols(source)
    assert len(matches) == 2
    assert [m.source_var for m in matches] == ["b", "a"] or sorted(
        m.line_number for m in matches
    ) == sorted(m.line_number for m in matches)
    # Stable sort by line then column.
    assert matches == sorted(
        matches, key=lambda m: (m.line_number, m.col_start, m.symbol)
    )
    from tacs.core.local_narrowing_scanner import narrowing_matches_to_candidates

    cands = narrowing_matches_to_candidates(matches)
    assert all(c.discovery_method == "time_t_cast" for c in cands)
    assert all(c.rule_id is None for c in cands)
    ids = [candidate_id_for(c, "sample.c") for c in prepare_candidates(cands)]
    assert ids == sorted(ids)
    assert len(set(ids)) == len(ids)


def test_pipeline_llm_none_emits_narrowing_candidate(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "narrow.c").write_text(
        "#include <time.h>\n"
        "#include <stdint.h>\n"
        "void report(void) {\n"
        "    time_t now = time(NULL);\n"
        "    int64_t seconds = (int64_t)now;\n"
        "    sink((int32_t)seconds);\n"
        "}\n",
        encoding="utf-8",
    )
    pipeline = ScanningPipeline(
        scanner_path=str(SCANNER),
        llm_type="none",
        model="none",
        function_first=True,
        enable_pass1=False,
        enable_io_analysis=False,
        enable_discovery=True,
    )
    results = pipeline.scan(
        root_path=str(root),
        rules_path=str(RULES),
        include_patterns=["**/*.c"],
        exclude_patterns=[],
        min_risk="low",
        session_dir=str(root / "session"),
    )
    out = root / "findings.json"
    pipeline.save_results(results, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    narrow = [
        c
        for c in data["candidates"]
        if c.get("discovery_method") == "time_t_cast"
        and "narrowing" in (c.get("description") or "").lower()
    ]
    assert narrow, "expected local narrowing candidate under --llm none"
    assert all(c.get("rule_id") is None for c in narrow)
    assert any(c.get("function_id") for c in narrow)


def test_text_and_html_render_narrowing_description() -> None:
    raw = {
        "file": "gnss/src/u_gnss_pos.c",
        "line": 180,
        "symbol": "cast_from_time_var",
        "y2038_issue": "abstain",
        "confidence": 0.0,
        "reason": "LLM disabled (--llm none)",
        "source_snippet": 'uPortLog("U_GNSS_POS: UTC time = %d.\\n", (int32_t) t);',
        "description": (
            "Potential time-representation narrowing: time-derived 64-bit "
            "int64_t 't' converted via explicit cast to int32_t."
        ),
        "discovery_method": "time_t_cast",
        "region": {"start_line": 180, "end_line": 180},
        "lines": [180],
        "function_id": "gnss/src/u_gnss_pos.c@posDecode:145-250",
    }
    # Compatibility findings may not carry description; put it in reason too.
    raw["reason"] = raw["description"]
    finding = normalize_findings([raw]).findings[0]
    text = render_text([finding])
    html = render_html([finding], title="narrowing", group_by="file")
    assert "narrowing" in text.lower() or "int32_t" in text
    assert "narrowing" in html.lower() or "int32_t" in html


def test_resolve_type_and_classify_helpers() -> None:
    src = resolve_type_repr("int64_t", environment_config=LP64)
    dst = resolve_type_repr("int32_t", environment_config=LP64)
    kind, unresolved = classify_conversion(src, dst)
    assert kind == "width_reduction"
    assert unresolved == []
    long_unknown = resolve_type_repr(
        "long", environment_config={"time_t_size_bits": 64}
    )
    assert long_unknown.known is False


@pytest.mark.parametrize(
    "source",
    [
        """\
#include <stdint.h>
int64_t getTimeoutSeconds(void);
void f(void) {
    int64_t value = getTimeoutSeconds();
    log_value((int32_t)value);
}
""",
        """\
#include <stdint.h>
int64_t getSecondsSinceBoot(void);
void f(void) {
    int64_t value = getSecondsSinceBoot();
    log_value((int32_t)value);
}
""",
        """\
#include <stdint.h>
int64_t calculateProcessingTime(void);
void f(void) {
    int64_t value = calculateProcessingTime();
    log_value((int32_t)value);
}
""",
        """\
#include <stdint.h>
int64_t getPacketCount(void);
void f(void) {
    int64_t value = getPacketCount();
    log_value((int32_t)value);
}
""",
        """\
#include <stdint.h>
int64_t getCounter(void);
struct rec { int32_t time; };
void f(void) {
    int64_t value = getCounter();
    struct rec record;
    record.time = (int32_t)value;
}
""",
        """\
#include <stdint.h>
int64_t getMonotonicSeconds(void);
void f(void) {
    int64_t value = getMonotonicSeconds();
    log_value((int32_t)value);
}
""",
        """\
#include <stdint.h>
int64_t getElapsedSeconds(void);
void f(void) {
    int64_t value = getElapsedSeconds();
    log_value((int32_t)value);
}
""",
        """\
#include <stdint.h>
int get_time_status(void);
void f(void) {
    int64_t value = get_time_status();
    log_value((int32_t)value);
}
""",
        """\
#include <stdint.h>
int64_t make_timeout(void);
void f(void) {
    int64_t value = make_timeout();
    log_value((int32_t)value);
}
""",
        """\
#include <stdint.h>
/* int64_t t = uTimeMonthsToSecondsUtc(0); (int32_t)t */
void f(void) {
    int64_t value = 1;
    const char *s = "uTimeMonthsToSecondsUtc((int32_t)t)";
    log_value((int32_t)value);
    (void)s;
}
""",
        """\
#include <time.h>
#include <stdint.h>
void f(void) {
    /* clock_gettime returns status, not a timestamp */
    int64_t rc = clock_gettime(0, 0);
    log_value((int32_t)rc);
}
""",
    ],
)
def test_non_epoch_calls_do_not_seed_unix_epoch_provenance(source: str) -> None:
    assert _match_symbols(source) == []


def test_new_scanner_ignores_time_like_variable_name_alone() -> None:
    source = """\
#include <stdint.h>
int64_t getCounter(void);
void f(void) {
    int64_t timestamp = getCounter();
    log_value((int32_t)timestamp);
}
"""
    assert _match_symbols(source) == []


def test_old_line_local_cast_detector_still_flags_time_like_names() -> None:
    """Document combined pipeline behavior for issue #52 review.

    The new local narrowing scanner does not seed from variable names alone.
    The older line-local ``detect_time_t_casts`` still treats substring name
    heuristics (``time``, ``timestamp``, ``ts``, ``tick``, ``epoch``,
    ``unix_time``) as sufficient for a same-line cast. That remains intentional
    compatibility behavior for this issue and is a separate false-positive
    surface, not corrected here.
    """
    from tacs.python.y2038scan_fast_json_group import detect_time_t_casts

    line = "log_value((int32_t)timestamp);"
    hit = detect_time_t_casts(line, line, time_t_aliases=[], time_functions=[])
    assert hit is not None
    assert hit["discovery_method"] == "time_t_cast"
    assert hit["symbol"] == "cast_from_time_var"

    # New scanner alone: no provenance => no candidate.
    source = (
        "#include <stdint.h>\n"
        "int64_t getCounter(void);\n"
        "void f(void) {\n"
        "    int64_t timestamp = getCounter();\n"
        "    log_value((int32_t)timestamp);\n"
        "}\n"
    )
    assert _match_symbols(source) == []


def test_combined_pipeline_still_emits_name_heuristic_cast(tmp_path: Path) -> None:
    """Final TACS behavior includes the older name-heuristic cast detector."""
    root = tmp_path / "name_heur"
    root.mkdir()
    (root / "name.c").write_text(
        "#include <stdint.h>\n"
        "int64_t getCounter(void);\n"
        "void f(void) {\n"
        "    int64_t timestamp = getCounter();\n"
        "    log_value((int32_t)timestamp);\n"
        "}\n",
        encoding="utf-8",
    )
    adapter = IRAdapter(str(SCANNER))
    cands = adapter.discover_candidates(
        str(root),
        str(RULES),
        min_risk="low",
        include_patterns=["**/*.c"],
        exclude_patterns=[],
        time_functions=["time", "mktime"],
        environment_config=LP64,
    )
    casts = [c for c in cands if c.discovery_method == "time_t_cast"]
    assert casts, (
        "older line-local name heuristic still emits cast_from_time_var "
        "for 'timestamp' without epoch provenance"
    )
    assert all(c.rule_id is None for c in casts)


def test_rule_id_null_matches_existing_dynamic_cast_policy() -> None:
    source = """\
#include <time.h>
#include <stdint.h>
void f(void) {
    time_t now = time(NULL);
    sink((int32_t)now);
}
"""
    from tacs.core.local_narrowing_scanner import narrowing_matches_to_candidates

    cands = narrowing_matches_to_candidates(_match_symbols(source))
    assert cands
    assert all(c.discovery_method == "time_t_cast" for c in cands)
    assert all(c.rule_id is None for c in cands)


@pytest.mark.skipif(not UBXLIB.is_dir(), reason="pinned ubxlib cache unavailable")
def test_pinned_ubxlib_posdecode_narrowing_candidate() -> None:
    import subprocess

    sha = subprocess.check_output(
        ["git", "-C", str(UBXLIB), "rev-parse", "HEAD"], text=True
    ).strip()
    assert sha == UBXLIB_SHA
    adapter = IRAdapter(str(SCANNER))
    cands = adapter.discover_candidates(
        str(UBXLIB),
        str(RULES),
        min_risk="low",
        include_patterns=["gnss/src/u_gnss_pos.c"],
        exclude_patterns=[],
        time_functions=["time", "mktime"],
        environment_config=LP64,
    )
    hits = [
        c
        for c in cands
        if "u_gnss_pos.c" in c.file
        and c.line == 180
        and c.discovery_method == "time_t_cast"
    ]
    assert hits, "expected narrowing candidate on u_gnss_pos.c:180"
    hit = hits[0]
    assert hit.symbol == "cast_from_time_var"
    assert hit.rule_id is None
    assert "int32_t" in hit.description
    assert "int64_t" in hit.description or "64-bit" in hit.description
