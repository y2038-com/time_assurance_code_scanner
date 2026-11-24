# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for one-hop direct-callee time propagation (issue #57)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from report_renderer.renderers import render_html, render_text
from tacs.core.call_resolution import resolve_call_site
from tacs.core.call_site_index import find_call_sites_in_function
from tacs.core.callee_propagation import propagate_direct_callee_time
from tacs.core.ir_adapter import IRAdapter
from tacs.core.pipeline import ScanningPipeline
from tacs.core.schema import (
    PUBLIC_RESULT_SCHEMA_VERSION,
    CallResolutionBasis,
    Candidate,
    PropagationArgument,
    PropagationCallSite,
    PropagationKind,
    PropagationParameter,
    PropagationPath,
    PropagationResolution,
    CallResolutionState,
    TimeSemantic,
)
from tacs.core.source_index import build_source_index

REPO = Path(__file__).resolve().parents[1]
RULES = REPO / "src" / "tacs" / "rules" / "y2038_sample_rules.json"
SCANNER = REPO / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"

LP64 = {
    "config_id": "lp64_signed_64bit",
    "hardware_model": "LP64",
    "time_t_size_bits": 64,
    "time_t_signed": "signed",
}

MOTIVATING = """\
#include <stdint.h>
#include <time.h>

struct stored_event {
    int32_t unix_seconds;
};

static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}

static void record_current_event(struct stored_event *dst)
{
    time_t now = time(NULL);

    if (now != (time_t)-1) {
        save_event(dst, (int64_t)now);
    }
}
"""


def _adapter() -> IRAdapter:
    return IRAdapter(SCANNER)


def _discover(tmp_path: Path, source: str, name: str = "sample.c") -> list[Candidate]:
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return _adapter().discover_candidates(
        root_path=str(tmp_path),
        rules_path=str(RULES),
        include_patterns=[f"**/{name}"],
        exclude_patterns=[],
        time_t_aliases={},
        time_functions=[],
        environment_config=LP64,
    )


def test_schema_version_is_1_3() -> None:
    assert PUBLIC_RESULT_SCHEMA_VERSION == "1.3"


def test_motivating_same_file_static(tmp_path: Path) -> None:
    cands = _discover(tmp_path, MOTIVATING)
    prop = [c for c in cands if c.discovery_method == "direct_callee_time_propagation"]
    assert len(prop) == 1
    c = prop[0]
    assert c.symbol == "cast_from_time_var"
    assert c.line == 10
    assert c.propagation_paths
    path = c.propagation_paths[0]
    assert path.kind == PropagationKind.DIRECT_CALLEE_ARGUMENT
    assert path.depth == 1
    assert path.resolution.state == CallResolutionState.RESOLVED
    assert path.resolution.basis == CallResolutionBasis.SAME_FILE_STATIC
    assert path.argument.index == 1  # zero-based
    assert "(int64_t)now" in path.argument.expression
    assert path.parameter.name == "epoch_seconds"
    assert path.parameter.declared_type == "int64_t"
    assert path.time_semantic in {
        TimeSemantic.UNIX_EPOCH_SECONDS,
        TimeSemantic.TIME_T_VALUE,
    }
    assert "record_current_event" in path.caller_function_id
    assert "save_event" in path.callee_function_id


def test_llm_none_pipeline_emits_propagation(tmp_path: Path) -> None:
    (tmp_path / "event.c").write_text(MOTIVATING, encoding="utf-8")
    env = tmp_path / "env.json"
    env.write_text(json.dumps(LP64), encoding="utf-8")
    out = tmp_path / "out.json"
    pipeline = ScanningPipeline(
        scanner_path=str(SCANNER),
        llm_type="none",
        model="none",
        function_first=True,
        enable_pass1=False,
        enable_io_analysis=False,
        enable_discovery=True,
        environment_config_path=str(env),
    )
    results = pipeline.scan(
        root_path=str(tmp_path),
        rules_path=str(RULES),
        include_patterns=["**/*.c"],
        exclude_patterns=[],
        min_risk="low",
        session_dir=str(tmp_path / "session"),
    )
    pipeline.save_results(results, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.3"
    prop = [
        c
        for c in data["candidates"]
        if c.get("discovery_method") == "direct_callee_time_propagation"
    ]
    assert len(prop) == 1
    assert prop[0]["propagation_paths"]
    assert data["meta"]["candidate_summary"]["functions_with_candidates"] >= 2


def test_unrelated_int64_not_propagated(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void record_count(struct stored_event *dst, int64_t total_packets)
{
    save_event(dst, total_packets);
}
"""
    cands = _discover(tmp_path, source)
    assert not any(
        c.discovery_method == "direct_callee_time_propagation" for c in cands
    )


def test_time_like_parameter_name_alone_insufficient(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void record(struct stored_event *dst)
{
    int64_t epoch_seconds = 42;
    save_event(dst, epoch_seconds);
}
"""
    cands = _discover(tmp_path, source)
    assert not any(
        c.discovery_method == "direct_callee_time_propagation" for c in cands
    )


def test_duration_and_timeout_not_propagated(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static int64_t getTimeoutSeconds(void) { return 5; }
static int64_t getSecondsSinceBoot(void) { return 9; }
static void record(struct stored_event *dst)
{
    save_event(dst, getTimeoutSeconds());
    save_event(dst, getSecondsSinceBoot());
}
"""
    cands = _discover(tmp_path, source)
    assert not any(
        c.discovery_method == "direct_callee_time_propagation" for c in cands
    )


def test_function_pointer_not_propagated(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void record(struct stored_event *dst)
{
    void (*fp)(struct stored_event *, int64_t) = save_event;
    time_t now = time(NULL);
    fp(dst, (int64_t)now);
}
"""
    cands = _discover(tmp_path, source)
    assert not any(
        c.discovery_method == "direct_callee_time_propagation" for c in cands
    )


def test_arity_mismatch_not_propagated(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds, int extra)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void record(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
"""
    cands = _discover(tmp_path, source)
    assert not any(
        c.discovery_method == "direct_callee_time_propagation" for c in cands
    )


def test_range_checked_callee_still_emits_with_guard_evidence(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
static int save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    if (epoch_seconds < INT32_MIN || epoch_seconds > INT32_MAX) {
        return -1;
    }
    dst->unix_seconds = (int32_t)epoch_seconds;
    return 0;
}
static void record(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
"""
    cands = _discover(tmp_path, source)
    prop = [c for c in cands if c.discovery_method == "direct_callee_time_propagation"]
    assert len(prop) == 1
    assert prop[0].risk == "medium"
    assert "range" in (prop[0].description or "").lower() or "INT32" in (
        prop[0].description or ""
    )


def test_duplicate_call_paths_one_candidate(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void record_a(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
static void record_b(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
"""
    cands = _discover(tmp_path, source)
    prop = [c for c in cands if c.discovery_method == "direct_callee_time_propagation"]
    assert len(prop) == 1
    assert prop[0].propagation_paths
    assert len(prop[0].propagation_paths) == 2


def test_comments_and_strings_do_not_create_calls(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void record(struct stored_event *dst)
{
    time_t now = time(NULL);
    /* save_event(dst, (int64_t)now); */
    const char *msg = "save_event(dst, (int64_t)now);";
    (void)msg;
    (void)now;
    (void)dst;
}
"""
    cands = _discover(tmp_path, source)
    assert not any(
        c.discovery_method == "direct_callee_time_propagation" for c in cands
    )


def test_cross_file_visible_declaration(tmp_path: Path) -> None:
    (tmp_path / "save.h").write_text(
        """\
#include <stdint.h>
struct stored_event { int32_t unix_seconds; };
void save_event(struct stored_event *dst, int64_t epoch_seconds);
""",
        encoding="utf-8",
    )
    (tmp_path / "save.c").write_text(
        """\
#include "save.h"
void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
""",
        encoding="utf-8",
    )
    (tmp_path / "record.c").write_text(
        """\
#include <time.h>
#include "save.h"
void record_current_event(struct stored_event *dst)
{
    time_t now = time(NULL);
    if (now != (time_t)-1) {
        save_event(dst, (int64_t)now);
    }
}
""",
        encoding="utf-8",
    )
    cands = _adapter().discover_candidates(
        root_path=str(tmp_path),
        rules_path=str(RULES),
        include_patterns=["**/*.c", "**/*.h"],
        exclude_patterns=[],
        time_t_aliases={},
        time_functions=[],
        environment_config=LP64,
    )
    prop = [c for c in cands if c.discovery_method == "direct_callee_time_propagation"]
    assert len(prop) == 1
    assert (
        prop[0].propagation_paths[0].resolution.basis
        == CallResolutionBasis.VISIBLE_DECLARATION_UNIQUE_DEFINITION
    )


def test_unique_definition_without_visible_declaration_rejected(tmp_path: Path) -> None:
    (tmp_path / "save.c").write_text(
        """\
#include <stdint.h>
struct stored_event { int32_t unix_seconds; };
void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
""",
        encoding="utf-8",
    )
    (tmp_path / "record.c").write_text(
        """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
void save_event(struct stored_event *dst, int64_t epoch_seconds);
void record_current_event(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
""",
        encoding="utf-8",
    )
    # Wait - record.c has a local declaration. That IS visible.
    # Rewrite without declaration:
    (tmp_path / "record.c").write_text(
        """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
void record_current_event(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
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
        time_functions=[],
        environment_config=LP64,
    )
    assert not any(
        c.discovery_method == "direct_callee_time_propagation" for c in cands
    )


def test_same_name_static_in_different_files_not_confused(tmp_path: Path) -> None:
    (tmp_path / "a.c").write_text(
        """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
void record_a(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
""",
        encoding="utf-8",
    )
    (tmp_path / "b.c").write_text(
        """\
#include <stdint.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
void record_b(struct stored_event *dst, int64_t n)
{
    save_event(dst, n);
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
        time_functions=[],
        environment_config=LP64,
    )
    prop = [c for c in cands if c.discovery_method == "direct_callee_time_propagation"]
    assert len(prop) == 1
    assert prop[0].file.endswith("a.c") or "a.c" in prop[0].file


def test_propagation_path_round_trip_and_render() -> None:
    path = PropagationPath(
        kind=PropagationKind.DIRECT_CALLEE_ARGUMENT,
        depth=1,
        origin_candidate_ids=["event.c:15:0:0:high:time"],
        caller_function_id="event.c@record_current_event:13-20",
        call_site=PropagationCallSite(file="event.c", line=18, column=9),
        resolution=PropagationResolution(
            state=CallResolutionState.RESOLVED,
            basis=CallResolutionBasis.SAME_FILE_STATIC,
        ),
        argument=PropagationArgument(index=1, expression="(int64_t)now"),
        callee_function_id="event.c@save_event:8-11",
        parameter=PropagationParameter(
            index=1, name="epoch_seconds", declared_type="int64_t"
        ),
        time_semantic=TimeSemantic.UNIX_EPOCH_SECONDS,
        propagation_depth=1,
        truncated=False,
        stop_reasons=[],
    )
    dumped = path.model_dump()
    restored = PropagationPath.model_validate(dumped)
    assert restored.argument.index == 1
    cand = {
        "candidate_id": "event.c:10:0:0:high:cast_from_time_var",
        "discovery_method": "direct_callee_time_propagation",
        "rule_id": None,
        "risk": "high",
        "symbol": "cast_from_time_var",
        "file": "event.c",
        "line": 10,
        "analysis_coverage": "grouped",
        "function_id": "event.c@save_event:8-11",
        "one_line_snippet": "dst->unix_seconds = (int32_t)epoch_seconds;",
        "propagation_paths": [dumped],
    }
    counts = {
        "total": 1,
        "grouped": 1,
        "ungrouped": 0,
        "functions_with_candidates": 1,
    }
    out = render_text(
        [],
        candidates=[cand],
        candidate_counts=counts,
        has_candidate_section=True,
    )
    assert "Time propagation:" in out
    assert "argument 2:" in out  # 1-based display of zero-based index 1
    assert "(int64_t)now" in out
    html = render_html(
        [],
        title="t",
        group_by="none",
        candidates=[cand],
        candidate_counts=counts,
        has_candidate_section=True,
    )
    assert "Time propagation" in html
    assert "(int64_t)now" in html
    evil = dict(cand)
    evil_path = dict(dumped)
    evil_path["argument"] = {"index": 1, "expression": "<script>alert(1)</script>"}
    evil["propagation_paths"] = [evil_path]
    html2 = render_html(
        [],
        title="t",
        group_by="none",
        candidates=[evil],
        candidate_counts=counts,
        has_candidate_section=True,
    )
    assert "<script>alert(1)</script>" not in html2
    assert "&lt;script&gt;" in html2


def test_malformed_propagation_path_fails_closed() -> None:
    with pytest.raises(ValidationError):
        PropagationPath.model_validate(
            {
                "kind": "direct_callee_argument",
                "depth": 2,  # only depth 1 allowed
                "caller_function_id": "a",
                "call_site": {"file": "a.c", "line": 1},
                "resolution": {"state": "resolved", "basis": "same_file_static"},
                "argument": {"index": 0, "expression": "x"},
                "callee_function_id": "b",
                "parameter": {"index": 0, "name": "x", "declared_type": "int"},
                "time_semantic": "unix_epoch_seconds",
            }
        )


def test_legacy_schema_has_no_invented_paths() -> None:
    for version in ("1.0", "1.1", "1.2"):
        doc = {
            "schema_version": version,
            "meta": {},
            "candidates": [
                {
                    "candidate_id": "a.c:1:0:0:high:time",
                    "file": "a.c",
                    "line": 1,
                    "symbol": "time",
                    "risk": "high",
                    "description": "",
                    "one_line_snippet": "time(NULL);",
                    "discovery_method": "catalog_symbol_match",
                    "rule_id": None,
                    "function_id": None,
                    "analysis_coverage": "ungrouped",
                }
            ],
            "assessments": [],
            "findings": [],
        }
        assert "propagation_paths" not in doc["candidates"][0]
        text = render_text(
            [],
            candidates=doc["candidates"],
            candidate_counts={"total": 1, "grouped": 0, "ungrouped": 1, "functions_with_candidates": 0},
            has_candidate_section=True,
        )
        assert "Time propagation:" not in text


# ---------------------------------------------------------------------------
# Issue #57 review regressions
# ---------------------------------------------------------------------------

from tacs.core.alias_scope import build_include_adjacency
from tacs.core.call_resolution import MAX_AMBIGUOUS_TARGETS, resolve_call_site
from tacs.core.call_site_index import MAX_CALL_EXPRESSION_CHARS, find_call_sites_in_function
from tacs.core.callee_propagation import (
    filter_origin_ids,
    merge_propagation_into_existing,
    path_referentially_valid,
)
from tacs.core.function_llm_client import FunctionLLMClient
from tacs.core.function_schemas import FunctionBatch, FunctionBody
from tacs.core.preprocessor_conditions import (
    condition_stack_at_line,
    conditions_compatible,
)
from tacs.core.schema import PropagationStopReason


def _index_and_sites(tmp_path: Path, files: dict[str, str]):
    paths = []
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        paths.append(p)
    index = build_source_index(paths, str(tmp_path))
    adjacency = build_include_adjacency(paths, str(tmp_path))
    sources = {str(p): p.read_text(encoding="utf-8") for p in paths}
    return index, adjacency, sources


def test_cross_file_static_never_resolves(tmp_path: Path) -> None:
    """static save_value in a.c must not resolve from b.c even if unique."""
    (tmp_path / "a.c").write_text(
        """\
#include <stdint.h>
static void save_value(int64_t value)
{
    (void)value;
}
""",
        encoding="utf-8",
    )
    (tmp_path / "b.c").write_text(
        """\
#include <stdint.h>
#include <time.h>
void caller(void)
{
    time_t now = time(NULL);
    save_value((int64_t)now);
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
        time_functions=[],
        environment_config=LP64,
    )
    assert not any(
        c.discovery_method == "direct_callee_time_propagation" for c in cands
    )


def test_visible_decl_incompatible_arity_rejected(tmp_path: Path) -> None:
    (tmp_path / "save.h").write_text(
        "void save_event(struct stored_event *dst, int64_t epoch_seconds, int extra);\n",
        encoding="utf-8",
    )
    (tmp_path / "save.c").write_text(
        """\
#include <stdint.h>
struct stored_event { int32_t unix_seconds; };
void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
""",
        encoding="utf-8",
    )
    (tmp_path / "record.c").write_text(
        """\
#include <stdint.h>
#include <time.h>
#include "save.h"
struct stored_event { int32_t unix_seconds; };
void record(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
""",
        encoding="utf-8",
    )
    cands = _adapter().discover_candidates(
        root_path=str(tmp_path),
        rules_path=str(RULES),
        include_patterns=["**/*"],
        exclude_patterns=[],
        time_t_aliases={},
        time_functions=[],
        environment_config=LP64,
    )
    assert not any(
        c.discovery_method == "direct_callee_time_propagation" for c in cands
    )


def test_visible_decl_incompatible_types_rejected(tmp_path: Path) -> None:
    (tmp_path / "save.h").write_text(
        "void save_event(struct stored_event *dst, int32_t epoch_seconds);\n",
        encoding="utf-8",
    )
    (tmp_path / "save.c").write_text(
        """\
#include <stdint.h>
struct stored_event { int32_t unix_seconds; };
void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
""",
        encoding="utf-8",
    )
    (tmp_path / "record.c").write_text(
        """\
#include <stdint.h>
#include <time.h>
#include "save.h"
struct stored_event { int32_t unix_seconds; };
void record(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
""",
        encoding="utf-8",
    )
    cands = _adapter().discover_candidates(
        root_path=str(tmp_path),
        rules_path=str(RULES),
        include_patterns=["**/*"],
        exclude_patterns=[],
        time_t_aliases={},
        time_functions=[],
        environment_config=LP64,
    )
    assert not any(
        c.discovery_method == "direct_callee_time_propagation" for c in cands
    )


def test_multiple_external_definitions_ambiguous(tmp_path: Path) -> None:
    (tmp_path / "a.c").write_text(
        """\
#include <stdint.h>
struct stored_event { int32_t unix_seconds; };
void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
""",
        encoding="utf-8",
    )
    (tmp_path / "b.c").write_text(
        """\
#include <stdint.h>
struct stored_event { int32_t unix_seconds; };
void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
""",
        encoding="utf-8",
    )
    (tmp_path / "save.h").write_text(
        "void save_event(struct stored_event *dst, int64_t epoch_seconds);\n",
        encoding="utf-8",
    )
    (tmp_path / "record.c").write_text(
        """\
#include <stdint.h>
#include <time.h>
#include "save.h"
struct stored_event { int32_t unix_seconds; };
void record(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
""",
        encoding="utf-8",
    )
    cands = _adapter().discover_candidates(
        root_path=str(tmp_path),
        rules_path=str(RULES),
        include_patterns=["**/*"],
        exclude_patterns=[],
        time_t_aliases={},
        time_functions=[],
        environment_config=LP64,
    )
    assert not any(
        c.discovery_method == "direct_callee_time_propagation" for c in cands
    )


def test_same_file_static_declaration_and_definition(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds);
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void record(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
"""
    cands = _discover(tmp_path, source)
    prop = [c for c in cands if c.discovery_method == "direct_callee_time_propagation"]
    assert len(prop) == 1


def test_preprocessor_same_condition_allows(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
#ifdef CONFIG_A
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void record(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
#endif
"""
    cands = _discover(tmp_path, source)
    prop = [c for c in cands if c.discovery_method == "direct_callee_time_propagation"]
    assert len(prop) == 1


def test_preprocessor_mutually_exclusive_rejected(tmp_path: Path) -> None:
    # Duplicate definitions under #if/#else → ambiguous (fail closed).
    source_dup = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
#ifdef CONFIG_A
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
#else
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
#endif
static void record(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
"""
    cands = _discover(tmp_path, source_dup, name="pp_dup.c")
    assert not any(
        c.discovery_method == "direct_callee_time_propagation" for c in cands
    )

    # Call under CONFIG_B, definition under CONFIG_A → configuration_dependent.
    source = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
#ifdef CONFIG_A
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
#endif
#ifdef CONFIG_B
static void record(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
#endif
"""
    index, adjacency, sources = _index_and_sites(tmp_path, {"pp_cd.c": source})
    callers = [f for f in index.definitions if f.symbol == "record"]
    assert callers
    sites = find_call_sites_in_function(sources[callers[0].file_abs], callers[0])
    save_sites = [s for s in sites if s.simple_name == "save_event"]
    assert save_sites
    resolved = resolve_call_site(
        save_sites[0], index, adjacency, sources_by_abs=sources
    )
    assert resolved.state == CallResolutionState.CONFIGURATION_DEPENDENT
    cands2 = _discover(tmp_path, source, name="pp_cd2.c")
    assert not any(
        c.discovery_method == "direct_callee_time_propagation" for c in cands2
    )


def test_preprocessor_condition_stacks() -> None:
    src = "#ifdef CONFIG_A\nint x;\n#endif\n#ifdef CONFIG_B\nint y;\n#endif\n"
    assert condition_stack_at_line(src, 2) == ("ifdef CONFIG_A",)
    assert condition_stack_at_line(src, 5) == ("ifdef CONFIG_B",)
    assert not conditions_compatible(
        condition_stack_at_line(src, 2), condition_stack_at_line(src, 5)
    )
    assert conditions_compatible((), ())


def test_definition_header_not_a_call_site(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    (void)dst;
    (void)epoch_seconds;
}
"""
    path = tmp_path / "d.c"
    path.write_text(source, encoding="utf-8")
    index = build_source_index([path], str(tmp_path))
    fn = index.definitions[0]
    sites = find_call_sites_in_function(source, fn)
    assert not any(s.simple_name == "save_event" for s in sites)


def test_control_casts_sizeof_not_calls(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
static void outer(void)
{
    int x = 0;
    if (x) { x = 1; }
    for (int i = 0; i < 1; i++) { x += i; }
    while (x > 0) { x--; }
    switch (x) { case 0: break; default: break; }
    x = sizeof(x);
    (void)(int)x;
}
"""
    path = tmp_path / "c.c"
    path.write_text(source, encoding="utf-8")
    index = build_source_index([path], str(tmp_path))
    fn = [f for f in index.definitions if f.symbol == "outer"][0]
    sites = find_call_sites_in_function(source, fn)
    names = {s.simple_name for s in sites}
    assert "if" not in names
    assert "for" not in names
    assert "while" not in names
    assert "switch" not in names
    assert "sizeof" not in names
    assert "int" not in names


def test_function_pointer_variable_shadowing(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void record(struct stored_event *dst)
{
    void (*save_event)(struct stored_event *, int64_t);
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
"""
    path = tmp_path / "fp.c"
    path.write_text(source, encoding="utf-8")
    index, adjacency, sources = _index_and_sites(tmp_path, {"fp.c": source})
    caller = [f for f in index.definitions if f.symbol == "record"][0]
    sites = [
        s
        for s in find_call_sites_in_function(sources[caller.file_abs], caller)
        if s.simple_name == "save_event"
    ]
    assert sites
    resolved = resolve_call_site(
        sites[0], index, adjacency, sources_by_abs=sources
    )
    assert resolved.state == CallResolutionState.INDIRECT
    cands = _discover(tmp_path, source, name="fp.c")
    assert not any(
        c.discovery_method == "direct_callee_time_propagation" for c in cands
    )


def test_local_variable_shadowing_blocks_resolution(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void record(struct stored_event *dst)
{
    int save_event = 0;
    time_t now = time(NULL);
    (void)save_event;
    /* still a call of the shadowed name — must not resolve */
    save_event(dst, (int64_t)now);
}
"""
    # Note: this is invalid C if save_event is an int, but the scanner must
    # still fail closed rather than linking to the static function.
    index, adjacency, sources = _index_and_sites(tmp_path, {"sh.c": source})
    caller = [f for f in index.definitions if f.symbol == "record"][0]
    sites = [
        s
        for s in find_call_sites_in_function(sources[caller.file_abs], caller)
        if s.simple_name == "save_event"
    ]
    assert sites
    resolved = resolve_call_site(
        sites[0], index, adjacency, sources_by_abs=sources
    )
    assert resolved.state == CallResolutionState.INDIRECT


def test_path_referential_integrity_rejects_bad_indexes(tmp_path: Path) -> None:
    cands = _discover(tmp_path, MOTIVATING)
    prop = [c for c in cands if c.propagation_paths]
    assert prop
    good = prop[0].propagation_paths[0]
    bad = good.model_copy(
        update={"argument": PropagationArgument(index=99, expression="x")}
    )
    # Reconstruct caller/callee from index for the validator.
    path = tmp_path / "sample.c"
    index = build_source_index([path], str(tmp_path))
    caller = [f for f in index.definitions if "record_current_event" in f.symbol][0]
    callee = [f for f in index.definitions if f.symbol.endswith("save_event") or f.symbol == "save_event"][0]
    sites = find_call_sites_in_function(path.read_text(encoding="utf-8"), caller)
    site = [s for s in sites if s.simple_name == "save_event"][0]
    assert not path_referentially_valid(
        bad,
        existing_candidates=cands,
        caller=caller,
        callee=callee,
        site=site,
        param_name=good.parameter.name,
        param_type=good.parameter.declared_type,
        param_index=good.parameter.index,
    )


def test_filter_origin_ids_does_not_invent() -> None:
    existing = [
        Candidate(
            file="a.c",
            line=1,
            symbol="time",
            one_line_snippet="time(NULL);",
            risk="high",
        )
    ]
    assert filter_origin_ids(["missing:1:0:0:high:time"], existing) == []
    assert filter_origin_ids([], existing) == []


def test_deterministic_path_ordering_independent_of_input_order(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void record_a(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
static void record_b(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
"""
    a = _discover(tmp_path, source, name="ord_a.c")
    b_path = tmp_path / "ord_b"
    b_path.mkdir()
    # Reverse function order in source text.
    reversed_src = "\n".join(
        [
            "#include <stdint.h>",
            "#include <time.h>",
            "struct stored_event { int32_t unix_seconds; };",
            "static void save_event(struct stored_event *dst, int64_t epoch_seconds)",
            "{",
            "    dst->unix_seconds = (int32_t)epoch_seconds;",
            "}",
            "static void record_b(struct stored_event *dst)",
            "{",
            "    time_t now = time(NULL);",
            "    save_event(dst, (int64_t)now);",
            "}",
            "static void record_a(struct stored_event *dst)",
            "{",
            "    time_t now = time(NULL);",
            "    save_event(dst, (int64_t)now);",
            "}",
        ]
    )
    b = _discover(b_path, reversed_src, name="ord_b.c")
    pa = [c for c in a if c.discovery_method == "direct_callee_time_propagation"][0]
    pb = [c for c in b if c.discovery_method == "direct_callee_time_propagation"][0]
    # Same sink identity shape (symbol/line relative).
    assert pa.symbol == pb.symbol
    assert pa.line == pb.line
    keys_a = [
        (
            p.caller_function_id.split("@")[1].split(":")[0],
            p.call_site.line,
            p.argument.index,
        )
        for p in pa.propagation_paths
    ]
    keys_b = [
        (
            p.caller_function_id.split("@")[1].split(":")[0],
            p.call_site.line,
            p.argument.index,
        )
        for p in pb.propagation_paths
    ]
    assert keys_a == sorted(keys_a)
    assert [k[0] for k in keys_a] == [k[0] for k in keys_b]


def test_local_and_propagated_dedupe_keeps_time_t_cast(tmp_path: Path) -> None:
    # Callee also has a local time_t that narrows — local method wins.
    source = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    time_t local = time(NULL);
    dst->unix_seconds = (int32_t)local;
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void record(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
"""
    cands = _discover(tmp_path, source)
    # Find the epoch_seconds sink if present as either method.
    epoch_sinks = [
        c
        for c in cands
        if "epoch_seconds" in (c.one_line_snippet or "")
        or c.symbol == "cast_from_time_var"
    ]
    # Merge behavior unit test:
    local = Candidate(
        file="x.c",
        line=10,
        symbol="cast_from_time_var",
        one_line_snippet="dst->unix_seconds = (int32_t)epoch_seconds;",
        risk="high",
        discovery_method="time_t_cast",
    )
    path = PropagationPath(
        kind=PropagationKind.DIRECT_CALLEE_ARGUMENT,
        depth=1,
        origin_candidate_ids=[],
        caller_function_id="x.c@record:20-25",
        call_site=PropagationCallSite(file="x.c", line=22, column=5),
        resolution=PropagationResolution(
            state=CallResolutionState.RESOLVED,
            basis=CallResolutionBasis.SAME_FILE_STATIC,
        ),
        argument=PropagationArgument(index=1, expression="(int64_t)now"),
        callee_function_id="x.c@save_event:5-12",
        parameter=PropagationParameter(
            index=1, name="epoch_seconds", declared_type="int64_t"
        ),
        time_semantic=TimeSemantic.UNIX_EPOCH_SECONDS,
    )
    prop = local.model_copy(
        update={
            "discovery_method": "direct_callee_time_propagation",
            "propagation_paths": [path],
        }
    )
    merged = merge_propagation_into_existing([local], [prop])
    assert len(merged) == 1
    assert merged[0].discovery_method == "time_t_cast"
    assert merged[0].propagation_paths
    assert len(merged[0].propagation_paths) == 1


def test_call_expression_too_long_not_propagated(tmp_path: Path) -> None:
    long_arg = "a" * (MAX_CALL_EXPRESSION_CHARS + 20)
    source = f"""\
#include <stdint.h>
#include <time.h>
struct stored_event {{ int32_t unix_seconds; }};
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{{
    dst->unix_seconds = (int32_t)epoch_seconds;
}}
static void record(struct stored_event *dst)
{{
    time_t now = time(NULL);
    save_event(dst, (int64_t)({long_arg}, now));
}}
"""
    path = tmp_path / "long.c"
    path.write_text(source, encoding="utf-8")
    index = build_source_index([path], str(tmp_path))
    caller = [f for f in index.definitions if f.symbol == "record"][0]
    sites = find_call_sites_in_function(source, caller)
    # Over-long call expressions are omitted entirely (not truncated+trusted).
    assert not any(s.simple_name == "save_event" for s in sites)


def test_schema_rejects_negative_index_and_absolute_path() -> None:
    with pytest.raises(ValidationError):
        PropagationArgument(index=-1, expression="x")
    with pytest.raises(ValidationError):
        PropagationCallSite(file="/abs/x.c", line=1)
    with pytest.raises(ValidationError):
        PropagationCallSite(file="../x.c", line=1)
    with pytest.raises(ValidationError):
        PropagationPath.model_validate(
            {
                "kind": "not_a_kind",
                "depth": 1,
                "caller_function_id": "a",
                "call_site": {"file": "a.c", "line": 1},
                "resolution": {"state": "resolved", "basis": "same_file_static"},
                "argument": {"index": 0, "expression": "x"},
                "callee_function_id": "b",
                "parameter": {"index": 0, "name": "x", "declared_type": "int"},
                "time_semantic": "unix_epoch_seconds",
            }
        )


def test_schema_rejects_excessive_expression_length() -> None:
    with pytest.raises(ValidationError):
        PropagationArgument(index=0, expression="x" * 600)


def _llm_client() -> FunctionLLMClient:
    return FunctionLLMClient(
        llm_type="none",
        model="none",
        environment_config=LP64,
        timeout_sec=5,
        batch_size_func=4,
        confidence_floor=0.5,
    )


def _func_body(with_paths: bool = False) -> FunctionBody:
    additions = {}
    if with_paths:
        additions["propagation_paths"] = [
            {
                "kind": "direct_callee_argument",
                "depth": 1,
                "caller_function_id": "a.c@caller:1-5",
                "callee_function_id": "a.c@callee:6-10",
            }
        ]
    return FunctionBody(
        function_id="a.c@foo:1-5",
        file_path="a.c",
        symbol="foo",
        start_line=1,
        end_line=5,
        body="void foo(void) { }",
        candidate_lines=[2],
        context_additions=additions or None,
    )


def test_prompt_isolation_no_propagation_matches_absence() -> None:
    client = _llm_client()
    batch = FunctionBatch(batch_id="b1", functions=[_func_body(False)])
    prompt = client._build_pass_f1_prompt(batch)
    assert "DIRECT-CALLEE TIME PROPAGATION" not in prompt.system
    assert "assess only supplied paths" not in prompt.system.lower()
    assert "do not invent edges" not in prompt.system.lower()


def test_prompt_includes_propagation_when_paths_present() -> None:
    client = _llm_client()
    batch = FunctionBatch(batch_id="b2", functions=[_func_body(True)])
    prompt = client._build_pass_f1_prompt(batch)
    assert "DIRECT-CALLEE TIME PROPAGATION" in prompt.system
    assert "assess only supplied paths" in prompt.system.lower()
    assert "do not invent edges" in prompt.system.lower()


def test_prompt_multiple_and_legacy_without_paths() -> None:
    client = _llm_client()
    multi = FunctionBatch(
        batch_id="b3",
        functions=[_func_body(True), _func_body(True)],
    )
    assert "DIRECT-CALLEE TIME PROPAGATION" in client._build_pass_f1_prompt(multi).system
    legacy = FunctionBatch(batch_id="b4", functions=[_func_body(False)])
    assert "DIRECT-CALLEE TIME PROPAGATION" not in client._build_pass_f1_prompt(legacy).system


def test_pointer_reference_variadic_not_propagated(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
#include <time.h>
static void take_ptr(int64_t *p)
{
    (void)p;
}
static void take_var(int64_t first, ...)
{
    (void)first;
}
static void record(void)
{
    time_t now = time(NULL);
    int64_t v = (int64_t)now;
    take_ptr(&v);
    take_var(v, 1);
}
"""
    cands = _discover(tmp_path, source)
    assert not any(
        c.discovery_method == "direct_callee_time_propagation" for c in cands
    )


def test_member_and_qualified_calls_unsupported(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
#include <time.h>
struct S { void (*save)(int64_t); };
static void record(struct S *s)
{
    time_t now = time(NULL);
    s->save((int64_t)now);
    ns::save((int64_t)now);
}
"""
    path = tmp_path / "m.c"
    path.write_text(source, encoding="utf-8")
    index, adjacency, sources = _index_and_sites(tmp_path, {"m.c": source})
    caller = [f for f in index.definitions if f.symbol == "record"][0]
    for site in find_call_sites_in_function(sources[caller.file_abs], caller):
        if site.simple_name == "save":
            r = resolve_call_site(site, index, adjacency, sources_by_abs=sources)
            assert r.state == CallResolutionState.UNRESOLVED
            assert "unsupported_call_form" in r.stop_reasons


def test_html_escapes_amp_quotes_and_angles() -> None:
    dumped = {
        "kind": "direct_callee_argument",
        "depth": 1,
        "origin_candidate_ids": [],
        "caller_function_id": "e.c@c:1-2",
        "call_site": {"file": "e.c", "line": 2},
        "resolution": {"state": "resolved", "basis": "same_file_static"},
        "argument": {"index": 0, "expression": 'a < b && c > "d" & e'},
        "callee_function_id": "e.c@s:3-4",
        "parameter": {"index": 0, "name": "x", "declared_type": "int"},
        "time_semantic": "unix_epoch_seconds",
        "propagation_depth": 1,
        "truncated": True,
        "stop_reasons": ["too_many_propagated_parameters"],
    }
    cand = {
        "candidate_id": "e.c:3:0:0:high:cast_from_time_var",
        "discovery_method": "direct_callee_time_propagation",
        "rule_id": None,
        "risk": "high",
        "symbol": "cast_from_time_var",
        "file": "e.c",
        "line": 3,
        "analysis_coverage": "grouped",
        "function_id": "e.c@s:3-4",
        "one_line_snippet": "x = (int)y;",
        "propagation_paths": [dumped],
    }
    counts = {
        "total": 1,
        "grouped": 1,
        "ungrouped": 0,
        "functions_with_candidates": 1,
    }
    html = render_html(
        [],
        title="t",
        group_by="none",
        candidates=[cand],
        candidate_counts=counts,
        has_candidate_section=True,
    )
    assert 'a < b && c > "d" & e' not in html
    assert "&lt;" in html
    assert "&amp;" in html
    assert "truncated" in html.lower() or "Too many" in html or "too_many" in html
    text = render_text(
        [],
        candidates=[cand],
        candidate_counts=counts,
        has_candidate_section=True,
    )
    assert "Time propagation:" in text


# ---------------------------------------------------------------------------
# Demand-driven performance fast paths (issue #57 optimization)
# ---------------------------------------------------------------------------

from tacs.core.callee_propagation import PropagationScanStats, propagate_direct_callee_time


def test_no_time_bearing_functions_skips_propagation(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
static void save_event(struct stored_event *dst, int64_t n)
{
    dst->unix_seconds = (int32_t)n;
}
static void record(struct stored_event *dst)
{
    save_event(dst, 42);
}
struct stored_event { int32_t unix_seconds; };
"""
    path = tmp_path / "none.c"
    path.write_text(source, encoding="utf-8")
    stats: list[PropagationScanStats] = []
    out = propagate_direct_callee_time(
        root_path=str(tmp_path),
        files=[path],
        existing_candidates=[],
        time_t_aliases={},
        time_functions=[],
        environment_config=LP64,
        _stats_out=stats,
    )
    assert out == []
    assert stats and stats[0].skipped_no_eligible_callers


def test_time_bearing_no_direct_calls_stops_before_seeds(tmp_path: Path) -> None:
    source = """\
#include <time.h>
static void record(void)
{
    time_t now = time(NULL);
    (void)now;
}
"""
    path = tmp_path / "nocall.c"
    path.write_text(source, encoding="utf-8")
    stats: list[PropagationScanStats] = []
    out = propagate_direct_callee_time(
        root_path=str(tmp_path),
        files=[path],
        existing_candidates=[],
        time_t_aliases={},
        time_functions=[],
        environment_config=LP64,
        _stats_out=stats,
    )
    assert out == []
    assert stats
    assert stats[0].eligible_callers >= 1
    assert stats[0].skipped_no_time_bearing_calls or stats[0].calls_with_time_args == 0


def test_direct_time_null_argument_propagates(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void record_current_event(struct stored_event *dst)
{
    save_event(dst, (int64_t)time(NULL));
}
"""
    cands = _discover(tmp_path, source, name="direct_time.c")
    prop = [c for c in cands if c.discovery_method == "direct_callee_time_propagation"]
    assert len(prop) == 1
    assert "time(NULL)" in prop[0].propagation_paths[0].argument.expression


def test_only_eligible_callers_are_call_parsed(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void unrelated(struct stored_event *dst)
{
    save_event(dst, 1);
}
static void record(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
"""
    path = tmp_path / "elig.c"
    path.write_text(source, encoding="utf-8")
    stats: list[PropagationScanStats] = []
    out = propagate_direct_callee_time(
        root_path=str(tmp_path),
        files=[path],
        existing_candidates=[],
        time_t_aliases={},
        time_functions=[],
        environment_config=LP64,
        _stats_out=stats,
    )
    assert len(out) == 1
    assert stats[0].eligible_callers == 1
    assert stats[0].callers_with_call_sites_parsed == 1
    assert stats[0].seeded_scans == 1


def test_shared_callee_seed_reuses_local_scan(tmp_path: Path) -> None:
    source = """\
#include <stdint.h>
#include <time.h>
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
static void record_a(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
static void record_b(struct stored_event *dst)
{
    time_t now = time(NULL);
    save_event(dst, (int64_t)now);
}
"""
    path = tmp_path / "share.c"
    path.write_text(source, encoding="utf-8")
    stats: list[PropagationScanStats] = []
    out = propagate_direct_callee_time(
        root_path=str(tmp_path),
        files=[path],
        existing_candidates=[],
        time_t_aliases={},
        time_functions=[],
        environment_config=LP64,
        _stats_out=stats,
    )
    assert len(out) == 1
    assert out[0].propagation_paths and len(out[0].propagation_paths) == 2
    assert stats[0].callees_seeded == 1
    assert stats[0].seeded_scans == 1


def test_fast_paths_preserve_motivating_case(tmp_path: Path) -> None:
    stats: list[PropagationScanStats] = []
    path = tmp_path / "mot.c"
    path.write_text(MOTIVATING, encoding="utf-8")
    out = propagate_direct_callee_time(
        root_path=str(tmp_path),
        files=[path],
        existing_candidates=[],
        time_t_aliases={},
        time_functions=[],
        environment_config=LP64,
        _stats_out=stats,
    )
    assert len(out) == 1
    assert not stats[0].skipped_no_eligible_callers
    assert stats[0].calls_resolved >= 1


# ---------------------------------------------------------------------------
# File-level lexical fast-path provenance coverage (issue #57 correctness)
# ---------------------------------------------------------------------------

_SINK_SAVE = """\
struct stored_event { int32_t unix_seconds; };
static void save_event(struct stored_event *dst, int64_t epoch_seconds)
{
    dst->unix_seconds = (int32_t)epoch_seconds;
}
"""


def _prop_out(tmp_path: Path, files: list[Path]) -> tuple[list, PropagationScanStats]:
    stats: list[PropagationScanStats] = []
    out = propagate_direct_callee_time(
        root_path=str(tmp_path),
        files=files,
        existing_candidates=[],
        time_t_aliases={},
        time_functions=[],
        environment_config=LP64,
        _stats_out=stats,
    )
    return out, stats[0]


def test_fast_path_admits_same_file_typedef_parameter(tmp_path: Path) -> None:
    src = tmp_path / "alias_param.c"
    src.write_text(
        '#include <stdint.h>\n'
        "typedef time_t epoch_t;\n"
        + _SINK_SAVE
        + """\
static void record_event(struct stored_event *dst, epoch_t now)
{
    save_event(dst, (int64_t)now);
}
""",
        encoding="utf-8",
    )
    out, stats = _prop_out(tmp_path, [src])
    assert stats.eligible_callers == 1
    assert len(out) == 1
    assert out[0].propagation_paths
    assert out[0].propagation_paths[0].argument.expression == "(int64_t)now"


def test_fast_path_admits_included_header_typedef_alias(tmp_path: Path) -> None:
    """Header-only ``time_t`` alias must keep the .c file eligible (no pipeline map)."""
    hdr = tmp_path / "time_types.h"
    hdr.write_text("typedef time_t epoch_t;\n", encoding="utf-8")
    src = tmp_path / "use_alias.c"
    src.write_text(
        '#include <stdint.h>\n#include "time_types.h"\n'
        + _SINK_SAVE
        + """\
static void record_event(struct stored_event *dst, epoch_t now)
{
    save_event(dst, (int64_t)now);
}
""",
        encoding="utf-8",
    )
    # Source spells only the alias; the literal token time_t lives in the header.
    import re as _re

    assert not _re.search(r"\btime_t\b", src.read_text(encoding="utf-8"))
    out, stats = _prop_out(tmp_path, [hdr, src])
    assert not stats.skipped_no_eligible_callers
    assert stats.eligible_callers == 1
    assert len(out) == 1
    assert out[0].propagation_paths[0].parameter.name == "epoch_seconds"


def test_fast_path_admits_chained_included_header_alias(tmp_path: Path) -> None:
    hdr = tmp_path / "chain.h"
    hdr.write_text(
        "typedef time_t epoch_t;\ntypedef epoch_t device_time_t;\n",
        encoding="utf-8",
    )
    src = tmp_path / "chain.c"
    src.write_text(
        '#include <stdint.h>\n#include "chain.h"\n'
        + _SINK_SAVE
        + """\
static void record_event(struct stored_event *dst, device_time_t now)
{
    save_event(dst, (int64_t)now);
}
""",
        encoding="utf-8",
    )
    out, stats = _prop_out(tmp_path, [hdr, src])
    assert stats.eligible_callers == 1
    assert len(out) == 1


def test_fast_path_admits_project_local_epoch_producers(tmp_path: Path) -> None:
    for producer_call in (
        "get_unix_seconds()",
        "uTimeMonthsToSecondsUtc(1)",
        "to_epoch_seconds(1)",
        "seconds_since_epoch()",
    ):
        src = tmp_path / f"prod_{producer_call.split('(')[0]}.c"
        src.write_text(
            "#include <stdint.h>\n"
            "static int64_t get_unix_seconds(void) { return 1; }\n"
            "static int64_t uTimeMonthsToSecondsUtc(int m) { return m; }\n"
            "static int64_t to_epoch_seconds(int x) { return x; }\n"
            "static int64_t seconds_since_epoch(void) { return 1; }\n"
            + _SINK_SAVE
            + f"""\
static void record_event(struct stored_event *dst)
{{
    save_event(dst, {producer_call});
}}
""",
            encoding="utf-8",
        )
        out, stats = _prop_out(tmp_path, [src])
        assert stats.eligible_callers == 1, producer_call
        assert len(out) == 1, producer_call


def test_fast_path_cast_chain_from_time_t_parameter(tmp_path: Path) -> None:
    src = tmp_path / "cast_chain.c"
    src.write_text(
        "#include <stdint.h>\n#include <time.h>\n"
        + _SINK_SAVE
        + """\
static void record_event(struct stored_event *dst, time_t now)
{
    int64_t expanded = (int64_t)now;
    save_event(dst, expanded);
}
""",
        encoding="utf-8",
    )
    out, stats = _prop_out(tmp_path, [src])
    assert stats.eligible_callers == 1
    assert len(out) == 1
    assert out[0].propagation_paths[0].argument.expression == "expanded"


def test_fast_path_skips_repo_without_lexical_hints(tmp_path: Path) -> None:
    src = tmp_path / "plain.c"
    src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    out, stats = _prop_out(tmp_path, [src])
    assert out == []
    assert stats.functions_scanned == 0
    assert stats.skipped_no_eligible_callers


def test_name_only_duration_timeout_counter_not_provenance(tmp_path: Path) -> None:
    src = tmp_path / "names_only.c"
    src.write_text(
        "#include <stdint.h>\n"
        + _SINK_SAVE
        + """\
static int64_t getCounter(void) { return 1; }
static int64_t getTimeoutSeconds(void) { return 2; }
static int64_t getSecondsSinceBoot(void) { return 3; }
static void record_event(struct stored_event *dst)
{
    int64_t timestamp = getCounter();
    save_event(dst, timestamp);
    save_event(dst, getTimeoutSeconds());
    save_event(dst, getSecondsSinceBoot());
}
""",
        encoding="utf-8",
    )
    out, stats = _prop_out(tmp_path, [src])
    assert out == []
    assert stats.eligible_callers == 0


def test_fast_path_propagation_ids_deterministic(tmp_path: Path) -> None:
    src = tmp_path / "det.c"
    src.write_text(MOTIVATING, encoding="utf-8")
    a, _ = _prop_out(tmp_path, [src])
    b, _ = _prop_out(tmp_path, [src])
    assert [(c.file, c.line, c.symbol, c.discovery_method) for c in a] == [
        (c.file, c.line, c.symbol, c.discovery_method) for c in b
    ]
    assert [p.model_dump() for p in a[0].propagation_paths] == [
        p.model_dump() for p in b[0].propagation_paths
    ]
