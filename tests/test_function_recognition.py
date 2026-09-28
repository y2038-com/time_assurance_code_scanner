# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for bounded lexical function recognition and association.

Functionization associates already-discovered candidates with enclosing
definitions. These tests prove recognition fixes without altering deterministic
candidate discovery identity fields.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

from tacs.core.candidate_evidence import (
    attach_candidate_ids_to_functions,
    build_candidate_evidence,
)
from tacs.core.candidate_utils import prepare_candidates
from tacs.core.function_analyzer import FunctionAnalyzer
from tacs.core.function_schemas import FunctionAnalysis, FunctionBody, Y2038Summary
from tacs.core.function_scanner import mask_non_code, scan_functions
from tacs.core.llm_prompt import LLMPromptParts
from tacs.core.schema import AnalysisCoverage, Candidate

FIXTURE = r"""
#include <stdint.h>
#include <time.h>

typedef unsigned my_stamp_t;

/* Prototype must not be a definition. */
time_t proto_now(void);

time_t now_s(void) {
    return time(NULL);
}

uint32_t stamp32(void) {
    return 0;
}

int32_t stamp32s(void) {
    return -1;
}

size_t count_bytes(void) {
    return sizeof(time_t);
}

my_stamp_t project_td(void) {
    return 0;
}

static inline const char *name_of(void) {
    return "not a brace } here";
}

int plain(void) {
    return 0;
}

int one_liner(void) { return (int)time(NULL); }

time_t
multiline_ret
(void)
{
    return 0;
}

struct Point { int x; int y; };
enum Color { RED, GREEN };

void call_site(void) {
    plain();
    now_s();
}

typedef void (*handler_t)(void);
int (*fp_var)(void);

#define LIKELY_MACRO(x) do { (void)(x); } while (0)

void braces_safe(void) {
    const char *closing = "}";
    const char *opening = "{";
    /* } */
    char brace = '}';
    if (1) {
        for (int i = 0; i < 1; i++) {
            while (0) { }
        }
    }
}

namespace demo {
int ns_fn(int x) { return x; }
}

int Widget::draw(int y) {
    return y;
}

Widget::Widget(int z) {
    (void)z;
}

Widget::~Widget() {
}

template<typename T>
void templated(T v) { (void)v; }

int values[] = {1, 2, 3};

time_t global_clock;
"""


def _cand(
    path: Path,
    line: int,
    symbol: str = "time_t",
    *,
    col_start: int = 0,
    col_end: int = 6,
) -> Candidate:
    return Candidate(
        file=str(path),
        line=line,
        symbol=symbol,
        one_line_snippet=f"{symbol} at {line}",
        risk="high",
        description="test",
        col_start=col_start,
        col_end=col_end,
        discovery_method="catalog_symbol_match",
        rule_id="TACS-RULE-0001",
    )


def _write_fixture(tmp_path: Path, text: str = FIXTURE) -> Path:
    path = tmp_path / "sample.c"
    path.write_text(text.lstrip("\n"), encoding="utf-8")
    return path


# --- scanner unit behavior -------------------------------------------------


def test_scanner_recognizes_typedef_and_fixed_width_returns():
    funcs = {f.symbol: f for f in scan_functions(FIXTURE)}
    for name in (
        "now_s",
        "stamp32",
        "stamp32s",
        "count_bytes",
        "project_td",
        "name_of",
        "plain",
        "one_liner",
        "multiline_ret",
        "call_site",
        "braces_safe",
        "ns_fn",
        "Widget::draw",
        "Widget::Widget",
        "Widget::~Widget",
    ):
        assert name in funcs, f"missing recognized function {name}"


def test_scanner_rejects_false_positives():
    symbols = {f.symbol for f in scan_functions(FIXTURE)}
    for bad in (
        "proto_now",
        "Point",
        "Color",
        "handler_t",
        "fp_var",
        "LIKELY_MACRO",
        "templated",
        "values",
        "global_clock",
        "if",
        "for",
        "while",
        "switch",
        "catch",
    ):
        assert bad not in symbols, f"false positive: {bad}"


def test_scanner_brace_literals_do_not_corrupt_ranges():
    src = """
void braces_safe(void) {
    const char *closing = "}";
    const char *opening = "{";
    /* } */
    char brace = '}';
    if (1) {
        (void)closing;
    }
}
int after(void) { return 1; }
"""
    funcs = scan_functions(src)
    by_name = {f.symbol: f for f in funcs}
    assert by_name["braces_safe"].start_line == 2
    assert by_name["braces_safe"].end_line == 10
    assert by_name["after"].start_line == 11
    masked = mask_non_code('const char *c = "}";\nchar b = \'}\';\n/* } */\n{ }')
    # Non-code braces become spaces; only the final structural pair remains.
    assert masked.count("{") == 1
    assert masked.count("}") == 1
    assert '"}"' not in masked


def test_multiline_signature_and_one_liner_ranges():
    src = """
time_t
multiline_ret
(void)
{
    return 0;
}

int one_liner(void) { return 0; }
"""
    funcs = {f.symbol: f for f in scan_functions(src)}
    assert funcs["multiline_ret"].start_line == 2
    assert funcs["multiline_ret"].end_line == 7
    assert funcs["one_liner"].start_line == 9
    assert funcs["one_liner"].end_line == 9


# --- association through FunctionAnalyzer ----------------------------------


def test_typedef_return_candidates_are_grouped(tmp_path: Path):
    path = _write_fixture(tmp_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    line_of: dict[str, int] = {}
    for i, line in enumerate(lines, start=1):
        if "time_t now_s" in line:
            line_of["now_s_sig"] = i
        if "uint32_t stamp32" in line:
            line_of["stamp32_sig"] = i
        if "int32_t stamp32s" in line:
            line_of["stamp32s_sig"] = i
        if "size_t count_bytes" in line:
            line_of["count_bytes_sig"] = i
        if "my_stamp_t project_td" in line:
            line_of["project_td_sig"] = i
        if "int one_liner" in line:
            line_of["one_liner"] = i
        if line.strip() == "return time(NULL);":
            # First body hit belongs to now_s in this fixture.
            line_of.setdefault("now_s_body", i)
        if line.strip() == "time_t global_clock;":
            line_of["global"] = i

    assert "now_s_sig" in line_of and "now_s_body" in line_of and "global" in line_of

    candidates = [
        _cand(path, line_of["now_s_sig"], "time_t"),
        _cand(path, line_of["now_s_body"], "time"),
        _cand(path, line_of["stamp32_sig"], "uint32_t"),
        _cand(path, line_of["stamp32s_sig"], "int32_t"),
        _cand(path, line_of["count_bytes_sig"], "size_t"),
        _cand(path, line_of["project_td_sig"], "my_stamp_t"),
        _cand(path, line_of["one_liner"], "time"),
        _cand(path, line_of["global"], "time_t"),
    ]

    analyzer = FunctionAnalyzer(root_path=str(tmp_path))
    functions = analyzer.extract_functions_with_candidates(candidates)
    functions = attach_candidate_ids_to_functions(functions, candidates, str(tmp_path))
    evidence = build_candidate_evidence(candidates, root_path=str(tmp_path), functions=functions)
    by_line = {e.line: e for e in evidence}

    assert by_line[line_of["now_s_sig"]].analysis_coverage == AnalysisCoverage.GROUPED
    assert by_line[line_of["now_s_sig"]].function_id and "now_s" in by_line[line_of["now_s_sig"]].function_id
    assert by_line[line_of["now_s_body"]].function_id == by_line[line_of["now_s_sig"]].function_id
    assert by_line[line_of["stamp32_sig"]].analysis_coverage == AnalysisCoverage.GROUPED
    assert by_line[line_of["stamp32s_sig"]].analysis_coverage == AnalysisCoverage.GROUPED
    assert by_line[line_of["count_bytes_sig"]].analysis_coverage == AnalysisCoverage.GROUPED
    assert by_line[line_of["project_td_sig"]].analysis_coverage == AnalysisCoverage.GROUPED
    assert by_line[line_of["one_liner"]].analysis_coverage == AnalysisCoverage.GROUPED
    assert by_line[line_of["global"]].analysis_coverage == AnalysisCoverage.UNGROUPED
    assert by_line[line_of["global"]].function_id is None


def test_signature_line_candidate_association_regression(tmp_path: Path):
    """Candidate on the signature line must group; old start+1 body-only logic fails this."""
    src = tmp_path / "sig.c"
    src.write_text(
        "time_t now_s(void) {\n    return time(NULL);\n}\n",
        encoding="utf-8",
    )
    candidates = [_cand(src, 1, "time_t"), _cand(src, 2, "time")]
    analyzer = FunctionAnalyzer(root_path=str(tmp_path))
    functions = analyzer.extract_functions_with_candidates(candidates)
    assert len(functions) == 1
    assert functions[0].symbol == "now_s"
    assert functions[0].start_line == 1
    assert functions[0].end_line == 3
    assert functions[0].candidate_lines == [1, 2]
    functions = attach_candidate_ids_to_functions(functions, candidates, str(tmp_path))
    assert len(functions[0].candidate_ids) == 2
    evidence = build_candidate_evidence(candidates, root_path=str(tmp_path), functions=functions)
    assert all(e.analysis_coverage == AnalysisCoverage.GROUPED for e in evidence)
    assert evidence[0].function_id == evidence[1].function_id


def test_multiple_candidates_same_function_no_loss_or_dup(tmp_path: Path):
    src = tmp_path / "multi.c"
    src.write_text(
        "int check(void) {\n"
        "  time_t a;\n"
        "  time_t b;\n"
        "  return (int)time(NULL);\n"
        "}\n",
        encoding="utf-8",
    )
    candidates = [
        _cand(src, 2, "time_t", col_start=2, col_end=8),
        _cand(src, 3, "time_t", col_start=2, col_end=8),
        _cand(src, 4, "time", col_start=14, col_end=18),
    ]
    analyzer = FunctionAnalyzer(root_path=str(tmp_path))
    functions = analyzer.extract_functions_with_candidates(candidates)
    functions = attach_candidate_ids_to_functions(functions, candidates, str(tmp_path))
    assert len(functions) == 1
    assert functions[0].candidate_lines == [2, 3, 4]
    assert len(functions[0].candidate_ids) == 3
    assert len(set(functions[0].candidate_ids)) == 3


def test_split_large_function_preserves_candidate_ids(tmp_path: Path):
    body_lines = ["  time_t t;\n"] * 6
    src = tmp_path / "big.c"
    src.write_text("int big(void) {\n" + "".join(body_lines) + "}\n", encoding="utf-8")
    # Candidates on lines 2 and 7 (inside body)
    candidates = [_cand(src, 2, "time_t"), _cand(src, 7, "time_t")]
    analyzer = FunctionAnalyzer(max_function_lines=3, root_path=str(tmp_path))
    parts = analyzer.extract_functions_with_candidates(candidates)
    assert len(parts) > 1
    parts = attach_candidate_ids_to_functions(parts, candidates, str(tmp_path))
    all_ids = [cid for p in parts for cid in (p.candidate_ids or [])]
    assert len(all_ids) == len(set(all_ids)) == 2


def test_ordinary_int_void_still_recognized(tmp_path: Path):
    src = tmp_path / "plain.c"
    src.write_text("void foo(void) {\n  int x = 0;\n}\n", encoding="utf-8")
    candidates = [_cand(src, 2, "int")]
    functions = FunctionAnalyzer(root_path=str(tmp_path)).extract_functions_with_candidates(
        candidates
    )
    assert len(functions) == 1
    assert functions[0].symbol == "foo"


def test_cpp_namespace_and_method(tmp_path: Path):
    src = tmp_path / "demo.cpp"
    src.write_text(
        "namespace demo {\n"
        "int ns_fn(int x) { return x; }\n"
        "}\n"
        "int Widget::draw(int y) { return y; }\n",
        encoding="utf-8",
    )
    candidates = [_cand(src, 2, "int"), _cand(src, 4, "int")]
    functions = FunctionAnalyzer(root_path=str(tmp_path)).extract_functions_with_candidates(
        candidates
    )
    symbols = {f.symbol for f in functions}
    assert "ns_fn" in symbols
    assert "Widget::draw" in symbols


# --- discovery invariance + mocked LLM path --------------------------------


def test_functionization_does_not_alter_deterministic_candidate_identity(tmp_path: Path):
    path = _write_fixture(
        tmp_path,
        "time_t now_s(void) {\n  return time(NULL);\n}\ntime_t global_clock;\n",
    )
    prepared = prepare_candidates(
        [
            _cand(path, 1, "time_t"),
            _cand(path, 2, "time"),
            _cand(path, 4, "time_t"),
        ]
    )
    before = [
        (
            c.file,
            c.line,
            c.symbol,
            c.discovery_method,
            c.rule_id,
            c.risk,
            c.description,
            c.col_start,
            c.col_end,
        )
        for c in prepared
    ]
    analyzer = FunctionAnalyzer(root_path=str(tmp_path))
    functions = analyzer.extract_functions_with_candidates(list(prepared))
    evidence = build_candidate_evidence(prepared, root_path=str(tmp_path), functions=functions)
    after = [
        (
            c.file,
            c.line,
            c.symbol,
            c.discovery_method,
            c.rule_id,
            c.risk,
            c.description,
            c.col_start,
            c.col_end,
        )
        for c in prepared
    ]
    assert before == after
    assert len(evidence) == 3
    assert evidence[0].analysis_coverage == AnalysisCoverage.GROUPED
    assert evidence[1].analysis_coverage == AnalysisCoverage.GROUPED
    assert evidence[2].analysis_coverage == AnalysisCoverage.UNGROUPED


class _RecordingLLMClient:
    """Records function batches presented to Pass F1; no network."""

    def __init__(self) -> None:
        self.f1_batches: List[FunctionBody] = []
        self.llm_type = "stub"
        self.model = "stub"
        self.migration_mode = False
        self.calls = 0

    def _analyses(self, function_batch):  # noqa: ANN001
        return [
            FunctionAnalysis(
                function_id=func.function_id,
                y2038_summary=Y2038Summary.YES,
                confidence=0.9,
                issues=[{"type": "y2038", "line": (func.candidate_lines or [func.start_line])[0], "description": "stub"}],
                needs_more_context=False,
            )
            for func in function_batch.functions
        ]

    def _build_pass_f1_prompt(self, function_batch):  # noqa: ANN001
        return LLMPromptParts(system="s", user="u")

    def _build_pass_f2_prompt(self, function_batch, iteration):  # noqa: ANN001
        return LLMPromptParts(system="s", user="u")

    def _build_pass_f3_prompt(self, function_batch):  # noqa: ANN001
        return LLMPromptParts(system="s", user="u")

    def analyze_functions_pass_f1(self, function_batch):  # noqa: ANN001
        self.calls += 1
        self.f1_batches.extend(function_batch.functions)
        return self._analyses(function_batch)

    def analyze_functions_pass_f2(self, function_batch, iteration):  # noqa: ANN001
        return self._analyses(function_batch)

    def analyze_functions_pass_f3(self, function_batch):  # noqa: ANN001
        return self._analyses(function_batch)


def test_newly_recognized_functions_reach_mocked_f1(tmp_path: Path):
    from tacs.core.pipeline import ScanningPipeline

    src = tmp_path / "typed.c"
    src.write_text(
        "#include <time.h>\n"
        "time_t now_s(void) {\n"
        "  return time(NULL);\n"
        "}\n"
        "uint32_t stamp32(void) {\n"
        "  return (uint32_t)time(NULL);\n"
        "}\n",
        encoding="utf-8",
    )
    repo = Path(__file__).resolve().parents[1]
    rules = repo / "src" / "tacs" / "rules" / "y2038_sample_rules.json"
    scanner = repo / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"
    if not rules.is_file() or not scanner.is_file():
        pytest.skip("sample rules or scanner missing")

    stub = _RecordingLLMClient()
    pipeline = ScanningPipeline(
        scanner_path=str(scanner),
        llm_type="openai",
        model="stub",
        function_first=True,
        confidence_floor=0.0,
        enable_pass1=False,
        enable_io_analysis=False,
    )
    pipeline.function_llm_client = stub
    results = pipeline.scan(
        root_path=str(tmp_path),
        rules_path=str(rules),
        min_risk="low",
        include_patterns=["*.c"],
        exclude_patterns=[],
        session_dir=str(tmp_path / "session"),
    )
    assert stub.calls >= 1
    symbols = {f.symbol for f in stub.f1_batches}
    assert "now_s" in symbols
    assert "stamp32" in symbols
    # Public candidates still present from deterministic discovery.
    out = tmp_path / "out.json"
    pipeline.save_results(results, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data["candidates"]) >= 1
    grouped = [c for c in data["candidates"] if c.get("analysis_coverage") == "grouped"]
    assert grouped, "expected newly recognized functions to group candidates"


def test_llm_none_makes_no_provider_call(tmp_path: Path):
    from tacs.core.pipeline import ScanningPipeline

    src = tmp_path / "typed.c"
    src.write_text(
        "time_t now_s(void) {\n  return time(NULL);\n}\n",
        encoding="utf-8",
    )
    repo = Path(__file__).resolve().parents[1]
    rules = repo / "src" / "tacs" / "rules" / "y2038_sample_rules.json"
    scanner = repo / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"
    if not rules.is_file() or not scanner.is_file():
        pytest.skip("sample rules or scanner missing")

    pipeline = ScanningPipeline(
        scanner_path=str(scanner),
        llm_type="none",
        model="none",
        function_first=True,
        confidence_floor=0.0,
        enable_pass1=False,
        enable_io_analysis=False,
    )
    assert pipeline.function_llm_client.llm_type == "none"
    calls = {"f1": 0, "f2": 0, "f3": 0}
    client = pipeline.function_llm_client
    orig_f1 = client.analyze_functions_pass_f1
    orig_f2 = client.analyze_functions_pass_f2
    orig_f3 = client.analyze_functions_pass_f3

    def wrap_f1(batch):  # noqa: ANN001
        calls["f1"] += 1
        return orig_f1(batch)

    def wrap_f2(batch, iteration):  # noqa: ANN001
        calls["f2"] += 1
        return orig_f2(batch, iteration)

    def wrap_f3(batch):  # noqa: ANN001
        calls["f3"] += 1
        return orig_f3(batch)

    client.analyze_functions_pass_f1 = wrap_f1  # type: ignore[method-assign]
    client.analyze_functions_pass_f2 = wrap_f2  # type: ignore[method-assign]
    client.analyze_functions_pass_f3 = wrap_f3  # type: ignore[method-assign]

    pipeline.scan(
        root_path=str(tmp_path),
        rules_path=str(rules),
        min_risk="low",
        include_patterns=["*.c"],
        exclude_patterns=[],
        session_dir=str(tmp_path / "session"),
    )
    assert calls == {"f1": 0, "f2": 0, "f3": 0}


def test_end_to_end_discovery_invariant_through_scan(tmp_path: Path):
    """Same fixture: discovery identity fields unchanged; only linkage may differ."""
    from tacs.core.pipeline import ScanningPipeline

    src = tmp_path / "main.c"
    src.write_text(
        "#include <time.h>\n"
        "time_t now_s(void) {\n"
        "  time_t now = time(NULL);\n"
        "  return now;\n"
        "}\n"
        "time_t orphan;\n",
        encoding="utf-8",
    )
    repo = Path(__file__).resolve().parents[1]
    rules = repo / "src" / "tacs" / "rules" / "y2038_sample_rules.json"
    scanner = repo / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"
    if not rules.is_file() or not scanner.is_file():
        pytest.skip("sample rules or scanner missing")

    pipeline = ScanningPipeline(
        scanner_path=str(scanner),
        llm_type="none",
        model="none",
        function_first=True,
        confidence_floor=0.0,
        enable_pass1=False,
        enable_io_analysis=False,
    )
    results = pipeline.scan(
        root_path=str(tmp_path),
        rules_path=str(rules),
        min_risk="low",
        include_patterns=["*.c"],
        exclude_patterns=[],
        session_dir=str(tmp_path / "session"),
    )
    out = tmp_path / "findings.json"
    pipeline.save_results(results, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.1"
    assert data["meta"]["candidate_summary"]["total"] == len(data["candidates"])
    assert any(c.get("analysis_coverage") == "grouped" for c in data["candidates"])
    assert any(c.get("analysis_coverage") == "ungrouped" for c in data["candidates"])
    # Identity fields present and stable shape
    for c in data["candidates"]:
        assert c.get("candidate_id")
        assert c.get("discovery_method")
        assert "line" in c and "symbol" in c


# --- in-class methods, extern "C", ranges, preprocessor --------------------


_INLINE_CLASS = """\
class Clock {
public:
    time_t now() {
        return time(nullptr);
    }
};
"""


def test_inline_class_method_is_grouped_and_reaches_mocked_f1(tmp_path: Path):
    """Straightforward in-class methods are functionized and enter Pass F1."""
    from tacs.core.pipeline import ScanningPipeline

    src = tmp_path / "clock.cpp"
    src.write_text(_INLINE_CLASS + "\ntime_t orphan;\n", encoding="utf-8")

    # Helper-level association
    lines = src.read_text(encoding="utf-8").splitlines()
    sig_line = next(i for i, ln in enumerate(lines, 1) if "time_t now()" in ln)
    body_line = next(i for i, ln in enumerate(lines, 1) if "time(nullptr)" in ln)
    orphan_line = next(i for i, ln in enumerate(lines, 1) if "orphan" in ln)
    candidates = [
        _cand(src, sig_line, "time_t"),
        _cand(src, body_line, "time"),
        _cand(src, orphan_line, "time_t"),
    ]
    analyzer = FunctionAnalyzer(root_path=str(tmp_path))
    functions = analyzer.extract_functions_with_candidates(candidates)
    assert len(functions) == 1
    assert functions[0].symbol == "now"
    assert sig_line in functions[0].candidate_lines
    assert body_line in functions[0].candidate_lines
    functions = attach_candidate_ids_to_functions(functions, candidates, str(tmp_path))
    evidence = build_candidate_evidence(
        candidates, root_path=str(tmp_path), functions=functions
    )
    by_line = {e.line: e for e in evidence}
    assert by_line[sig_line].analysis_coverage == AnalysisCoverage.GROUPED
    assert by_line[body_line].analysis_coverage == AnalysisCoverage.GROUPED
    assert by_line[orphan_line].analysis_coverage == AnalysisCoverage.UNGROUPED

    # Pipeline: newly recognized method reaches mocked F1
    repo = Path(__file__).resolve().parents[1]
    rules = repo / "src" / "tacs" / "rules" / "y2038_sample_rules.json"
    scanner = repo / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"
    if not rules.is_file() or not scanner.is_file():
        pytest.skip("sample rules or scanner missing")

    stub = _RecordingLLMClient()
    pipeline = ScanningPipeline(
        scanner_path=str(scanner),
        llm_type="openai",
        model="stub",
        function_first=True,
        confidence_floor=0.0,
        enable_pass1=False,
        enable_io_analysis=False,
    )
    pipeline.function_llm_client = stub
    pipeline.scan(
        root_path=str(tmp_path),
        rules_path=str(rules),
        min_risk="low",
        include_patterns=["*.cpp"],
        exclude_patterns=[],
        session_dir=str(tmp_path / "session"),
    )
    assert stub.calls >= 1
    assert any(f.symbol == "now" for f in stub.f1_batches)


def test_in_class_adversarial_rejects_fields_prototypes_ctors_initializers():
    """Fields, prototypes, access labels, brace inits, and ctor-init are not methods."""
    src = """
class Clock {
public:
    time_t epoch;
    time_t later();
    int flags{0};
    Clock() : cache_(0) {
        (void)cache_;
    }
    Clock(int x) {
        (void)x;
    }
    time_t now() {
        return time(nullptr);
    }
private:
    time_t cache_;
    struct Nested {
        int field;
        time_t nested_now() { return 0; }
    };
};
"""
    funcs = scan_functions(src)
    symbols = {f.symbol for f in funcs}
    assert symbols == {"now", "nested_now"}
    assert "epoch" not in symbols
    assert "later" not in symbols
    assert "flags" not in symbols
    assert "cache_" not in symbols
    assert "Clock" not in symbols
    assert "field" not in symbols


def test_in_class_constructor_without_return_type_remains_ungrouped(tmp_path: Path):
    """In-class constructors need a real C++ parser; keep them honestly ungrouped."""
    src = tmp_path / "ctor.cpp"
    src.write_text(
        "class Clock {\n"
        "public:\n"
        "    Clock() {\n"
        "        time_t t = time(nullptr);\n"
        "        (void)t;\n"
        "    }\n"
        "};\n",
        encoding="utf-8",
    )
    assert scan_functions(src.read_text(encoding="utf-8")) == []
    candidates = [_cand(src, 4, "time_t"), _cand(src, 4, "time", col_start=18, col_end=22)]
    # Same line two symbols — use distinct cols via second cand already
    candidates[1] = _cand(src, 4, "time", col_start=18, col_end=22)
    functions = FunctionAnalyzer(root_path=str(tmp_path)).extract_functions_with_candidates(
        candidates
    )
    assert functions == []
    evidence = build_candidate_evidence(
        candidates, root_path=str(tmp_path), functions=functions
    )
    assert all(e.analysis_coverage == AnalysisCoverage.UNGROUPED for e in evidence)


def test_extern_c_block_recognizes_nested_function(tmp_path: Path):
    src = tmp_path / "linkage.c"
    src.write_text(
        'extern "C" {\n'
        "time_t now_s(void) {\n"
        "    return time(NULL);\n"
        "}\n"
        "}\n"
        "int after(void) { return 1; }\n",
        encoding="utf-8",
    )
    text = src.read_text(encoding="utf-8")
    funcs = {f.symbol: f for f in scan_functions(text)}
    assert "now_s" in funcs
    assert funcs["now_s"].start_line == 2
    assert funcs["now_s"].end_line == 4
    assert "after" in funcs

    candidates = [_cand(src, 2, "time_t"), _cand(src, 3, "time")]
    functions = FunctionAnalyzer(root_path=str(tmp_path)).extract_functions_with_candidates(
        candidates
    )
    assert len(functions) == 1
    assert functions[0].symbol == "now_s"
    assert functions[0].candidate_lines == [2, 3]


def test_ordinary_function_ranges_match_corrected_parsing():
    """Ordinary free-function spans stay on the definition lines (not incidental drift)."""
    src = """#include <time.h>

int measure_window(void) {
    time_t now = time(NULL);
    long later = now + 86400;
    return (int)later;
}

static void helper(void) {
    (void)0;
}

int one_liner(void) { return 0; }
"""
    funcs = {f.symbol: f for f in scan_functions(src)}
    assert funcs["measure_window"].start_line == 3
    assert funcs["measure_window"].end_line == 7
    assert funcs["helper"].start_line == 9
    assert funcs["helper"].end_line == 11
    assert funcs["one_liner"].start_line == 13
    assert funcs["one_liner"].end_line == 13
    # Inclusive 1-based bounds are the ones embedded in function_id by FunctionAnalyzer.
    fid_span = f"{funcs['measure_window'].start_line}-{funcs['measure_window'].end_line}"
    assert fid_span == "3-7"


def test_preprocessor_directive_braces_do_not_corrupt_grouping(tmp_path: Path):
    """Braces / function-like text on # lines must not regroup unrelated candidates."""
    src = tmp_path / "pp.c"
    src.write_text(
        "time_t before(void) {\n"
        "    return 0;\n"
        "}\n"
        "#define WEIRD {\n"
        "#define WEIRD_END }\n"
        "#define MACRO_FN(x) do { (void)(x); } while (0)\n"
        "time_t after(void) {\n"
        "    MACRO_FN(1);\n"
        "    time_t t = 0;\n"
        "    return t;\n"
        "}\n"
        "time_t orphan;\n",
        encoding="utf-8",
    )
    text = src.read_text(encoding="utf-8")
    funcs = {f.symbol: f for f in scan_functions(text)}
    assert set(funcs) == {"before", "after"}
    assert funcs["before"].start_line == 1
    assert funcs["before"].end_line == 3
    assert funcs["after"].start_line == 7
    assert funcs["after"].end_line == 11
    assert "MACRO_FN" not in funcs
    assert "WEIRD" not in funcs

    candidates = [
        _cand(src, 1, "time_t"),
        _cand(src, 9, "time_t"),
        _cand(src, 12, "time_t"),
    ]
    functions = FunctionAnalyzer(root_path=str(tmp_path)).extract_functions_with_candidates(
        candidates
    )
    functions = attach_candidate_ids_to_functions(functions, candidates, str(tmp_path))
    evidence = build_candidate_evidence(
        candidates, root_path=str(tmp_path), functions=functions
    )
    by_line = {e.line: e for e in evidence}
    assert by_line[1].function_id and "before" in by_line[1].function_id
    assert by_line[9].function_id and "after" in by_line[9].function_id
    assert by_line[1].function_id != by_line[9].function_id
    assert by_line[12].analysis_coverage == AnalysisCoverage.UNGROUPED
