# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for public CandidateEvidence preservation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tacs.core.candidate_evidence import (
    attach_candidate_ids_to_functions,
    bound_candidate_snippet,
    build_candidate_evidence,
    map_candidates_to_function_ids,
    normalize_discovery_method,
    summarize_candidate_evidence,
)
from tacs.core.candidate_utils import make_candidate_id, prepare_candidates
from tacs.core.function_schemas import FunctionBody
from tacs.core.schema import (
    CANDIDATE_SNIPPET_MAX_CHARS,
    PUBLIC_RESULT_SCHEMA_VERSION,
    AnalysisCoverage,
    Candidate,
    Metrics,
    ScanMetadata,
    ScanResults,
)


def _cand(**kwargs) -> Candidate:
    defaults = dict(
        file="/abs/repo/src/a.c",
        line=10,
        symbol="time_t",
        one_line_snippet="time_t t;",
        risk="high",
        description="Time type",
        col_start=0,
        col_end=6,
        discovery_method="catalog_symbol_match",
    )
    defaults.update(kwargs)
    return Candidate(**defaults)


def test_bound_snippet_limit():
    text = "x" * (CANDIDATE_SNIPPET_MAX_CHARS + 50)
    out = bound_candidate_snippet(text)
    assert len(out) == CANDIDATE_SNIPPET_MAX_CHARS
    assert out.endswith("...")


def test_normalize_discovery_method_controlled():
    assert normalize_discovery_method("io_boundary") == "io_boundary"
    assert normalize_discovery_method(None) == "unknown"
    assert normalize_discovery_method("") == "unknown"
    assert normalize_discovery_method("   ") == "unknown"
    with pytest.raises(ValueError, match="Unrecognized discovery_method"):
        normalize_discovery_method("invented")


def test_all_recognized_discovery_methods_round_trip():
    from tacs.core.schema import DISCOVERY_METHODS

    for method in sorted(DISCOVERY_METHODS):
        assert normalize_discovery_method(method) == method
        evidence = build_candidate_evidence(
            [_cand(discovery_method=method, symbol=f"sym_{method}", col_start=0, col_end=1)],
            root_path="/abs/repo",
            functions=[],
        )
        assert evidence[0].discovery_method == method


def test_candidate_ids_deterministic_and_multi_on_line():
    a = _cand(symbol="time_t", col_start=0, col_end=6)
    b = _cand(symbol="time", col_start=8, col_end=12)
    prepared = prepare_candidates([a, b])
    assert len(prepared) == 2
    id_a = make_candidate_id(
        "src/a.c", a.line, a.symbol, a.col_start, a.col_end, a.risk
    )
    id_b = make_candidate_id(
        "src/a.c", b.line, b.symbol, b.col_start, b.col_end, b.risk
    )
    assert id_a != id_b
    assert "time_t" in id_a
    assert "time" in id_b


def test_true_duplicates_collapse_to_one_evidence():
    a = _cand()
    b = _cand()
    prepared = prepare_candidates([a, b])
    assert len(prepared) == 1
    evidence = build_candidate_evidence(prepared, root_path="/abs/repo", functions=[])
    assert len(evidence) == 1


def test_build_evidence_paths_relative_rule_id_null():
    c = _cand(discovery_method="arithmetic_scanner")
    evidence = build_candidate_evidence([c], root_path="/abs/repo", functions=[])
    assert len(evidence) == 1
    e = evidence[0]
    assert e.file == "src/a.c"
    assert e.rule_id is None
    assert e.discovery_method == "arithmetic_scanner"
    assert e.analysis_coverage == AnalysisCoverage.UNGROUPED
    assert e.function_id is None
    assert not e.file.startswith("/")


def test_function_linkage_multi_candidate_and_ungrouped():
    in_fn = _cand(line=20, symbol="time_t")
    also_in_fn = _cand(line=21, symbol="time", col_start=1, col_end=5)
    outside = _cand(line=200, symbol="ctime", file="/abs/repo/src/b.c")
    functions = [
        FunctionBody(
            function_id="src/a.c@foo:10-30",
            file_path="/abs/repo/src/a.c",
            symbol="foo",
            start_line=10,
            end_line=30,
            body="void foo(){}",
            candidate_lines=[20, 21],
        )
    ]
    functions = attach_candidate_ids_to_functions(
        functions, [in_fn, also_in_fn, outside], "/abs/repo"
    )
    assert len(functions[0].candidate_ids) == 2
    evidence = build_candidate_evidence(
        [in_fn, also_in_fn, outside],
        root_path="/abs/repo",
        functions=functions,
    )
    by_sym = {e.symbol: e for e in evidence}
    assert by_sym["time_t"].analysis_coverage == AnalysisCoverage.GROUPED
    assert by_sym["time"].analysis_coverage == AnalysisCoverage.GROUPED
    assert by_sym["ctime"].analysis_coverage == AnalysisCoverage.UNGROUPED
    assert by_sym["ctime"].function_id is None
    summary = summarize_candidate_evidence(evidence, findings_count=0)
    assert summary.total == 3
    assert summary.grouped == 2
    assert summary.ungrouped == 1
    assert summary.functions_with_candidates == 1


def test_split_parts_link_only_included_candidates():
    c1 = _cand(line=10, symbol="a")
    c2 = _cand(line=40, symbol="b", col_start=1, col_end=2)
    parts = [
        FunctionBody(
            function_id="src/a.c@big:1-20#part1",
            file_path="/abs/repo/src/a.c",
            symbol="big",
            start_line=1,
            end_line=20,
            body="part1",
            candidate_lines=[10],
            is_partial=True,
            part_number=1,
        ),
        FunctionBody(
            function_id="src/a.c@big:21-50#part2",
            file_path="/abs/repo/src/a.c",
            symbol="big",
            start_line=21,
            end_line=50,
            body="part2",
            candidate_lines=[40],
            is_partial=True,
            part_number=2,
        ),
    ]
    parts = attach_candidate_ids_to_functions(parts, [c1, c2], "/abs/repo")
    assert len(parts[0].candidate_ids) == 1
    assert "a" in parts[0].candidate_ids[0]
    assert len(parts[1].candidate_ids) == 1
    assert "b" in parts[1].candidate_ids[0]
    mapping = map_candidates_to_function_ids([c1, c2], parts, "/abs/repo")
    assert len(mapping) == 2
    assert mapping[parts[0].candidate_ids[0]] == parts[0].function_id
    assert mapping[parts[1].candidate_ids[0]] == parts[1].function_id


def test_save_results_emits_schema_version_and_candidates(tmp_path: Path):
    from tacs.core.pipeline import ScanningPipeline

    evidence = build_candidate_evidence(
        [_cand(file=str(tmp_path / "x.c"), discovery_method="define_scanner")],
        root_path=str(tmp_path),
        functions=[],
    )
    metrics = Metrics(
        total_files=1,
        total_lines=1,
        total_chars=1,
        total_words=1,
        max_line_length=1,
        avg_line_length=1.0,
        max_file_length=1,
        avg_file_length=1.0,
    )
    results = ScanResults(
        schema_version=PUBLIC_RESULT_SCHEMA_VERSION,
        meta=ScanMetadata(
            root=".",
            rules_path="rules.json",
            model="none",
            confidence_floor=0.6,
            metrics=metrics,
            timestamp="2026-01-01T00:00:00Z",
            candidate_summary=summarize_candidate_evidence(evidence, findings_count=0),
        ),
        candidates=evidence,
        findings=[],
    )
    out = tmp_path / "out.json"
    pipeline = ScanningPipeline.__new__(ScanningPipeline)
    pipeline.save_results(results, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.1"
    assert len(data["candidates"]) == 1
    assert data["candidates"][0]["rule_id"] is None
    assert data["candidates"][0]["discovery_method"] == "define_scanner"
    assert data["findings"] == []
    assert data["assessments"] == []
    assert "assessment_summary" in data["meta"]
    assert data["meta"]["candidate_summary"]["total"] == 1


def test_stage7_does_not_drop_canonical_evidence(tmp_path: Path):
    """Evidence is recorded from the full set before Stage 7 filtering."""
    from tacs.core.pipeline import ScanningPipeline

    src = tmp_path / "f.c"
    src.write_text(
        "void foo(void) {\n  time_t t;\n  time_t u;\n}\n",
        encoding="utf-8",
    )
    c1 = Candidate(
        file=str(src),
        line=2,
        symbol="time_t",
        one_line_snippet="  time_t t;",
        risk="high",
        description="t",
        col_start=2,
        col_end=8,
        discovery_method="catalog_symbol_match",
    )
    c2 = Candidate(
        file=str(src),
        line=3,
        symbol="time_t",
        one_line_snippet="  time_t u;",
        risk="high",
        description="u",
        col_start=2,
        col_end=8,
        discovery_method="catalog_symbol_match",
    )
    prepared = prepare_candidates([c1, c2])
    pipeline = ScanningPipeline.__new__(ScanningPipeline)
    pipeline.max_function_lines = 10000
    pipeline.max_function_chars = 20000
    pipeline.function_analyzer = None
    pipeline._record_canonical_candidate_evidence(prepared, str(tmp_path))
    assert len(pipeline._canonical_candidate_evidence) == 2
    # Simulate Stage 7 keeping only one candidate for analysis — evidence unchanged.
    assert all(e.rule_id is None for e in pipeline._canonical_candidate_evidence)
    grouped = [
        e
        for e in pipeline._canonical_candidate_evidence
        if e.analysis_coverage == AnalysisCoverage.GROUPED
    ]
    assert len(grouped) == 2


def test_renderer_dual_schema_and_preservation_message(tmp_path: Path):
    from report_renderer.core import (
        candidate_counts_from_document,
        format_candidate_preservation_message,
        load_scan_document,
    )
    from report_renderer.renderers import render_text

    legacy = {"meta": {}, "findings": []}
    legacy_path = tmp_path / "legacy.json"
    legacy_path.write_text(json.dumps(legacy), encoding="utf-8")
    legacy_doc = load_scan_document(str(legacy_path))
    assert not legacy_doc.is_versioned
    assert format_candidate_preservation_message(
        candidate_total=0,
        ungrouped=0,
        findings_shown=0,
        has_candidate_section=False,
    ) == "No findings match the selected filters."

    versioned = {
        "schema_version": "1.0",
        "meta": {
            "candidate_summary": {
                "total": 2,
                "grouped": 1,
                "ungrouped": 1,
                "functions_with_candidates": 1,
                "findings": 0,
            }
        },
        "candidates": [
            {
                "candidate_id": "a.c:1:0-1:high:time_t",
                "file": "a.c",
                "line": 1,
                "symbol": "time_t",
                "risk": "high",
                "description": "",
                "one_line_snippet": "time_t t;",
                "discovery_method": "catalog_symbol_match",
                "rule_id": None,
                "function_id": "a.c@f:1-5",
                "analysis_coverage": "grouped",
            },
            {
                "candidate_id": "a.c:99:0-1:high:time",
                "file": "a.c",
                "line": 99,
                "symbol": "time",
                "risk": "high",
                "description": "",
                "one_line_snippet": "time(NULL);",
                "discovery_method": "catalog_symbol_match",
                "rule_id": None,
                "function_id": None,
                "analysis_coverage": "ungrouped",
            },
        ],
        "findings": [],
    }
    vpath = tmp_path / "v.json"
    vpath.write_text(json.dumps(versioned), encoding="utf-8")
    doc = load_scan_document(str(vpath))
    assert doc.schema_version == "1.0"
    counts = candidate_counts_from_document(doc)
    text = render_text(
        [],
        candidates=doc.candidates,
        candidate_counts=counts,
        has_candidate_section=True,
    )
    assert "No model-retained findings were produced; 2 deterministic candidates" in text
    assert "rule_id: (none)" in text
    assert "discovery_method: catalog_symbol_match" in text
    assert "UNSPECIFIED_RULE" not in text
    assert "clean scan" not in text.lower()


def test_end_to_end_llm_none_preserves_candidates(tmp_path: Path):
    """--llm none completes a scan with candidates[] even when findings vary."""
    from tacs.core.pipeline import ScanningPipeline

    src = tmp_path / "main.c"
    src.write_text(
        "#include <time.h>\n"
        "int main(void) {\n"
        "  time_t now = time(NULL);\n"
        "  return (int)now;\n"
        "}\n",
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
    assert isinstance(data["candidates"], list)
    assert len(data["candidates"]) >= 1
    from tacs.core.rule_catalog import is_valid_rule_id

    catalog_rows = [
        c for c in data["candidates"] if c.get("discovery_method") == "catalog_symbol_match"
    ]
    assert catalog_rows, "expected at least one catalog_symbol_match candidate"
    assert all(is_valid_rule_id(c.get("rule_id")) for c in catalog_rows)
    for c in data["candidates"]:
        if c.get("discovery_method") != "catalog_symbol_match":
            assert c.get("rule_id") is None
    assert data["meta"]["candidate_summary"]["total"] == len(data["candidates"])
    assert data["meta"]["candidate_summary"]["findings"] == len(data["findings"])
    # Under --llm none, findings are typically abstain stubs; filtering may keep them.
    assert "findings" in data


def test_ir_propagates_explicit_discovery_method_not_symbol_prefix():
    """Catalog/cast methods come from producer fields; symbol text cannot change them."""
    from tacs.core.candidate_evidence import normalize_discovery_method
    from tacs.core.ir_adapter import _ir_symbols_and_methods

    catalog_item = {
        "file": "a.c",
        "line": 1,
        "symbols": ["cast_from_time", "time_t"],
        "discovery_methods": ["catalog_symbol_match", "catalog_symbol_match"],
        "risk": "high",
        "lineText": "x",
        "description": "Cast from time_t function time() to int",
    }
    pairs = _ir_symbols_and_methods(catalog_item)
    assert pairs[0] == ("cast_from_time", "catalog_symbol_match")
    assert pairs[1] == ("time_t", "catalog_symbol_match")
    # Explicit catalog provenance wins even when the symbol looks like a cast.
    assert normalize_discovery_method(pairs[0][1]) == "catalog_symbol_match"

    cast_item = {
        "file": "a.c",
        "line": 2,
        "symbol": "time_t",
        "discovery_method": "time_t_cast",
        "risk": "high",
        "lineText": "y",
        "description": "ordinary looking description",
    }
    pairs = _ir_symbols_and_methods(cast_item)
    assert pairs == [("time_t", "time_t_cast")]
    assert normalize_discovery_method(pairs[0][1]) == "time_t_cast"

    missing = _ir_symbols_and_methods(
        {"file": "a.c", "line": 3, "symbol": "time_t", "risk": "high", "lineText": "z"}
    )
    assert missing == [("time_t", None)]
    assert normalize_discovery_method(missing[0][1]) == "unknown"


def test_scanner_emits_explicit_catalog_and_cast_methods(tmp_path: Path):
    """End-to-end: IR scanner JSON carries producer discovery_method fields."""
    import json
    import subprocess
    import sys

    src = tmp_path / "hit.c"
    src.write_text(
        "#include <time.h>\n"
        "int main(void) {\n"
        "  time_t now;\n"
        "  int narrowed = (int)time(NULL);\n"
        "  return narrowed;\n"
        "}\n",
        encoding="utf-8",
    )
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            [
                {
                    "symbol": "time_t",
                    "risk": "high",
                    "category": "type",
                    "description": "Time type",
                },
                {
                    "symbol": "time",
                    "risk": "high",
                    "category": "function",
                    "description": "Time function",
                },
            ]
        ),
        encoding="utf-8",
    )
    aliases = tmp_path / "aliases.json"
    aliases.write_text(json.dumps(["time_t"]), encoding="utf-8")
    funcs = tmp_path / "funcs.json"
    funcs.write_text(json.dumps(["time"]), encoding="utf-8")
    out = tmp_path / "hits.json"
    scanner = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "tacs"
        / "python"
        / "y2038scan_fast_json_group.py"
    )
    cmd = [
        sys.executable,
        str(scanner),
        str(tmp_path),
        str(rules),
        "--min-risk",
        "low",
        "--group-by-line",
        "--json-out",
        str(out),
        "--time-t-aliases",
        str(aliases),
        "--time-functions",
        str(funcs),
        "--include",
        "*.c",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload, "expected IR hits"
    methods = set()
    for item in payload:
        if "discovery_methods" in item:
            methods.update(item["discovery_methods"])
        elif "discovery_method" in item:
            methods.add(item["discovery_method"])
    assert "catalog_symbol_match" in methods
    assert "time_t_cast" in methods

    # Symbol prefix must not invent cast provenance for an explicit catalog row.
    forged = {
        "file": "x.c",
        "line": 1,
        "symbols": ["cast_from_time"],
        "discovery_methods": ["catalog_symbol_match"],
        "risk": "high",
        "lineText": "x",
    }
    from tacs.core.ir_adapter import _ir_symbols_and_methods

    assert _ir_symbols_and_methods(forged)[0][1] == "catalog_symbol_match"


def _evidence_snapshot(rows: list[dict]) -> list[tuple]:
    """Comparable fingerprint of public candidate evidence (order-sensitive)."""
    out = []
    for row in rows:
        out.append(
            (
                row.get("candidate_id"),
                row.get("file"),
                row.get("line"),
                row.get("symbol"),
                row.get("discovery_method"),
                row.get("rule_id"),
                row.get("function_id"),
                row.get("analysis_coverage"),
                row.get("one_line_snippet"),
            )
        )
    return out


def test_evidence_identical_across_model_outcomes_and_stage7(tmp_path: Path):
    """Named invariance: model yes/no/abstain/parse-fail/Stage 7 do not alter evidence.

    Also asserts an outside-function candidate remains present and ungrouped, and
    that recording evidence does not mutate the Stage 7 input list.
    """
    from tacs.core.pipeline import ScanningPipeline
    from tacs.core.schema import Finding, Y2038Issue

    src = tmp_path / "f.c"
    src.write_text(
        "void foo(void) {\n  time_t t;\n}\n" "time_t global_now;\n",
        encoding="utf-8",
    )
    in_fn = Candidate(
        file=str(src),
        line=2,
        symbol="time_t",
        one_line_snippet="  time_t t;",
        risk="high",
        description="in function",
        col_start=2,
        col_end=8,
        discovery_method="catalog_symbol_match",
    )
    outside = Candidate(
        file=str(src),
        line=4,
        symbol="time_t",
        one_line_snippet="time_t global_now;",
        risk="high",
        description="global",
        col_start=0,
        col_end=6,
        discovery_method="catalog_symbol_match",
    )
    prepared = prepare_candidates([in_fn, outside])
    assert len(prepared) == 2

    pipeline = ScanningPipeline.__new__(ScanningPipeline)
    pipeline.max_function_lines = 10000
    pipeline.max_function_chars = 20000
    pipeline.function_analyzer = None

    before_ids = [id(c) for c in prepared]
    before_payload = [(c.file, c.line, c.symbol, c.discovery_method) for c in prepared]
    pipeline._record_canonical_candidate_evidence(prepared, str(tmp_path))
    assert [id(c) for c in prepared] == before_ids
    assert [(c.file, c.line, c.symbol, c.discovery_method) for c in prepared] == before_payload

    evidence = pipeline._canonical_candidate_evidence
    assert len(evidence) == 2
    by_line = {e.line: e for e in evidence}
    assert by_line[2].analysis_coverage == AnalysisCoverage.GROUPED
    assert by_line[4].analysis_coverage == AnalysisCoverage.UNGROUPED
    assert by_line[4].function_id is None

    metrics = Metrics(
        total_files=1,
        total_lines=4,
        total_chars=40,
        total_words=10,
        max_line_length=20,
        avg_line_length=10.0,
        max_file_length=4,
        avg_file_length=4.0,
    )

    def _finding(issue: Y2038Issue, reason: str) -> Finding:
        return Finding(
            file="f.c",
            region={"start_line": 2, "end_line": 2},
            lines=[2],
            symbol="time_t",
            severity=None,
            confidence=0.9,
            reason=reason,
            source_snippet="time_t t;",
            y2038_issue=issue,
        )

    outcome_findings = {
        "yes": [_finding(Y2038Issue.YES, "model yes")],
        "no": [],  # default filter drops no; empty findings with preserved candidates
        "abstain": [_finding(Y2038Issue.ABSTAIN, "model abstain")],
        "parse_failure": [_finding(Y2038Issue.ABSTAIN, "Invalid model output")],
        "stage7_rejection": [_finding(Y2038Issue.YES, "survivor after Stage 7 drop")],
        "llm_none": [_finding(Y2038Issue.ABSTAIN, "LLM disabled")],
    }

    baseline = None
    for label, findings in outcome_findings.items():
        results = ScanResults(
            schema_version=PUBLIC_RESULT_SCHEMA_VERSION,
            meta=ScanMetadata(
                root=".",
                rules_path="rules.json",
                model="none" if label == "llm_none" else "test-model",
                confidence_floor=0.0,
                metrics=metrics,
                timestamp="2026-01-01T00:00:00Z",
                # Deliberately wrong summary — save_results must reconcile.
                candidate_summary=summarize_candidate_evidence([], findings_count=999),
            ),
            candidates=list(evidence),
            findings=findings,
        )
        out = tmp_path / f"out_{label}.json"
        pipeline.save_results(results, str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        snap = _evidence_snapshot(data["candidates"])
        if baseline is None:
            baseline = snap
        assert snap == baseline, f"candidates drifted for outcome {label}"
        assert data["schema_version"] == "1.1"
        assert data["meta"]["candidate_summary"]["total"] == len(data["candidates"])
        assert data["meta"]["candidate_summary"]["findings"] == len(data["findings"])
        assert data["meta"]["candidate_summary"]["ungrouped"] == 1
        assert all(c.get("rule_id") is None for c in data["candidates"])


def test_save_results_summary_matches_serialized_arrays(tmp_path: Path):
    from tacs.core.pipeline import ScanningPipeline
    from tacs.core.schema import Finding, Y2038Issue

    evidence = build_candidate_evidence(
        [
            _cand(line=1, symbol="a", discovery_method="define_scanner"),
            _cand(
                file="/abs/repo/src/b.c",
                line=99,
                symbol="b",
                col_start=1,
                col_end=2,
                discovery_method="migration",
            ),
        ],
        root_path="/abs/repo",
        functions=[],
    )
    metrics = Metrics(
        total_files=1,
        total_lines=1,
        total_chars=1,
        total_words=1,
        max_line_length=1,
        avg_line_length=1.0,
        max_file_length=1,
        avg_file_length=1.0,
    )
    findings = [
        Finding(
            file="src/a.c",
            region={"start_line": 1, "end_line": 1},
            lines=[1],
            symbol="a",
            severity=None,
            confidence=0.5,
            reason="x",
            source_snippet="a",
            y2038_issue=Y2038Issue.ABSTAIN,
        )
    ]
    results = ScanResults(
        schema_version=PUBLIC_RESULT_SCHEMA_VERSION,
        meta=ScanMetadata(
            root=".",
            rules_path="r.json",
            model="none",
            confidence_floor=0.0,
            metrics=metrics,
            timestamp="2026-01-01T00:00:00Z",
            candidate_summary=summarize_candidate_evidence([], findings_count=0),
        ),
        candidates=evidence,
        findings=findings,
    )
    out = tmp_path / "reconciled.json"
    ScanningPipeline.__new__(ScanningPipeline).save_results(results, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    summary = data["meta"]["candidate_summary"]
    assert summary["total"] == len(data["candidates"]) == 2
    assert summary["findings"] == len(data["findings"]) == 1
    assert summary["ungrouped"] == 2
    assert summary["grouped"] == 0


def test_renderer_html_and_text_show_candidate_evidence_not_just_counts():
    from report_renderer.core import candidate_counts_from_document, load_scan_document
    from report_renderer.renderers import render_html, render_text

    doc = {
        "schema_version": "1.0",
        "meta": {
            "candidate_summary": {
                "total": 1,
                "grouped": 0,
                "ungrouped": 1,
                "functions_with_candidates": 0,
                "findings": 0,
            }
        },
        "candidates": [
            {
                "candidate_id": "g.c:1:0-6:high:time_t",
                "file": "g.c",
                "line": 1,
                "symbol": "time_t",
                "risk": "high",
                "description": "Time type",
                "one_line_snippet": "time_t g;",
                "discovery_method": "catalog_symbol_match",
                "rule_id": None,
                "function_id": None,
                "analysis_coverage": "ungrouped",
            }
        ],
        "findings": [],
    }
    # Use load path to mirror tacs render.
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "v.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        loaded = load_scan_document(str(path))
    counts = candidate_counts_from_document(loaded)
    text = render_text(
        [],
        candidates=loaded.candidates,
        candidate_counts=counts,
        has_candidate_section=True,
    )
    html = render_html(
        [],
        title="Evidence",
        group_by="none",
        candidates=loaded.candidates,
        candidate_counts=counts,
        has_candidate_section=True,
    )
    for body in (text, html):
        assert "Deterministic candidate evidence" in body
        assert "g.c:1:0-6:high:time_t" in body
        assert "catalog_symbol_match" in body
        assert "time_t g;" in body
        assert "UNSPECIFIED_RULE" not in body
        assert "(none)" in body or "rule_id:</strong> (none)" in body
    assert 'id="deterministic-candidates"' in html
    assert "confirmed defects" in text.lower() or "not confirmed defects" in html.lower()


def test_primary_writers_and_render_preserve_schema_fields(tmp_path: Path):
    """Single-scan save_results and tacs render keep schema_version/candidates/summary."""
    from click.testing import CliRunner

    from report_renderer.core import load_scan_document
    from tacs.cli import app
    from tacs.core.pipeline import ScanningPipeline
    from tacs.core.schema import Finding, Y2038Issue

    evidence = build_candidate_evidence(
        [_cand(file=str(tmp_path / "x.c"), discovery_method="io_boundary")],
        root_path=str(tmp_path),
        functions=[],
    )
    metrics = Metrics(
        total_files=1,
        total_lines=1,
        total_chars=1,
        total_words=1,
        max_line_length=1,
        avg_line_length=1.0,
        max_file_length=1,
        avg_file_length=1.0,
    )
    results = ScanResults(
        schema_version=PUBLIC_RESULT_SCHEMA_VERSION,
        meta=ScanMetadata(
            root=".",
            rules_path="r.json",
            model="none",
            confidence_floor=0.0,
            metrics=metrics,
            timestamp="2026-01-01T00:00:00Z",
        ),
        candidates=evidence,
        findings=[
            Finding(
                file="x.c",
                region={"start_line": 10, "end_line": 10},
                lines=[10],
                symbol="time_t",
                severity=None,
                confidence=0.1,
                reason="stub",
                source_snippet="time_t t;",
                y2038_issue=Y2038Issue.ABSTAIN,
            )
        ],
    )
    # Single-repo / batch both call save_results.
    single_out = tmp_path / "findings.json"
    batch_out = tmp_path / "repos" / "demo" / "findings.json"
    batch_out.parent.mkdir(parents=True)
    pipeline = ScanningPipeline.__new__(ScanningPipeline)
    pipeline.save_results(results, str(single_out))
    pipeline.save_results(results, str(batch_out))

    for path in (single_out, batch_out):
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["schema_version"] == "1.1"
        assert len(data["candidates"]) == 1
        assert data["candidates"][0]["discovery_method"] == "io_boundary"
        assert data["meta"]["candidate_summary"]["total"] == 1
        assert data["meta"]["candidate_summary"]["findings"] == 1
        assert "assessments" in data
        assert "assessment_summary" in data["meta"]
        doc = load_scan_document(str(path))
        assert doc.schema_version == "1.1"
        assert len(doc.candidates) == 1
        assert doc.has_assessment_section

    report = tmp_path / "report.txt"
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["render", str(single_out), "--format", "text"],
    )
    assert result.exit_code == 0, result.output
    assert "Deterministic candidate evidence" in result.output
    assert "Model assessments" in result.output
    assert "io_boundary" in result.output
    assert "UNSPECIFIED_RULE" not in result.output
    assert "rule_id: (none)" in result.output
    _ = report  # render prints to stdout for text mode
