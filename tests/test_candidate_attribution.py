# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Adversarial regression for per-match IR attribution (matches[] authoritative)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tacs.core.candidate_evidence import build_candidate_evidence
from tacs.core.candidate_utils import (
    CandidateProvenanceConflictError,
    CandidateRuleIdConflictError,
    candidate_id_for,
    make_candidate_id,
    prepare_candidates,
)
from tacs.core.ir_adapter import IRAdapter
from tacs.core.ir_match import (
    IRMatchError,
    extract_matches_from_ir_item,
    group_by_line,
    iter_match_field_sets,
)
from tacs.core.schema import AnalysisCoverage, Candidate
from tacs.python.y2038scan_fast_json_group import group_by_line as scanner_group_by_line


REPO = Path(__file__).resolve().parents[1]
RULES = REPO / "src" / "tacs" / "rules" / "y2038_sample_rules.json"
SCANNER = REPO / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"


def _discover(tmp_path: Path, source: str) -> list[Candidate]:
    src = tmp_path / "sample.c"
    src.write_text(source, encoding="utf-8")
    adapter = IRAdapter(str(SCANNER))
    return [
        c
        for c in adapter.discover_candidates(
            str(tmp_path),
            str(RULES),
            min_risk="low",
            include_patterns=["*.c"],
        )
        if "sample.c" in c.file
    ]


def test_k_sleep_alone_vs_with_time_t_preserves_independent_attribution(tmp_path: Path):
    alone = {c.symbol: c for c in _discover(tmp_path, "void f(void) {\n  k_sleep(5);\n}\n")}
    assert alone["k_sleep"].risk == "low"
    assert "ticks" in (alone["k_sleep"].description or "")
    assert alone["k_sleep"].rule_id == "TACS-RULE-0204"
    alone_id = make_candidate_id(
        "sample.c",
        alone["k_sleep"].line,
        "k_sleep",
        alone["k_sleep"].col_start,
        alone["k_sleep"].col_end,
        alone["k_sleep"].risk,
    )
    assert ":low:k_sleep" in alone_id

    mixed_path = tmp_path / "mixed"
    mixed_path.mkdir()
    mixed = {
        c.symbol: c
        for c in _discover(mixed_path, "void f(void) {\n  time_t x; k_sleep(5);\n}\n")
    }
    assert mixed["k_sleep"].risk == "low"
    assert mixed["time_t"].risk == "high"
    assert "ticks" in (mixed["k_sleep"].description or "")
    assert "epoch" in (mixed["time_t"].description or "").lower() or "Secs" in (
        mixed["time_t"].description or ""
    )
    assert mixed["k_sleep"].rule_id == "TACS-RULE-0204"
    assert mixed["time_t"].rule_id == "TACS-RULE-0192"
    assert mixed["k_sleep"].discovery_method == "catalog_symbol_match"
    assert mixed["time_t"].discovery_method == "catalog_symbol_match"
    mixed_ksleep_id = make_candidate_id(
        "sample.c",
        mixed["k_sleep"].line,
        "k_sleep",
        mixed["k_sleep"].col_start,
        mixed["k_sleep"].col_end,
        mixed["k_sleep"].risk,
    )
    assert mixed_ksleep_id == alone_id


def test_group_by_line_emits_matches_not_scalar_risk_description():
    results = [
        {
            "file": "/x.c",
            "line": 1,
            "symbol": "k_sleep",
            "risk": "low",
            "lineText": "time_t x; k_sleep(5);",
            "description": "sleep",
            "discovery_method": "catalog_symbol_match",
            "rule_id": "TACS-RULE-0204",
        },
        {
            "file": "/x.c",
            "line": 1,
            "symbol": "time_t",
            "risk": "high",
            "lineText": "time_t x; k_sleep(5);",
            "description": "type",
            "discovery_method": "catalog_symbol_match",
            "rule_id": "TACS-RULE-0192",
        },
    ]
    grouped = group_by_line(results)
    assert scanner_group_by_line(results) == grouped
    g = grouped[0]
    assert "risk" not in g
    assert "description" not in g
    assert "symbols" not in g
    assert g["line_max_risk"] == "high"
    assert g["match_count"] == 2
    by_sym = {m["symbol"]: m for m in g["matches"]}
    assert by_sym["k_sleep"]["risk"] == "low"
    assert by_sym["time_t"]["risk"] == "high"
    assert by_sym["k_sleep"]["description"] == "sleep"
    assert by_sym["time_t"]["description"] == "type"


def test_same_symbol_different_discovery_methods_preserved():
    results = [
        {
            "file": "/x.c",
            "line": 1,
            "symbol": "time_t",
            "risk": "high",
            "lineText": "x",
            "description": "catalog",
            "discovery_method": "catalog_symbol_match",
            "rule_id": "TACS-RULE-0192",
        },
        {
            "file": "/x.c",
            "line": 1,
            "symbol": "time_t",
            "risk": "medium",
            "lineText": "x",
            "description": "define hit",
            "discovery_method": "define_scanner",
            "rule_id": None,
        },
    ]
    g = group_by_line(results)[0]
    assert g["match_count"] == 2
    methods = {m["discovery_method"] for m in g["matches"]}
    assert methods == {"catalog_symbol_match", "define_scanner"}


def test_exact_duplicate_observations_collapse_once():
    hit = {
        "file": "/x.c",
        "line": 1,
        "symbol": "k_sleep",
        "risk": "low",
        "lineText": "k_sleep(5);",
        "description": "sleep",
        "discovery_method": "catalog_symbol_match",
        "rule_id": "TACS-RULE-0204",
    }
    g = group_by_line([hit, dict(hit)])[0]
    assert g["match_count"] == 1


def test_conflicting_rule_ids_same_identity_fail_closed(tmp_path: Path):
    a = Candidate(
        file=str(tmp_path / "a.c"),
        line=1,
        symbol="time_t",
        one_line_snippet="x",
        risk="high",
        description="a",
        discovery_method="catalog_symbol_match",
        rule_id="TACS-RULE-0192",
    )
    b = a.model_copy(update={"rule_id": "TACS-RULE-0001", "description": "a"})
    with pytest.raises(CandidateRuleIdConflictError):
        prepare_candidates([a, b])


def test_conflicting_discovery_method_same_identity_fail_closed(tmp_path: Path):
    a = Candidate(
        file=str(tmp_path / "a.c"),
        line=1,
        symbol="time_t",
        one_line_snippet="x",
        risk="high",
        description="same",
        discovery_method="catalog_symbol_match",
        rule_id=None,
    )
    b = a.model_copy(update={"discovery_method": "define_scanner"})
    with pytest.raises(CandidateProvenanceConflictError, match="discovery_method"):
        prepare_candidates([a, b])


def test_line_summaries_never_feed_candidate_fields():
    item = {
        "file": "/x.c",
        "line": 9,
        "lineText": "time_t x; k_sleep(5);",
        "matches": [
            {
                "symbol": "k_sleep",
                "risk": "low",
                "description": "sleep",
                "discovery_method": "catalog_symbol_match",
                "rule_id": "TACS-RULE-0204",
                "line": 9,
            },
            {
                "symbol": "time_t",
                "risk": "high",
                "description": "type",
                "discovery_method": "catalog_symbol_match",
                "rule_id": "TACS-RULE-0192",
                "line": 9,
            },
        ],
        "match_count": 2,
        "line_max_risk": "high",
    }
    fields = list(iter_match_field_sets(item))
    assert {f["symbol"]: f["risk"] for f in fields} == {"k_sleep": "low", "time_t": "high"}
    assert all(f["risk"] != "high" or f["symbol"] == "time_t" for f in fields)
    # Summaries are not Candidate inputs
    for f in fields:
        assert "line_max_risk" not in f
        assert "match_count" not in f


def test_legacy_unequal_parallel_arrays_rejected():
    with pytest.raises(IRMatchError, match="unequal|length"):
        extract_matches_from_ir_item(
            {
                "file": "/x.c",
                "line": 1,
                "symbols": ["time_t", "k_sleep"],
                "discovery_methods": ["catalog_symbol_match"],
                "rule_ids": ["TACS-RULE-0192", "TACS-RULE-0204"],
                "risk": "high",
                "lineText": "x",
            }
        )


def test_legacy_ambiguous_multi_symbol_rejected():
    with pytest.raises(IRMatchError, match="ambiguous legacy multi-symbol"):
        extract_matches_from_ir_item(
            {
                "file": "/x.c",
                "line": 1,
                "symbols": ["time_t", "k_sleep"],
                "discovery_methods": [
                    "catalog_symbol_match",
                    "catalog_symbol_match",
                ],
                "rule_ids": ["TACS-RULE-0192", "TACS-RULE-0204"],
                "risk": "high",
                "description": "sleep",
                "lineText": "x",
            }
        )


def test_legacy_single_symbol_accepted():
    matches = extract_matches_from_ir_item(
        {
            "file": "/x.c",
            "line": 2,
            "symbol": "k_sleep",
            "discovery_method": "catalog_symbol_match",
            "rule_id": "TACS-RULE-0204",
            "risk": "low",
            "description": "sleep",
            "lineText": "k_sleep(5);",
        }
    )
    assert len(matches) == 1
    assert matches[0]["risk"] == "low"
    assert matches[0]["rule_id"] == "TACS-RULE-0204"


def test_new_and_legacy_inconsistent_fail_closed():
    with pytest.raises(IRMatchError, match="conflict"):
        extract_matches_from_ir_item(
            {
                "file": "/x.c",
                "line": 1,
                "lineText": "x",
                "matches": [
                    {
                        "symbol": "k_sleep",
                        "risk": "low",
                        "description": "sleep",
                        "discovery_method": "catalog_symbol_match",
                        "rule_id": "TACS-RULE-0204",
                        "line": 1,
                    }
                ],
                "symbols": ["time_t"],
                "discovery_methods": ["catalog_symbol_match"],
                "rule_ids": ["TACS-RULE-0192"],
            }
        )


def test_scalar_risk_with_multi_match_rejected():
    with pytest.raises(IRMatchError, match="scalar risk"):
        extract_matches_from_ir_item(
            {
                "file": "/x.c",
                "line": 1,
                "lineText": "x",
                "risk": "high",
                "matches": [
                    {
                        "symbol": "k_sleep",
                        "risk": "low",
                        "description": "sleep",
                        "discovery_method": "catalog_symbol_match",
                        "rule_id": "TACS-RULE-0204",
                        "line": 1,
                    },
                    {
                        "symbol": "time_t",
                        "risk": "high",
                        "description": "type",
                        "discovery_method": "catalog_symbol_match",
                        "rule_id": "TACS-RULE-0192",
                        "line": 1,
                    },
                ],
            }
        )


def test_catalog_plus_cast_matches_independent(tmp_path: Path):
    # Cast symbol differs from catalog time_t; both must keep own metadata when grouped.
    results = [
        {
            "file": str(tmp_path / "c.c"),
            "line": 1,
            "symbol": "time_t",
            "risk": "high",
            "lineText": "(int)time(NULL);",
            "description": "type",
            "discovery_method": "catalog_symbol_match",
            "rule_id": "TACS-RULE-0192",
        },
        {
            "file": str(tmp_path / "c.c"),
            "line": 1,
            "symbol": "cast_from_time",
            "risk": "high",
            "lineText": "(int)time(NULL);",
            "description": "cast",
            "discovery_method": "time_t_cast",
            "rule_id": None,
        },
    ]
    g = group_by_line(results)[0]
    assert g["match_count"] == 2
    fields = list(iter_match_field_sets(g))
    by_sym = {f["symbol"]: f for f in fields}
    assert by_sym["time_t"]["rule_id"] == "TACS-RULE-0192"
    assert by_sym["cast_from_time"]["rule_id"] is None
    assert by_sym["cast_from_time"]["discovery_method"] == "time_t_cast"
    assert by_sym["cast_from_time"]["description"] == "cast"


def test_catalog_plus_direct_non_catalog_candidates(tmp_path: Path):
    catalog = Candidate(
        file=str(tmp_path / "a.c"),
        line=3,
        symbol="time_t",
        one_line_snippet="time_t t; /* arith */ t + 1",
        risk="high",
        description="type",
        discovery_method="catalog_symbol_match",
        rule_id="TACS-RULE-0192",
    )
    arith = Candidate(
        file=str(tmp_path / "a.c"),
        line=3,
        symbol="arithmetic_+",
        one_line_snippet="time_t t; /* arith */ t + 1",
        risk="medium",
        description="Arithmetic operation on time_t",
        discovery_method="arithmetic_scanner",
        rule_id=None,
    )
    prepared = prepare_candidates([catalog, arith])
    assert len(prepared) == 2
    evidence = build_candidate_evidence(prepared, root_path=str(tmp_path))
    by_sym = {e.symbol: e for e in evidence}
    assert by_sym["time_t"].risk == "high"
    assert by_sym["arithmetic_+"].risk == "medium"
    assert by_sym["time_t"].rule_id == "TACS-RULE-0192"
    assert by_sym["arithmetic_+"].rule_id is None


def test_assessment_referential_integrity_with_corrected_ids(tmp_path: Path):
    from tacs.core.function_schemas import FunctionBody
    from tacs.core.candidate_evidence import attach_candidate_ids_to_functions

    cands = _discover(tmp_path, "void f(void) {\n  time_t x; k_sleep(5);\n}\n")
    by_sym = {c.symbol: c for c in cands}
    rel = "sample.c"
    ids = {
        sym: candidate_id_for(c, rel)
        for sym, c in by_sym.items()
    }
    assert ":low:k_sleep" in ids["k_sleep"]
    assert ":high:time_t" in ids["time_t"]

    func = FunctionBody(
        function_id=f"{rel}@f:1-3",
        file_path=str(tmp_path / "sample.c"),
        symbol="f",
        start_line=1,
        end_line=3,
        body="void f(void) {\n  time_t x; k_sleep(5);\n}\n",
        candidate_lines=sorted({c.line for c in cands}),
    )
    funcs = attach_candidate_ids_to_functions([func], cands, str(tmp_path))
    assert set(funcs[0].candidate_ids) == set(ids.values())


def test_public_evidence_and_renderers_preserve_per_match_fields(tmp_path: Path):
    from report_renderer.renderers import render_html, render_text

    cands = _discover(tmp_path, "void f(void) {\n  time_t x; k_sleep(5);\n}\n")
    evidence = build_candidate_evidence(cands, root_path=str(tmp_path))
    rows = [e.model_dump(mode="json") for e in evidence]
    counts = {
        "total": len(rows),
        "grouped": sum(1 for e in evidence if e.analysis_coverage == AnalysisCoverage.GROUPED),
        "ungrouped": sum(1 for e in evidence if e.analysis_coverage == AnalysisCoverage.UNGROUPED),
        "functions_with_candidates": len({e.function_id for e in evidence if e.function_id}),
        "findings": 0,
    }
    text = render_text([], candidates=rows, candidate_counts=counts, has_candidate_section=True)
    html = render_html(
        [],
        title="attribution",
        group_by="file",
        candidates=rows,
        candidate_counts=counts,
        has_candidate_section=True,
    )
    assert "k_sleep" in text and "time_t" in text
    assert "TACS-RULE-0204" in text and "TACS-RULE-0192" in text
    assert "k_sleep" in html and "time_t" in html
    by_sym = {e.symbol: e for e in evidence}
    assert by_sym["k_sleep"].risk == "low"
    assert by_sym["time_t"].risk == "high"


def test_old_schema_1_0_report_still_renders(tmp_path: Path):
    from report_renderer.core import load_scan_document
    from report_renderer.renderers import render_text

    path = tmp_path / "old.json"
    path.write_text(
        json.dumps(
            {
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
                        "candidate_id": "a.c:1:0:0:high:time_t",
                        "file": "a.c",
                        "line": 1,
                        "symbol": "time_t",
                        "risk": "high",
                        "description": "type",
                        "one_line_snippet": "time_t t;",
                        "discovery_method": "catalog_symbol_match",
                        "rule_id": None,
                        "function_id": None,
                        "analysis_coverage": "ungrouped",
                    }
                ],
                "findings": [],
            }
        ),
        encoding="utf-8",
    )
    doc = load_scan_document(str(path))
    text = render_text(
        [],
        candidates=doc.candidates,
        candidate_counts={
            "total": 1,
            "grouped": 0,
            "ungrouped": 1,
            "functions_with_candidates": 0,
        },
        has_candidate_section=True,
    )
    assert "time_t" in text


def test_model_outcomes_do_not_alter_deterministic_evidence(tmp_path: Path):
    from tacs.core.pipeline import ScanningPipeline
    from tacs.core.candidate_utils import prepare_candidates

    src = tmp_path / "f.c"
    src.write_text("void foo(void) {\n  time_t x; k_sleep(5);\n}\n", encoding="utf-8")
    cands = prepare_candidates(_discover(tmp_path, src.read_text(encoding="utf-8")))
    before = [
        (c.symbol, c.risk, c.description, c.rule_id, c.discovery_method)
        for c in cands
    ]
    pipeline = ScanningPipeline.__new__(ScanningPipeline)
    pipeline.max_function_lines = 10000
    pipeline.max_function_chars = 20000
    pipeline.function_analyzer = None
    pipeline._record_canonical_candidate_evidence(cands, str(tmp_path))
    after = [
        (c.symbol, c.risk, c.description, c.rule_id, c.discovery_method)
        for c in cands
    ]
    assert before == after
    evidence = pipeline._canonical_candidate_evidence
    by_sym = {e.symbol: e for e in evidence}
    assert by_sym["k_sleep"].risk == "low"
    assert by_sym["time_t"].risk == "high"


def test_single_scan_writer_preserves_attribution(tmp_path: Path):
    from tacs.core.pipeline import ScanningPipeline

    if not RULES.is_file() or not SCANNER.is_file():
        pytest.skip("rules/scanner missing")
    (tmp_path / "main.c").write_text(
        "void f(void) {\n  time_t x; k_sleep(5);\n}\n", encoding="utf-8"
    )
    pipeline = ScanningPipeline(
        scanner_path=str(SCANNER),
        llm_type="none",
        model="none",
        function_first=True,
        confidence_floor=0.0,
        enable_pass1=False,
        enable_io_analysis=False,
    )
    results = pipeline.scan(
        root_path=str(tmp_path),
        rules_path=str(RULES),
        min_risk="low",
        include_patterns=["*.c"],
        exclude_patterns=[],
        session_dir=str(tmp_path / "session"),
    )
    out = tmp_path / "findings.json"
    pipeline.save_results(results, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.1"
    by_sym = {c["symbol"]: c for c in data["candidates"] if c["symbol"] in ("k_sleep", "time_t")}
    assert by_sym["k_sleep"]["risk"] == "low"
    assert by_sym["time_t"]["risk"] == "high"
    assert by_sym["k_sleep"]["rule_id"] == "TACS-RULE-0204"
    assert by_sym["time_t"]["rule_id"] == "TACS-RULE-0192"
    assert ":low:k_sleep" in by_sym["k_sleep"]["candidate_id"]


def test_description_order_cannot_select_retained_text(tmp_path: Path):
    """Materially different descriptions fail closed regardless of input order."""
    a = Candidate(
        file=str(tmp_path / "a.c"),
        line=1,
        symbol="k_sleep",
        one_line_snippet="k_sleep(5);",
        risk="low",
        description="first wording",
        discovery_method="catalog_symbol_match",
        rule_id="TACS-RULE-0204",
    )
    b = a.model_copy(update={"description": "second wording"})
    with pytest.raises(CandidateProvenanceConflictError, match="Conflicting description"):
        prepare_candidates([a, b])
    with pytest.raises(CandidateProvenanceConflictError, match="Conflicting description"):
        prepare_candidates([b, a])


def test_empty_matches_rejected():
    with pytest.raises(IRMatchError, match="empty matches"):
        extract_matches_from_ir_item(
            {"file": "/x.c", "line": 1, "lineText": "x", "matches": []}
        )


def test_match_line_must_equal_parent_line():
    with pytest.raises(IRMatchError, match="match line disagrees"):
        extract_matches_from_ir_item(
            {
                "file": "/x.c",
                "line": 3,
                "lineText": "x",
                "matches": [
                    {
                        "symbol": "time_t",
                        "risk": "high",
                        "description": "type",
                        "discovery_method": "catalog_symbol_match",
                        "rule_id": "TACS-RULE-0192",
                        "line": 4,
                    }
                ],
            }
        )


def test_invalid_column_ranges_rejected():
    with pytest.raises(IRMatchError, match="both be absent|both present"):
        extract_matches_from_ir_item(
            {
                "file": "/x.c",
                "line": 1,
                "lineText": "x",
                "matches": [
                    {
                        "symbol": "time_t",
                        "risk": "high",
                        "description": "type",
                        "discovery_method": "catalog_symbol_match",
                        "rule_id": None,
                        "line": 1,
                        "col_start": 0,
                        "col_end": None,
                    }
                ],
            }
        )
    with pytest.raises(IRMatchError, match="nonnegative|col_start"):
        extract_matches_from_ir_item(
            {
                "file": "/x.c",
                "line": 1,
                "lineText": "x",
                "matches": [
                    {
                        "symbol": "time_t",
                        "risk": "high",
                        "description": "type",
                        "discovery_method": "catalog_symbol_match",
                        "rule_id": None,
                        "line": 1,
                        "col_start": 5,
                        "col_end": 2,
                    }
                ],
            }
        )


def test_summaries_must_match_derived_values():
    base_matches = [
        {
            "symbol": "k_sleep",
            "risk": "low",
            "description": "sleep",
            "discovery_method": "catalog_symbol_match",
            "rule_id": "TACS-RULE-0204",
            "line": 1,
        },
        {
            "symbol": "time_t",
            "risk": "high",
            "description": "type",
            "discovery_method": "catalog_symbol_match",
            "rule_id": "TACS-RULE-0192",
            "line": 1,
        },
    ]
    with pytest.raises(IRMatchError, match="match_count"):
        extract_matches_from_ir_item(
            {
                "file": "/x.c",
                "line": 1,
                "lineText": "x",
                "matches": base_matches,
                "match_count": 99,
                "line_max_risk": "high",
            }
        )
    with pytest.raises(IRMatchError, match="line_max_risk"):
        extract_matches_from_ir_item(
            {
                "file": "/x.c",
                "line": 1,
                "lineText": "x",
                "matches": base_matches,
                "match_count": 2,
                "line_max_risk": "low",
            }
        )


def test_match_ordering_and_evidence_are_deterministic():
    hits_a = [
        {
            "file": "/x.c",
            "line": 1,
            "symbol": "time_t",
            "risk": "high",
            "lineText": "time_t x; k_sleep(5);",
            "description": "type",
            "discovery_method": "catalog_symbol_match",
            "rule_id": "TACS-RULE-0192",
        },
        {
            "file": "/x.c",
            "line": 1,
            "symbol": "k_sleep",
            "risk": "low",
            "lineText": "time_t x; k_sleep(5);",
            "description": "sleep",
            "discovery_method": "catalog_symbol_match",
            "rule_id": "TACS-RULE-0204",
        },
    ]
    hits_b = list(reversed(hits_a))
    g1 = group_by_line(hits_a)[0]
    g2 = group_by_line(hits_b)[0]
    assert [m["symbol"] for m in g1["matches"]] == [m["symbol"] for m in g2["matches"]]
    assert g1["match_count"] == len(g1["matches"])
    assert g1["line_max_risk"] == "high"
    # Re-reading yields the same ordered matches.
    again = extract_matches_from_ir_item(g1)
    assert [m["symbol"] for m in again] == [m["symbol"] for m in g1["matches"]]


def test_ir_error_messages_omit_source_text():
    with pytest.raises(IRMatchError) as excinfo:
        extract_matches_from_ir_item(
            {
                "file": "/secret/path.c",
                "line": 1,
                "lineText": "SUPER_SECRET_SOURCE_LINE_SHOULD_NOT_APPEAR();",
                "matches": [],
            }
        )
    msg = str(excinfo.value)
    assert "SUPER_SECRET" not in msg
    assert "SOURCE_LINE" not in msg
    assert "empty matches" in msg
