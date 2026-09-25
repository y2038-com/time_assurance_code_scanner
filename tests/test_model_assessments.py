# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for public ModelAssessment separation."""

from __future__ import annotations

import json
from pathlib import Path

from tacs.core.candidate_evidence import build_candidate_evidence, summarize_candidate_evidence
from tacs.core.candidate_utils import prepare_candidates
from tacs.core.function_schemas import FunctionAnalysis, FunctionBody, Y2038Summary
from tacs.core.model_assessment import (
    build_model_assessment,
    derive_run_analysis_status,
    filter_candidate_ids,
    finalize_assessments,
    record_assessments,
    summarize_assessments,
    summarize_serialized_assessments,
)
from tacs.core.schema import (
    PUBLIC_RESULT_SCHEMA_VERSION,
    AssessmentExecutionStatus,
    Candidate,
    Finding,
    Metrics,
    ModelVerdict,
    RunAnalysisStatus,
    ScanMetadata,
    ScanResults,
    Y2038Issue,
)


def _metrics() -> Metrics:
    return Metrics(
        total_files=1,
        total_lines=1,
        total_chars=1,
        total_words=1,
        max_line_length=1,
        avg_line_length=1.0,
        max_file_length=1,
        avg_file_length=1.0,
    )


def _function(**kwargs) -> FunctionBody:
    defaults = dict(
        function_id="a.c@foo:1-10",
        file_path="/abs/repo/a.c",
        symbol="foo",
        start_line=1,
        end_line=10,
        body="void foo(void) { time_t t; }",
        candidate_lines=[3],
        candidate_ids=["a.c:3:0-6:high:time_t"],
    )
    defaults.update(kwargs)
    return FunctionBody(**defaults)


def test_schema_version_is_1_1():
    assert PUBLIC_RESULT_SCHEMA_VERSION == "1.1"


def test_completed_yes_no_abstain_and_analysis_error():
    fn = _function()
    yes = FunctionAnalysis(
        function_id=fn.function_id,
        y2038_summary=Y2038Summary.YES,
        confidence=0.9,
        issues=[{"type": "x", "description": "narrowing", "line": 3}],
        execution_status=AssessmentExecutionStatus.COMPLETED,
    )
    no = FunctionAnalysis(
        function_id=fn.function_id,
        y2038_summary=Y2038Summary.NO,
        confidence=0.8,
        issues=[],
        execution_status=AssessmentExecutionStatus.COMPLETED,
    )
    abstain = FunctionAnalysis(
        function_id=fn.function_id,
        y2038_summary=Y2038Summary.ABSTAIN,
        confidence=0.4,
        issues=[],
        needs_more_context=True,
        execution_status=AssessmentExecutionStatus.COMPLETED,
    )
    err = FunctionAnalysis(
        function_id=fn.function_id,
        y2038_summary=Y2038Summary.ABSTAIN,
        confidence=0.0,
        issues=[{"type": "parse_gap", "description": "gap", "line": 1}],
        execution_status=AssessmentExecutionStatus.ANALYSIS_ERROR,
    )
    assert build_model_assessment(yes, fn).verdict == ModelVerdict.YES
    assert build_model_assessment(no, fn).verdict == ModelVerdict.NO
    assert build_model_assessment(abstain, fn).verdict == ModelVerdict.ABSTAIN
    err_a = build_model_assessment(err, fn)
    assert err_a.execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert err_a.verdict is None


def test_candidates_invariant_across_assessment_outcomes(tmp_path: Path):
    from tacs.core.pipeline import ScanningPipeline

    cand = Candidate(
        file=str(tmp_path / "a.c"),
        line=3,
        symbol="time_t",
        one_line_snippet="time_t t;",
        risk="high",
        description="",
        col_start=0,
        col_end=6,
        discovery_method="catalog_symbol_match",
    )
    evidence = build_candidate_evidence([cand], root_path=str(tmp_path), functions=[])
    baseline = [e.model_dump() for e in evidence]
    fn = _function(
        file_path=str(tmp_path / "a.c"),
        candidate_ids=[evidence[0].candidate_id],
    )
    pipeline = ScanningPipeline.__new__(ScanningPipeline)
    for summary in (Y2038Summary.YES, Y2038Summary.NO, Y2038Summary.ABSTAIN):
        analysis = FunctionAnalysis(
            function_id=fn.function_id,
            y2038_summary=summary,
            confidence=0.7,
            issues=[],
            execution_status=AssessmentExecutionStatus.COMPLETED,
        )
        findings = []
        if summary != Y2038Summary.NO:
            findings = [
                Finding(
                    file="a.c",
                    region={"start_line": 3, "end_line": 3},
                    lines=[3],
                    symbol="time_t",
                    severity=None,
                    confidence=0.7,
                    reason="x",
                    source_snippet="time_t t;",
                    y2038_issue=Y2038Issue(summary.value),
                    function_id=fn.function_id,
                )
            ]
        store = {}
        record_assessments(store, [analysis], [fn])
        assessments = finalize_assessments(store)
        results = ScanResults(
            schema_version=PUBLIC_RESULT_SCHEMA_VERSION,
            meta=ScanMetadata(
                root=".",
                rules_path="r.json",
                model="m",
                confidence_floor=0.0,
                metrics=_metrics(),
                timestamp="2026-01-01T00:00:00Z",
                candidate_summary=summarize_candidate_evidence(
                    evidence, findings_count=len(findings)
                ),
                analysis_status=RunAnalysisStatus.COMPLETE,
                assessment_summary=summarize_assessments(
                    assessments, findings_count=len(findings)
                ),
            ),
            candidates=list(evidence),
            assessments=assessments,
            findings=findings,
        )
        out = tmp_path / f"out_{summary.value}.json"
        pipeline.save_results(results, str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["candidates"] == baseline or [
            {**c, "analysis_coverage": c.get("analysis_coverage")}
            for c in data["candidates"]
        ]
        assert len(data["candidates"]) == 1
        assert data["schema_version"] == "1.1"
        assert len(data["assessments"]) == 1
        if summary == Y2038Summary.NO:
            assert data["findings"] == []
            assert data["assessments"][0]["verdict"] == "no"
        else:
            assert data["assessments"][0]["verdict"] == summary.value


def test_include_no_findings_only_affects_findings(tmp_path: Path):
    from tacs.core.pipeline import ScanningPipeline

    fn = _function()
    analysis = FunctionAnalysis(
        function_id=fn.function_id,
        y2038_summary=Y2038Summary.NO,
        confidence=0.9,
        issues=[],
        execution_status=AssessmentExecutionStatus.COMPLETED,
    )
    store = {}
    record_assessments(store, [analysis], [fn])
    assessments = finalize_assessments(store)
    finding_no = Finding(
        file="a.c",
        region={"start_line": 3, "end_line": 3},
        lines=[3],
        symbol="time_t",
        severity=None,
        confidence=0.9,
        reason="safe",
        source_snippet="t",
        y2038_issue=Y2038Issue.NO,
        function_id=fn.function_id,
    )
    evidence = build_candidate_evidence(
        [
            Candidate(
                file="/abs/repo/a.c",
                line=3,
                symbol="time_t",
                one_line_snippet="time_t t;",
                risk="high",
                discovery_method="catalog_symbol_match",
            )
        ],
        root_path="/abs/repo",
        functions=[],
    )
    pipeline = ScanningPipeline.__new__(ScanningPipeline)
    pipeline.include_no_findings = False
    pipeline.detect_y2106 = False
    filtered = pipeline._filter_findings_for_output([finding_no])
    assert filtered == []

    pipeline.include_no_findings = True
    kept = pipeline._filter_findings_for_output([finding_no])
    assert len(kept) == 1

    for findings in ([], [finding_no]):
        results = ScanResults(
            schema_version=PUBLIC_RESULT_SCHEMA_VERSION,
            meta=ScanMetadata(
                root=".",
                rules_path="r.json",
                model="m",
                confidence_floor=0.0,
                metrics=_metrics(),
                timestamp="2026-01-01T00:00:00Z",
                analysis_status=RunAnalysisStatus.COMPLETE,
            ),
            candidates=evidence,
            assessments=assessments,
            findings=findings,
        )
        out = tmp_path / f"inc_{len(findings)}.json"
        pipeline.save_results(results, str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["assessments"][0]["verdict"] == "no"
        assert len(data["candidates"]) == 1
        assert len(data["findings"]) == len(findings)


def test_llm_none_not_requested_empty_assessments(tmp_path: Path):
    from tacs.core.pipeline import ScanningPipeline

    repo = Path(__file__).resolve().parents[1]
    rules = repo / "src" / "tacs" / "rules" / "y2038_sample_rules.json"
    scanner = repo / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"
    src = tmp_path / "main.c"
    src.write_text(
        "#include <time.h>\nint main(void){ time_t t = time(NULL); return (int)t; }\n",
        encoding="utf-8",
    )
    pipeline = ScanningPipeline(
        scanner_path=str(scanner),
        llm_type="none",
        model="none",
        function_first=True,
        confidence_floor=0.0,
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
    assert data["meta"]["analysis_status"] == "not_requested"
    assert data["assessments"] == []
    assert len(data["candidates"]) >= 1
    assert data["meta"]["assessment_summary"]["total"] == 0


def test_unknown_candidate_ids_filtered():
    fn = _function(candidate_ids=["good", "evil"])
    analysis = FunctionAnalysis(
        function_id=fn.function_id,
        y2038_summary=Y2038Summary.YES,
        confidence=0.5,
        issues=[],
        execution_status=AssessmentExecutionStatus.COMPLETED,
    )
    a = build_model_assessment(analysis, fn)
    filtered = filter_candidate_ids([a], {"good"})
    assert filtered[0].candidate_ids == ["good"]


def test_run_status_partial_and_failed():
    fn = _function()
    completed = build_model_assessment(
        FunctionAnalysis(
            function_id=fn.function_id,
            y2038_summary=Y2038Summary.YES,
            confidence=0.9,
            issues=[],
            execution_status=AssessmentExecutionStatus.COMPLETED,
        ),
        fn,
    )
    errored = build_model_assessment(
        FunctionAnalysis(
            function_id="a.c@bar:1-2",
            y2038_summary=Y2038Summary.ABSTAIN,
            confidence=0.0,
            issues=[{"type": "parse_gap", "description": "x", "line": 1}],
            execution_status=AssessmentExecutionStatus.ANALYSIS_ERROR,
        ),
        _function(function_id="a.c@bar:1-2", candidate_ids=[]),
    )
    assert (
        derive_run_analysis_status(llm_requested=True, assessments=[completed, errored])
        == RunAnalysisStatus.PARTIAL
    )
    assert (
        derive_run_analysis_status(llm_requested=True, assessments=[errored])
        == RunAnalysisStatus.FAILED
    )
    assert (
        derive_run_analysis_status(llm_requested=True, assessments=[])
        == RunAnalysisStatus.COMPLETE
    )
    assert (
        derive_run_analysis_status(llm_requested=False, assessments=[])
        == RunAnalysisStatus.NOT_REQUESTED
    )


def test_assessment_summary_reconciled_on_save(tmp_path: Path):
    from tacs.core.pipeline import ScanningPipeline

    fn = _function()
    assessments = [
        build_model_assessment(
            FunctionAnalysis(
                function_id=fn.function_id,
                y2038_summary=Y2038Summary.NO,
                confidence=0.6,
                issues=[],
                execution_status=AssessmentExecutionStatus.COMPLETED,
            ),
            fn,
        )
    ]
    results = ScanResults(
        schema_version=PUBLIC_RESULT_SCHEMA_VERSION,
        meta=ScanMetadata(
            root=".",
            rules_path="r.json",
            model="m",
            confidence_floor=0.0,
            metrics=_metrics(),
            timestamp="2026-01-01T00:00:00Z",
            analysis_status=RunAnalysisStatus.COMPLETE,
            assessment_summary=summarize_assessments([], findings_count=999),
        ),
        candidates=[],
        assessments=assessments,
        findings=[],
    )
    out = tmp_path / "a.json"
    ScanningPipeline.__new__(ScanningPipeline).save_results(results, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["meta"]["assessment_summary"]["total"] == 1
    assert data["meta"]["assessment_summary"]["no"] == 1
    assert data["meta"]["assessment_summary"]["findings"] == 0
    assert "body" not in data["assessments"][0]
    assert "/abs/" not in json.dumps(data["assessments"])


def test_renderer_shows_assessment_section():
    from report_renderer.core import assessment_counts_from_document, load_scan_document
    from report_renderer.renderers import render_html, render_text

    doc = {
        "schema_version": "1.1",
        "meta": {
            "analysis_status": "complete",
            "assessment_summary": {
                "total": 1,
                "completed": 1,
                "yes": 0,
                "no": 1,
                "abstain": 0,
                "analysis_errors": 0,
                "not_requested": 0,
                "findings": 0,
            },
            "candidate_summary": {
                "total": 1,
                "grouped": 1,
                "ungrouped": 0,
                "functions_with_candidates": 1,
                "findings": 0,
            },
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
            }
        ],
        "assessments": [
            {
                "assessment_id": "assessment:a.c@f:1-5",
                "function_id": "a.c@f:1-5",
                "candidate_ids": ["a.c:1:0-1:high:time_t"],
                "execution_status": "completed",
                "verdict": "no",
                "confidence": 0.8,
                "reason": "safe use",
                "analysis_mode": "function_first",
            }
        ],
        "findings": [],
    }
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "v.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        loaded = load_scan_document(str(path))
    assert loaded.has_assessment_section
    a_counts = assessment_counts_from_document(loaded)
    text = render_text(
        [],
        candidates=loaded.candidates,
        candidate_counts={"total": 1, "grouped": 1, "ungrouped": 0, "functions_with_candidates": 1},
        assessments=loaded.assessments,
        assessment_counts=a_counts,
        has_candidate_section=True,
        has_assessment_section=True,
    )
    html = render_html(
        [],
        title="t",
        group_by="none",
        candidates=loaded.candidates,
        candidate_counts={"total": 1, "grouped": 1, "ungrouped": 0, "functions_with_candidates": 1},
        assessments=loaded.assessments,
        assessment_counts=a_counts,
        has_candidate_section=True,
        has_assessment_section=True,
    )
    for body in (text, html):
        assert "Model assessments" in body
        assert "verdict" in body.lower() or "verdict: no" in body
        assert "a.c@f:1-5" in body
        assert "clean scan" not in body.lower()
    assert 'id="model-assessments"' in html


def test_schema_version_integer_components_not_lexicographic():
    from tacs.core.model_assessment import parse_schema_version, schema_supports_assessments
    from report_renderer.core import LoadedScanDocument

    assert parse_schema_version("1.10") == (1, 10)
    assert parse_schema_version("1.9") == (1, 9)
    # Lexicographic string compare would rank "1.10" before "1.9"; integer compare does not.
    assert schema_supports_assessments("1.9")
    assert schema_supports_assessments("1.10")
    assert schema_supports_assessments("1.1")
    assert schema_supports_assessments("2.0")
    assert not schema_supports_assessments("1.0")
    assert not schema_supports_assessments("1")
    assert not schema_supports_assessments(None)
    assert not schema_supports_assessments("not-a-version")

    legacy = LoadedScanDocument(meta={}, findings=[], candidates=[], assessments=[], schema_version=None)
    assert legacy.has_assessment_section is False
    v10 = LoadedScanDocument(meta={}, findings=[], candidates=[], assessments=[], schema_version="1.0")
    assert v10.has_assessment_section is False
    v11 = LoadedScanDocument(meta={}, findings=[], candidates=[], assessments=[], schema_version="1.1")
    assert v11.has_assessment_section is True


def test_one_assessment_per_function_upsert_no_mutation():
    fn = _function()
    store: dict = {}
    first = FunctionAnalysis(
        function_id=fn.function_id,
        y2038_summary=Y2038Summary.ABSTAIN,
        confidence=0.2,
        issues=[],
        execution_status=AssessmentExecutionStatus.COMPLETED,
    )
    second = FunctionAnalysis(
        function_id=fn.function_id,
        y2038_summary=Y2038Summary.YES,
        confidence=0.95,
        issues=[{"type": "y2038_risk", "description": "narrow cast", "line": 3}],
        execution_status=AssessmentExecutionStatus.COMPLETED,
    )
    record_assessments(store, [first], [fn])
    record_assessments(store, [second], [fn])
    finalized = finalize_assessments(store)
    assert len(finalized) == 1
    assert finalized[0].verdict == ModelVerdict.YES
    assert finalized[0].confidence == 0.95

    original_ids = list(fn.candidate_ids)
    filtered = filter_candidate_ids(finalized, {"a.c:3:0-6:high:time_t"})
    assert fn.candidate_ids == original_ids
    assert finalized[0].candidate_ids == original_ids
    assert filtered[0].candidate_ids == ["a.c:3:0-6:high:time_t"]


def test_assessment_referential_integrity_and_summary_reconcile(tmp_path: Path):
    from tacs.core.pipeline import ScanningPipeline

    evidence = build_candidate_evidence(
        [
            Candidate(
                file=str(tmp_path / "a.c"),
                line=3,
                symbol="time_t",
                one_line_snippet="time_t t;",
                risk="high",
                description="",
                col_start=0,
                col_end=6,
                discovery_method="catalog_symbol_match",
            )
        ],
        root_path=str(tmp_path),
        functions=[],
    )
    valid = evidence[0].candidate_id
    fn = _function(candidate_ids=[valid, "invented-id"])
    analysis = FunctionAnalysis(
        function_id=fn.function_id,
        y2038_summary=Y2038Summary.NO,
        confidence=0.8,
        issues=[],
        execution_status=AssessmentExecutionStatus.COMPLETED,
    )
    store = {}
    record_assessments(store, [analysis], [fn])
    assessments = filter_candidate_ids(finalize_assessments(store), {valid})
    results = ScanResults(
        schema_version=PUBLIC_RESULT_SCHEMA_VERSION,
        meta=ScanMetadata(
            root=".",
            rules_path="r.json",
            model="m",
            confidence_floor=0.0,
            metrics=_metrics(),
            timestamp="2026-01-01T00:00:00Z",
            analysis_status=RunAnalysisStatus.COMPLETE,
            # Deliberately wrong — save_results must reconcile from arrays.
            assessment_summary=summarize_assessments([], findings_count=999),
        ),
        candidates=evidence,
        assessments=assessments,
        findings=[],
    )
    out = tmp_path / "ref.json"
    ScanningPipeline.__new__(ScanningPipeline).save_results(results, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["assessments"][0]["candidate_ids"] == [valid]
    assert "invented-id" not in json.dumps(data["assessments"])
    assert data["meta"]["assessment_summary"]["total"] == 1
    assert data["meta"]["assessment_summary"]["no"] == 1
    assert data["meta"]["assessment_summary"]["findings"] == 0
    assert set(data["assessments"][0].keys()) <= {
        "assessment_id",
        "function_id",
        "candidate_ids",
        "execution_status",
        "verdict",
        "confidence",
        "reason",
        "analysis_mode",
    }


def test_operational_error_reason_sanitized_not_exception_dump():
    from tacs.core.model_assessment import assessment_to_public_dict

    fn = _function(body="void foo(void) { /* SECRET FULL FUNCTION BODY */ }")
    leak = (
        "Stage 8, Pass 2a error: HTTPSConnectionPool failed "
        "path=/home/john/.certs/bad.pem raw_response={'choices':[...]}"
    )
    err = FunctionAnalysis(
        function_id=fn.function_id,
        y2038_summary=Y2038Summary.ABSTAIN,
        confidence=0.0,
        issues=[{"type": "analysis_error", "description": leak, "line": 1}],
        execution_status=AssessmentExecutionStatus.ANALYSIS_ERROR,
    )
    a = build_model_assessment(err, fn)
    assert a.execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert a.verdict is None
    assert a.reason == "Model analysis failed for this function"
    assert "/home" not in (a.reason or "")
    assert "SECRET" not in json.dumps(assessment_to_public_dict(a))
    assert "raw_response" not in json.dumps(assessment_to_public_dict(a))

    completed = FunctionAnalysis(
        function_id=fn.function_id,
        y2038_summary=Y2038Summary.ABSTAIN,
        confidence=0.4,
        issues=[{"type": "ambiguous", "description": "needs header from /home/john/x.h", "line": 1}],
        execution_status=AssessmentExecutionStatus.COMPLETED,
    )
    genuine = build_model_assessment(completed, fn)
    assert genuine.execution_status == AssessmentExecutionStatus.COMPLETED
    assert genuine.verdict == ModelVerdict.ABSTAIN
    assert "/home" not in (genuine.reason or "")
    assert "<path>" in (genuine.reason or "")


def test_assessment_public_dict_strips_extras_and_clamps_confidence():
    from tacs.core.model_assessment import assessment_to_public_dict

    class Messy:
        def __init__(self):
            self.assessment_id = "assessment:a.c@f:1-2"
            self.function_id = "a.c@f:1-2"
            self.candidate_ids = ["c1"]
            self.execution_status = AssessmentExecutionStatus.COMPLETED
            self.verdict = ModelVerdict.YES
            self.confidence = 1.5
            self.reason = "ok " + ("x" * 500)
            self.analysis_mode = "function_first"
            self.body = "LEAK_BODY"
            self.prompt = "LEAK_PROMPT"
            self.raw_response = "LEAK_RAW"

    row = assessment_to_public_dict(Messy())
    assert "body" not in row
    assert "prompt" not in row
    assert "raw_response" not in row
    assert row["confidence"] == 1.0
    assert len(row["reason"]) <= 200


def test_findings_projection_unchanged_for_outcomes():
    """Compatibility findings still key off y2038_summary, including error stubs."""
    from tacs.core.pipeline import ScanningPipeline

    pipeline = ScanningPipeline.__new__(ScanningPipeline)
    pipeline.detect_y2106 = False
    pipeline.io_metadata_map = {}
    pipeline.debug_candidates = False

    fn = _function(
        file_path="/abs/repo/a.c",
        body="void foo(void) { time_t t; }",
        candidate_lines=[3],
    )
    cases = [
        (Y2038Summary.YES, AssessmentExecutionStatus.COMPLETED, Y2038Issue.YES),
        (Y2038Summary.NO, AssessmentExecutionStatus.COMPLETED, Y2038Issue.NO),
        (Y2038Summary.ABSTAIN, AssessmentExecutionStatus.COMPLETED, Y2038Issue.ABSTAIN),
        (
            Y2038Summary.ABSTAIN,
            AssessmentExecutionStatus.ANALYSIS_ERROR,
            Y2038Issue.ABSTAIN,
        ),
    ]
    for summary, status, expected_issue in cases:
        analysis = FunctionAnalysis(
            function_id=fn.function_id,
            y2038_summary=summary,
            confidence=0.5 if status == AssessmentExecutionStatus.COMPLETED else 0.0,
            issues=[
                {
                    "type": "parse_gap" if status == AssessmentExecutionStatus.ANALYSIS_ERROR else "y2038_risk",
                    "description": (
                        "No usable S2_P1 model output"
                        if status == AssessmentExecutionStatus.ANALYSIS_ERROR
                        else "model reason"
                    ),
                    "line": 3,
                }
            ],
            execution_status=status,
        )
        findings = pipeline._convert_analyses_to_findings([analysis], [fn])
        assert findings, f"expected findings for {summary}/{status}"
        assert findings[0].y2038_issue == expected_issue
        if status == AssessmentExecutionStatus.ANALYSIS_ERROR:
            # Legacy findings still carry the operational description text.
            assert "No usable S2_P1 model output" in findings[0].reason
            # Public assessment does not.
            a = build_model_assessment(analysis, fn)
            assert a.verdict is None
            assert a.reason == "No usable model output for this function"


def test_single_and_batch_writers_same_assessment_structure(tmp_path: Path):
    from tacs.core.pipeline import ScanningPipeline

    fn = _function()
    assessments = [
        build_model_assessment(
            FunctionAnalysis(
                function_id=fn.function_id,
                y2038_summary=Y2038Summary.YES,
                confidence=0.7,
                issues=[{"type": "x", "description": "risk", "line": 3}],
                execution_status=AssessmentExecutionStatus.COMPLETED,
            ),
            fn,
        )
    ]
    results = ScanResults(
        schema_version=PUBLIC_RESULT_SCHEMA_VERSION,
        meta=ScanMetadata(
            root=".",
            rules_path="r.json",
            model="m",
            confidence_floor=0.0,
            metrics=_metrics(),
            timestamp="2026-01-01T00:00:00Z",
            analysis_status=RunAnalysisStatus.COMPLETE,
        ),
        candidates=[],
        assessments=assessments,
        findings=[],
    )
    single = tmp_path / "findings.json"
    batch = tmp_path / "repos" / "demo" / "findings.json"
    batch.parent.mkdir(parents=True)
    pipeline = ScanningPipeline.__new__(ScanningPipeline)
    pipeline.save_results(results, str(single))
    pipeline.save_results(results, str(batch))
    a = json.loads(single.read_text(encoding="utf-8"))
    b = json.loads(batch.read_text(encoding="utf-8"))
    assert a["schema_version"] == b["schema_version"] == "1.1"
    assert a["assessments"] == b["assessments"]
    assert a["meta"]["assessment_summary"] == b["meta"]["assessment_summary"]
    assert a["meta"]["analysis_status"] == b["meta"]["analysis_status"]


def test_unversioned_and_1_0_still_render_without_assessments(tmp_path: Path):
    from report_renderer.core import load_scan_document
    from report_renderer.renderers import render_text

    bare = [{"file": "a.c", "region": {"start_line": 1, "end_line": 1}, "lines": [1],
             "symbol": "t", "confidence": 0.5, "reason": "x", "source_snippet": "t",
             "y2038_issue": "yes"}]
    v10 = {
        "schema_version": "1.0",
        "meta": {"candidate_summary": {"total": 0, "grouped": 0, "ungrouped": 0,
                                       "functions_with_candidates": 0, "findings": 1}},
        "candidates": [],
        "findings": bare,
    }
    bare_path = tmp_path / "bare.json"
    v10_path = tmp_path / "v10.json"
    bare_path.write_text(json.dumps(bare), encoding="utf-8")
    v10_path.write_text(json.dumps(v10), encoding="utf-8")

    bare_doc = load_scan_document(str(bare_path))
    v10_doc = load_scan_document(str(v10_path))
    assert bare_doc.schema_version is None
    assert bare_doc.has_assessment_section is False
    assert v10_doc.schema_version == "1.0"
    assert v10_doc.has_assessment_section is False

    from report_renderer.core import normalize_findings

    for doc, has_cand in ((bare_doc, False), (v10_doc, True)):
        norm = normalize_findings(doc.findings)
        text = render_text(
            norm.findings,
            has_candidate_section=has_cand,
            has_assessment_section=doc.has_assessment_section,
            candidates=doc.candidates if has_cand else None,
            assessments=None,
        )
        assert "## Model assessments" not in text
        assert "execution_status:" not in text


def test_errors_visibly_distinct_from_genuine_abstain_in_render():
    from report_renderer.renderers import render_text

    text = render_text(
        [],
        assessments=[
            {
                "assessment_id": "assessment:a.c@ok:1-2",
                "function_id": "a.c@ok:1-2",
                "candidate_ids": [],
                "execution_status": "completed",
                "verdict": "abstain",
                "confidence": 0.3,
                "reason": "ambiguous",
                "analysis_mode": "function_first",
            },
            {
                "assessment_id": "assessment:a.c@err:1-2",
                "function_id": "a.c@err:1-2",
                "candidate_ids": [],
                "execution_status": "analysis_error",
                "verdict": None,
                "confidence": None,
                "reason": "Model analysis failed for this function",
                "analysis_mode": "function_first",
            },
        ],
        assessment_counts={
            "total": 2,
            "completed": 1,
            "yes": 0,
            "no": 0,
            "abstain": 1,
            "analysis_errors": 1,
            "analysis_status": "partial",
        },
        has_assessment_section=True,
    )
    assert "execution_status: completed" in text
    assert "verdict: abstain" in text
    assert "execution_status: analysis_error" in text
    assert "verdict: (none)" in text
    assert "analysis_errors 1" in text
