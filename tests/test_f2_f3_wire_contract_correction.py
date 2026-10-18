# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Pass F2/F3 shared wire-contract, progress, and analysis-error presentation."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from report_renderer.core import normalize_findings
from report_renderer.renderers import render_html, render_text
from tacs.core.function_analysis_response import (
    ISSUE_INVALID_SCHEMA,
    canonical_wire_contract_prompt,
    count_analyses_by_execution,
    format_classification_counts,
)
from tacs.core.function_llm_client import FunctionLLMClient
from tacs.core.function_schemas import (
    FunctionAnalysis,
    FunctionBatch,
    FunctionBody,
    Y2038Summary,
)
from tacs.core.llm_client import LLMClient
from tacs.core.model_assessment import build_model_assessment, record_assessments
from tacs.core.pipeline import ScanningPipeline
from tacs.core.schema import AssessmentExecutionStatus


def _func(
    function_id: str,
    *,
    symbol: str = "fn",
    start: int = 1,
    end: int = 2,
) -> FunctionBody:
    return FunctionBody(
        function_id=function_id,
        file_path=f"/tmp/{function_id.split('@')[0]}",
        symbol=symbol,
        start_line=start,
        end_line=end,
        body=f"int {symbol}(void) {{ return 0; }}",
        candidate_lines=[start],
    )


def _item(
    function_id: str,
    summary: str = "no",
    *,
    confidence: float = 0.9,
    needs_more_context: bool = False,
    needs: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "function_id": function_id,
        "y2038_summary": summary,
        "confidence": confidence,
        "issues": [],
        "needs_more_context": needs_more_context,
        "needs": list(needs or []),
    }


def _client() -> FunctionLLMClient:
    return FunctionLLMClient(
        llm_type="none",
        model="none",
        environment_config=None,
        timeout_sec=30,
        batch_size_func=8,
        confidence_floor=0.5,
    )


def _batch(functions: List[FunctionBody]) -> FunctionBatch:
    return FunctionBatch(batch_id="b", functions=functions)


def _response(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "choices": [
            {
                "message": {"content": json.dumps(items)},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }


def _invalid_item(function_id: str) -> Dict[str, Any]:
    # Missing required fields + forbidden extra → schema fail-closed.
    return {
        "function_id": function_id,
        "y2038_summary": "maybe",
        "extra_field": True,
    }


# --- shared wire-contract prompt --------------------------------------------


def test_f1_f2_f3_embed_identical_canonical_wire_contract() -> None:
    contract = canonical_wire_contract_prompt(detect_y2106=False)
    assert "WIRE CONTRACT (authoritative" in contract
    assert "Extra top-level or issue fields are forbidden" in contract
    assert '"y2038_summary": "yes|no|abstain"' in contract

    client = _client()
    batch = _batch([_func("a.c@a:1-1", symbol="a")])
    systems = [
        client._build_pass_f1_prompt(batch).system,
        client._build_pass_f2_prompt(batch, iteration=2).system,
        client._build_pass_f3_prompt(batch).system,
    ]
    for system in systems:
        assert contract in system
        assert "same schema as Pass F1" not in system
        assert "identical schema" not in system.lower()

    # Exactly one shared fragment definition; all three reuse it verbatim.
    assert systems[0].count(contract) == 1
    assert systems[1].count(contract) == 1
    assert systems[2].count(contract) == 1


def test_y2106_wire_contract_also_shared_across_passes() -> None:
    contract = canonical_wire_contract_prompt(detect_y2106=True)
    client = FunctionLLMClient(
        llm_type="none",
        model="none",
        environment_config=None,
        timeout_sec=30,
        batch_size_func=8,
        confidence_floor=0.5,
        detect_y2106=True,
    )
    batch = _batch([_func("a.c@a:1-1", symbol="a")])
    for system in (
        client._build_pass_f1_prompt(batch).system,
        client._build_pass_f2_prompt(batch, iteration=1).system,
        client._build_pass_f3_prompt(batch).system,
    ):
        assert contract in system
        assert "y2106_summary" in system


# --- enrichment eligibility / valid abstain ---------------------------------


def test_valid_f1_abstention_remains_enrichment_eligible(tmp_path: Path) -> None:
    ok = _func("ok.c@ok:1-1", symbol="ok")
    ok = ok.model_copy(update={"file_path": str(tmp_path / "ok.c")})
    (tmp_path / "ok.c").write_text("int ok(void){return 0;}\n", encoding="utf-8")

    scanner_path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "tacs"
        / "python"
        / "y2038scan_fast_json_group.py"
    )
    pipeline = ScanningPipeline(
        scanner_path=str(scanner_path),
        llm_type="none",
        model="none",
        function_first=True,
        confidence_floor=0.5,
    )
    record_assessments(
        pipeline._assessment_store,
        [
            FunctionAnalysis(
                function_id=ok.function_id,
                y2038_summary=Y2038Summary.ABSTAIN,
                confidence=0.4,
                issues=[],
                needs_more_context=True,
                needs=["header"],
                execution_status=AssessmentExecutionStatus.COMPLETED,
            )
        ],
        [ok],
    )
    assert ok.function_id in pipeline._completed_abstain_function_ids()


def test_valid_f2_abstention_is_completed_assessment() -> None:
    a = _func("a.c@a:1-1", symbol="a")
    client = _client()
    items = [
        _item(
            a.function_id,
            "abstain",
            needs_more_context=True,
            needs=["header"],
            confidence=0.35,
        )
    ]
    analyses = client._parse_pass_f2_response(_response(items), [a])
    assert len(analyses) == 1
    assert analyses[0].execution_status == AssessmentExecutionStatus.COMPLETED
    assert analyses[0].y2038_summary == Y2038Summary.ABSTAIN
    assessment = build_model_assessment(analyses[0], a)
    assert assessment.execution_status == AssessmentExecutionStatus.COMPLETED
    assert assessment.verdict.value == "abstain"


# --- invalid F2/F3 schema: one analysis_error, no HTTP retry ----------------


@pytest.mark.parametrize("pass_name", ["f2", "f3"])
def test_invalid_enrichment_response_one_analysis_error_no_http_retry(
    monkeypatch: pytest.MonkeyPatch, pass_name: str
) -> None:
    a = _func("a.c@a:1-1", symbol="a")
    calls: list[int] = []

    def fake_make(self, prompt):  # noqa: ANN001
        calls.append(1)
        return _response([_invalid_item(a.function_id)])

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setattr(LLMClient, "_make_api_request", fake_make)
    monkeypatch.setattr("time.sleep", lambda *_a, **_k: None)

    client = FunctionLLMClient(
        llm_type="openai",
        model="gpt-4.1-mini",
        environment_config=None,
        timeout_sec=5,
        batch_size_func=8,
        confidence_floor=0.5,
    )
    batch = _batch([a])
    if pass_name == "f2":
        analyses = client.analyze_functions_pass_f2(batch, iteration=2)
    else:
        analyses = client.analyze_functions_pass_f3(batch)

    assert len(calls) == 1
    assert len(analyses) == 1
    assert analyses[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert analyses[0].y2038_summary == Y2038Summary.ABSTAIN  # compatibility stub
    types = [
        i.get("type") for i in (analyses[0].issues or []) if isinstance(i, dict)
    ]
    assert ISSUE_INVALID_SCHEMA in types
    assessment = build_model_assessment(analyses[0], a)
    assert assessment.execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert assessment.verdict is None


def test_forbidden_extra_field_rejected() -> None:
    a = _func("a.c@a:1-1", symbol="a")
    item = _item(a.function_id, "no")
    item["classification"] = "safe"
    analyses = _client()._parse_pass_f2_response(_response([item]), [a])
    assert analyses[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    types = [
        i.get("type") for i in (analyses[0].issues or []) if isinstance(i, dict)
    ]
    assert ISSUE_INVALID_SCHEMA in types


# --- progress counters ------------------------------------------------------


def test_analysis_errors_do_not_increment_genuine_abstain_counters() -> None:
    analyses = [
        FunctionAnalysis(
            function_id="a.c@a:1-1",
            y2038_summary=Y2038Summary.ABSTAIN,
            confidence=0.4,
            issues=[],
            needs_more_context=True,
            needs=[],
            execution_status=AssessmentExecutionStatus.COMPLETED,
        ),
        FunctionAnalysis(
            function_id="b.c@b:2-2",
            y2038_summary=Y2038Summary.ABSTAIN,
            confidence=0.0,
            issues=[
                {
                    "type": ISSUE_INVALID_SCHEMA,
                    "line": 2,
                    "description": "invalid",
                }
            ],
            needs_more_context=False,
            needs=[],
            execution_status=AssessmentExecutionStatus.ANALYSIS_ERROR,
        ),
        FunctionAnalysis(
            function_id="c.c@c:3-3",
            y2038_summary=Y2038Summary.YES,
            confidence=0.9,
            issues=[{"type": "risk", "line": 3, "description": "narrow"}],
            needs_more_context=False,
            needs=[],
            execution_status=AssessmentExecutionStatus.COMPLETED,
        ),
    ]
    counts = count_analyses_by_execution(analyses)
    assert counts == {
        "yes": 1,
        "no": 0,
        "abstain": 1,
        "analysis_errors": 1,
        "total": 3,
    }
    formatted = format_classification_counts(counts)
    assert formatted == "1 yes, 0 no, 1 abstain, 1 analysis_error"
    assert "2 abstain" not in formatted


def test_progress_output_reports_yes_no_abstain_analysis_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    a = _func("a.c@a:1-1", symbol="a")
    b = _func("b.c@b:2-2", symbol="b", start=2, end=2)

    def fake_make(self, prompt):  # noqa: ANN001
        return _response(
            [
                _item(a.function_id, "abstain", needs_more_context=True, needs=["header"]),
                _invalid_item(b.function_id),
            ]
        )

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setattr(LLMClient, "_make_api_request", fake_make)

    client = FunctionLLMClient(
        llm_type="openai",
        model="gpt-4.1-mini",
        environment_config=None,
        timeout_sec=5,
        batch_size_func=8,
        confidence_floor=0.5,
    )
    with caplog.at_level(logging.INFO, logger="tacs"):
        client.analyze_functions_pass_f2(_batch([a, b]), iteration=2)
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "0 yes, 0 no, 1 abstain, 1 analysis_error" in joined


def test_assessment_store_counters_separate_errors(tmp_path: Path) -> None:
    scanner_path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "tacs"
        / "python"
        / "y2038scan_fast_json_group.py"
    )
    pipeline = ScanningPipeline(
        scanner_path=str(scanner_path),
        llm_type="none",
        model="none",
        function_first=True,
        confidence_floor=0.5,
    )
    a = _func("a.c@a:1-1", symbol="a")
    b = _func("b.c@b:2-2", symbol="b", start=2, end=2)
    record_assessments(
        pipeline._assessment_store,
        [
            FunctionAnalysis(
                function_id=a.function_id,
                y2038_summary=Y2038Summary.ABSTAIN,
                confidence=0.4,
                issues=[],
                needs_more_context=True,
                needs=[],
                execution_status=AssessmentExecutionStatus.COMPLETED,
            ),
            FunctionAnalysis(
                function_id=b.function_id,
                y2038_summary=Y2038Summary.ABSTAIN,
                confidence=0.0,
                issues=[
                    {
                        "type": ISSUE_INVALID_SCHEMA,
                        "line": 2,
                        "description": "bad",
                    }
                ],
                needs_more_context=False,
                needs=[],
                execution_status=AssessmentExecutionStatus.ANALYSIS_ERROR,
            ),
        ],
        [a, b],
    )
    counts = pipeline._function_classification_counts_from_assessments()
    assert counts["abstain"] == 1
    assert counts["analysis_errors"] == 1
    assert "1 abstain, 1 analysis_error" in pipeline._format_function_classification_counts(
        counts
    )


# --- public rendering -------------------------------------------------------


def test_text_and_html_distinguish_analysis_error_from_abstain() -> None:
    findings_raw = [
        {
            "file": "ok.c",
            "region": {"start_line": 1, "end_line": 1},
            "lines": [1],
            "function_id": "ok.c@ok:1-1",
            "source_snippet": "int ok(void){return 0;}\n",
            "y2038_issue": "abstain",
            "severity": "low",
            "confidence": 0.4,
            "reason": "Function analysis: abstain (needs more context)",
            "rule_id": "TACS-RULE-0001",
        },
        {
            "file": "err.c",
            "region": {"start_line": 2, "end_line": 2},
            "lines": [2],
            "function_id": "err.c@err:2-2",
            "source_snippet": "int err(void){return 0;}\n",
            "y2038_issue": "abstain",  # compatibility stub shape
            "severity": "low",
            "confidence": 0.0,
            "reason": "Model analysis failed for this function",
            "rule_id": "TACS-RULE-0001",
        },
    ]
    assessments = [
        {
            "assessment_id": "assessment:ok.c@ok:1-1",
            "function_id": "ok.c@ok:1-1",
            "candidate_ids": [],
            "execution_status": "completed",
            "verdict": "abstain",
            "confidence": 0.4,
            "reason": "ambiguous",
            "analysis_mode": "function_first",
        },
        {
            "assessment_id": "assessment:err.c@err:2-2",
            "function_id": "err.c@err:2-2",
            "candidate_ids": [],
            "execution_status": "analysis_error",
            "verdict": None,
            "confidence": None,
            "reason": "Model analysis failed for this function",
            "analysis_mode": "function_first",
        },
    ]
    norm = normalize_findings(findings_raw).findings
    text = render_text(
        norm,
        assessments=assessments,
        has_assessment_section=True,
    )
    html = render_html(
        norm,
        title="t",
        group_by="none",
        assessments=assessments,
        has_assessment_section=True,
    )
    assert "Issue: abstain classification" in text
    assert "Issue: analysis_error classification" in text
    assert text.count("Issue: abstain classification") == 1
    assert 'class="badge abstain">abstain</span>' in html
    assert 'class="badge analysis_error">analysis_error</span>' in html
    assert "analysis_error: 1" in html
    assert "abstain: 1" in html


def test_legacy_reports_without_assessments_still_render_abstain() -> None:
    findings_raw = [
        {
            "file": "legacy.c",
            "region": {"start_line": 1, "end_line": 1},
            "lines": [1],
            "function_id": "legacy.c@fn:1-1",
            "source_snippet": "int fn(void){return 0;}\n",
            "y2038_issue": "abstain",
            "severity": "low",
            "confidence": 0.3,
            "reason": "needs context",
            "rule_id": "TACS-RULE-0001",
        }
    ]
    norm = normalize_findings(findings_raw).findings
    text = render_text(norm)
    html = render_html(norm, title="t", group_by="none")
    assert "Issue: abstain classification" in text
    assert "analysis_error" not in text
    assert 'class="badge abstain">abstain</span>' in html


def test_empty_result_rendering_keeps_provenance() -> None:
    meta = {
        "model": "gpt-6-luna",
        "llm_provider": "openai",
        "reasoning_effort": "none",
    }
    text = render_text([], meta=meta)
    html = render_html([], title="t", group_by="file", meta=meta)
    assert "provider: openai" in text
    assert "model: gpt-6-luna" in text
    assert "reasoning_effort: none" in text
    assert "provider: openai" in html
    assert "model: gpt-6-luna" in html
    assert "reasoning_effort: none" in html


# --- offline demos (mocked; no live provider) -------------------------------


def test_offline_demo_valid_f2_abstain_invalid_schema_and_counters(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Offline demonstration: valid F2 abstain, invalid F2 schema, final counters."""
    good = _func("good.c@g:1-1", symbol="g")
    bad = _func("bad.c@b:2-2", symbol="b", start=2, end=2)
    calls: list[int] = []

    def fake_make(self, prompt):  # noqa: ANN001
        calls.append(1)
        return _response(
            [
                _item(
                    good.function_id,
                    "abstain",
                    needs_more_context=True,
                    needs=["typedef"],
                    confidence=0.3,
                ),
                _invalid_item(bad.function_id),
            ]
        )

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setattr(LLMClient, "_make_api_request", fake_make)

    client = FunctionLLMClient(
        llm_type="openai",
        model="gpt-4.1-mini",
        environment_config=None,
        timeout_sec=5,
        batch_size_func=8,
        confidence_floor=0.5,
    )
    with caplog.at_level(logging.INFO, logger="tacs"):
        analyses = client.analyze_functions_pass_f2(_batch([good, bad]), iteration=2)

    assert len(calls) == 1  # no schema HTTP retry
    by_id = {a.function_id: a for a in analyses}
    assert by_id[good.function_id].execution_status == AssessmentExecutionStatus.COMPLETED
    assert by_id[good.function_id].y2038_summary == Y2038Summary.ABSTAIN
    assert by_id[bad.function_id].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR

    counts = count_analyses_by_execution(analyses)
    assert counts["abstain"] == 1
    assert counts["analysis_errors"] == 1
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert "1 abstain, 1 analysis_error" in joined
