# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Exact function_id binding and strict wire-contract regression tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from tacs.core.function_analysis_response import (
    ISSUE_DUPLICATE_ID,
    ISSUE_INVALID_SCHEMA,
    ISSUE_MISSING_EXPECTED,
    align_model_items_to_functions,
)
from tacs.core.function_llm_client import FunctionLLMClient
from tacs.core.function_schemas import FunctionAnalysis, FunctionBatch, FunctionBody, Y2038Summary
from tacs.core.llm_prompt import LLMPromptParts
from tacs.core.model_assessment import build_model_assessment, record_assessments
from tacs.core.schema import (
    AssessmentExecutionStatus,
    Candidate,
    Finding,
    ModelVerdict,
    Y2038Issue,
)
from tacs.core.scan_session import ScanSession


def _func(
    function_id: str,
    *,
    symbol: str = "fn",
    start: int = 1,
    end: int = 2,
    candidate_ids: Optional[List[str]] = None,
) -> FunctionBody:
    return FunctionBody(
        function_id=function_id,
        file_path=f"/tmp/{function_id.split('@')[0]}",
        symbol=symbol,
        start_line=start,
        end_line=end,
        body=f"int {symbol}(void) {{ return 0; }}",
        candidate_lines=[start],
        candidate_ids=list(candidate_ids or []),
    )


def _item(
    function_id: str,
    summary: str = "no",
    *,
    confidence: float = 0.9,
    needs_more_context: bool = False,
    needs: Optional[List[str]] = None,
    issue_type: str = "safe",
    line: int = 1,
) -> Dict[str, Any]:
    return {
        "function_id": function_id,
        "y2038_summary": summary,
        "confidence": confidence,
        "issues": [
            {
                "type": issue_type,
                "line": line,
                "description": f"{summary} for {function_id}",
            }
        ],
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


def _parse(items: List[Dict[str, Any]], functions: List[FunctionBody]) -> List[FunctionAnalysis]:
    client = _client()
    payload = {"choices": [{"message": {"content": json.dumps(items)}}]}
    return client._parse_function_response(payload, functions, "S2_P1")


def _issue_types(analysis: FunctionAnalysis) -> List[str]:
    return [
        str(i.get("type"))
        for i in (analysis.issues or [])
        if isinstance(i, dict) and i.get("type")
    ]


# --- Core alignment ----------------------------------------------------------


def test_reordered_valid_items_map_by_exact_id() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    b = _func("b.c@beta:3-4", symbol="beta", start=3, end=4)
    analyses = _parse([_item(b.function_id, "yes"), _item(a.function_id, "no")], [a, b])
    assert [x.function_id for x in analyses] == [a.function_id, b.function_id]
    assert analyses[0].y2038_summary == Y2038Summary.NO
    assert analyses[1].y2038_summary == Y2038Summary.YES
    assert all(x.execution_status == AssessmentExecutionStatus.COMPLETED for x in analyses)


def test_idless_items_are_not_bound_by_position() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    b = _func("b.c@beta:3-4", symbol="beta", start=3, end=4)
    idless = [
        {
            "y2038_summary": "yes",
            "confidence": 0.99,
            "issues": [{"type": "risk", "line": 3, "description": "meant for beta"}],
            "needs_more_context": False,
            "needs": [],
        },
        {
            "y2038_summary": "no",
            "confidence": 0.99,
            "issues": [{"type": "safe", "line": 1, "description": "meant for alpha"}],
            "needs_more_context": False,
            "needs": [],
        },
    ]
    analyses = _parse(idless, [a, b])
    assert all(x.execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR for x in analyses)
    assert all(x.y2038_summary == Y2038Summary.ABSTAIN for x in analyses)
    assert ISSUE_MISSING_EXPECTED in _issue_types(analyses[0])
    assert ISSUE_MISSING_EXPECTED in _issue_types(analyses[1])
    assert build_model_assessment(analyses[0], a).verdict is None


@pytest.mark.parametrize(
    "bad_id",
    [
        "",
        "   ",
        "\ta.c@alpha:1-2",
        "a.c@alpha:1-2 ",
        "A.C@ALPHA:1-2",
        "prefix-a.c@alpha:1-2",
        "a.c@alpha:1-2-extra",
    ],
)
def test_nonexact_ids_do_not_complete(bad_id: Any) -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    analyses = _parse([_item(bad_id, "yes")], [a])
    assert analyses[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert build_model_assessment(analyses[0], a).verdict is None


def test_non_string_function_id_rejected() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    item = _item(a.function_id, "yes")
    item["function_id"] = 123
    analyses = _parse([item], [a])
    assert analyses[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR


def test_unknown_and_extra_ids_do_not_affect_siblings() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    b = _func("b.c@beta:3-4", symbol="beta", start=3, end=4)
    analyses = _parse(
        [
            _item("other.c@ghost:9-9", "yes"),
            _item(b.function_id, "no"),
        ],
        [a, b],
    )
    assert analyses[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert analyses[1].execution_status == AssessmentExecutionStatus.COMPLETED
    assert analyses[1].y2038_summary == Y2038Summary.NO


def test_duplicate_ids_identical_and_conflicting_fail_closed() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    b = _func("b.c@beta:3-4", symbol="beta", start=3, end=4)
    identical = _parse(
        [_item(a.function_id, "yes", confidence=0.4), _item(a.function_id, "yes", confidence=0.99)],
        [a, b],
    )
    assert identical[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert ISSUE_DUPLICATE_ID in _issue_types(identical[0])
    assert identical[1].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR

    conflicting = _parse(
        [_item(a.function_id, "yes"), _item(a.function_id, "no")],
        [a, b],
    )
    assert conflicting[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert ISSUE_DUPLICATE_ID in _issue_types(conflicting[0])
    assert build_model_assessment(conflicting[0], a).verdict is None


def test_invalid_duplicate_cannot_leave_sibling_completed() -> None:
    """One malformed duplicate must poison the ID even if another item looks valid."""
    a = _func("a.c@alpha:1-2", symbol="alpha")
    valid = _item(a.function_id, "yes")
    invalid = {"function_id": a.function_id, "classification": "safe", "confidence": 0.9}
    analyses = _parse([valid, invalid], [a])
    assert analyses[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert ISSUE_DUPLICATE_ID in _issue_types(analyses[0])


def test_mixed_valid_invalid_preserves_valid_exact_ids() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    b = _func("b.c@beta:3-4", symbol="beta", start=3, end=4)
    analyses = _parse(
        [
            _item(a.function_id, "yes"),
            {"function_id": b.function_id, "classification": "safe", "confidence": 0.9},
        ],
        [a, b],
    )
    assert analyses[0].execution_status == AssessmentExecutionStatus.COMPLETED
    assert analyses[0].y2038_summary == Y2038Summary.YES
    assert analyses[1].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert ISSUE_INVALID_SCHEMA in _issue_types(analyses[1])


def test_missing_one_expected_while_other_valid() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    b = _func("b.c@beta:3-4", symbol="beta", start=3, end=4)
    analyses = _parse([_item(b.function_id, "no")], [a, b])
    assert analyses[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert ISSUE_MISSING_EXPECTED in _issue_types(analyses[0])
    assert analyses[1].execution_status == AssessmentExecutionStatus.COMPLETED


def test_split_function_ids_are_opaque() -> None:
    part = _func("src/x.c@big:10-40:part2", symbol="big", start=10, end=40)
    analyses = _parse([_item(part.function_id, "abstain", needs_more_context=True, needs=["header"])], [part])
    assert analyses[0].execution_status == AssessmentExecutionStatus.COMPLETED
    assert analyses[0].function_id == part.function_id
    # Near-miss without :part2 must not bind.
    analyses2 = _parse([_item("src/x.c@big:10-40", "yes")], [part])
    assert analyses2[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR


@pytest.mark.parametrize(
    "payload",
    [
        {"classification": "safe"},
        {"y2038_summary": "safe"},
        {"y2038_summary": "YES"},
        {"y2038_summary": "true"},
        {"y2038_summary": "risky"},
        {"functionID": "a.c@alpha:1-2", "y2038_summary": "no"},
        {"function": "a.c@alpha:1-2", "y2038_summary": "no"},
        {"y2038_summary": "no", "confidence": "high"},
        {"y2038_summary": "no", "confidence": True},
        {"y2038_summary": "no", "confidence": 1.5},
        {"y2038_summary": "no", "needs_more_context": "yes"},
        {"y2038_summary": "no", "needs": "header"},
        {"y2038_summary": "no", "issues": "x"},
    ],
)
def test_alias_fields_and_values_rejected(payload: Dict[str, Any]) -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    item = _item(a.function_id, "no")
    item.update(payload)
    if "functionID" in payload or "function" in payload:
        item.pop("function_id", None)
    analyses = _parse([item], [a])
    assert analyses[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR


def test_canonical_yes_no_abstain_complete() -> None:
    funcs = [
        _func("a.c@a:1-1", symbol="a", start=1, end=1),
        _func("b.c@b:2-2", symbol="b", start=2, end=2),
        _func("c.c@c:3-3", symbol="c", start=3, end=3),
    ]
    analyses = _parse(
        [
            _item(funcs[0].function_id, "yes"),
            _item(funcs[1].function_id, "no"),
            _item(funcs[2].function_id, "abstain", needs_more_context=True, needs=["macro"]),
        ],
        funcs,
    )
    assert [a.y2038_summary for a in analyses] == [
        Y2038Summary.YES,
        Y2038Summary.NO,
        Y2038Summary.ABSTAIN,
    ]
    assert all(a.execution_status == AssessmentExecutionStatus.COMPLETED for a in analyses)
    assessments = [build_model_assessment(a, f) for a, f in zip(analyses, funcs)]
    assert [x.verdict for x in assessments] == [
        ModelVerdict.YES,
        ModelVerdict.NO,
        ModelVerdict.ABSTAIN,
    ]


def test_safe_allowed_only_as_issue_type() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    analyses = _parse([_item(a.function_id, "no", issue_type="safe")], [a])
    assert analyses[0].execution_status == AssessmentExecutionStatus.COMPLETED
    assert analyses[0].issues[0]["type"] == "safe"


def _empty_issues_item(
    function_id: str,
    summary: str,
    *,
    needs_more_context: bool = False,
    needs: Optional[List[str]] = None,
    confidence: float = 0.9,
) -> Dict[str, Any]:
    return {
        "function_id": function_id,
        "y2038_summary": summary,
        "confidence": confidence,
        "issues": [],
        "needs_more_context": needs_more_context,
        "needs": list(needs or []),
    }


def test_exact_id_no_with_empty_issues_completes() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    analyses = _parse([_empty_issues_item(a.function_id, "no")], [a])
    assert analyses[0].execution_status == AssessmentExecutionStatus.COMPLETED
    assert analyses[0].y2038_summary == Y2038Summary.NO
    assert analyses[0].issues == []
    assert build_model_assessment(analyses[0], a).verdict == ModelVerdict.NO


def test_exact_id_genuine_abstain_with_empty_issues_completes() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    analyses = _parse(
        [
            _empty_issues_item(
                a.function_id,
                "abstain",
                needs_more_context=True,
                needs=["typedef"],
                confidence=0.4,
            )
        ],
        [a],
    )
    assert analyses[0].execution_status == AssessmentExecutionStatus.COMPLETED
    assert analyses[0].y2038_summary == Y2038Summary.ABSTAIN
    assert analyses[0].issues == []
    assessment = build_model_assessment(analyses[0], a)
    assert assessment.verdict == ModelVerdict.ABSTAIN
    assert assessment.execution_status == AssessmentExecutionStatus.COMPLETED


def test_undocumented_issue_or_top_level_field_fails_only_claimed_id() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    b = _func("b.c@beta:3-4", symbol="beta", start=3, end=4)
    bad_nested = _empty_issues_item(a.function_id, "no")
    bad_nested["issues"] = [
        {
            "type": "safe",
            "line": 1,
            "description": "ok",
            "severity": "high",  # undocumented nested extra
        }
    ]
    analyses = _parse([bad_nested, _empty_issues_item(b.function_id, "no")], [a, b])
    assert analyses[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert ISSUE_INVALID_SCHEMA in _issue_types(analyses[0])
    assert analyses[1].execution_status == AssessmentExecutionStatus.COMPLETED
    assert analyses[1].y2038_summary == Y2038Summary.NO

    bad_top = _empty_issues_item(a.function_id, "no")
    bad_top["notes"] = "undocumented top-level"
    analyses2 = _parse([bad_top, _item(b.function_id, "yes")], [a, b])
    assert analyses2[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert ISSUE_INVALID_SCHEMA in _issue_types(analyses2[0])
    assert analyses2[1].execution_status == AssessmentExecutionStatus.COMPLETED
    assert analyses2[1].y2038_summary == Y2038Summary.YES


def test_empty_issues_compatibility_findings_match_prior_projection() -> None:
    from tacs.core.pipeline import ScanningPipeline

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
    )
    funcs = [
        _func("a.c@yes:1-1", symbol="yes_fn", start=1, end=1),
        _func("b.c@no:2-2", symbol="no_fn", start=2, end=2),
        _func("c.c@abs:3-3", symbol="abs_fn", start=3, end=3),
    ]
    analyses = [
        FunctionAnalysis(
            function_id=funcs[0].function_id,
            y2038_summary=Y2038Summary.YES,
            confidence=0.9,
            issues=[],
            needs_more_context=False,
            needs=[],
            execution_status=AssessmentExecutionStatus.COMPLETED,
        ),
        FunctionAnalysis(
            function_id=funcs[1].function_id,
            y2038_summary=Y2038Summary.NO,
            confidence=0.9,
            issues=[],
            needs_more_context=False,
            needs=[],
            execution_status=AssessmentExecutionStatus.COMPLETED,
        ),
        FunctionAnalysis(
            function_id=funcs[2].function_id,
            y2038_summary=Y2038Summary.ABSTAIN,
            confidence=0.4,
            issues=[],
            needs_more_context=True,
            needs=[],
            execution_status=AssessmentExecutionStatus.COMPLETED,
        ),
    ]
    findings = pipeline._convert_analyses_to_findings(analyses, funcs)
    assert [f.y2038_issue for f in findings] == [
        Y2038Issue.YES,
        Y2038Issue.NO,
        Y2038Issue.ABSTAIN,
    ]
    assert findings[0].symbol == "yes_fn"
    assert findings[1].symbol == "no_fn"
    assert findings[2].symbol == "abs_fn"
    assert "Function analysis: yes" in findings[0].reason
    assert "Function analysis: no" in findings[1].reason
    assert "abstain" in findings[2].reason
    assert findings[2].needs_more_context is True


def test_f2_f3_accept_empty_issues_abstain_exclude_analysis_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "ok.c").write_text("int ok(void){return 0;}\n", encoding="utf-8")
    stub = _RecordingLLM()
    pipeline = _pipeline_with_stub(tmp_path, stub)
    ok = _func("ok.c@ok:1-1", symbol="ok", start=1, end=1)
    ok = ok.model_copy(update={"file_path": str(tmp_path / "ok.c")})
    err = _func("err.c@err:2-2", symbol="err", start=2, end=2)
    record_assessments(
        pipeline._assessment_store,
        [
            FunctionAnalysis(
                function_id=ok.function_id,
                y2038_summary=Y2038Summary.ABSTAIN,
                confidence=0.4,
                issues=[],
                needs_more_context=True,
                needs=[],
                execution_status=AssessmentExecutionStatus.COMPLETED,
            ),
            FunctionAnalysis(
                function_id=err.function_id,
                y2038_summary=Y2038Summary.ABSTAIN,
                confidence=0.0,
                issues=[{"type": ISSUE_MISSING_EXPECTED, "line": 2, "description": "gap"}],
                needs_more_context=True,
                execution_status=AssessmentExecutionStatus.ANALYSIS_ERROR,
            ),
        ],
        [ok, err],
    )
    findings = [
        Finding(
            file=ok.file_path,
            region={"start_line": 1, "end_line": 1},
            lines=[1],
            symbol="ok",
            confidence=0.4,
            reason="Function analysis: abstain (needs more context: header)",
            source_snippet="",
            y2038_issue=Y2038Issue.ABSTAIN,
            needs_more_context=True,
            function_id=ok.function_id,
        ),
        Finding(
            file=err.file_path,
            region={"start_line": 2, "end_line": 2},
            lines=[2],
            symbol="err",
            confidence=0.0,
            reason="analysis_error projected as abstain",
            source_snippet="",
            y2038_issue=Y2038Issue.ABSTAIN,
            needs_more_context=True,
            function_id=err.function_id,
        ),
    ]
    session = ScanSession(root_path=str(tmp_path), output_base=str(tmp_path / "out"))
    pipeline._run_pass_f2(findings, {ok.function_id: ok, err.function_id: err}, session)
    assert stub.calls == [f"f2:{ok.function_id}"]

    stub.calls.clear()
    # Reset ok to completed abstain with empty issues for F3 eligibility.
    record_assessments(
        pipeline._assessment_store,
        [
            FunctionAnalysis(
                function_id=ok.function_id,
                y2038_summary=Y2038Summary.ABSTAIN,
                confidence=0.4,
                issues=[],
                needs_more_context=True,
                needs=[],
                execution_status=AssessmentExecutionStatus.COMPLETED,
            )
        ],
        [ok],
    )
    pipeline._run_pass_f3(
        [
            Finding(
                file=ok.file_path,
                region={"start_line": 1, "end_line": 1},
                lines=[1],
                symbol="ok",
                confidence=0.4,
                reason="abstain",
                source_snippet="",
                y2038_issue=Y2038Issue.ABSTAIN,
                needs_more_context=True,
                function_id=ok.function_id,
            )
        ],
        {ok.function_id: ok, err.function_id: err},
        session,
    )
    assert stub.calls == [f"f3:{ok.function_id}"]


@pytest.mark.parametrize(
    "confidence",
    [
        True,
        False,
        "0.9",
        "high",
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
def test_confidence_rejects_bool_string_nan_infinity_without_coercion(confidence: Any) -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    item = _empty_issues_item(a.function_id, "no")
    item["confidence"] = confidence
    analyses = _parse([item], [a])
    assert analyses[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert ISSUE_INVALID_SCHEMA in _issue_types(analyses[0])
    assert build_model_assessment(analyses[0], a).verdict is None


def test_prompts_document_empty_issues_array() -> None:
    client = _client()
    batch = FunctionBatch(batch_id="b", functions=[_func("a.c@a:1-1", symbol="a")])
    prompt = client._build_pass_f1_prompt(batch)
    assert '`[]` is valid' in prompt.system or '[]` is valid' in prompt.system
    assert "ALWAYS provide at least one issue" not in prompt.system
    assert "exactly the fields type, line, and description" in prompt.system
    assert '"issues": []' in prompt.system


def test_analysis_error_has_null_verdict_and_controlled_reason() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    analyses = _parse([], [a])
    assessment = build_model_assessment(analyses[0], a)
    assert assessment.execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert assessment.verdict is None
    assert assessment.reason == "No usable model output for this function"
    assert "S2_P1" not in (assessment.reason or "")


def test_public_assessments_omit_raw_response_and_bodies() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    analyses = _parse([_item(a.function_id, "yes")], [a])
    assessment = build_model_assessment(analyses[0], a)
    blob = assessment.model_dump()
    assert "body" not in blob
    assert "prompt" not in blob
    assert a.body not in json.dumps(blob)


def test_model_candidate_ids_cannot_alter_trusted_linkage() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha", candidate_ids=["trusted:1"])
    item = _item(a.function_id, "yes")
    item["candidate_ids"] = ["model-forged:9"]
    # Extra top-level field forbidden by wire DTO.
    analyses = _parse([item], [a])
    assert analyses[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    # Valid item without forged ids still takes candidate_ids from FunctionBody.
    analyses = _parse([_item(a.function_id, "yes")], [a])
    assessment = build_model_assessment(analyses[0], a)
    assert assessment.candidate_ids == ["trusted:1"]


def test_zero_valid_ids_marks_all_requested_as_errors() -> None:
    funcs = [_func("a.c@a:1-1", symbol="a"), _func("b.c@b:2-2", symbol="b", start=2, end=2)]
    analyses = _parse([_item("z.c@z:9-9", "yes")], funcs)
    assert all(a.execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR for a in analyses)


def test_whitespace_rejected_without_trimming_to_match() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    item = _item("a.c@alpha:1-2", "yes")
    item["function_id"] = " a.c@alpha:1-2"
    analyses = _parse([item], [a])
    assert analyses[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR


def test_aligned_order_is_request_order() -> None:
    funcs = [
        _func("c.c@c:3-3", symbol="c", start=3, end=3),
        _func("a.c@a:1-1", symbol="a", start=1, end=1),
        _func("b.c@b:2-2", symbol="b", start=2, end=2),
    ]
    items = [_item(f.function_id, "no") for f in reversed(funcs)]
    out, _ = align_model_items_to_functions(items, funcs, pass_name="S2_P1")
    assert [a.function_id for a in out] == [f.function_id for f in funcs]


# --- F1 / F2 / F3 / pipeline -------------------------------------------------


def test_f1_exact_alignment_via_client_entrypoints() -> None:
    a = _func("a.c@alpha:1-2", symbol="alpha")
    b = _func("b.c@beta:3-4", symbol="beta", start=3, end=4)
    client = _client()
    payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        [_item(b.function_id, "yes"), _item(a.function_id, "abstain", needs=["header"], needs_more_context=True)]
                    )
                }
            }
        ]
    }
    analyses = client._parse_pass_f1_response(payload, [a, b])
    assert analyses[0].y2038_summary == Y2038Summary.ABSTAIN
    assert analyses[1].y2038_summary == Y2038Summary.YES


class _RecordingLLM:
    def __init__(self) -> None:
        self.calls: List[str] = []
        self.llm_type = "stub"
        self.model = "stub"
        self.total_batch_failures = 0
        self.max_total_failures = 3

    def _build_pass_f2_prompt(self, function_batch, iteration):  # noqa: ANN001
        return LLMPromptParts(system="f2", user="data")

    def _build_pass_f3_prompt(self, function_batch):  # noqa: ANN001
        return LLMPromptParts(system="f3", user="data")

    def analyze_functions_pass_f2(self, function_batch, iteration):  # noqa: ANN001
        self.calls.append("f2:" + ",".join(f.function_id for f in function_batch.functions))
        return [
            FunctionAnalysis(
                function_id=func.function_id,
                y2038_summary=Y2038Summary.NO,
                confidence=0.9,
                issues=[{"type": "safe", "line": func.start_line, "description": "resolved"}],
                needs_more_context=False,
                needs=[],
                execution_status=AssessmentExecutionStatus.COMPLETED,
            )
            for func in function_batch.functions
        ]

    def analyze_functions_pass_f3(self, function_batch):  # noqa: ANN001
        self.calls.append("f3:" + ",".join(f.function_id for f in function_batch.functions))
        return [
            FunctionAnalysis(
                function_id=func.function_id,
                y2038_summary=Y2038Summary.NO,
                confidence=0.9,
                issues=[{"type": "safe", "line": func.start_line, "description": "resolved"}],
                needs_more_context=False,
                needs=[],
                execution_status=AssessmentExecutionStatus.COMPLETED,
            )
            for func in function_batch.functions
        ]


def _pipeline_with_stub(tmp_path: Path, stub: _RecordingLLM):
    from tacs.core.pipeline import ScanningPipeline

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
    )
    pipeline.function_llm_client = stub
    pipeline._llm_analysis_requested = True
    return pipeline



def test_f2_updates_only_named_completed_abstain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    stub = _RecordingLLM()
    pipeline = _pipeline_with_stub(tmp_path, stub)
    keep = _func("a.c@keep:1-2", symbol="keep", candidate_ids=["keep:1"])
    enrich = _func("b.c@enrich:3-4", symbol="enrich", start=3, end=4, candidate_ids=["enrich:1"])
    record_assessments(
        pipeline._assessment_store,
        [
            FunctionAnalysis(
                function_id=keep.function_id,
                y2038_summary=Y2038Summary.YES,
                confidence=0.9,
                issues=[{"type": "r", "line": 1, "description": "yes"}],
                execution_status=AssessmentExecutionStatus.COMPLETED,
            ),
            FunctionAnalysis(
                function_id=enrich.function_id,
                y2038_summary=Y2038Summary.ABSTAIN,
                confidence=0.4,
                issues=[{"type": "need", "line": 3, "description": "needs more context: header"}],
                needs_more_context=True,
                execution_status=AssessmentExecutionStatus.COMPLETED,
            ),
        ],
        [keep, enrich],
    )
    findings = [
        Finding(
            file=keep.file_path,
            region={"start_line": 1, "end_line": 2},
            lines=[1],
            symbol="keep",
            confidence=0.9,
            reason="yes",
            source_snippet="",
            y2038_issue=Y2038Issue.YES,
            function_id=keep.function_id,
        ),
        Finding(
            file=enrich.file_path,
            region={"start_line": 3, "end_line": 4},
            lines=[3],
            symbol="enrich",
            confidence=0.4,
            reason="Function analysis: abstain (needs more context: header)",
            source_snippet="",
            y2038_issue=Y2038Issue.ABSTAIN,
            needs_more_context=True,
            function_id=enrich.function_id,
        ),
    ]
    session = ScanSession(root_path=str(tmp_path), output_base=str(tmp_path / "out"))
    out = pipeline._run_pass_f2(findings, {keep.function_id: keep, enrich.function_id: enrich}, session)
    assert stub.calls == [f"f2:{enrich.function_id}"]
    assert pipeline._assessment_store[keep.function_id].verdict == ModelVerdict.YES
    assert pipeline._assessment_store[enrich.function_id].verdict == ModelVerdict.NO
    assert pipeline._assessment_store[enrich.function_id].candidate_ids == ["enrich:1"]
    assert any(f.function_id == keep.function_id and f.y2038_issue == Y2038Issue.YES for f in out)


def test_protocol_error_excluded_from_f2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    stub = _RecordingLLM()
    pipeline = _pipeline_with_stub(tmp_path, stub)
    err_fn = _func("a.c@err:1-2", symbol="err")
    record_assessments(
        pipeline._assessment_store,
        [
            FunctionAnalysis(
                function_id=err_fn.function_id,
                y2038_summary=Y2038Summary.ABSTAIN,
                confidence=0.0,
                issues=[{"type": ISSUE_MISSING_EXPECTED, "line": 1, "description": "gap"}],
                needs_more_context=True,
                execution_status=AssessmentExecutionStatus.ANALYSIS_ERROR,
            )
        ],
        [err_fn],
    )
    finding = Finding(
        file=err_fn.file_path,
        region={"start_line": 1, "end_line": 2},
        lines=[1],
        symbol="err",
        confidence=0.0,
        reason="analysis_error projected as abstain",
        source_snippet="",
        y2038_issue=Y2038Issue.ABSTAIN,
        needs_more_context=True,
        function_id=err_fn.function_id,
    )
    session = ScanSession(root_path=str(tmp_path), output_base=str(tmp_path / "out"))
    out = pipeline._run_pass_f2([finding], {err_fn.function_id: err_fn}, session)
    assert stub.calls == []
    assert out == [finding]
    assert pipeline._assessment_store[err_fn.function_id].execution_status == (
        AssessmentExecutionStatus.ANALYSIS_ERROR
    )


def test_f3_updates_only_named_function(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a.c").write_text("int keep(void){return 0;}\n", encoding="utf-8")
    (tmp_path / "b.c").write_text("int enrich(void){return 0;}\n", encoding="utf-8")
    stub = _RecordingLLM()
    pipeline = _pipeline_with_stub(tmp_path, stub)
    keep = _func("a.c@keep:1-2", symbol="keep", candidate_ids=["keep:1"])
    keep = keep.model_copy(update={"file_path": str(tmp_path / "a.c")})
    enrich = _func("b.c@enrich:3-4", symbol="enrich", start=3, end=4, candidate_ids=["enrich:1"])
    enrich = enrich.model_copy(update={"file_path": str(tmp_path / "b.c")})
    record_assessments(
        pipeline._assessment_store,
        [
            FunctionAnalysis(
                function_id=keep.function_id,
                y2038_summary=Y2038Summary.NO,
                confidence=0.9,
                issues=[{"type": "safe", "line": 1, "description": "ok"}],
                execution_status=AssessmentExecutionStatus.COMPLETED,
            ),
            FunctionAnalysis(
                function_id=enrich.function_id,
                y2038_summary=Y2038Summary.ABSTAIN,
                confidence=0.4,
                issues=[{"type": "need", "line": 3, "description": "need file"}],
                needs_more_context=True,
                execution_status=AssessmentExecutionStatus.COMPLETED,
            ),
        ],
        [keep, enrich],
    )
    findings = [
        Finding(
            file=keep.file_path,
            region={"start_line": 1, "end_line": 2},
            lines=[1],
            symbol="keep",
            confidence=0.9,
            reason="no",
            source_snippet="",
            y2038_issue=Y2038Issue.NO,
            function_id=keep.function_id,
        ),
        Finding(
            file=enrich.file_path,
            region={"start_line": 3, "end_line": 4},
            lines=[3],
            symbol="enrich",
            confidence=0.4,
            reason="abstain",
            source_snippet="",
            y2038_issue=Y2038Issue.ABSTAIN,
            needs_more_context=True,
            function_id=enrich.function_id,
        ),
    ]
    session = ScanSession(root_path=str(tmp_path), output_base=str(tmp_path / "out"))
    pipeline._run_pass_f3(findings, {keep.function_id: keep, enrich.function_id: enrich}, session)
    assert stub.calls == [f"f3:{enrich.function_id}"]
    assert pipeline._assessment_store[keep.function_id].verdict == ModelVerdict.NO
    assert pipeline._assessment_store[enrich.function_id].verdict == ModelVerdict.NO


def test_no_positional_overwrite_across_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    stub = _RecordingLLM()
    pipeline = _pipeline_with_stub(tmp_path, stub)
    first = _func("a.c@one:1-2", symbol="one", candidate_ids=["one"])
    second = _func("b.c@two:3-4", symbol="two", start=3, end=4, candidate_ids=["two"])
    record_assessments(
        pipeline._assessment_store,
        [
            FunctionAnalysis(
                function_id=first.function_id,
                y2038_summary=Y2038Summary.YES,
                confidence=0.9,
                issues=[{"type": "r", "line": 1, "description": "yes"}],
                execution_status=AssessmentExecutionStatus.COMPLETED,
            ),
            FunctionAnalysis(
                function_id=second.function_id,
                y2038_summary=Y2038Summary.ABSTAIN,
                confidence=0.4,
                issues=[{"type": "need", "line": 3, "description": "needs more context: header"}],
                needs_more_context=True,
                execution_status=AssessmentExecutionStatus.COMPLETED,
            ),
        ],
        [first, second],
    )
    findings = [
        Finding(
            file=first.file_path,
            region={"start_line": 1, "end_line": 2},
            lines=[1],
            symbol="one",
            confidence=0.9,
            reason="yes",
            source_snippet="",
            y2038_issue=Y2038Issue.YES,
            function_id=first.function_id,
        ),
        Finding(
            file=second.file_path,
            region={"start_line": 3, "end_line": 4},
            lines=[3],
            symbol="two",
            confidence=0.4,
            reason="Function analysis: abstain (needs more context: header)",
            source_snippet="",
            y2038_issue=Y2038Issue.ABSTAIN,
            needs_more_context=True,
            function_id=second.function_id,
        ),
    ]
    session = ScanSession(root_path=str(tmp_path), output_base=str(tmp_path / "out"))
    pipeline._run_pass_f2(findings, {first.function_id: first, second.function_id: second}, session)
    assert pipeline._assessment_store[first.function_id].verdict == ModelVerdict.YES
    assert pipeline._assessment_store[second.function_id].candidate_ids == ["two"]


def test_fatal_abort_threshold_unchanged() -> None:
    client = _client()
    assert client.max_total_failures == 3


def test_llm_none_remains_provider_free() -> None:
    client = _client()
    batch = FunctionBatch(batch_id="b", functions=[_func("a.c@a:1-1", symbol="a")])
    analyses = client.analyze_functions_pass_f1(batch)
    assert analyses[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert client.total_batch_failures == 0


def test_compatibility_findings_still_project_abstain_for_errors() -> None:
    from tacs.core.pipeline import ScanningPipeline

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
    )
    func = _func("a.c@a:1-2", symbol="a")
    analysis = FunctionAnalysis(
        function_id=func.function_id,
        y2038_summary=Y2038Summary.ABSTAIN,
        confidence=0.0,
        issues=[{"type": ISSUE_MISSING_EXPECTED, "line": 1, "description": "gap"}],
        execution_status=AssessmentExecutionStatus.ANALYSIS_ERROR,
    )
    findings = pipeline._convert_analyses_to_findings([analysis], [func])
    assert findings
    assert findings[0].y2038_issue == Y2038Issue.ABSTAIN
    assessment = build_model_assessment(analysis, func)
    assert assessment.verdict is None
    assert assessment.execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR


def test_candidates_unchanged_across_malformed_model_responses(tmp_path: Path) -> None:
    from tacs.core.candidate_utils import prepare_candidates

    cands = prepare_candidates(
        [
            Candidate(
                file=str(tmp_path / "a.c"),
                line=1,
                symbol="time_t",
                one_line_snippet="time_t t;",
                risk="high",
            )
        ]
    )
    a = _func("a.c@a:1-2", symbol="a")
    _parse([_item(a.function_id, "yes")], [a])
    _parse([{"classification": "safe"}], [a])
    _parse([], [a])
    again = prepare_candidates(cands)
    assert [c.model_dump() for c in again] == [c.model_dump() for c in cands]


def test_mocked_pipeline_cli_path_uses_exact_ids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Pipeline-level mocked provider: reverse-order IDs still map correctly."""
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "demo.c"
    src.write_text(
        "time_t alpha(void) { return time(NULL); }\n"
        "time_t beta(void) { return time(NULL); }\n",
        encoding="utf-8",
    )

    class _Provider:
        llm_type = "stub"
        model = "stub"
        total_batch_failures = 0
        max_total_failures = 3
        detect_y2106 = False

        def _build_pass_f1_prompt(self, function_batch):  # noqa: ANN001
            return LLMPromptParts(system="f1", user="data")

        def analyze_functions_pass_f1(self, function_batch):  # noqa: ANN001
            # Intentionally reverse order in a real parse path via FunctionLLMClient helper.
            client = _client()
            items = [
                _item(func.function_id, "yes" if i == 0 else "no")
                for i, func in enumerate(reversed(function_batch.functions))
            ]
            return client._parse_function_response(
                {"choices": [{"message": {"content": json.dumps(items)}}]},
                list(function_batch.functions),
                "S2_P1",
            )

        def analyze_functions_pass_f2(self, function_batch, iteration):  # noqa: ANN001
            return []

        def analyze_functions_pass_f3(self, function_batch):  # noqa: ANN001
            return []

    from tacs.core.pipeline import ScanningPipeline

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
    )
    pipeline.function_llm_client = _Provider()
    pipeline._llm_analysis_requested = True

    funcs = [
        _func("demo.c@alpha:1-1", symbol="alpha", start=1, end=1),
        _func("demo.c@beta:2-2", symbol="beta", start=2, end=2),
    ]
    funcs[0] = funcs[0].model_copy(update={"file_path": str(src)})
    funcs[1] = funcs[1].model_copy(update={"file_path": str(src)})
    session = ScanSession(root_path=str(tmp_path), output_base=str(tmp_path / "out"))
    findings = pipeline._run_pass_f1(funcs, session)
    assert pipeline._assessment_store[funcs[0].function_id].verdict == ModelVerdict.NO
    assert pipeline._assessment_store[funcs[1].function_id].verdict == ModelVerdict.YES
    assert findings
