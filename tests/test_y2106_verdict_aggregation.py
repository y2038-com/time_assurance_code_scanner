# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression for issue #56: Y2106-positive must not hide behind verdict=no.

When ``--detect-y2106`` is enabled, the model classifies Y2038 and Y2106
independently. Public aggregate verdicts and summary counts must treat any
enabled ``yes`` as a positive result while leaving issue-specific finding
fields intact. Fixtures and stubs only — no live LLM providers.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from tacs.batch_scan_repos import (
    _format_llm_repo_summary,
    _parse_findings_summary,
)
from tacs.core.function_analysis_response import count_analyses_by_execution
from tacs.core.function_schemas import FunctionAnalysis, FunctionBody, Y2038Summary
from tacs.core.model_assessment import (
    aggregate_finding_issue_class,
    aggregate_issue_verdict,
    build_model_assessment,
    summarize_assessments,
)
from tacs.core.pipeline import ScanningPipeline
from tacs.core.schema import (
    AssessmentExecutionStatus,
    Finding,
    ModelVerdict,
    TimeIssueType,
    Y2038Issue,
)
from report_renderer.core import (
    LoadedScanDocument,
    apply_filters,
    assessment_counts_from_document,
    normalize_findings,
)
from report_renderer.renderers import render_html, render_text


def _function(**kwargs) -> FunctionBody:
    defaults = dict(
        function_id="a.c@foo:1-10",
        file_path="/abs/repo/a.c",
        symbol="foo",
        start_line=1,
        end_line=10,
        body="void foo(void) { uint32_t t; }",
        candidate_lines=[3],
        candidate_ids=["a.c:3:0-6:high:time_t"],
    )
    defaults.update(kwargs)
    return FunctionBody(**defaults)


def _analysis(
    *,
    y2038: Y2038Summary,
    y2106: Y2038Summary | None = None,
    status: AssessmentExecutionStatus = AssessmentExecutionStatus.COMPLETED,
    issues: list | None = None,
    confidence: float = 0.9,
) -> FunctionAnalysis:
    return FunctionAnalysis(
        function_id="a.c@foo:1-10",
        y2038_summary=y2038,
        y2106_summary=y2106,
        confidence=confidence,
        issues=issues
        or (
            [
                {
                    "type": "y2106",
                    "line": 3,
                    "description": "32-bit unsigned time_t overflows in 2106",
                }
            ]
            if y2106 == Y2038Summary.YES
            else []
        ),
        execution_status=status,
        issue_type=(
            TimeIssueType.Y2106
            if y2106 == Y2038Summary.YES and y2038 != Y2038Summary.YES
            else None
        ),
    )


def _finding(
    *,
    y2038: Y2038Issue,
    y2106: Y2038Issue | None = None,
    function_id: str = "a.c@foo:1-10",
    issue_type: TimeIssueType | None = None,
) -> Finding:
    return Finding(
        file="a.c",
        region={"start_line": 1, "end_line": 10},
        lines=[3],
        symbol="foo",
        confidence=0.9,
        reason="32-bit unsigned time_t overflows in 2106",
        source_snippet="uint32_t t = time(NULL);",
        y2038_issue=y2038,
        y2106_issue=y2106,
        issue_type=issue_type,
        function_id=function_id,
        needs_more_context=False,
    )


def test_aggregate_y2038_no_y2106_yes() -> None:
    assert (
        aggregate_issue_verdict(Y2038Summary.NO, Y2038Summary.YES) == ModelVerdict.YES
    )
    a = build_model_assessment(
        _analysis(y2038=Y2038Summary.NO, y2106=Y2038Summary.YES),
        _function(),
    )
    assert a.execution_status == AssessmentExecutionStatus.COMPLETED
    assert a.verdict == ModelVerdict.YES
    assert a.reason and "2106" in a.reason


def test_aggregate_y2038_yes_y2106_no() -> None:
    assert (
        aggregate_issue_verdict(Y2038Summary.YES, Y2038Summary.NO) == ModelVerdict.YES
    )
    a = build_model_assessment(
        _analysis(
            y2038=Y2038Summary.YES,
            y2106=Y2038Summary.NO,
            issues=[
                {
                    "type": "y2038",
                    "line": 3,
                    "description": "signed time_t overflows in 2038",
                }
            ],
        ),
        _function(),
    )
    assert a.verdict == ModelVerdict.YES


def test_aggregate_both_yes() -> None:
    assert (
        aggregate_issue_verdict(Y2038Summary.YES, Y2038Summary.YES) == ModelVerdict.YES
    )


def test_aggregate_both_no() -> None:
    assert aggregate_issue_verdict(Y2038Summary.NO, Y2038Summary.NO) == ModelVerdict.NO
    a = build_model_assessment(
        _analysis(y2038=Y2038Summary.NO, y2106=Y2038Summary.NO, issues=[]),
        _function(),
    )
    assert a.verdict == ModelVerdict.NO


def test_y2106_disabled_preserves_y2038_only_verdict() -> None:
    """Missing y2106_summary must keep prior Y2038-only semantics."""
    assert aggregate_issue_verdict(Y2038Summary.NO, None) == ModelVerdict.NO
    assert aggregate_issue_verdict(Y2038Summary.YES, None) == ModelVerdict.YES
    assert aggregate_issue_verdict(Y2038Summary.ABSTAIN, None) == ModelVerdict.ABSTAIN
    a = build_model_assessment(_analysis(y2038=Y2038Summary.NO), _function())
    assert a.verdict == ModelVerdict.NO


def test_model_abstention_not_converted_to_yes_or_no() -> None:
    assert (
        aggregate_issue_verdict(Y2038Summary.ABSTAIN, Y2038Summary.NO)
        == ModelVerdict.ABSTAIN
    )
    assert (
        aggregate_issue_verdict(Y2038Summary.NO, Y2038Summary.ABSTAIN)
        == ModelVerdict.ABSTAIN
    )
    a = build_model_assessment(
        _analysis(y2038=Y2038Summary.ABSTAIN, y2106=Y2038Summary.ABSTAIN, issues=[]),
        _function(),
    )
    assert a.verdict == ModelVerdict.ABSTAIN
    # Yes still wins over abstain when either issue is positive.
    assert (
        aggregate_issue_verdict(Y2038Summary.ABSTAIN, Y2038Summary.YES)
        == ModelVerdict.YES
    )


def test_analysis_error_keeps_null_verdict() -> None:
    a = build_model_assessment(
        _analysis(
            y2038=Y2038Summary.ABSTAIN,
            y2106=Y2038Summary.YES,
            status=AssessmentExecutionStatus.ANALYSIS_ERROR,
            issues=[{"type": "parse_gap", "description": "gap", "line": 1}],
        ),
        _function(),
    )
    assert a.execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    assert a.verdict is None


def test_missing_or_legacy_y2106_data() -> None:
    assert aggregate_finding_issue_class(Y2038Issue.NO, None) == "no"
    assert aggregate_finding_issue_class("no", None) == "no"
    assert aggregate_finding_issue_class("yes", None) == "yes"
    # String legacy payloads without y2106_issue stay Y2038-only.
    assert aggregate_finding_issue_class("no", "") == "no"
    assert aggregate_finding_issue_class("abstain", None) == "abstain"


def test_count_analyses_treats_y2106_only_yes_as_positive() -> None:
    analyses = [
        _analysis(y2038=Y2038Summary.NO, y2106=Y2038Summary.YES),
        _analysis(y2038=Y2038Summary.NO, y2106=Y2038Summary.NO, issues=[]),
        _analysis(
            y2038=Y2038Summary.ABSTAIN,
            y2106=None,
            status=AssessmentExecutionStatus.ANALYSIS_ERROR,
            issues=[{"type": "parse_gap", "description": "gap", "line": 1}],
        ),
    ]
    counts = count_analyses_by_execution(analyses)
    assert counts["yes"] == 1
    assert counts["no"] == 1
    assert counts["abstain"] == 0
    assert counts["analysis_errors"] == 1


def test_console_summary_counts_from_assessments_and_findings() -> None:
    pipeline = ScanningPipeline.__new__(ScanningPipeline)
    pipeline.detect_y2106 = True
    pipeline.include_no_findings = False

    fn = _function()
    assessment = build_model_assessment(
        _analysis(y2038=Y2038Summary.NO, y2106=Y2038Summary.YES),
        fn,
    )
    pipeline._assessment_store = {fn.function_id: assessment}
    fn_counts = pipeline._function_classification_counts_from_assessments()
    assert fn_counts["yes"] == 1
    assert fn_counts["no"] == 0

    findings = [
        _finding(
            y2038=Y2038Issue.NO,
            y2106=Y2038Issue.YES,
            issue_type=TimeIssueType.Y2106,
        ),
        _finding(
            y2038=Y2038Issue.NO,
            y2106=Y2038Issue.NO,
            function_id="a.c@bar:20-30",
            issue_type=TimeIssueType.NONE,
        ),
    ]
    finding_counts = ScanningPipeline._classification_counts(findings)
    assert finding_counts["yes"] == 1
    assert finding_counts["no"] == 1

    fn_from_findings = ScanningPipeline._function_classification_counts(findings)
    assert fn_from_findings["yes"] == 1
    assert fn_from_findings["no"] == 1

    summary = summarize_assessments([assessment], findings_count=1)
    assert summary.yes == 1
    assert summary.no == 0


def test_batch_aggregation_counts_y2106_only_as_yes(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        json.dumps(
            {
                "schema_version": "1.2",
                "findings": [
                    {
                        "file": "a.c",
                        "y2038_issue": "no",
                        "y2106_issue": "yes",
                        "issue_type": "y2106",
                        "function_id": "a.c@foo:1-10",
                    },
                    {
                        "file": "b.c",
                        "y2038_issue": "no",
                        "y2106_issue": "no",
                        "issue_type": "none",
                        "function_id": "b.c@bar:1-5",
                    },
                    {
                        "file": "c.c",
                        "y2038_issue": "abstain",
                        "function_id": "c.c@baz:1-5",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    summary = _parse_findings_summary(findings_path)
    assert summary["yes_findings"] == 1
    assert summary["no_findings"] == 1
    assert summary["abstain_findings"] == 1
    assert summary["total_findings"] == 3

    line = _format_llm_repo_summary(
        "linux__stmmac",
        summary,
        {"yes": 1, "no": 1, "abstain": 1, "total": 3},
        {"yes": 1, "no": 0, "abstain": 0, "total": 1},
    )
    assert "1 yes" in line
    assert "0 no" in line or "final function classifications: 1 yes" in line
    assert "retained finding records: 3" in line


def test_retained_findings_keep_issue_specific_fields() -> None:
    dummy = SimpleNamespace(include_no_findings=False, detect_y2106=True)
    kept = ScanningPipeline._filter_findings_for_output(
        dummy,
        [
            _finding(
                y2038=Y2038Issue.NO,
                y2106=Y2038Issue.YES,
                issue_type=TimeIssueType.Y2106,
            ),
            _finding(
                y2038=Y2038Issue.NO,
                y2106=Y2038Issue.NO,
                function_id="a.c@safe:1-2",
                issue_type=TimeIssueType.NONE,
            ),
        ],
    )
    assert len(kept) == 1
    assert kept[0].y2038_issue == Y2038Issue.NO
    assert kept[0].y2106_issue == Y2038Issue.YES
    # Filter still drops pure negatives when Y2106 is disabled.
    off = SimpleNamespace(include_no_findings=False, detect_y2106=False)
    assert (
        ScanningPipeline._filter_findings_for_output(
            off,
            [
                _finding(
                    y2038=Y2038Issue.NO,
                    y2106=Y2038Issue.YES,
                    issue_type=TimeIssueType.Y2106,
                )
            ],
        )
        == []
    )


def test_text_and_html_rendering_surface_y2106_positive() -> None:
    raw = {
        "file": "drivers/net/stmmac.c",
        "y2038_issue": "no",
        "y2106_issue": "yes",
        "issue_type": "y2106",
        "function_id": "drivers/net/stmmac.c@stmmac_init_tstamp_counter:10-20",
        "symbol": "stmmac_init_tstamp_counter",
        "reason": "32-bit unsigned PTP seconds overflow in 2106",
        "source_snippet": "u32 sec = ...;",
        "region": {"start_line": 10, "end_line": 20},
        "lines": [15],
        "confidence": 0.91,
        "severity": "medium",
    }
    finding = normalize_findings([raw]).findings[0]
    only_yes = apply_filters(
        [finding], only="yes", min_confidence=None, file_globs=[], rules=[]
    )
    assert len(only_yes) == 1
    assert finding.issue_class == "no"
    assert finding.raw.get("y2106_issue") == "yes"

    assessments = [
        {
            "assessment_id": (
                "assessment:drivers/net/stmmac.c@stmmac_init_tstamp_counter:10-20"
            ),
            "function_id": "drivers/net/stmmac.c@stmmac_init_tstamp_counter:10-20",
            "candidate_ids": [],
            "execution_status": "completed",
            "verdict": "yes",
            "confidence": 0.91,
            "reason": "32-bit unsigned PTP seconds overflow in 2106",
            "analysis_mode": "function_first",
        }
    ]
    meta = {
        "analysis_status": "complete",
        "assessment_summary": {
            "total": 1,
            "completed": 1,
            "yes": 1,
            "no": 0,
            "abstain": 0,
            "analysis_errors": 0,
            "not_requested": 0,
            "findings": 1,
        },
    }
    doc = LoadedScanDocument(
        meta=meta,
        findings=[raw],
        candidates=[],
        assessments=assessments,
        schema_version="1.2",
    )
    counts = assessment_counts_from_document(doc)
    assert counts["yes"] == 1
    assert counts["no"] == 0

    text = render_text(
        [finding],
        assessments=assessments,
        assessment_counts=counts,
        has_assessment_section=True,
        meta=meta,
    )
    assert "yes(y2106)" in text
    assert "verdict: yes" in text

    html = render_html(
        [finding],
        title="Y2106 aggregation",
        group_by="file",
        assessments=assessments,
        assessment_counts=counts,
        has_assessment_section=True,
        meta=meta,
    )
    assert "yes(y2106)" in html
    assert "stmmac_init_tstamp_counter" in html
    assert "verdict: yes" in html or ">yes<" in html.lower()


def test_legacy_schema_reports_do_not_invent_y2106(tmp_path: Path) -> None:
    """Schema 1.0 / 1.1 findings without y2106_issue stay Y2038-only."""
    for version in ("1.0", "1.1", "1.2"):
        path = tmp_path / f"legacy_{version}.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": version,
                    "findings": [
                        {
                            "file": "old.c",
                            "y2038_issue": "no",
                            "function_id": "old.c@f:1-2",
                            "region": {"start_line": 1, "end_line": 2},
                            "lines": [1],
                            "confidence": 0.5,
                            "reason": "safe",
                            "source_snippet": "int x;",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        summary = _parse_findings_summary(path)
        assert summary["yes_findings"] == 0
        assert summary["no_findings"] == 1

    legacy = normalize_findings(
        [
            {
                "file": "old.c",
                "y2038_issue": "no",
                "reason": "safe",
                "source_snippet": "int x;",
                "region": {"start_line": 1, "end_line": 2},
                "lines": [1],
                "confidence": 0.5,
            }
        ]
    ).findings
    assert (
        apply_filters(legacy, only="yes", min_confidence=None, file_globs=[], rules=[])
        == []
    )
    text = render_text(legacy, meta={"analysis_status": "complete"})
    assert "yes(y2106)" not in text
