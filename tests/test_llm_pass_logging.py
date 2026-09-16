# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for INFO/DEBUG levels in the function-first LLM passes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tacs.core.function_schemas import FunctionAnalysis, FunctionBody, Y2038Summary
from tacs.core.logging_config import configure_logging
from tacs.core.schema import Finding, Y2038Issue
from tacs.core.scan_session import ScanSession


@pytest.fixture(autouse=True)
def _scan_from_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep session artifacts out of the checkout's own results/ tree.

    A standalone scan writes results/scans/<session-id>/ relative to the working
    directory and takes no option to move it, so the working directory is the
    only lever these tests have.
    """
    monkeypatch.chdir(tmp_path)


SOURCE = """#include <time.h>
#include "benchmark.h"

#define STEP_WIDTH 100

int measure_window(void) {
    time_t now = time(NULL);
    int width = compute_width(STEP_WIDTH);
    return (int)now + width;
}
"""


class _StubLLMClient:
    """Stands in for FunctionLLMClient so passes run without a provider."""

    def __init__(self, summary: Y2038Summary) -> None:
        self.summary = summary
        self.llm_type = "stub"
        self.model = "stub"

    def _build_pass_f2_prompt(self, function_batch, iteration):  # noqa: ANN001
        return "pass 2b prompt"

    def _build_pass_f3_prompt(self, function_batch):  # noqa: ANN001
        return "stage 9 prompt"

    def _analyses(self, function_batch):  # noqa: ANN001
        return [
            FunctionAnalysis(
                function_id=func.function_id,
                y2038_summary=self.summary,
                confidence=0.9,
                needs_more_context=False,
            )
            for func in function_batch.functions
        ]

    def analyze_functions_pass_f2(self, function_batch, iteration):  # noqa: ANN001
        return self._analyses(function_batch)

    def analyze_functions_pass_f3(self, function_batch):  # noqa: ANN001
        return self._analyses(function_batch)


def _pipeline(tmp_path: Path, summary: Y2038Summary = Y2038Summary.ABSTAIN):
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
    pipeline.function_llm_client = _StubLLMClient(summary)
    return pipeline


def _function(tmp_path: Path) -> FunctionBody:
    source = tmp_path / "benchmark.c"
    source.write_text(SOURCE, encoding="utf-8")
    return FunctionBody(
        function_id="benchmark.c@measure_window:6-10",
        file_path=str(source),
        symbol="measure_window",
        start_line=6,
        end_line=10,
        body="\n".join(SOURCE.splitlines()[5:10]),
        candidate_lines=[7],
    )


def _abstain_finding(function: FunctionBody) -> Finding:
    return Finding(
        file=function.file_path,
        region={"start_line": function.start_line, "end_line": function.end_line},
        lines=list(function.candidate_lines),
        symbol=function.symbol,
        confidence=0.4,
        reason="Function analysis: abstain (needs more context: header, macro, callee)",
        source_snippet="time_t now = time(NULL);",
        y2038_issue=Y2038Issue.ABSTAIN,
        needs_more_context=True,
        function_id=function.function_id,
    )


def _run_pass(tmp_path: Path, level: str, pass_name: str, summary: Y2038Summary):
    configure_logging(level)
    pipeline = _pipeline(tmp_path, summary)
    function = _function(tmp_path)
    session = ScanSession(root_path=str(tmp_path), output_base=str(tmp_path))
    findings = [_abstain_finding(function)]
    function_map = {function.function_id: function}
    if pass_name == "f2":
        return pipeline._run_pass_f2(findings, function_map, session)
    return pipeline._run_pass_f3(findings, function_map, session)


# --- Stage 8, Pass 2b --------------------------------------------------------


def test_pass_2b_info_keeps_only_progress_and_results(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run_pass(tmp_path, "INFO", "f2", Y2038Summary.ABSTAIN)
    err = capsys.readouterr().err

    assert "Stage 8, Pass 2b: enriching 1 abstained function" in err
    assert "Stage 8, Pass 2b results: 0 yes, 0 no, 1 abstain" in err

    # Extracted context detail belongs at DEBUG.
    assert "Extracted" not in err
    assert '#include "benchmark.h"' not in err
    assert "#define STEP_WIDTH 100" not in err
    assert "compute_width" not in err
    assert "needs: header" not in err
    assert "Processing batch" not in err
    assert "abstain(s) remaining after enrichment" not in err


def test_pass_2b_debug_keeps_extracted_context_detail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run_pass(tmp_path, "DEBUG", "f2", Y2038Summary.ABSTAIN)
    err = capsys.readouterr().err

    assert "Stage 8, Pass 2b: enriching 1 abstained function" in err
    assert "Stage 8, Pass 2b: Extracted" in err
    assert '#include "benchmark.h"' in err
    assert "#define STEP_WIDTH 100" in err
    assert "Stage 8, Pass 2b: Processing batch 1 of 1" in err
    assert "abstain(s) remaining after enrichment" in err


def test_pass_2b_enriching_line_is_plural_for_many(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging("INFO")
    pipeline = _pipeline(tmp_path)
    first = _function(tmp_path)
    second = first.model_copy(update={"function_id": "benchmark.c@other:6-10"})
    session = ScanSession(root_path=str(tmp_path), output_base=str(tmp_path))
    findings = [_abstain_finding(first), _abstain_finding(second)]
    findings[1].function_id = second.function_id
    function_map = {first.function_id: first, second.function_id: second}

    pipeline._run_pass_f2(findings, function_map, session)
    err = capsys.readouterr().err
    assert "Stage 8, Pass 2b: enriching 2 abstained functions" in err


# --- Stage 9 ----------------------------------------------------------------


def test_stage_9_info_keeps_only_results(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run_pass(tmp_path, "INFO", "f3", Y2038Summary.NO)
    err = capsys.readouterr().err

    assert "Stage 9 results: 0 yes, 1 no, 0 abstain" in err
    # Per-batch chatter carries long absolute/cache-relative paths.
    assert "Stage 9: Processing batch" not in err
    assert str(tmp_path / "benchmark.c") not in err


def test_stage_9_debug_keeps_batch_detail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run_pass(tmp_path, "DEBUG", "f3", Y2038Summary.ABSTAIN)
    err = capsys.readouterr().err

    assert "Stage 9 results: 0 yes, 0 no, 1 abstain" in err
    assert "Stage 9: Processing batch 1 of 1" in err
    assert "final abstain(s) after file context" in err


def test_stage_9_final_abstain_ids_not_at_info(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _run_pass(tmp_path, "INFO", "f3", Y2038Summary.ABSTAIN)
    err = capsys.readouterr().err

    assert "Stage 9 results: 0 yes, 0 no, 1 abstain" in err
    assert "final abstain(s) after file context" not in err
    assert "benchmark.c@measure_window" not in err


def test_scan_info_output_has_no_llm_pass_chatter(tmp_path: Path) -> None:
    """A normal --llm none scan must not gain any of the pass-level lines."""
    from click.testing import CliRunner

    from tacs.cli import app

    (tmp_path / "t.c").write_text(
        "#include <time.h>\nint main(void) { time_t t = time(NULL); return (int)t; }\n",
        encoding="utf-8",
    )
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            [
                {
                    "id": "time_call",
                    "pattern": "time",
                    "risk": "high",
                    "category": "function",
                    "description": "time",
                }
            ]
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--root",
            str(tmp_path),
            "--rules",
            str(rules),
            "--include",
            "*.c",
            "--llm",
            "none",
            "--out",
            str(tmp_path / "out.json"),
            "--log-level",
            "INFO",
        ],
    )
    assert result.exit_code == 0, result.stderr or result.output
    err = result.stderr or ""
    assert "Pass 2b" not in err
    assert "Stage 9 results" not in err
    assert "Extracted 1 macros" not in err
