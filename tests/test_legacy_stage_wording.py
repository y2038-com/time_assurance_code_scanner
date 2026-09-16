# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for count agreement in the legacy Stage S1/S2/S3 messages.

The default function-first path had its count nouns fixed; the legacy pipeline
and the legacy LLM client that drives it still read "1 candidates", "1 survivors",
"1 unique files", and "after 1 attempt(s)". These tests exercise each message at
one and at two, so a naive plural cannot come back unnoticed.

Only the wording is under test here. Stage names, levels, and control flow are
asserted as they were.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tacs.core.logging_config import configure_logging
from tacs.core.schema import Candidate, Finding, LLMResponse, Y2038Issue
from tacs.core.scan_session import ScanSession

SCANNER = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "tacs"
    / "python"
    / "y2038scan_fast_json_group.py"
)

SOURCE = """#include <time.h>

int measure_window(void) {
    time_t now = time(NULL);
    return (int)now;
}
"""


def _pipeline(**overrides):
    from tacs.core.pipeline import ScanningPipeline

    kwargs = dict(
        scanner_path=str(SCANNER),
        llm_type="none",
        model="none",
        function_first=False,
    )
    kwargs.update(overrides)
    return ScanningPipeline(**kwargs)


def _candidate(source: Path, line: int = 4) -> Candidate:
    return Candidate(
        file=str(source),
        line=line,
        symbol="time",
        one_line_snippet="    time_t now = time(NULL);",
        risk="high",
        description="time",
    )


def _abstain_response(source: Path, line: int = 4) -> LLMResponse:
    return LLMResponse(
        id=f"{source}:{line}",
        y2038_issue=Y2038Issue.ABSTAIN,
        confidence=0.4,
        reason="needs more context",
        needs_more_context=True,
        line=line,
    )


def _abstain_finding(source: Path, line: int = 4) -> Finding:
    return Finding(
        file=str(source),
        region={"start_line": 3, "end_line": 5},
        lines=[line],
        symbol="time",
        confidence=0.4,
        reason="needs more context",
        source_snippet="    time_t now = time(NULL);",
        y2038_issue=Y2038Issue.ABSTAIN,
        needs_more_context=True,
    )


def _write_source(tmp_path: Path, name: str = "t.c") -> Path:
    source = tmp_path / name
    source.write_text(SOURCE, encoding="utf-8")
    return source


# --- Stage S1 ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("count", "expected"),
    [(1, "Stage S1, Pass P1: 1 survivor, 0 dropped"),
     (2, "Stage S1, Pass P1: 2 survivors, 0 dropped")],
)
def test_stage_s1_survivor_count_agrees(
    count: int,
    expected: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("INFO")
    source = _write_source(tmp_path)
    # bypass_pass1 makes every candidate a survivor without calling a provider.
    pipeline = _pipeline(bypass_pass1=True)
    monkeypatch.setattr(pipeline, "pass2_widened_region_context", lambda *a, **k: [])
    candidates = [_candidate(source, 4 + i) for i in range(count)]
    session = ScanSession(root_path=str(tmp_path), output_base=str(tmp_path))

    pipeline._run_legacy_analysis(candidates, session)

    assert expected in capsys.readouterr().err


# --- Stage S2 ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("count", "expected"),
    [(1, "Stage S2, Pass P1: Processing 1 abstain candidate with widened context"),
     (2, "Stage S2, Pass P1: Processing 2 abstain candidates with widened context")],
)
def test_stage_s2_header_count_agrees(
    count: int,
    expected: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("INFO")
    source = _write_source(tmp_path)
    pipeline = _pipeline()
    monkeypatch.setattr(pipeline, "_process_pass2_batch", lambda batch: [])
    survivors = [_abstain_response(source, 4 + i) for i in range(count)]
    candidate_map = {
        f"{source}:{4 + i}": _candidate(source, 4 + i) for i in range(count)
    }

    pipeline.pass2_widened_region_context(survivors, candidate_map)

    assert expected in capsys.readouterr().err


@pytest.mark.parametrize(
    ("count", "expected"),
    [(1, "batch of 1 candidate with widened context (batch 1 of 1)"),
     (2, "batch of 2 candidates with widened context (batch 1 of 1)")],
)
def test_stage_s2_batch_count_agrees(
    count: int,
    expected: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("INFO")
    source = _write_source(tmp_path)
    pipeline = _pipeline()
    monkeypatch.setattr(pipeline, "_process_pass2_batch", lambda batch: [])
    survivors = [_abstain_response(source, 4 + i) for i in range(count)]
    candidate_map = {
        f"{source}:{4 + i}": _candidate(source, 4 + i) for i in range(count)
    }

    pipeline.pass2_widened_region_context(survivors, candidate_map)

    assert expected in capsys.readouterr().err


# --- Stage S3 ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("count", "expected"),
    [(1, "Stage S3, Pass P1: Processing 1 abstain finding with file context"),
     (2, "Stage S3, Pass P1: Processing 2 abstain findings with file context")],
)
def test_stage_s3_header_count_agrees(
    count: int,
    expected: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("INFO")
    source = _write_source(tmp_path)
    pipeline = _pipeline()
    monkeypatch.setattr(
        pipeline, "_process_file_group_pass3", lambda path, findings, cmap: []
    )
    findings = [_abstain_finding(source, 4 + i) for i in range(count)]

    pipeline.pass3_file_leading_context(findings, {})

    assert expected in capsys.readouterr().err


@pytest.mark.parametrize(
    ("files", "expected"),
    [(1, "Stage S3, Pass P1: Grouped into 1 unique file"),
     (2, "Stage S3, Pass P1: Grouped into 2 unique files")],
)
def test_stage_s3_file_group_count_agrees(
    files: int,
    expected: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("INFO")
    pipeline = _pipeline()
    monkeypatch.setattr(
        pipeline, "_process_file_group_pass3", lambda path, findings, cmap: []
    )
    findings = [
        _abstain_finding(_write_source(tmp_path, f"t{index}.c"))
        for index in range(files)
    ]

    pipeline.pass3_file_leading_context(findings, {})

    err = capsys.readouterr().err
    assert expected in err
    # "1 unique file" must not be matched by asserting a prefix of "1 unique files".
    if files == 1:
        assert "1 unique files" not in err


# --- the legacy LLM client that drives those passes -------------------------


def _client(monkeypatch: pytest.MonkeyPatch, *, fail_with: str | None = None):
    from tacs.core.llm_client import LLMClient

    client = LLMClient(llm_type="ollama", model="stub-model")
    if fail_with is not None:
        def explode(prompt):  # noqa: ANN001
            raise RuntimeError(fail_with)

        monkeypatch.setattr(client, "_make_api_request", explode)
    else:
        monkeypatch.setattr(client, "_make_api_request", lambda prompt: {})
        monkeypatch.setattr(client, "_parse_response", lambda data, candidates: [])
    return client


@pytest.mark.parametrize(
    ("count", "expected"),
    [(1, "Processing batch of 1 candidate with ollama LLM"),
     (2, "Processing batch of 2 candidates with ollama LLM")],
)
def test_legacy_client_batch_count_agrees(
    count: int,
    expected: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("INFO")
    source = _write_source(tmp_path)
    client = _client(monkeypatch)

    client._process_batch([_candidate(source, 4 + i) for i in range(count)])

    assert expected in capsys.readouterr().err


@pytest.mark.parametrize(
    ("count", "expected"),
    [(1, "Processing Pass 2 batch of 1 candidate with widened context"),
     (2, "Processing Pass 2 batch of 2 candidates with widened context")],
)
def test_legacy_client_pass2_batch_count_agrees(
    count: int,
    expected: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging("INFO")
    source = _write_source(tmp_path)
    client = _client(monkeypatch)
    monkeypatch.setattr(client, "_parse_response", lambda data, candidates: [])
    batch = [
        (_abstain_response(source, 4 + i), _candidate(source, 4 + i), "context")
        for i in range(count)
    ]

    client._process_pass2_batch(batch)

    assert expected in capsys.readouterr().err


def test_legacy_client_attempt_count_agrees(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A non-retryable failure gives up after one attempt, so it reads "1 attempt"."""
    configure_logging("INFO")
    source = _write_source(tmp_path)
    # A message with none of the retryable markers stops the loop immediately.
    client = _client(monkeypatch, fail_with="malformed model reply")

    client._process_batch([_candidate(source)])

    err = capsys.readouterr().err
    assert "failed after 1 attempt:" in err
    assert "1 attempt(s)" not in err
    assert "1 attempts" not in err
