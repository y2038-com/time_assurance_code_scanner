# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Adversarial canary tests for LLM error / raw-response hardening.

Distinct canaries cover provider bodies, exception/URL/token material, raw
prompts and full bodies, invalid model items, intentional candidate snippets,
and validated finding descriptions. Provider/error/raw-input canaries must be
absent from ordinary logs and public artifacts. Intentional bounded candidate
context and validated finding content remain present in the appropriate public
artifacts.
"""

from __future__ import annotations

import io
import json
import logging
import traceback
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest
import requests

from tacs.core.function_llm_client import FunctionLLMClient
from tacs.core.function_schemas import FunctionAnalysis, FunctionBatch, FunctionBody, Y2038Summary
from tacs.core.llm_client import LLMClient
from tacs.core.llm_errors import (
    LLMErrorCategory,
    LLMProviderError,
    format_exception_for_log,
)
from tacs.core.llm_prompt import LLMPromptParts
from tacs.core.model_assessment import build_model_assessment, controlled_reason_for_issue_type
from tacs.core.pipeline import ScanningPipeline
from tacs.core.scan_session import ScanSession
from tacs.core.schema import AssessmentExecutionStatus

CANARY_BODY = "CANARY_PROVIDER_BODY_9f3a7c"
CANARY_EXC = "CANARY_EXCEPTION_URL_user:token@host/path?q=1#frag"
CANARY_TOKEN = "CANARY_BEARER_sk-live-secret-xyz"
CANARY_PROMPT = "CANARY_RAW_PROMPT_full_body_secret"
CANARY_INVALID_ITEM = "CANARY_INVALID_MODEL_ITEM_value"
CANARY_SNIPPET = "CANARY_CANDIDATE_SNIPPET_time_t_x"
CANARY_FINDING = "CANARY_VALIDATED_FINDING_narrowing_cast"


def _capture_logs() -> tuple[logging.Handler, io.StringIO]:
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setLevel(logging.DEBUG)
    root = logging.getLogger("tacs")
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    return handler, buf


def _detach(handler: logging.Handler) -> None:
    logging.getLogger("tacs").removeHandler(handler)


def _http_response(status: int, text: str) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.text = text
    response.content = text.encode("utf-8")
    response.json.side_effect = ValueError("no json")
    return response


def test_provider_body_canary_absent_from_exception_and_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = LLMClient(llm_type="openai", model="m", timeout_sec=10)
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: _http_response(500, CANARY_BODY)
    )
    handler, buf = _capture_logs()
    try:
        with pytest.raises(LLMProviderError) as excinfo:
            client._post_json(
                "https://user:pass@evil.example/v1",
                {},
                provider_name="OpenAI",
            )
        err = excinfo.value
        surfaces = [
            str(err),
            repr(err),
            format_exception_for_log(err),
            traceback.format_exc(),
            buf.getvalue(),
        ]
        diag = err.to_diagnostic_dict()
        assert err.provider == "OpenAI"
        assert err.status_code == 500
        assert err.category == LLMErrorCategory.SERVER_ERROR
        assert err.retryable is True
        assert err.response_body_len == len(CANARY_BODY.encode("utf-8"))
        assert err.__cause__ is None
        assert err.__context__ is None
        for surface in surfaces:
            assert CANARY_BODY not in surface
            assert "user:pass" not in surface
        assert diag["status_code"] == 500
        assert "body" not in diag
    finally:
        _detach(handler)


def test_third_party_exception_canary_not_chained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = LLMClient(llm_type="openai", model="m", timeout_sec=10)

    class Boom(requests.exceptions.ConnectionError):
        def __str__(self) -> str:  # noqa: D105
            return CANARY_EXC

    monkeypatch.setattr(requests, "post", MagicMock(side_effect=Boom()))
    with pytest.raises(LLMProviderError) as excinfo:
        client._post_json("https://example.invalid", {}, provider_name="OpenAI")
    err = excinfo.value
    assert CANARY_EXC not in str(err)
    assert CANARY_EXC not in repr(err)
    assert err.__cause__ is None
    assert err.__context__ is None
    formatted = ""
    try:
        raise err
    except LLMProviderError:
        formatted = traceback.format_exc()
    assert CANARY_EXC not in formatted


def test_function_fallback_uses_controlled_reason_not_provider_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FunctionLLMClient(
        llm_type="openai",
        model="m",
        environment_config=None,
        timeout_sec=10,
        batch_size_func=5,
        confidence_floor=0.85,
    )
    batch = FunctionBatch(
        batch_id="b",
        functions=[
            FunctionBody(
                function_id="a.c@f:1-2",
                file_path="a.c",
                symbol="f",
                start_line=1,
                end_line=2,
                body=f"void f(void) {{ {CANARY_PROMPT} }}",
                candidate_lines=[1],
            )
        ],
    )

    def boom(_prompt: LLMPromptParts) -> Dict[str, Any]:
        raise LLMProviderError(
            provider="OpenAI",
            category=LLMErrorCategory.SERVER_ERROR,
            retryable=True,
            status_code=503,
            response_body_len=99,
        )

    monkeypatch.setattr(
        client,
        "_build_pass_f1_prompt",
        lambda _b: LLMPromptParts(system="sys", user=CANARY_PROMPT),
    )
    monkeypatch.setattr(client.base_client, "_make_api_request", boom)
    monkeypatch.setattr("time.sleep", lambda _s: None)
    # Force single-attempt exhaustion by raising on every try; max_retries=3
    # then fallback (do not abort: total_batch_failures stays below threshold).
    analyses = client.analyze_functions_pass_f1(batch)
    assert len(analyses) == 1
    analysis = analyses[0]
    assert analysis.execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR
    desc = analysis.issues[0]["description"]
    assert desc == controlled_reason_for_issue_type("analysis_error")
    assert CANARY_BODY not in desc
    assert CANARY_PROMPT not in desc

    assessment = build_model_assessment(analysis, batch.functions[0])
    assert assessment.reason == controlled_reason_for_issue_type("analysis_error")

    pipeline = ScanningPipeline.__new__(ScanningPipeline)
    pipeline.detect_y2106 = False
    pipeline.io_metadata_map = {}
    pipeline.debug_candidates = False
    findings = pipeline._convert_analyses_to_findings(analyses, batch.functions)
    assert findings
    for finding in findings:
        assert CANARY_PROMPT not in finding.reason
        assert finding.reason == controlled_reason_for_issue_type("analysis_error")


def test_session_default_output_omits_model_issue_text(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    session = ScanSession(
        root_path=str(root),
        output_base=str(tmp_path),
        enable_llm_logging=False,
        allow_raw_code_logging=False,
    )
    fn = FunctionBody(
        function_id="f.c@f:1-1",
        file_path=str(root / "f.c"),
        symbol="f",
        start_line=1,
        end_line=1,
        body=CANARY_PROMPT,
        candidate_lines=[1],
    )
    response = [
        {
            "function_id": fn.function_id,
            "y2038_summary": "yes",
            "execution_status": "completed",
            "confidence": 0.95,
            "issues": [{"type": "narrowing", "description": CANARY_FINDING, "line": 1}],
        }
    ]
    session.save_function_batch(
        pass_name="stage_8_pass_2a",
        batch_num=1,
        function_batch=FunctionBatch(batch_id="b", functions=[fn]),
        prompt=LLMPromptParts(system="s", user=CANARY_PROMPT),
        response=response,
    )
    out = (session.llm_dir / "stage_8_pass_2a" / "batches" / "0001_output.json").read_text(
        encoding="utf-8"
    )
    assert CANARY_FINDING not in out
    assert CANARY_PROMPT not in out
    assert "response_sha256" in out
    assert '"response"' not in out or '"response_item_count"' in out


def test_session_raw_output_requires_both_flags(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    session = ScanSession(
        root_path=str(root),
        output_base=str(tmp_path),
        enable_llm_logging=True,
        allow_raw_code_logging=True,
    )
    fn = FunctionBody(
        function_id="f.c@f:1-1",
        file_path=str(root / "f.c"),
        symbol="f",
        start_line=1,
        end_line=1,
        body="int f(void) { return 0; }",
        candidate_lines=[1],
    )
    response = [
        {
            "function_id": fn.function_id,
            "y2038_summary": "yes",
            "execution_status": "completed",
            "confidence": 0.95,
            "issues": [{"type": "narrowing", "description": CANARY_FINDING, "line": 1}],
        }
    ]
    session.save_function_batch(
        pass_name="stage_8_pass_2a",
        batch_num=1,
        function_batch=FunctionBatch(batch_id="b", functions=[fn]),
        prompt=LLMPromptParts(system="s", user="u"),
        response=response,
    )
    out_path = session.llm_dir / "stage_8_pass_2a" / "batches" / "0001_output.json"
    out = out_path.read_text(encoding="utf-8")
    assert CANARY_FINDING in out
    mode = out_path.stat().st_mode & 0o777
    assert mode & 0o077 == 0, f"raw artifact should not be group/world-accessible, got {oct(mode)}"


def test_validated_finding_and_snippet_preserved_in_public_projection() -> None:
    """Intentional product content must remain in findings/assessments."""
    fn = FunctionBody(
        function_id="f.c@f:1-3",
        file_path="f.c",
        symbol="f",
        start_line=1,
        end_line=3,
        body=f"void f(void) {{\n  {CANARY_SNIPPET};\n}}",
        candidate_lines=[2],
    )
    analysis = FunctionAnalysis(
        function_id=fn.function_id,
        y2038_summary=Y2038Summary.YES,
        confidence=0.91,
        issues=[{"type": "narrowing", "description": CANARY_FINDING, "line": 2}],
        needs_more_context=False,
        needs=[],
        execution_status=AssessmentExecutionStatus.COMPLETED,
    )
    assessment = build_model_assessment(analysis, fn)
    assert assessment.reason == CANARY_FINDING

    pipeline = ScanningPipeline.__new__(ScanningPipeline)
    pipeline.detect_y2106 = False
    pipeline.io_metadata_map = {}
    pipeline.debug_candidates = False
    findings = pipeline._convert_analyses_to_findings([analysis], [fn])
    assert len(findings) == 1
    assert findings[0].reason == CANARY_FINDING
    assert CANARY_SNIPPET in (findings[0].source_snippet or "")


def test_invalid_model_item_canary_not_in_ordinary_logs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    client = FunctionLLMClient(
        llm_type="openai",
        model="m",
        environment_config=None,
        timeout_sec=10,
        batch_size_func=5,
        confidence_floor=0.85,
        debug_llm_raw=False,
    )
    fn = FunctionBody(
        function_id="a.c@f:1-2",
        file_path="a.c",
        symbol="f",
        start_line=1,
        end_line=2,
        body="void f(void) {}",
        candidate_lines=[1],
    )
    payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        [
                            {
                                "function_id": "a.c@f:1-2",
                                "y2038_summary": "maybe",
                                "confidence": CANARY_INVALID_ITEM,
                                "issues": [],
                            }
                        ]
                    )
                }
            }
        ]
    }
    with caplog.at_level(logging.DEBUG, logger="tacs"):
        analyses = client._parse_pass_f1_response(payload, [fn])
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert CANARY_INVALID_ITEM not in joined
    assert analyses[0].execution_status == AssessmentExecutionStatus.ANALYSIS_ERROR


def test_config_debug_does_not_print_raw_response(capsys: pytest.CaptureFixture[str]) -> None:
    from config_detector.llm_analyzer import LLMAnalyzer

    analyzer = LLMAnalyzer(debug=True, debug_llm_raw=False)
    prompt = analyzer._build_prompt(
        {"Makefile": CANARY_PROMPT},
        {},
        ["hardware_model"],
    )
    # Exercise the safe debug branch from analyze_build_system's prompt logging
    # by calling the same print path indirectly through a stubbed request.
    analyzer.llm_type = "none"
    analyzer.analyze_build_system({"Makefile": CANARY_PROMPT}, {}, ["hardware_model"])
    # With llm none, prompt debug is skipped before print; call print path via
    # temporary debug dump of sizes only by invoking analyze with a patched request.
    analyzer.llm_type = "ollama"
    analyzer.debug = True
    analyzer.debug_llm_raw = False

    def fake_request(_prompt: LLMPromptParts) -> Dict[str, Any]:
        return {"response": json.dumps({
            "hardware_model": "ILP32",
            "time_t_size_bits": 32,
            "time_t_signed": "signed",
            "c_library": "glibc",
            "confidence": {},
            "reasoning": {},
        })}

    analyzer._make_api_request = fake_request  # type: ignore[method-assign]
    analyzer.analyze_build_system({"Makefile": CANARY_PROMPT}, {}, ["hardware_model"])
    captured = capsys.readouterr().out
    assert CANARY_PROMPT not in captured
    assert "debug-llm-raw" in captured.lower() or "system_chars=" in captured


def test_positive_safe_diagnostics_present(monkeypatch: pytest.MonkeyPatch) -> None:
    client = LLMClient(llm_type="anthropic", model="m", timeout_sec=10)
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: _http_response(429, CANARY_BODY)
    )
    with pytest.raises(LLMProviderError) as excinfo:
        client._post_json("https://example.invalid", {}, provider_name="Anthropic")
    err = excinfo.value
    assert err.provider == "Anthropic"
    assert err.status_code == 429
    assert err.category == LLMErrorCategory.RATE_LIMIT
    assert err.retryable is True
    assert isinstance(err.response_body_len, int) and err.response_body_len > 0
    message = str(err)
    assert "Anthropic" in message
    assert "429" in message
    assert "rate_limit" in message
    assert CANARY_BODY not in message


def test_json_decode_failure_has_no_third_party_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = LLMClient(llm_type="openai", model="m", timeout_sec=10)
    response = MagicMock()
    response.status_code = 200
    response.text = f'{{"bad": "{CANARY_BODY}"'
    response.content = response.text.encode("utf-8")
    response.json.side_effect = ValueError(f"Expecting value: {CANARY_BODY}")
    monkeypatch.setattr(requests, "post", lambda *a, **k: response)

    with pytest.raises(LLMProviderError) as excinfo:
        client._post_json("https://example.invalid", {}, provider_name="OpenAI")
    err = excinfo.value
    assert err.category == LLMErrorCategory.DECODE
    assert err.__cause__ is None
    assert err.__context__ is None
    assert CANARY_BODY not in str(err)
    assert CANARY_BODY not in repr(err)
    assert CANARY_BODY not in traceback.format_exception(type(err), err, err.__traceback__)


def test_abort_threshold_raise_clears_context(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FunctionLLMClient(
        llm_type="openai",
        model="m",
        environment_config=None,
        timeout_sec=10,
        batch_size_func=5,
        confidence_floor=0.85,
    )
    client.max_total_failures = 1
    batch = FunctionBatch(
        batch_id="b",
        functions=[
            FunctionBody(
                function_id="a.c@f:1-2",
                file_path="a.c",
                symbol="f",
                start_line=1,
                end_line=2,
                body="void f(void) {}",
                candidate_lines=[1],
            )
        ],
    )

    class Boom(RuntimeError):
        def __str__(self) -> str:
            return CANARY_EXC

    monkeypatch.setattr(
        client,
        "_build_pass_f1_prompt",
        lambda _b: LLMPromptParts(system="sys", user="user"),
    )
    monkeypatch.setattr(
        client.base_client, "_make_api_request", MagicMock(side_effect=Boom())
    )
    monkeypatch.setattr("time.sleep", lambda _s: None)

    with pytest.raises(RuntimeError) as excinfo:
        client.analyze_functions_pass_f1(batch)
    err = excinfo.value
    assert "Aborting scan" in str(err)
    assert CANARY_EXC not in str(err)
    assert CANARY_EXC not in repr(err)
    assert err.__cause__ is None
    assert err.__context__ is None
    assert CANARY_EXC not in "".join(
        traceback.format_exception(type(err), err, err.__traceback__)
    )


def test_truncate_utf8_marker_fits_within_cap() -> None:
    from tacs.core.llm_errors import RAW_TRUNCATION_MARKER, truncate_utf8_bytes

    # Multi-byte code point near the boundary.
    text = "α" * 100 + CANARY_BODY + "β" * 100
    cap = 64
    out = truncate_utf8_bytes(text, cap, marker=RAW_TRUNCATION_MARKER)
    encoded = out.encode("utf-8")
    assert len(encoded) <= cap
    # Round-trip decode must succeed (valid UTF-8).
    assert out.encode("utf-8").decode("utf-8") == out
    assert RAW_TRUNCATION_MARKER in out or len(text.encode("utf-8")) <= cap


def test_raw_output_requires_both_flags_and_restrictive_mode(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    # log-llm alone: summary only
    session = ScanSession(
        root_path=str(root),
        output_base=str(tmp_path / "a"),
        enable_llm_logging=True,
        allow_raw_code_logging=False,
    )
    fn = FunctionBody(
        function_id="f.c@f:1-1",
        file_path=str(root / "f.c"),
        symbol="f",
        start_line=1,
        end_line=1,
        body=CANARY_PROMPT,
        candidate_lines=[1],
    )
    response = [
        {
            "function_id": fn.function_id,
            "y2038_summary": "yes",
            "execution_status": "completed",
            "confidence": 0.9,
            "issues": [{"type": "narrowing", "description": CANARY_FINDING, "line": 1}],
        }
    ]
    batch = FunctionBatch(batch_id="b", functions=[fn])
    prompt = LLMPromptParts(system="s", user=CANARY_PROMPT)
    session.save_function_batch(
        pass_name="stage_8_pass_2a",
        batch_num=1,
        function_batch=batch,
        prompt=prompt,
        response=response,
    )
    out = (
        session.llm_dir / "stage_8_pass_2a" / "batches" / "0001_output.json"
    ).read_text(encoding="utf-8")
    assert "response_sha256" in out
    assert '"response"' not in out or "response_item_count" in out
    assert CANARY_FINDING not in out
    assert CANARY_PROMPT not in out
    # Dual flags: raw present, mode not group/world-writable, no headers/credentials keys
    session2 = ScanSession(
        root_path=str(root),
        output_base=str(tmp_path / "b"),
        enable_llm_logging=True,
        allow_raw_code_logging=True,
    )
    session2.save_function_batch(
        pass_name="stage_8_pass_2a",
        batch_num=1,
        function_batch=batch,
        prompt=prompt,
        response=response,
        error_diagnostic={
            "provider": "OpenAI",
            "category": "server_error",
            "status_code": 500,
            "retryable": True,
            "attempt": 3,
            "response_body_len": 12,
            "Authorization": f"Bearer {CANARY_TOKEN}",
            "headers": {"x-api-key": CANARY_TOKEN},
        },
    )
    out_path = session2.llm_dir / "stage_8_pass_2a" / "batches" / "0001_output.json"
    err_path = session2.llm_dir / "stage_8_pass_2a" / "batches" / "0001_error.json"
    assert CANARY_FINDING in out_path.read_text(encoding="utf-8")
    assert out_path.stat().st_mode & 0o077 == 0
    err_payload = json.loads(err_path.read_text(encoding="utf-8"))
    assert set(err_payload.keys()) <= {
        "provider",
        "category",
        "status_code",
        "retryable",
        "attempt",
        "response_body_len",
        "detail",
        "batch_id",
        "pass",
        "batch_num",
        "timestamp",
    }
    assert CANARY_TOKEN not in err_path.read_text(encoding="utf-8")
    assert "Authorization" not in err_payload
    assert "headers" not in err_payload
    assert err_path.stat().st_mode & 0o077 == 0


def test_default_output_summary_allowlisted_fields_only(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    session = ScanSession(
        root_path=str(root),
        output_base=str(tmp_path),
        enable_llm_logging=False,
        allow_raw_code_logging=False,
    )
    fn = FunctionBody(
        function_id="f.c@f:1-1",
        file_path=str(root / "f.c"),
        symbol="f",
        start_line=1,
        end_line=1,
        body=CANARY_PROMPT,
        candidate_lines=[1],
    )
    session.save_function_batch(
        pass_name="stage_8_pass_2a",
        batch_num=1,
        function_batch=FunctionBatch(batch_id="b", functions=[fn]),
        prompt=LLMPromptParts(system="s", user=CANARY_PROMPT),
        response=[
            {
                "function_id": fn.function_id,
                "y2038_summary": "yes",
                "execution_status": "completed",
                "confidence": 0.91,
                "issues": [
                    {"type": "narrowing", "description": CANARY_FINDING, "line": 1}
                ],
            }
        ],
    )
    payload = json.loads(
        (session.llm_dir / "stage_8_pass_2a" / "batches" / "0001_output.json").read_text(
            encoding="utf-8"
        )
    )
    assert "response" not in payload
    assert "response_raw_truncated" not in payload
    allowed_top = {
        "batch_id",
        "pass",
        "batch_num",
        "timestamp",
        "response_item_count",
        "response_bytes",
        "response_sha256",
        "status_counts",
        "verdict_counts",
        "items",
        "privacy",
    }
    assert set(payload.keys()) <= allowed_top
    item = payload["items"][0]
    assert set(item.keys()) <= {
        "function_id",
        "execution_status",
        "y2038_summary",
        "confidence",
        "issue_count",
    }
    assert item["issue_count"] == 1
    blob = json.dumps(payload)
    assert CANARY_FINDING not in blob
    assert CANARY_PROMPT not in blob
    assert "repr" not in blob.lower()
