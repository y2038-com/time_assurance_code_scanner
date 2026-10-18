# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""GPT-6 Luna request policy, payloads, CLI validation, shape, and retries."""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from report_renderer.core import load_scan_document
from report_renderer.renderers import _format_run_provenance, render_html, render_text
from tacs.core.function_llm_client import FunctionLLMClient
from tacs.core.function_schemas import FunctionBatch, FunctionBody
from tacs.core.llm_client import LLMClient
from tacs.core.llm_errors import LLMErrorCategory, LLMProviderError
from tacs.core.llm_prompt import LLMPromptParts
from tacs.core.schema import PUBLIC_RESULT_SCHEMA_VERSION, Metrics, ScanMetadata
from tacs.llm.env import DEFAULT_MODEL
from tacs.llm.openai_models import (
    DEFAULT_OPENAI_TEMPERATURE,
    GPT_6_LUNA,
    InvalidReasoningEffortError,
    build_openai_chat_payload,
    is_official_openai_base_url,
    openai_model_policy,
    recorded_reasoning_effort,
    resolve_reasoning_effort,
)


def _prompt() -> LLMPromptParts:
    return LLMPromptParts(system="sys", user="user payload")


def _ok(
    content: str = '{"results": []}',
    *,
    finish_reason: object = "stop",
    usage: dict | None = None,
    omit_finish_reason: bool = False,
    refusal: str | None = None,
) -> dict:
    message: dict[str, Any] = {"content": content}
    if refusal is not None:
        message["refusal"] = refusal
    choice: dict[str, Any] = {"message": message}
    if not omit_finish_reason:
        choice["finish_reason"] = finish_reason
    return {
        "choices": [choice],
        "usage": usage or {"prompt_tokens": 1, "completion_tokens": 1},
    }


def _capture_openai(
    monkeypatch,
    responder,
    *,
    model: str = GPT_6_LUNA,
    reasoning_effort: str | None = None,
    base_url: str | None = None,
):
    captured: dict[str, Any] = {"calls": []}

    def fake_post_and_normalize(self, url, data, *, headers=None, provider_name="OpenAI"):
        captured["calls"].append(
            {"url": url, "payload": copy.deepcopy(data), "headers": headers}
        )
        return responder(captured["calls"][-1])

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    if base_url is None:
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    else:
        monkeypatch.setenv("OPENAI_BASE_URL", base_url)
    monkeypatch.setattr(LLMClient, "_post_and_normalize", fake_post_and_normalize)
    client = LLMClient(
        llm_type="openai",
        model=model,
        timeout_sec=10,
        reasoning_effort=reasoning_effort,
    )
    captured["client"] = client
    captured["response"] = client._make_openai_request(_prompt())
    return captured


def _tiny_batch() -> FunctionBatch:
    return FunctionBatch(
        batch_id="b1",
        iteration=1,
        functions=[
            FunctionBody(
                function_id="f.c@g:1-2",
                file_path="f.c",
                symbol="g",
                start_line=1,
                end_line=2,
                body="int g(void) { return 0; }",
                candidate_lines=[1],
            )
        ],
    )


# --- policy / payload matrix -------------------------------------------------


def test_default_model_unchanged():
    assert DEFAULT_MODEL == "gpt-oss:120b-cloud"


def test_luna_policy_none_and_low_only():
    policy = openai_model_policy(GPT_6_LUNA)
    assert policy.supports_reasoning_effort is True
    assert policy.completion_token_param is None
    assert policy.default_completion_tokens is None
    assert policy.allowed_reasoning_efforts == frozenset({"none", "low"})
    assert resolve_reasoning_effort(policy, None) == "none"


def test_luna_omits_max_completion_tokens():
    """No Luna-only completion cap; matches pre-Luna OpenAI (unset limit)."""
    for effort in (None, "none", "low"):
        payload = build_openai_chat_payload(
            model_id=GPT_6_LUNA, system="s", user="u", reasoning_effort=effort
        )
        assert "max_completion_tokens" not in payload
        assert "max_tokens" not in payload


def test_unknown_openai_model_keeps_pre_luna_shape():
    payload = build_openai_chat_payload(
        model_id="gpt-4.1-mini",
        system="s",
        user="u",
    )
    assert payload == {
        "model": "gpt-4.1-mini",
        "messages": [
            {"role": "system", "content": "s"},
            {"role": "user", "content": "u"},
        ],
        "temperature": DEFAULT_OPENAI_TEMPERATURE,
    }
    assert "reasoning_effort" not in payload
    assert "max_tokens" not in payload
    assert "max_completion_tokens" not in payload


def test_luna_unset_sends_none_with_temperature():
    payload = build_openai_chat_payload(
        model_id=GPT_6_LUNA,
        system="s",
        user="u",
        reasoning_effort=None,
    )
    assert payload["model"] == GPT_6_LUNA
    assert payload["reasoning_effort"] == "none"
    assert payload["temperature"] == DEFAULT_OPENAI_TEMPERATURE
    assert set(payload.keys()) == {
        "model",
        "messages",
        "reasoning_effort",
        "temperature",
    }


def test_luna_explicit_none_same_as_unset():
    a = build_openai_chat_payload(
        model_id=GPT_6_LUNA, system="s", user="u", reasoning_effort=None
    )
    b = build_openai_chat_payload(
        model_id=GPT_6_LUNA, system="s", user="u", reasoning_effort="none"
    )
    assert a == b


def test_luna_low_omits_sampling():
    payload = build_openai_chat_payload(
        model_id=GPT_6_LUNA,
        system="s",
        user="u",
        reasoning_effort="low",
    )
    assert payload["reasoning_effort"] == "low"
    assert "temperature" not in payload
    assert "top_p" not in payload
    assert "logprobs" not in payload
    assert "max_completion_tokens" not in payload


def test_existing_models_never_receive_reasoning_effort():
    for model in ("gpt-4.1-mini", "gpt-oss:120b-cloud", "unknown-model"):
        payload = build_openai_chat_payload(model_id=model, system="s", user="u")
        assert "reasoning_effort" not in payload


def test_unknown_model_rejects_explicit_effort():
    with pytest.raises(InvalidReasoningEffortError):
        build_openai_chat_payload(
            model_id="gpt-4.1-mini",
            system="s",
            user="u",
            reasoning_effort="none",
        )


def test_luna_rejects_medium_and_high():
    for effort in ("medium", "high", "xhigh", "max"):
        with pytest.raises(InvalidReasoningEffortError):
            resolve_reasoning_effort(openai_model_policy(GPT_6_LUNA), effort)


def test_case_and_whitespace_normalization():
    assert resolve_reasoning_effort(openai_model_policy(GPT_6_LUNA), " Low ") == "low"
    assert resolve_reasoning_effort(openai_model_policy(GPT_6_LUNA), "NONE") == "none"


def test_no_pricing_or_context_window_in_policy():
    policy = openai_model_policy(GPT_6_LUNA)
    assert not hasattr(policy, "pricing")
    assert not hasattr(policy, "context_window_tokens")


# --- client validation before HTTP ------------------------------------------


def test_client_rejects_effort_for_non_openai_before_http(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(InvalidReasoningEffortError):
        LLMClient(llm_type="anthropic", model="claude", reasoning_effort="low")
    with pytest.raises(InvalidReasoningEffortError):
        LLMClient(llm_type="ollama", model="m", reasoning_effort="none")
    with pytest.raises(InvalidReasoningEffortError):
        LLMClient(llm_type="gemini", model="g", reasoning_effort="low")
    with pytest.raises(InvalidReasoningEffortError):
        LLMClient(llm_type="none", model="none", reasoning_effort="none")


def test_client_rejects_effort_for_unknown_openai_model():
    with pytest.raises(InvalidReasoningEffortError):
        LLMClient(
            llm_type="openai",
            model="gpt-4.1-mini",
            reasoning_effort="low",
        )


def test_http_payload_luna_none(monkeypatch):
    cap = _capture_openai(
        monkeypatch,
        lambda _call: _ok(),
        model=GPT_6_LUNA,
        reasoning_effort=None,
    )
    payload = cap["calls"][0]["payload"]
    assert payload["model"] == GPT_6_LUNA
    assert payload["reasoning_effort"] == "none"
    assert payload["temperature"] == 0.1
    assert "max_completion_tokens" not in payload
    assert "max_tokens" not in payload
    assert cap["calls"][0]["url"].endswith("/chat/completions")


def test_http_payload_luna_low(monkeypatch):
    cap = _capture_openai(
        monkeypatch,
        lambda _call: _ok(),
        model=GPT_6_LUNA,
        reasoning_effort="low",
    )
    payload = cap["calls"][0]["payload"]
    assert payload["reasoning_effort"] == "low"
    assert "temperature" not in payload
    assert "max_completion_tokens" not in payload


def test_http_payload_non_luna_unchanged(monkeypatch):
    cap = _capture_openai(
        monkeypatch,
        lambda _call: _ok(),
        model="gpt-4.1-mini",
        reasoning_effort=None,
    )
    payload = cap["calls"][0]["payload"]
    assert payload == {
        "model": "gpt-4.1-mini",
        "messages": [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "user payload"},
        ],
        "temperature": 0.1,
    }


# --- finish_reason matrix ---------------------------------------------------


def test_valid_luna_response_parses(monkeypatch):
    cap = _capture_openai(monkeypatch, lambda _c: _ok('{"ok": true}'))
    assert cap["response"]["choices"][0]["message"]["content"] == '{"ok": true}'


def test_refusal_fails_safely(monkeypatch):
    with pytest.raises(LLMProviderError) as ei:
        _capture_openai(
            monkeypatch,
            lambda _c: _ok(content="x", refusal="I cannot help"),
        )
    assert ei.value.detail == "unexpected_response_format"
    assert ei.value.retryable is False
    assert "I cannot help" not in str(ei.value)


def test_missing_null_non_string_content_fails(monkeypatch):
    for bad in (None, 123, {"a": 1}):
        with pytest.raises(LLMProviderError) as ei:
            _capture_openai(
                monkeypatch,
                lambda _c, content=bad: {
                    "choices": [
                        {"message": {"content": content}, "finish_reason": "stop"}
                    ],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                },
            )
        assert ei.value.detail == "unexpected_response_format"
        assert ei.value.retryable is False


def test_truncation_fails_before_parsing(monkeypatch):
    with pytest.raises(LLMProviderError) as ei:
        _capture_openai(
            monkeypatch,
            lambda _c: _ok(content='{"partial"', finish_reason="length"),
        )
    assert ei.value.detail == "output_truncated"
    assert ei.value.retryable is False


@pytest.mark.parametrize(
    "finish_reason,detail",
    [
        ("content_filter", "output_rejected"),
        ("tool_calls", "unexpected_output_type"),
        ("function_call", "unexpected_output_type"),
        ("mystery", "unexpected_response_format"),
    ],
)
def test_finish_reason_fail_closed(monkeypatch, finish_reason, detail):
    with pytest.raises(LLMProviderError) as ei:
        _capture_openai(
            monkeypatch,
            lambda _c: _ok(finish_reason=finish_reason),
        )
    assert ei.value.detail == detail
    assert ei.value.retryable is False
    assert finish_reason not in str(ei.value)


def test_official_missing_finish_reason_fails(monkeypatch):
    assert is_official_openai_base_url(None) is True
    with pytest.raises(LLMProviderError) as ei:
        _capture_openai(
            monkeypatch,
            lambda _c: _ok(omit_finish_reason=True),
        )
    assert ei.value.detail == "unexpected_response_format"
    assert ei.value.retryable is False


def test_official_null_finish_reason_fails(monkeypatch):
    with pytest.raises(LLMProviderError) as ei:
        _capture_openai(
            monkeypatch,
            lambda _c: _ok(finish_reason=None),
        )
    assert ei.value.detail == "unexpected_response_format"


def test_compat_missing_finish_reason_accepted(monkeypatch):
    cap = _capture_openai(
        monkeypatch,
        lambda _c: _ok(omit_finish_reason=True),
        base_url="http://127.0.0.1:8080/v1",
    )
    assert cap["response"]["choices"][0]["message"]["content"]


# --- retry / provider-call counts -------------------------------------------


def _count_function_pass_calls(monkeypatch, *, responder, expect_raise=False):
    """Drive Pass F1 once; return provider call count (and optional exception)."""
    calls: list[Any] = []

    def fake_make(self, prompt):
        calls.append(1)
        return responder(len(calls))

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.setattr(LLMClient, "_make_api_request", fake_make)
    # Avoid real sleep on retries
    monkeypatch.setattr("time.sleep", lambda *_a, **_k: None)

    client = FunctionLLMClient(
        llm_type="openai",
        model=GPT_6_LUNA,
        environment_config=None,
        timeout_sec=5,
        batch_size_func=15,
        confidence_floor=0.7,
        reasoning_effort="none",
    )
    batch = _tiny_batch()
    if expect_raise:
        with pytest.raises(LLMProviderError):
            client.analyze_functions_pass_f1(batch)
    else:
        client.analyze_functions_pass_f1(batch)
    return len(calls)


def test_retry_count_transient_transport(monkeypatch):
    err = LLMProviderError(
        provider="OpenAI",
        category=LLMErrorCategory.CONNECTION,
        retryable=True,
        detail="connection",
    )

    def responder(_n):
        raise err

    assert _count_function_pass_calls(monkeypatch, responder=responder) == 3


def test_retry_count_http_retryable_status(monkeypatch):
    err = LLMProviderError(
        provider="OpenAI",
        category=LLMErrorCategory.RATE_LIMIT,
        retryable=True,
        status_code=429,
    )

    def responder(_n):
        raise err

    assert _count_function_pass_calls(monkeypatch, responder=responder) == 3


@pytest.mark.parametrize(
    "detail",
    [
        "unexpected_response_format",  # refusal / missing / unknown
        "output_truncated",
        "output_rejected",
        "unexpected_output_type",
    ],
)
def test_retry_count_deterministic_shape_errors_once(monkeypatch, detail):
    err = LLMProviderError(
        provider="OpenAI",
        category=LLMErrorCategory.DECODE,
        retryable=False,
        detail=detail,
    )

    def responder(_n):
        raise err

    assert (
        _count_function_pass_calls(
            monkeypatch, responder=responder, expect_raise=True
        )
        == 1
    )


def test_retry_count_malformed_json_once_no_http_retry(monkeypatch):
    def responder(_n):
        return {
            "choices": [
                {"message": {"content": "{not-json"}, "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        }

    # Parse fallback is not an HTTP retry: one successful provider response.
    assert _count_function_pass_calls(monkeypatch, responder=responder) == 1


def test_retry_count_function_id_validation_once(monkeypatch):
    def responder(_n):
        # Valid JSON array but wrong function_id → local alignment stubs, no retry.
        return {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            [
                                {
                                    "function_id": "other.c@x:1-1",
                                    "y2038_summary": "no",
                                    "confidence": 0.9,
                                    "issues": [],
                                    "needs_more_context": False,
                                    "needs": [],
                                }
                            ]
                        )
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        }

    assert _count_function_pass_calls(monkeypatch, responder=responder) == 1


def test_shape_error_via_make_openai_request_is_non_retryable(monkeypatch):
    """Direct proof: truncation from _make_openai_request carries retryable=False."""
    with pytest.raises(LLMProviderError) as ei:
        _capture_openai(
            monkeypatch,
            lambda _c: _ok(finish_reason="length"),
        )
    assert ei.value.retryable is False
    assert ei.value.detail == "output_truncated"


# --- usage / provenance -----------------------------------------------------


def test_reasoning_tokens_optional_not_double_counted(monkeypatch):
    usage = {
        "prompt_tokens": 10,
        "completion_tokens": 100,
        "completion_tokens_details": {"reasoning_tokens": 40},
    }
    cap = _capture_openai(
        monkeypatch,
        lambda _c: _ok(usage=usage),
        model=GPT_6_LUNA,
    )
    out_usage = cap["response"]["usage"]
    assert out_usage["completion_tokens"] == 100
    assert out_usage["reasoning_tokens"] == 40
    assert out_usage["total_tokens"] == 110
    client = cap["client"]
    client._track_tokens(10, 100, "S2_P1", reasoning_tokens=40)
    stats = client.get_token_stats()
    assert stats["total_completion_tokens"] == 100
    assert stats["total_reasoning_tokens"] == 40
    assert stats["total_tokens"] == 110


def test_boolean_and_negative_usage_rejected(monkeypatch):
    for usage in (
        {"prompt_tokens": True, "completion_tokens": 1},
        {"prompt_tokens": 1, "completion_tokens": -1},
        {
            "prompt_tokens": 1,
            "completion_tokens": 10,
            "completion_tokens_details": {"reasoning_tokens": True},
        },
        {
            "prompt_tokens": 1,
            "completion_tokens": 10,
            "completion_tokens_details": {"reasoning_tokens": -3},
        },
    ):
        with pytest.raises(LLMProviderError) as ei:
            _capture_openai(monkeypatch, lambda _c, u=usage: _ok(usage=u))
        assert ei.value.detail == "invalid_usage"
        assert ei.value.retryable is False


def test_recorded_effort_provenance():
    assert (
        recorded_reasoning_effort(
            provider_id="openai", model=GPT_6_LUNA, requested=None
        )
        == "none"
    )
    assert (
        recorded_reasoning_effort(
            provider_id="openai", model=GPT_6_LUNA, requested="low"
        )
        == "low"
    )
    assert (
        recorded_reasoning_effort(
            provider_id="openai", model="gpt-4.1-mini", requested=None
        )
        is None
    )
    assert (
        recorded_reasoning_effort(provider_id="ollama", model="x", requested=None)
        is None
    )


def test_schema_version_is_1_2():
    assert PUBLIC_RESULT_SCHEMA_VERSION == "1.2"


def test_meta_round_trip_reasoning_effort():
    meta = ScanMetadata(
        root=".",
        rules_path="rules.json",
        model=GPT_6_LUNA,
        llm_provider="openai",
        reasoning_effort="low",
        confidence_floor=0.7,
        metrics=Metrics(
            total_files=1,
            total_lines=1,
            total_chars=1,
            total_words=1,
            max_line_length=80,
            avg_line_length=40.0,
            max_file_length=100,
            avg_file_length=50.0,
        ),
        timestamp="2026-01-01T00:00:00Z",
    )
    raw = meta.model_dump() if hasattr(meta, "model_dump") else meta.dict()
    assert raw["reasoning_effort"] == "low"
    assert raw["llm_provider"] == "openai"
    restored = (
        ScanMetadata.model_validate(raw)
        if hasattr(ScanMetadata, "model_validate")
        else ScanMetadata.parse_obj(raw)
    )
    assert restored.reasoning_effort == "low"


def test_legacy_schema_1_0_and_1_1_load_without_invented_provenance():
    for version in ("1.0", "1.1"):
        payload = {
            "schema_version": version,
            "meta": {
                "root": ".",
                "rules_path": "r.json",
                "model": "none",
                "confidence_floor": 0.7,
                "metrics": {
                    "total_files": 0,
                    "total_lines": 0,
                    "total_chars": 0,
                    "total_words": 0,
                    "max_line_length": 0,
                    "avg_line_length": 0.0,
                    "max_file_length": 0,
                    "avg_file_length": 0.0,
                },
                "timestamp": "2026-01-01T00:00:00Z",
            },
            "candidates": [],
            "assessments": [],
            "findings": [],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(payload, fh)
            name = fh.name
        try:
            before = Path(name).read_text(encoding="utf-8")
            doc = load_scan_document(name)
            after = Path(name).read_text(encoding="utf-8")
            assert before == after  # load does not rewrite
            assert doc.schema_version == version
            assert "reasoning_effort" not in (doc.meta or {})
            assert "llm_provider" not in (doc.meta or {})
            text = render_text([], meta=doc.meta, has_candidate_section=True)
            html = render_html(
                [], title="t", group_by="file", meta=doc.meta, has_candidate_section=True
            )
            assert "reasoning_effort" not in text
            assert "reasoning_effort" not in html
            assert "llm_provider" not in text
        finally:
            Path(name).unlink(missing_ok=True)


def test_render_shows_reasoning_effort_consistently():
    meta = {
        "model": GPT_6_LUNA,
        "llm_provider": "openai",
        "reasoning_effort": "none",
    }
    line = _format_run_provenance(meta)
    assert line is not None
    text = render_text([], meta=meta)
    html = render_html([], title="t", group_by="file", meta=meta)
    assert "provider: openai" in text and "provider: openai" in html
    assert "model: gpt-6-luna" in text and "model: gpt-6-luna" in html
    assert "reasoning_effort: none" in text and "reasoning_effort: none" in html


# --- CLI / batch / structured-output ----------------------------------------


def test_scan_and_repos_expose_reasoning_effort():
    from tacs.batch_scan_repos import _build_parser
    from tacs.scan_command import main as scan_command

    scan_flags = {
        opt for p in scan_command.params for opt in p.opts + p.secondary_opts
    }
    repos_flags = {
        opt for a in _build_parser()._actions for opt in a.option_strings
    }
    assert "--reasoning-effort" in scan_flags
    assert "--reasoning-effort" in repos_flags


def test_pipeline_propagates_reasoning_effort():
    from tacs.core.pipeline import ScanningPipeline

    scanner = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "tacs"
        / "python"
        / "y2038scan_fast_json_group.py"
    )
    pipeline = ScanningPipeline(
        scanner_path=str(scanner),
        llm_type="openai",
        model=GPT_6_LUNA,
        reasoning_effort="low",
        function_first=True,
    )
    assert pipeline.reasoning_effort == "low"
    assert pipeline.function_llm_client.base_client.effective_reasoning_effort() == "low"


def test_no_native_structured_output_in_payload():
    payload = build_openai_chat_payload(
        model_id=GPT_6_LUNA, system="s", user="u", reasoning_effort="none"
    )
    assert "response_format" not in payload
