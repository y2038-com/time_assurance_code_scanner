# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for LLM HTTP error typing and connect-timeout diagnostics.

``_post_json`` must preserve ``LLMNonRetryableError`` (so function-LLM retries
stop) and must catch ``ConnectTimeout`` before its ``ConnectionError``
superclass so the specialized connect-timeout message remains reachable.
Provider response bodies must not appear in exception text.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import pytest
import requests

from tacs.core.function_llm_client import FunctionLLMClient
from tacs.core.function_schemas import FunctionBatch, FunctionBody
from tacs.core.llm_client import LLMClient, LLMNonRetryableError
from tacs.core.llm_errors import LLMErrorCategory, LLMProviderError
from tacs.core.llm_prompt import LLMPromptParts


def _client() -> LLMClient:
    return LLMClient(llm_type="openai", model="test-model", timeout_sec=30)


def _response(
    status: int,
    text: str = "error body",
    json_data: Optional[Dict[str, Any]] = None,
) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.text = text
    response.content = text.encode("utf-8")
    if json_data is None:
        response.json.side_effect = ValueError("no json")
    else:
        response.json.return_value = json_data
    return response


def test_post_json_preserves_nonretryable_for_401(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client()
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: _response(401, "CANARY_BODY_unauthorized_secret")
    )

    with pytest.raises(LLMNonRetryableError) as excinfo:
        client._post_json(
            "https://example.invalid/v1/chat",
            {},
            provider_name="OpenAI",
        )

    assert type(excinfo.value) is LLMNonRetryableError
    assert excinfo.value.status_code == 401
    assert excinfo.value.category == LLMErrorCategory.AUTH
    assert excinfo.value.retryable is False
    message = str(excinfo.value)
    assert "401" in message
    assert "CANARY_BODY_unauthorized_secret" not in message
    assert excinfo.value.__cause__ is None


def test_post_json_preserves_nonretryable_for_insufficient_quota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client()
    monkeypatch.setattr(
        requests,
        "post",
        lambda *a, **k: _response(
            429,
            "CANARY_BODY_billing_secret",
            {"error": {"type": "insufficient_quota"}},
        ),
    )

    with pytest.raises(LLMNonRetryableError) as excinfo:
        client._post_json(
            "https://example.invalid/v1/chat",
            {},
            provider_name="OpenAI",
        )

    assert type(excinfo.value) is LLMNonRetryableError
    assert excinfo.value.category == LLMErrorCategory.INSUFFICIENT_QUOTA
    assert "insufficient_quota" in str(excinfo.value)
    assert "CANARY_BODY_billing_secret" not in str(excinfo.value)


@pytest.mark.parametrize("status", [400, 403, 404, 413])
def test_post_json_preserves_nonretryable_for_client_errors(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    client = _client()
    monkeypatch.setattr(
        requests, "post", lambda *a, **k: _response(status, f"CANARY_status-{status}")
    )

    with pytest.raises(LLMNonRetryableError) as excinfo:
        client._post_json(
            "https://example.invalid/v1/chat",
            {},
            provider_name="OpenAI",
        )

    assert type(excinfo.value) is LLMNonRetryableError
    assert str(status) in str(excinfo.value)
    assert f"CANARY_status-{status}" not in str(excinfo.value)


def test_post_json_connect_timeout_uses_specialized_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client()
    monkeypatch.setattr(
        requests, "post", MagicMock(side_effect=requests.exceptions.ConnectTimeout())
    )

    with pytest.raises(LLMProviderError) as excinfo:
        client._post_json(
            "https://example.invalid/v1/chat",
            {},
            provider_name="OpenAI",
        )

    message = str(excinfo.value)
    assert type(excinfo.value) is LLMProviderError
    assert excinfo.value.category == LLMErrorCategory.CONNECT_TIMEOUT
    assert excinfo.value.retryable is True
    assert "connect_timeout" in message
    assert "Cannot connect to OpenAI endpoint" not in message
    assert excinfo.value.__cause__ is None


def test_post_json_connection_error_uses_generic_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client()
    monkeypatch.setattr(
        requests, "post", MagicMock(side_effect=requests.exceptions.ConnectionError())
    )

    with pytest.raises(LLMProviderError) as excinfo:
        client._post_json(
            "https://example.invalid/v1/chat",
            {},
            provider_name="OpenAI",
        )

    assert excinfo.value.category == LLMErrorCategory.CONNECTION
    assert "connection" in str(excinfo.value).lower() or excinfo.value.category.value == "connection"
    assert excinfo.value.__cause__ is None


def _tiny_batch() -> FunctionBatch:
    return FunctionBatch(
        batch_id="b1",
        functions=[
            FunctionBody(
                function_id="f.c@f:1-3",
                file_path="f.c",
                symbol="f",
                start_line=1,
                end_line=3,
                body="void f(void) { time_t t = time(NULL); }",
                candidate_lines=[2],
            )
        ],
    )


def test_function_llm_does_not_retry_nonretryable_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FunctionLLMClient(
        llm_type="openai",
        model="test-model",
        environment_config=None,
        timeout_sec=30,
        batch_size_func=10,
        confidence_floor=0.85,
    )
    calls = {"n": 0}

    def boom(_prompt: LLMPromptParts) -> Dict[str, Any]:
        calls["n"] += 1
        raise LLMNonRetryableError(
            provider="OpenAI",
            category=LLMErrorCategory.AUTH,
            status_code=401,
        )

    monkeypatch.setattr(
        client,
        "_build_pass_f1_prompt",
        lambda _batch: LLMPromptParts(system="instructions", user="analysis data"),
    )
    monkeypatch.setattr(client.base_client, "_make_api_request", boom)
    monkeypatch.setattr("time.sleep", lambda _s: None)

    with pytest.raises(LLMNonRetryableError):
        client.analyze_functions_pass_f1(_tiny_batch())

    assert calls["n"] == 1


def test_function_llm_still_retries_retryable_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FunctionLLMClient(
        llm_type="openai",
        model="test-model",
        environment_config=None,
        timeout_sec=30,
        batch_size_func=10,
        confidence_floor=0.85,
    )
    calls = {"n": 0}

    def flaky(_prompt: LLMPromptParts) -> Dict[str, Any]:
        calls["n"] += 1
        if calls["n"] < 2:
            raise LLMProviderError(
                provider="OpenAI",
                category=LLMErrorCategory.CONNECTION,
                retryable=True,
            )
        return {
            "choices": [{"message": {"content": "[]"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        }

    monkeypatch.setattr(
        client,
        "_build_pass_f1_prompt",
        lambda _batch: LLMPromptParts(system="instructions", user="analysis data"),
    )
    monkeypatch.setattr(client.base_client, "_make_api_request", flaky)
    monkeypatch.setattr(
        client,
        "_parse_pass_f1_response",
        lambda _data, functions: client._fallback_pass_f1_responses(functions, "ok"),
    )
    monkeypatch.setattr("time.sleep", lambda _s: None)

    results = client.analyze_functions_pass_f1(_tiny_batch())

    assert calls["n"] == 2
    assert len(results) == 1
