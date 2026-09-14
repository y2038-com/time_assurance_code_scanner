# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for shared LLM env / Ollama routing helpers."""

from __future__ import annotations

import pytest

from tacs.llm.env import (
    DEFAULT_CLOUD_HOST,
    DEFAULT_LOCAL_HOST,
    DEFAULT_MODEL,
    api_model_for_ollama,
    default_llm_type,
    default_model_id,
    ollama_host,
    ollama_is_cloud_host,
    resolve_ollama_request_target,
)


def test_default_llm_type_is_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TACS_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("TACS_PROVIDER", raising=False)
    assert default_llm_type() == "none"


def test_default_llm_type_env_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TACS_LLM_PROVIDER", "ollama")
    assert default_llm_type() == "ollama"


def test_default_model_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TACS_MODEL", raising=False)
    monkeypatch.delenv("TACS_LLM_MODEL", raising=False)
    assert default_model_id() == DEFAULT_MODEL
    monkeypatch.setenv("TACS_MODEL", "gpt-oss:20b-cloud")
    assert default_model_id() == "gpt-oss:20b-cloud"


def test_ollama_host_defaults_to_cloud(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("OLLAMA_CLOUD_BASE_URL", raising=False)
    assert ollama_host() == DEFAULT_CLOUD_HOST
    assert ollama_is_cloud_host()


def test_ollama_host_local(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_HOST", DEFAULT_LOCAL_HOST)
    assert ollama_host() == DEFAULT_LOCAL_HOST
    assert not ollama_is_cloud_host()


def test_resolve_cloud_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_CLOUD_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="OLLAMA_API_KEY"):
        resolve_ollama_request_target("gpt-oss:120b-cloud")


def test_resolve_cloud_with_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.setenv("OLLAMA_API_KEY", "test-key")
    url, headers, api_model, is_cloud = resolve_ollama_request_target("gpt-oss:120b-cloud")
    assert is_cloud
    assert url.startswith(DEFAULT_CLOUD_HOST)
    assert headers is not None
    assert headers["Authorization"] == "Bearer test-key"
    assert api_model == "gpt-oss:120b"


def test_resolve_local_no_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_HOST", DEFAULT_LOCAL_HOST)
    url, headers, api_model, is_cloud = resolve_ollama_request_target("llama3.1")
    assert not is_cloud
    assert headers is None
    assert api_model == "llama3.1"
    assert url.startswith(DEFAULT_LOCAL_HOST)


def test_api_model_strips_cloud_suffix() -> None:
    assert api_model_for_ollama("gpt-oss:120b-cloud", cloud=True) == "gpt-oss:120b"
    assert api_model_for_ollama("gpt-oss:120b-cloud", cloud=False) == "gpt-oss:120b-cloud"


def test_legacy_cloud_token_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    monkeypatch.setenv("OLLAMA_CLOUD_TOKEN", "legacy-token")
    _url, headers, _model, is_cloud = resolve_ollama_request_target("gpt-oss:120b-cloud")
    assert is_cloud
    assert headers["Authorization"] == "Bearer legacy-token"
