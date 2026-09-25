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
    hostname_of,
    ollama_host,
    ollama_is_cloud_host,
    resolve_ollama_request_target,
)

# Hosts that contain the string "ollama.com" but are not Ollama Cloud. A
# substring test would classify each as cloud and attach OLLAMA_API_KEY.
IMPOSTOR_HOSTS = [
    "https://evilollama.com",
    "https://notollama.com/api",
    "https://ollama.com.evil.example",
    "https://ollama.compute.example",
    "https://ollama.com@evil.example",
    "https://evil.example/?upstream=https://ollama.com",
    "https://evil.example/ollama.com",
    "http://127.0.0.1:11434/?proxy=ollama.com",
]


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


# --- cloud host identification ----------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://ollama.com", "ollama.com"),
        ("https://OLLAMA.COM/api/generate", "ollama.com"),
        ("https://ollama.com.", "ollama.com"),
        ("ollama.com", "ollama.com"),
        ("ollama.com:443", "ollama.com"),
        ("http://127.0.0.1:11434", "127.0.0.1"),
        ("127.0.0.1:11434", "127.0.0.1"),
        ("https://ollama.com@evil.example", "evil.example"),
        ("", ""),
        ("   ", ""),
    ],
)
def test_hostname_of_reads_the_authority(value: str, expected: str) -> None:
    """Hostnames come from the URL authority, with or without a scheme."""
    assert hostname_of(value) == expected


@pytest.mark.parametrize("host", ["https://ollama.com", "https://api.ollama.com"])
def test_cloud_host_accepts_ollama_com_and_subdomains(host: str) -> None:
    assert ollama_is_cloud_host(host)


@pytest.mark.parametrize("host", IMPOSTOR_HOSTS)
def test_cloud_host_rejects_lookalike_hosts(host: str) -> None:
    """A host that merely contains "ollama.com" must not be treated as cloud."""
    assert not ollama_is_cloud_host(host)


@pytest.mark.parametrize("host", IMPOSTOR_HOSTS)
def test_api_key_is_never_sent_to_a_lookalike_host(
    host: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The API key must not leave the machine for a host that is not the cloud."""
    monkeypatch.setenv("OLLAMA_HOST", host)
    monkeypatch.setenv("OLLAMA_API_KEY", "secret-key")

    _url, headers, _model, is_cloud = resolve_ollama_request_target("gpt-oss:120b-cloud")

    assert not is_cloud
    assert headers is None


def test_local_host_named_ollama_com_subdomain_is_cloud(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real cloud subdomain still authenticates."""
    monkeypatch.setenv("OLLAMA_HOST", "https://api.ollama.com")
    monkeypatch.setenv("OLLAMA_API_KEY", "secret-key")

    _url, headers, _model, is_cloud = resolve_ollama_request_target("gpt-oss:120b-cloud")

    assert is_cloud
    assert headers is not None
    assert headers["Authorization"] == "Bearer secret-key"


# --- the request the client actually sends ----------------------------------


class _CapturedPost:
    """Records the outgoing request instead of performing it."""

    def __init__(self) -> None:
        self.kwargs: dict = {}

    def __call__(self, url, **kwargs):  # noqa: ANN001
        self.kwargs = {"url": url, **kwargs}

        class _Response:
            status_code = 200

            @staticmethod
            def json():
                return {"response": "ok", "prompt_eval_count": 1, "eval_count": 1}

        return _Response()


def _post_to_ollama(monkeypatch: pytest.MonkeyPatch, host: str) -> dict:
    """Run one Ollama request against ``host`` and return the captured call.

    A plain model id is used so the request timeout reflects the resolved cloud
    flag alone; a ``-cloud`` model id doubles the timeout on its own.
    """
    import requests

    from tacs.core.llm_client import LLMClient
    from tacs.core.llm_prompt import LLMPromptParts

    monkeypatch.setenv("OLLAMA_HOST", host)
    monkeypatch.setenv("OLLAMA_API_KEY", "secret-key")
    captured = _CapturedPost()
    monkeypatch.setattr(requests, "post", captured)

    client = LLMClient(llm_type="ollama", model="llama3.1", timeout_sec=30)
    client._make_local_request(LLMPromptParts(system="instructions", user="analysis data"))
    return captured.kwargs


@pytest.mark.parametrize("host", IMPOSTOR_HOSTS)
def test_client_sends_no_credentials_to_a_lookalike_host(
    host: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The client must not authenticate to a host that only looks like the cloud."""
    call = _post_to_ollama(monkeypatch, host)

    assert call["headers"] is None
    assert "secret-key" not in str(call)
    # Treated as local throughout, including the timeout allowance.
    assert call["timeout"] == 30


def test_client_authenticates_to_the_real_cloud(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    call = _post_to_ollama(monkeypatch, "https://ollama.com")

    assert call["headers"]["Authorization"] == "Bearer secret-key"
    assert call["url"] == "https://ollama.com/api/generate"
    assert call["timeout"] == 60
