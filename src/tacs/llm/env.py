# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Shared environment helpers for LLM defaults and Ollama routing.

Aligned with the tads operator model:
- ``OLLAMA_HOST`` unset → Ollama Cloud (``https://ollama.com``)
- Local daemon: ``OLLAMA_HOST=http://127.0.0.1:11434``
- Prefer ``OLLAMA_API_KEY``; accept legacy ``OLLAMA_CLOUD_TOKEN``

CLI default remains ``--llm none`` unless the user opts in via ``--llm``
or by setting ``TACS_LLM_PROVIDER`` (explicit env opt-in).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

DEFAULT_CLOUD_HOST = "https://ollama.com"
DEFAULT_LOCAL_HOST = "http://127.0.0.1:11434"
DEFAULT_MODEL = "gpt-oss:120b-cloud"
CLOUD_HOSTNAME = "ollama.com"


def load_dotenv(path: Optional[Path] = None) -> None:
    """Best-effort ``.env`` loader without requiring python-dotenv.

    Only sets keys that are not already present in ``os.environ``.
    """
    env_path = path or (Path.cwd() / ".env")
    if not env_path.is_file():
        return
    try:
        text = env_path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


def env_first(*names: str, default: str = "") -> str:
    """Return the first non-empty environment value among ``names``."""
    for name in names:
        value = os.getenv(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def ollama_api_key() -> str:
    """Ollama Cloud API key (preferred) or legacy cloud token."""
    return env_first("OLLAMA_API_KEY", "OLLAMA_CLOUD_TOKEN")


def default_llm_type() -> str:
    """
    Preferred: ``TACS_LLM_PROVIDER``.
    Alias: ``TACS_PROVIDER``.
    Default: ``none`` (no external LLM until explicit opt-in).
    """
    return env_first("TACS_LLM_PROVIDER", "TACS_PROVIDER", default="none").lower()


def default_model_id() -> str:
    """Preferred: ``TACS_MODEL``. Alias: ``TACS_LLM_MODEL``."""
    return env_first("TACS_MODEL", "TACS_LLM_MODEL", default=DEFAULT_MODEL)


def ollama_host() -> str:
    """Resolved Ollama base URL (cloud when ``OLLAMA_HOST`` is unset)."""
    raw = (os.getenv("OLLAMA_HOST") or "").strip()
    if not raw:
        # Optional override used by older installs / tests.
        cloud = (os.getenv("OLLAMA_CLOUD_BASE_URL") or "").strip()
        return (cloud or DEFAULT_CLOUD_HOST).rstrip("/")
    return raw.rstrip("/")


def hostname_of(host: str) -> str:
    """
    Extract the lowercase hostname from a base URL or a bare ``host[:port]``.

    ``OLLAMA_HOST`` is conventionally a URL but is also accepted without a
    scheme, so an authority prefix is added when one is missing: urlsplit would
    otherwise read ``ollama.com:443`` as the scheme ``ollama.com`` and
    ``127.0.0.1:11434`` as a path, leaving the hostname empty either way.
    """
    text = (host or "").strip()
    if not text:
        return ""
    if "//" not in text:
        text = "//" + text
    try:
        hostname = urlsplit(text).hostname or ""
    except ValueError:
        return ""
    # A trailing dot is the fully qualified form of the same name.
    return hostname.rstrip(".").lower()


def ollama_is_cloud_host(host: Optional[str] = None) -> bool:
    """
    True when the resolved host is Ollama Cloud.

    The hostname must be exactly ``ollama.com`` or a subdomain of it. This
    decides whether ``OLLAMA_API_KEY`` is attached to the request, so it is
    matched structurally rather than as a substring: ``evilollama.com``,
    ``ollama.com.evil.example``, and ``https://ollama.com@evil.example`` all
    contain the string ``ollama.com`` but are not Ollama Cloud.
    """
    hostname = hostname_of(host or ollama_host())
    return hostname == CLOUD_HOSTNAME or hostname.endswith("." + CLOUD_HOSTNAME)


def looks_like_cloud_model(model: str) -> bool:
    """Heuristic: model id is a hosted / ``*-cloud`` style name."""
    name = (model or "").strip().lower()
    return "-cloud" in name or name.endswith(":cloud")


def api_model_for_ollama(model: str, *, cloud: bool) -> str:
    """Map CLI/model picker ids to the id expected by the Ollama HTTP API."""
    if cloud and (model or "").endswith("-cloud"):
        return model[:-6]
    return model


def resolve_ollama_request_target(
    model: str,
) -> tuple[str, dict[str, str] | None, str, bool]:
    """
    Resolve Ollama generate URL, optional auth headers, API model id, and cloud flag.

    Returns:
        ``(url, headers_or_none, api_model, is_cloud)``
    """
    host = ollama_host()
    is_cloud = ollama_is_cloud_host(host)
    api_model = api_model_for_ollama(model, cloud=is_cloud)
    url = f"{host}/api/generate"

    if is_cloud:
        token = ollama_api_key()
        if not token:
            raise RuntimeError(
                "Ollama Cloud is not configured. Set OLLAMA_API_KEY "
                f"(default host is {DEFAULT_CLOUD_HOST}). "
                f"For a local daemon use OLLAMA_HOST={DEFAULT_LOCAL_HOST}."
            )
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        return url, headers, api_model, True

    return url, None, api_model, False
