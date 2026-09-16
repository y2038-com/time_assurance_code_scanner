# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""LLM configuration helpers and a thin client factory seam.

Provider HTTP adapters still live on ``tacs.core.llm_client.LLMClient``.
This package holds shared env/host/key resolution so a fuller provider
registry can be added later without changing adapter call sites.
"""

from __future__ import annotations

from tacs.llm.env import (
    CLOUD_HOSTNAME,
    DEFAULT_CLOUD_HOST,
    DEFAULT_LOCAL_HOST,
    DEFAULT_MODEL,
    env_first,
    hostname_of,
    load_dotenv,
    ollama_api_key,
    ollama_is_cloud_host,
    resolve_ollama_request_target,
    default_llm_type,
    default_model_id,
)
from tacs.llm.factory import create_llm_client

__all__ = [
    "CLOUD_HOSTNAME",
    "DEFAULT_CLOUD_HOST",
    "DEFAULT_LOCAL_HOST",
    "DEFAULT_MODEL",
    "create_llm_client",
    "default_llm_type",
    "default_model_id",
    "env_first",
    "hostname_of",
    "load_dotenv",
    "ollama_api_key",
    "ollama_is_cloud_host",
    "resolve_ollama_request_target",
]
