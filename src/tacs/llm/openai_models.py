# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""OpenAI Chat Completions model request policy.

Narrow capability table for payload construction. Local JSON / function_id
validation remains authoritative for model output. Not a general model registry.

GPT-6 Luna support in TACS exposes ``none`` and ``low`` reasoning efforts only.

Completion-token fields: pre-Luna TACS OpenAI payloads omit any completion
budget (unlike Anthropic ``max_tokens=8000`` / Ollama ``num_predict=8000``).
Luna matches that contract — no ``max_completion_tokens`` — so there is no
unexplained Luna-only cap. Pricing and context-window figures live in docs only;
TACS has no cost estimator and does not use context window for batching.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

# Efforts supported by the TACS CLI / payload builder for GPT-6 Luna.
LUNA_REASONING_EFFORTS = frozenset({"none", "low"})

# Existing TACS OpenAI sampling default (pre-Luna contract).
DEFAULT_OPENAI_TEMPERATURE = 0.1

# Official Chat Completions base (no trailing slash). Custom OPENAI_BASE_URL
# values are treated as OpenAI-compatible compatibility endpoints.
OFFICIAL_OPENAI_BASE_URL = "https://api.openai.com/v1"

GPT_6_LUNA = "gpt-6-luna"


@dataclass(frozen=True)
class OpenAIModelPolicy:
    """Per-model Chat Completions request policy."""

    model_id: str
    # ``None`` means omit the completion-token field (pre-Luna TACS OpenAI shape).
    completion_token_param: Optional[str]
    supports_reasoning_effort: bool
    allowed_reasoning_efforts: frozenset[str]
    default_reasoning_effort: Optional[str]
    send_temperature_when_reasoning_none: bool
    default_completion_tokens: Optional[int] = None


_GPT_6_LUNA_POLICY = OpenAIModelPolicy(
    model_id=GPT_6_LUNA,
    # Omit completion budget: same as pre-Luna OpenAI in TACS (API model default).
    completion_token_param=None,
    supports_reasoning_effort=True,
    allowed_reasoning_efforts=LUNA_REASONING_EFFORTS,
    default_reasoning_effort="none",
    send_temperature_when_reasoning_none=True,
    default_completion_tokens=None,
)

_POLICIES: dict[str, OpenAIModelPolicy] = {
    GPT_6_LUNA: _GPT_6_LUNA_POLICY,
}


class InvalidReasoningEffortError(ValueError):
    """Controlled failure for an unsupported or unknown reasoning effort."""


def openai_model_policy(model: str) -> OpenAIModelPolicy:
    """Return the policy for a known OpenAI model, or a pre-Luna compatible default."""
    key = (model or "").strip().lower()
    if key in _POLICIES:
        return _POLICIES[key]
    # Unknown OpenAI models keep the pre-Luna Chat Completions shape:
    # messages + temperature only (no max_tokens, no reasoning_effort).
    return OpenAIModelPolicy(
        model_id=key or "unknown",
        completion_token_param=None,
        supports_reasoning_effort=False,
        allowed_reasoning_efforts=frozenset(),
        default_reasoning_effort=None,
        send_temperature_when_reasoning_none=True,
        default_completion_tokens=None,
    )


def resolve_reasoning_effort(
    policy: OpenAIModelPolicy,
    requested: Optional[str],
) -> Optional[str]:
    """Resolve and validate reasoning effort for a request.

    Returns the effort string to send, or ``None`` when the field must be omitted.
    """
    if requested is not None:
        token = str(requested).strip().casefold()
        if not token:
            raise InvalidReasoningEffortError("reasoning_effort must be nonempty")
        if not policy.supports_reasoning_effort:
            raise InvalidReasoningEffortError(
                f"reasoning_effort is not supported for model {policy.model_id!r}"
            )
        if token not in policy.allowed_reasoning_efforts:
            allowed = ", ".join(sorted(policy.allowed_reasoning_efforts))
            raise InvalidReasoningEffortError(
                f"unsupported reasoning_effort {token!r}; allowed: {allowed}"
            )
        return token
    if policy.supports_reasoning_effort:
        return policy.default_reasoning_effort
    return None


def reject_unsupported_reasoning_effort(requested: Optional[str]) -> None:
    """Non-reasoning providers reject an explicit reasoning_effort before HTTP."""
    if requested is None:
        return
    token = str(requested).strip()
    if not token:
        raise InvalidReasoningEffortError("reasoning_effort must be nonempty")
    raise InvalidReasoningEffortError(
        "reasoning_effort is only supported for OpenAI models that advertise it"
    )


def recorded_reasoning_effort(
    *,
    provider_id: str,
    model: str,
    requested: Optional[str],
) -> Optional[str]:
    """Validate and return the effective effort to record in scan metadata.

    OpenAI reasoning models return the normalized effective value (Luna default
    ``none`` when unset). Non-reasoning providers and models return ``None``
    after rejecting any explicit effort.
    """
    provider_key = (provider_id or "").strip().lower()
    if provider_key != "openai":
        reject_unsupported_reasoning_effort(requested)
        return None
    return resolve_reasoning_effort(openai_model_policy(model), requested)


def is_official_openai_base_url(base_url: Optional[str]) -> bool:
    """True when ``base_url`` is unset or the official ``api.openai.com`` host."""
    raw = (base_url or OFFICIAL_OPENAI_BASE_URL).strip().rstrip("/")
    return raw.casefold() == OFFICIAL_OPENAI_BASE_URL.casefold()


def build_openai_chat_payload(
    *,
    model_id: str,
    system: str,
    user: str,
    reasoning_effort: Optional[str] = None,
    temperature: float = DEFAULT_OPENAI_TEMPERATURE,
) -> Dict[str, Any]:
    """Build a Chat Completions JSON body for ``model_id``.

    Validates reasoning effort before any HTTP call. Completion-token fields are
    omitted unless a policy explicitly sets both ``completion_token_param`` and
    ``default_completion_tokens`` (none do today for OpenAI, including Luna).
    """
    policy = openai_model_policy(model_id)
    effort = resolve_reasoning_effort(policy, reasoning_effort)
    payload: Dict[str, Any] = {
        "model": model_id,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    if policy.completion_token_param and policy.default_completion_tokens is not None:
        payload[policy.completion_token_param] = int(policy.default_completion_tokens)
    if effort is not None:
        payload["reasoning_effort"] = effort
    send_temperature = policy.send_temperature_when_reasoning_none and (
        effort is None or effort == "none"
    )
    if send_temperature:
        payload["temperature"] = temperature
    # Never send both token parameters.
    if "max_tokens" in payload and "max_completion_tokens" in payload:
        raise RuntimeError("internal error: both max_tokens and max_completion_tokens set")
    return payload
