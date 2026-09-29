# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Allowlisted LLM provider / transport errors for TACS-owned diagnostics.

Provider HTTP bodies, third-party exception strings, URLs, headers, and credentials
must never enter ordinary exception messages, logs, or public findings. Classification
may inspect those values privately; only the fields on :class:`LLMProviderError`
are safe to format.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Mapping, Optional


class LLMErrorCategory(str, Enum):
    """Safe, stable categories for provider / transport failures."""

    AUTH = "auth"
    CLIENT_ERROR = "client_error"
    RATE_LIMIT = "rate_limit"
    INSUFFICIENT_QUOTA = "insufficient_quota"
    SERVER_ERROR = "server_error"
    HTTP_ERROR = "http_error"
    CONNECT_TIMEOUT = "connect_timeout"
    READ_TIMEOUT = "read_timeout"
    TIMEOUT = "timeout"
    CONNECTION = "connection"
    DECODE = "decode"
    UNEXPECTED = "unexpected"


# Default ceiling for explicitly authorized raw diagnostic dumps (bytes).
RAW_DIAGNOSTIC_MAX_BYTES = 256 * 1024


class LLMProviderError(RuntimeError):
    """TACS-owned provider/transport error with allowlisted diagnostic fields only."""

    def __init__(
        self,
        *,
        provider: str,
        category: LLMErrorCategory | str,
        retryable: bool,
        status_code: Optional[int] = None,
        attempt: Optional[int] = None,
        response_body_len: Optional[int] = None,
        detail: Optional[str] = None,
    ) -> None:
        self.provider = str(provider or "unknown")
        if isinstance(category, LLMErrorCategory):
            self.category = category
        else:
            try:
                self.category = LLMErrorCategory(str(category))
            except ValueError:
                self.category = LLMErrorCategory.UNEXPECTED
        self.retryable = bool(retryable)
        self.status_code = int(status_code) if status_code is not None else None
        self.attempt = int(attempt) if attempt is not None else None
        self.response_body_len = (
            int(response_body_len) if response_body_len is not None else None
        )
        # Optional short allowlisted token (e.g. "insufficient_quota"), never a body.
        self.detail = _bound_token(detail) if detail else None
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        parts = [
            f"{self.provider} request failed",
            f"category={self.category.value}",
        ]
        if self.status_code is not None:
            parts.append(f"status={self.status_code}")
        parts.append(f"retryable={str(self.retryable).lower()}")
        if self.attempt is not None:
            parts.append(f"attempt={self.attempt}")
        if self.response_body_len is not None:
            parts.append(f"response_bytes={self.response_body_len}")
        if self.detail:
            parts.append(f"detail={self.detail}")
        return ": ".join(parts[:1] + [", ".join(parts[1:])])

    def with_attempt(self, attempt: int) -> "LLMProviderError":
        """Return a copy carrying the current attempt number."""
        cls = type(self)
        return cls(
            provider=self.provider,
            category=self.category,
            retryable=self.retryable,
            status_code=self.status_code,
            attempt=attempt,
            response_body_len=self.response_body_len,
            detail=self.detail,
        )

    def to_diagnostic_dict(self) -> Dict[str, Any]:
        """Allowlisted fields for session error artifacts (no bodies/URLs/headers)."""
        return {
            "provider": self.provider,
            "category": self.category.value,
            "status_code": self.status_code,
            "retryable": self.retryable,
            "attempt": self.attempt,
            "response_body_len": self.response_body_len,
            "detail": self.detail,
        }


class LLMNonRetryableError(LLMProviderError):
    """Provider/client failure where retries will not help (auth, bad request, quota)."""

    def __init__(
        self,
        *,
        provider: str,
        category: LLMErrorCategory | str,
        status_code: Optional[int] = None,
        attempt: Optional[int] = None,
        response_body_len: Optional[int] = None,
        detail: Optional[str] = None,
    ) -> None:
        super().__init__(
            provider=provider,
            category=category,
            retryable=False,
            status_code=status_code,
            attempt=attempt,
            response_body_len=response_body_len,
            detail=detail,
        )


def _bound_token(value: str, *, max_chars: int = 64) -> str:
    """Keep only a short, printable token suitable for diagnostics."""
    cleaned = "".join(ch for ch in str(value).strip() if ch.isprintable() and ch not in "\r\n\t")
    if len(cleaned) > max_chars:
        return cleaned[:max_chars]
    return cleaned


def response_body_byte_length(response: Any) -> int:
    """Best-effort byte length of an HTTP response body without logging content."""
    try:
        content = getattr(response, "content", None)
        if content is not None:
            return len(content)
    except Exception:
        pass
    try:
        text = getattr(response, "text", None)
        if isinstance(text, str):
            return len(text.encode("utf-8", errors="replace"))
    except Exception:
        pass
    return 0


def truncate_utf8_bytes(
    text: str,
    max_bytes: int,
    *,
    marker: str | None = None,
) -> str:
    """Truncate ``text`` to at most ``max_bytes`` UTF-8 bytes without splitting code points.

    When ``marker`` is provided, it is appended and the total encoded size still
    respects ``max_bytes`` (the marker is reserved first).
    """
    if max_bytes <= 0:
        return ""
    encoded = text.encode("utf-8")
    if marker is None:
        if len(encoded) <= max_bytes:
            return text
        truncated = encoded[:max_bytes]
        while truncated:
            try:
                return truncated.decode("utf-8")
            except UnicodeDecodeError:
                truncated = truncated[:-1]
        return ""

    marker_bytes = marker.encode("utf-8")
    if len(marker_bytes) >= max_bytes:
        # Marker alone would exceed the cap; return a valid UTF-8 prefix only.
        truncated = encoded[:max_bytes]
        while truncated:
            try:
                return truncated.decode("utf-8")
            except UnicodeDecodeError:
                truncated = truncated[:-1]
        return ""
    if len(encoded) <= max_bytes:
        return text
    budget = max_bytes - len(marker_bytes)
    truncated = encoded[:budget]
    while truncated:
        try:
            return truncated.decode("utf-8") + marker
        except UnicodeDecodeError:
            truncated = truncated[:-1]
    return marker[:max_bytes]


#: Marker embedded in truncated raw diagnostic payloads; counted within the byte cap.
RAW_TRUNCATION_MARKER = "\n...[truncated]..."


def format_exception_for_log(exc: BaseException) -> str:
    """Safe one-line diagnostic for logs; never interpolates third-party ``str(exc)``."""
    if isinstance(exc, LLMProviderError):
        return str(exc)
    return f"{type(exc).__name__}"


def controlled_transport_failure_reason() -> str:
    """Stable public/compatibility reason for provider or transport failures."""
    return "Model analysis failed for this function"


def category_for_http_status(status_code: int) -> LLMErrorCategory:
    if status_code in (401, 403):
        return LLMErrorCategory.AUTH
    if status_code in (400, 404, 405, 413):
        return LLMErrorCategory.CLIENT_ERROR
    if status_code == 429:
        return LLMErrorCategory.RATE_LIMIT
    if 500 <= status_code <= 599:
        return LLMErrorCategory.SERVER_ERROR
    return LLMErrorCategory.HTTP_ERROR


def provider_error_for_http_status(
    *,
    provider: str,
    status_code: int,
    response: Any,
    openai_insufficient_quota: bool = False,
) -> LLMProviderError:
    """Build an allowlisted provider error for a non-success HTTP status.

    May inspect the response body privately for classification only. Callers that
    catch third-party exceptions must raise the returned error *after* leaving the
    ``except`` block so ``__context__`` does not retain the original exception.
    """
    body_len = response_body_byte_length(response)
    category = category_for_http_status(status_code)
    detail: Optional[str] = None

    if openai_insufficient_quota:
        return LLMNonRetryableError(
            provider=provider,
            category=LLMErrorCategory.INSUFFICIENT_QUOTA,
            status_code=status_code,
            response_body_len=body_len,
            detail="insufficient_quota",
        )

    if status_code in (400, 401, 403, 404, 405, 413):
        return LLMNonRetryableError(
            provider=provider,
            category=category,
            status_code=status_code,
            response_body_len=body_len,
            detail=detail,
        )

    return LLMProviderError(
        provider=provider,
        category=category,
        retryable=True,
        status_code=status_code,
        response_body_len=body_len,
        detail=detail,
    )


def raise_for_http_status(
    *,
    provider: str,
    status_code: int,
    response: Any,
    openai_insufficient_quota: bool = False,
) -> None:
    """Raise :func:`provider_error_for_http_status` (for use outside ``except`` handlers)."""
    raise provider_error_for_http_status(
        provider=provider,
        status_code=status_code,
        response=response,
        openai_insufficient_quota=openai_insufficient_quota,
    )


def detect_openai_insufficient_quota(response: Any) -> bool:
    """Privately classify OpenAI 429 insufficient_quota without retaining the body."""
    try:
        payload = response.json()
    except Exception:
        return False
    if not isinstance(payload, Mapping):
        return False
    error = payload.get("error")
    if not isinstance(error, Mapping):
        return False
    return error.get("type") == "insufficient_quota"


def provider_error_from_requests_exc(
    *,
    provider: str,
    exc: BaseException,
    connect_timeout_s: Optional[float] = None,
    read_timeout_s: Optional[float] = None,
) -> LLMProviderError:
    """Map a ``requests`` failure to an allowlisted error (no chaining of ``exc``)."""
    import requests

    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return LLMProviderError(
            provider=provider,
            category=LLMErrorCategory.CONNECT_TIMEOUT,
            retryable=True,
            detail=(
                f"connect_timeout_{int(connect_timeout_s)}s"
                if connect_timeout_s is not None
                else "connect_timeout"
            ),
        )
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return LLMProviderError(
            provider=provider,
            category=LLMErrorCategory.READ_TIMEOUT,
            retryable=True,
            detail=(
                f"read_timeout_{int(read_timeout_s)}s"
                if read_timeout_s is not None
                else "read_timeout"
            ),
        )
    if isinstance(exc, requests.exceptions.Timeout):
        return LLMProviderError(
            provider=provider,
            category=LLMErrorCategory.TIMEOUT,
            retryable=True,
        )
    if isinstance(exc, requests.exceptions.ConnectionError):
        return LLMProviderError(
            provider=provider,
            category=LLMErrorCategory.CONNECTION,
            retryable=True,
        )
    return LLMProviderError(
        provider=provider,
        category=LLMErrorCategory.UNEXPECTED,
        retryable=True,
    )
