# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Strict structural reading of model responses.

A response is accepted only when the whole of it is the JSON document the prompt
asked for. Salvaging fragments out of a malformed reply lets a truncation or an
injected span decide part of a batch, so anything short of a complete document
is left for the caller to abstain on.
"""

from __future__ import annotations

import re

#: A single fence wrapping the entire response, with an optional language tag.
_WHOLE_RESPONSE_FENCE = re.compile(
    r"\A```[ \t]*[A-Za-z0-9_+-]*[ \t]*\r?\n(?P<body>.*?)\r?\n?```\Z",
    re.DOTALL,
)


def strip_optional_code_fence(content: str) -> str:
    """Unwrap one markdown fence that encloses the whole response.

    Only the whole-response form is unwrapped. Fences appearing mid-response mean
    the model wrote something other than the requested document, which is a parse
    failure rather than something to edit into shape.
    """
    stripped = (content or "").strip()
    match = _WHOLE_RESPONSE_FENCE.match(stripped)
    if match:
        return match.group("body").strip()
    return stripped
