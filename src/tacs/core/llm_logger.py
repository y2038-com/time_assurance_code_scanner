# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Redaction applied to prompts before they are written to a scan's artifacts."""

from __future__ import annotations

import hashlib


def redact_prompt_text(prompt: str) -> str:
    """
    Redact sensitive information from a prompt.

    Source file paths become hashes and long lines are truncated, so a reader of
    the artifacts can tell one prompt from another without the tree leaking into
    them. ``ScanSession`` applies this whenever ``--log-llm`` is set without
    ``--allow-raw-code-logging``.
    """
    import re

    # Pattern to match file paths
    file_path_pattern = r'/[^\s\n]+\.(c|h|cpp|hpp)'

    def hash_path(match):
        path = match.group(0)
        return f"<HASH:{hashlib.md5(path.encode()).hexdigest()[:8]}>"

    redacted = re.sub(file_path_pattern, hash_path, prompt)

    # Remove long code spans (keep only line numbers and short context)
    lines = redacted.split('\n')
    redacted_lines = []

    for line in lines:
        if len(line) > 200:  # Long lines
            # Keep first part and indicate truncation
            redacted_lines.append(line[:100] + "... [TRUNCATED]")
        else:
            redacted_lines.append(line)

    return '\n'.join(redacted_lines)
