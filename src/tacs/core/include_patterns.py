# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Build include glob patterns from file extensions and folders."""

from __future__ import annotations

from typing import List, Optional, Sequence


def build_include_patterns(
    extensions: Sequence[str],
    folders: Optional[Sequence[str]] = None,
) -> List[str]:
    """
    Convert file extensions and folders to glob patterns.

    Args:
        extensions: File extensions (with leading dot), e.g. ``[".c", ".h"]``.
        folders: Optional relative folder paths to scope the globs.

    Returns:
        List of glob patterns suitable for the scanning pipeline.
    """
    if folders:
        return [f"{folder}/**/*{ext}" for folder in folders for ext in extensions]
    return [f"**/*{ext}" for ext in extensions]
