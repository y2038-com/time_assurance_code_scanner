# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Default source globs and helpers for building include patterns.

``DEFAULT_INCLUDE_PATTERNS`` is the single authoritative default scan scope for
``tacs scan`` and ``tacs repos``. Explicit ``--include`` and per-repository
``scan_overrides.include`` replace these defaults rather than extending them.
"""

from __future__ import annotations

from typing import List, Optional, Sequence

# Common C and C++ translation-unit extensions. Implementation fragments
# (``.ipp``, ``.tpp``, ``.inl``, ``.tcc``) and uncommon uppercase spellings are
# omitted from the default globs. Explicit ``--include`` replaces the globs; it
# does not add those names to the catalog IR allowlist (``SRC_EXTS``).
DEFAULT_SOURCE_EXTENSIONS: tuple[str, ...] = (
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cxx",
    ".hh",
    ".hpp",
    ".hxx",
)

DEFAULT_INCLUDE_PATTERNS: tuple[str, ...] = tuple(
    f"**/*{ext}" for ext in DEFAULT_SOURCE_EXTENSIONS
)

DEFAULT_EXCLUDE_PATTERNS: tuple[str, ...] = ("**/tests/**",)


def format_default_include_help(*, extra: str = "") -> str:
    """CLI help listing the exact default include globs."""
    listed = ", ".join(DEFAULT_INCLUDE_PATTERNS)
    suffix = f" {extra}" if extra else ""
    return (
        "Include glob patterns (repeatable; default: "
        f"{listed}). Explicit --include replaces the defaults.{suffix}"
    )


def format_default_exclude_help(*, extra: str = "") -> str:
    """CLI help listing the exact default exclude globs."""
    listed = ", ".join(DEFAULT_EXCLUDE_PATTERNS)
    suffix = f" {extra}" if extra else ""
    return (
        "Exclude glob patterns (repeatable; default: "
        f"{listed}). Explicit --exclude replaces the defaults.{suffix}"
    )


def resolved_include_patterns(
    include_patterns: Optional[Sequence[str]] = None,
) -> List[str]:
    """Return caller patterns, or a copy of the shared defaults when empty."""
    if include_patterns:
        return list(include_patterns)
    return list(DEFAULT_INCLUDE_PATTERNS)


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
