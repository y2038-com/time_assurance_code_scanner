# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Shared path helpers for persisted artifacts and console diagnostics.

Scanning reads absolute paths (``tacs repos`` works out of a clone under
``--cache-dir``), but the identifiers TACS persists and prints should name files
the way the repository does: ``benchmark/timezone_gmt_time.c`` rather than a
path rooted in the cache or the host filesystem.

Also holds the ``latest`` convenience symlink used by scan sessions and batch
runs, so both point at their newest output the same way.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union

PathInput = Union[str, os.PathLike]


def canonical_source_path(path: Optional[PathInput]) -> str:
    """
    Resolve ``path`` to a unique absolute location for a source file.

    Symlink aliases of the same file (common in vendored trees) collapse to one
    real path so IR discovery and functionization see the file once. A path that
    cannot be resolved is returned as an absolute path without following links.
    """
    if path is None:
        return ""

    text = os.fspath(path)
    if not text:
        return ""

    try:
        return str(Path(text).resolve())
    except OSError:
        try:
            return os.path.abspath(text)
        except OSError:
            return text


def repo_relative_path(path: Optional[PathInput], root: Optional[PathInput]) -> str:
    """
    Express ``path`` relative to the scan root ``root``.

    Returns a POSIX-style relative path when ``path`` is inside ``root``. A path
    outside the root is returned unchanged rather than reached with ``..``, so an
    unrelated file is never presented as if it belonged to the repository. Paths
    that are already repository-relative are left alone for the same reason.
    """
    if path is None:
        return ""

    text = os.fspath(path)
    if not text or root is None:
        return text

    root_text = os.fspath(root)
    if not root_text:
        return text

    try:
        relative = Path(text).resolve().relative_to(Path(root_text).resolve())
    except (ValueError, OSError):
        return text

    return relative.as_posix() or "."


def update_latest_symlink(link_path: PathInput, target: PathInput) -> bool:
    """
    Repoint a ``latest`` symlink at ``target``, replacing whatever is there.

    The link is written relative to its own directory so the output tree can be
    moved or copied without breaking. Returns False if the link could not be
    written — a filesystem without symlink support, or a real directory already
    holding the name — because a missing convenience link must never fail a run.
    """
    link = Path(link_path)
    destination = Path(target)

    try:
        link.parent.mkdir(parents=True, exist_ok=True)
        # exists() follows the link, so a dangling one needs is_symlink() too.
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(
            os.path.relpath(destination, link.parent), target_is_directory=True
        )
    except OSError:
        return False

    return True
