# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Canonical source-file enumeration for metrics, IR discovery, and scanners.

Contract:
* one underlying in-repo source file is counted/scanned once
* in-repo symlink aliases resolve to that file
* symlink targets outside the repository root are skipped, not followed
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Set

from tacs.core.file_limits import is_within_size_limit
from tacs.core.path_utils import canonical_source_path, repo_relative_path

PathLike = str | os.PathLike


@dataclass
class SourceEnumeration:
    """Result of walking a repository for scannable source files."""

    files: List[Path]
    skipped_external: List[str] = field(default_factory=list)
    skipped_too_large: List[dict] = field(default_factory=list)


def path_is_within_root(path: PathLike, root: PathLike) -> bool:
    """True when ``path`` resolves to a location under ``root``."""
    try:
        Path(canonical_source_path(path)).relative_to(Path(canonical_source_path(root)))
        return True
    except (ValueError, OSError):
        return False


def _expand_patterns(root: Path, patterns: Sequence[str]) -> Set[str]:
    matches: Set[str] = set()
    for pattern in patterns:
        if not pattern.startswith("/") and not os.path.isabs(pattern):
            pattern_path = str(root / pattern)
        else:
            pattern_path = str(root / pattern.lstrip("/")) if pattern.startswith("/") else pattern
        matches.update(glob.glob(pattern_path, recursive=True))
    return matches


def lexically_relative_path(path: PathLike, root: PathLike) -> str:
    """
    Name ``path`` relative to ``root`` without following symlinks.

    Used when reporting a skipped external symlink so the message names the
    in-repo link path (``escape/out.c``) rather than the external target.
    """
    abs_path = os.path.abspath(os.fspath(path))
    abs_root = os.path.abspath(os.fspath(root))
    try:
        return Path(abs_path).relative_to(abs_root).as_posix()
    except ValueError:
        return abs_path


def enumerate_source_files(
    root_path: PathLike,
    include_patterns: Sequence[str],
    exclude_patterns: Optional[Sequence[str]] = None,
    max_file_size: Optional[int] = None,
    allowed_extensions: Optional[Iterable[str]] = None,
    on_skip_external: Optional[Callable[[str, str], None]] = None,
) -> SourceEnumeration:
    """
    List unique in-repo source files for scanning and metrics.

    Symlink aliases that resolve inside ``root_path`` collapse to one canonical
    path. Symlinks (absolute or ``../``-escaping) that resolve outside the root
    are recorded in ``skipped_external`` and never opened.
    """
    root = Path(canonical_source_path(root_path))
    include = list(include_patterns) if include_patterns else ["**/*"]
    exclude = list(exclude_patterns or [])
    ext_filter = {e.lower() for e in allowed_extensions} if allowed_extensions else None

    raw_matches = _expand_patterns(root, include)
    excluded: Set[str] = set()
    for match in _expand_patterns(root, exclude):
        try:
            excluded.add(canonical_source_path(match))
        except OSError:
            excluded.add(os.path.abspath(match))

    unique: dict[str, Path] = {}
    skipped_external: List[str] = []
    skipped_too_large: List[dict] = []
    seen_external: Set[str] = set()

    for match in sorted(raw_matches):
        path = Path(match)
        # is_file() follows symlinks; is_symlink() catches dangling ones too.
        if not path.is_file() and not path.is_symlink():
            continue
        if not path.is_file():
            # Dangling symlink — ignore quietly.
            continue
        if ext_filter is not None and path.suffix.lower() not in ext_filter:
            continue

        display = lexically_relative_path(path, root)
        try:
            canonical = canonical_source_path(path)
        except OSError:
            continue

        if not path_is_within_root(canonical, root):
            if display not in seen_external:
                seen_external.add(display)
                skipped_external.append(display)
                if on_skip_external is not None:
                    on_skip_external(display, canonical)
            continue

        if canonical in excluded:
            continue

        if not is_within_size_limit(canonical, max_file_size):
            try:
                size_bytes = os.path.getsize(canonical)
            except OSError:
                size_bytes = None
            skipped_too_large.append(
                {"path": repo_relative_path(canonical, str(root)), "size_bytes": size_bytes}
            )
            continue

        unique.setdefault(canonical, Path(canonical))

    files = sorted(unique.values(), key=lambda p: str(p))
    return SourceEnumeration(
        files=files,
        skipped_external=sorted(skipped_external),
        skipped_too_large=sorted(skipped_too_large, key=lambda e: e["path"]),
    )
