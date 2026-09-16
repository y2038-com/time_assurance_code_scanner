# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Optional per-scan source file size limit.

A scan enumerates files in several places (metrics, prescan discovery, the IR
scanner subprocess, the arithmetic and I/O passes), and every one of them reads
the contents it enumerates. The limit therefore lives here as one predicate that
each enumerator consults, rather than as a filter bolted onto a single layer that
the others would bypass.

No limit applies unless one is asked for: ``None`` means unlimited.
"""

from __future__ import annotations

import os
from typing import Any, Optional, Union

PathInput = Union[str, "os.PathLike[str]"]

# Cap on how many individual skipped files a scan records. The count is always
# exact; the per-file detail exists for spot checks, not as a second manifest of
# the repository.
MAX_RECORDED_SKIPS = 100


def validate_max_file_size(value: Any) -> Optional[int]:
    """
    Normalize a ``max_file_size`` setting to bytes, or ``None`` for no limit.

    Absent or null means unlimited, which is the default for v0.1.0. Anything
    else must be a positive integer count of bytes. Raises ``ValueError`` with a
    message naming the offending value so a caller can fail one repository
    cleanly instead of scanning under a limit nobody specified.
    """
    if value is None:
        return None

    # bool is an int subclass, and "max_file_size": true is a mistake, not a size.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"max_file_size must be an integer number of bytes, got "
            f"{type(value).__name__}: {value!r}"
        )

    if value <= 0:
        raise ValueError(f"max_file_size must be greater than 0 bytes, got {value}")

    return value


def is_within_size_limit(path: PathInput, max_file_size: Optional[int]) -> bool:
    """
    Report whether ``path`` may be scanned under ``max_file_size``.

    A file exactly at the threshold is scanned. A file whose size cannot be read
    is scanned too: the limit exists to bound work, so an unreadable ``stat`` is
    not a reason to drop source silently.
    """
    if max_file_size is None:
        return True

    try:
        return os.path.getsize(path) <= max_file_size
    except OSError:
        return True
