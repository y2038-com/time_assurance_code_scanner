# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Dict, List, Optional

from tacs.core.file_limits import MAX_RECORDED_SKIPS
from tacs.core.schema import Metrics
from tacs.core.source_files import enumerate_source_files
from tacs.core.status_logger import StatusLogger


def calculate_metrics(
    root_path: str,
    include_patterns: List[str],
    exclude_patterns: List[str],
    max_file_size: Optional[int] = None,
) -> Metrics:
    """
    Calculate code metrics for the given root path with include/exclude patterns.

    Uses the same canonical file-enumeration contract as IR discovery: one
    underlying in-repo source file is counted once, and symlink targets outside
    the repository root are skipped.
    """
    enumeration = enumerate_source_files(
        root_path,
        include_patterns,
        exclude_patterns=exclude_patterns,
        max_file_size=max_file_size,
    )

    for display in enumeration.skipped_external:
        StatusLogger.timestamped_debug(
            f"Ignoring source symlink outside repository root: {display}"
        )

    skipped_count = len(enumeration.skipped_too_large)
    skipped_detail: List[Dict[str, Any]] = enumeration.skipped_too_large[:MAX_RECORDED_SKIPS]

    total_files = 0
    total_lines = 0
    total_chars = 0
    total_words = 0
    max_line_length = 0
    max_file_length = 0
    file_lengths: List[int] = []

    for file_path in enumeration.files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                file_lines = 0
                file_chars = 0
                file_words = 0

                for line in f:
                    line = line.rstrip("\n\r")
                    file_lines += 1
                    file_chars += len(line)
                    file_words += len(line.split())
                    max_line_length = max(max_line_length, len(line))

                total_files += 1
                total_lines += file_lines
                total_chars += file_chars
                total_words += file_words
                file_lengths.append(file_lines)
                max_file_length = max(max_file_length, file_lines)
        except OSError:
            continue

    avg_line_length = total_chars / total_lines if total_lines > 0 else 0.0
    avg_file_length = sum(file_lengths) / len(file_lengths) if file_lengths else 0.0

    return Metrics(
        total_files=total_files,
        total_lines=total_lines,
        total_chars=total_chars,
        total_words=total_words,
        max_line_length=max_line_length,
        avg_line_length=avg_line_length,
        max_file_length=max_file_length,
        avg_file_length=avg_file_length,
        max_file_size=max_file_size,
        files_skipped_too_large=skipped_count,
        skipped_too_large=skipped_detail,
    )
