# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

import sys
from pathlib import Path

# Ensure repo root is on import path for `scanner.*`
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tacs.core.function_schemas import FunctionBody
from tacs.core.pipeline import ScanningPipeline


def _make_function(*, start_line: int, end_line: int, candidate_lines: list[int]) -> FunctionBody:
    n = end_line - start_line + 1
    body_lines = [f"line_{i}" for i in range(n)]
    body = "\n".join(body_lines) + "\n"
    return FunctionBody(
        function_id=f"file.c@fn:{start_line}-{end_line}",
        file_path="file.c",
        symbol="fn",
        start_line=start_line,
        end_line=end_line,
        body=body,
        candidate_lines=candidate_lines,
    )


def test_resolve_absolute_line_passthrough():
    fn = _make_function(start_line=100, end_line=110, candidate_lines=[103, 107])
    assert ScanningPipeline._resolve_llm_issue_line(107, fn) == 107


def test_resolve_local_1_based_index_to_candidate():
    # local line=4 means 1-based within the function body
    # abs = start_line + (4-1)
    fn = _make_function(start_line=100, end_line=110, candidate_lines=[103])
    assert ScanningPipeline._resolve_llm_issue_line(4, fn) == 103


def test_resolve_local_0_based_index_to_start_line():
    fn = _make_function(start_line=100, end_line=110, candidate_lines=[100])
    assert ScanningPipeline._resolve_llm_issue_line(0, fn) == 100


def test_candidate_region_prefers_candidate_lines():
    fn = _make_function(start_line=100, end_line=110, candidate_lines=[105, 107])
    assert ScanningPipeline._candidate_region([105, 107], fn) == (105, 107)

