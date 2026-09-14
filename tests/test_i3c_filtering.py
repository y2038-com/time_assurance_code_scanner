# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""DefineScanner should filter I3C hardware timing #defines."""

from __future__ import annotations

import pytest

from tacs.core.define_scanner import DefineScanner


I3C_CASES = [
    "#define I3C_RENESAS_RA_OD_RISING_NS     (0U)         /* Open Drain Logic Rising Time (ns) */",
    "#define I3C_RENESAS_RA_OD_FALLING_NS    (0U)         /* Open Drain Logic Falling Time (ns) */",
    "#define I3C_RENESAS_RA_PP_RISING_NS     (0U)         /* Open Drain Logic Rising Time (ns) */",
    "#define I3C_RENESAS_RA_PP_FALLING_NS    (0U)         /* Open Drain Logic Falling Time (ns) */",
    "#define I3C_RENESAS_RA_OD_HIGH_NS       (167U)       /* Open Drain Logic High Time (ns) */",
    "#define I3C_RENESAS_RA_PP_HIGH_NS       (167U)       /* Push Pull Logic High Time (ns) */",
]

Y2038_CASES = [
    ("#define MY_TIME_T time_t", "time_type_alias"),
    ("#define SECONDS_PER_MINUTE 60", "time_constant"),
    ("#define TIMEOUT_SECONDS 60", "time_constant"),
    ("#define GET_TIME gettimeofday", "time_function_alias"),
]


@pytest.mark.parametrize("line", I3C_CASES)
def test_i3c_timing_defines_are_filtered(line: str) -> None:
    scanner = DefineScanner()
    assert scanner.scan_line_for_defines(line, "test.c", 1) == []


@pytest.mark.parametrize("line,expected_type", Y2038_CASES)
def test_y2038_defines_still_match_alongside_i3c_filter(
    line: str, expected_type: str
) -> None:
    scanner = DefineScanner()
    matches = scanner.scan_line_for_defines(line, "test.c", 1)
    assert len(matches) == 1
    assert matches[0].subcheck_type == expected_type
