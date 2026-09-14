# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for DefineScanner match / non-match classification."""

from __future__ import annotations

import pytest

from tacs.core.define_scanner import DefineScanner


@pytest.mark.parametrize(
    "line,expected_type",
    [
        ("#define MY_TIME_T time_t", "time_type_alias"),
        ("#define CLOCK_TYPE clock_t", "time_type_alias"),
        ("#define TIMER_TYPE timer_t", "time_type_alias"),
        ("#define MY_TIME_FUNC time()", "time_function_alias"),
        ("#define GET_TIME gettimeofday", "time_function_alias"),
        ("#define LOCAL_TIME localtime", "time_function_alias"),
        ("#define MY_TIMESPEC struct timespec", "time_struct_alias"),
        ("#define TIMEVAL_TYPE struct timeval", "time_struct_alias"),
        ("#define SECONDS_PER_MINUTE 60", "time_constant"),
        ("#define SECONDS_PER_HOUR 3600", "time_constant"),
        ("#define SECONDS_PER_DAY 86400", "time_constant"),
        ("#define TIMEOUT_SECONDS 60", "time_constant"),
    ],
)
def test_define_scanner_matches_time_related_macros(line: str, expected_type: str) -> None:
    scanner = DefineScanner()
    matches = scanner.scan_line_for_defines(line, "test.c", 10)
    assert len(matches) == 1, f"expected one match for {line!r}, got {matches!r}"
    assert matches[0].subcheck_type == expected_type


@pytest.mark.parametrize(
    "line",
    [
        "#define RTC_REGISTER 0x1234",
        "#define PORT_NUMBER 1000",
        "#define BUFFER_SIZE 1000000",
        "#define CTL_VALUE 0x456",
        "#define BICR_MASK 0xFF",
        "#define ONE_THOUSAND 1000",
        # Bare `time` without call form is intentionally not treated as a function alias
        "#define MY_TIME_FUNC time",
        # 1000 is not a canonical seconds-scale constant pattern
        "#define TIMEOUT_MS 1000",
    ],
)
def test_define_scanner_rejects_non_time_or_ambiguous_macros(line: str) -> None:
    scanner = DefineScanner()
    matches = scanner.scan_line_for_defines(line, "test.c", 10)
    assert matches == [], f"expected no match for {line!r}, got {matches!r}"


def test_define_scanner_followup_rules_from_aliases() -> None:
    scanner = DefineScanner()
    matches = []
    for line in (
        "#define MY_TIME_T time_t",
        "#define GET_TIME gettimeofday",
        "#define SECONDS_PER_MINUTE 60",
    ):
        matches.extend(scanner.scan_line_for_defines(line, "test.c", 1))

    followup = scanner.generate_followup_rules(matches)
    symbols = {rule["symbol"] for rule in followup}
    # Alias macros that need follow-up scanning should produce rules
    assert "MY_TIME_T" in symbols
    assert "GET_TIME" in symbols
    # Constants do not request follow-up scanning
    assert "SECONDS_PER_MINUTE" not in symbols
