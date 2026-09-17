#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Quick verification of the time constant fix.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tacs.core.define_scanner import DefineScanner

def quick_test():
    """Quick test of the time constant subcheck.

    A macro is a time constant only when both gates pass: the value is one of
    the canonical seconds-scale constants (60, 3600, 86400, ...) and the name
    carries a time-context token. A time-sounding name alone is not enough, so
    most of these are expected to be filtered.
    """
    scanner = DefineScanner()

    # (line, should_match, why)
    test_cases = [
        ("#define SECONDS_PER_MINUTE 60", True,
         "value 60 is seconds-scale, name has 'seconds'/'per'/'minute'"),
        ("#define TIMEOUT_SECONDS 60", True,
         "value 60 is seconds-scale, name has 'timeout'/'seconds'"),
        ("#define TIMEOUT_SECONDS 30", False,
         "time-context name, but 30 is not a seconds-scale constant"),
        ("#define SLEEP_DELAY_MS 1000", False,
         "time-context name, but 1000 is not a seconds-scale constant"),
        ("#define WAIT_INTERVAL 500", False,
         "time-context name, but 500 is not a seconds-scale constant"),
        ("#define CLOCK_FREQUENCY_100MHZ 100000000", False,
         "hardware frequency: name looks time-related, value gate rejects it"),
        ("#define TIMER_PRESCALER_64 64", False,
         "hardware prescaler: name looks time-related, value gate rejects it"),
    ]

    print("Testing time constant patterns:")
    mismatches = 0
    for line, should_match, why in test_cases:
        matches = scanner.scan_line_for_defines(line, "test.c", 1)
        outcome = "matched" if matches else "filtered"
        expected = "matched" if should_match else "filtered"
        if outcome == expected:
            print(f"✅ as expected ({outcome}): {line}")
            print(f"     {why}")
            for match in matches:
                print(f"     -> {match.subcheck_type}: {match.macro_name}")
        else:
            mismatches += 1
            print(f"❌ UNEXPECTED: {line}")
            print(f"     expected {expected}, got {outcome} -- {why}")

    print()
    if mismatches:
        print(f"{mismatches} case(s) did not behave as expected")
    else:
        print(f"All {len(test_cases)} cases behaved as expected")
    return 1 if mismatches else 0

if __name__ == "__main__":
    raise SystemExit(quick_test())
