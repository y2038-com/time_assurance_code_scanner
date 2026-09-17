#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Manual harness: exercise #define scanning on a small synthetic tree.

Prefer the unit coverage in tests/test_define_scanner.py for CI. This script
only scaffolds a temporary sample and prints a suggested tacs scan command.
"""

from __future__ import annotations

import tempfile
from pathlib import Path


def main() -> None:
    print("Testing Improved #define Scanning")
    print("=" * 50)

    test_files = {
        "test_time_defines.c": """
#include <time.h>

// Time type aliases (should match)
#define MY_TIME_T time_t
#define CLOCK_TYPE clock_t
#define TIMER_TYPE timer_t

// Time function aliases (should match)
#define MY_TIME_FUNC time
#define GET_TIME gettimeofday
#define LOCAL_TIME localtime

// Time struct aliases (should match)
#define MY_TIMESPEC struct timespec
#define TIMEVAL_TYPE struct timeval

// Time constants (should match with time context)
#define SECONDS_PER_MINUTE 60
#define SECONDS_PER_HOUR 3600
#define SECONDS_PER_DAY 86400
#define TIMEOUT_MS 1000

// Non-time-related (should NOT match)
#define RTC_REGISTER 0x1234
#define PORT_NUMBER 1000
#define BUFFER_SIZE 1000000
#define CTL_VALUE 0x456
#define BICR_MASK 0xFF
#define ONE_THOUSAND 1000

// Edge cases
#define LFCLK_FREQ 32768
#define SLEEP_DELAY 100
""",
        "test_regular_code.c": """
#include <stdio.h>

int main() {
    printf("Hello World\\n");
    return 0;
}
""",
    }

    with tempfile.TemporaryDirectory(prefix="tacs_define_scan_") as tmp:
        test_dir = Path(tmp)
        for filename, content in test_files.items():
            (test_dir / filename).write_text(content, encoding="utf-8")

        print(f"Created temporary test directory: {test_dir}")
        print("Test files created with various #define patterns")
        print("\nRunning scanner...")
        cmd = (
            f"tacs scan --root {test_dir} --rules configs/example.rules.json "
            f"--llm none --debug-candidates"
        )
        print(f"Command: {cmd}")

        print("\nExpected results:")
        print("- Should find Y2038-relevant #define statements (types/structs/functions/constants)")
        print("- Should NOT find RTC_REGISTER, PORT_NUMBER, BUFFER_SIZE, CTL_VALUE, BICR_MASK")
        print("- Should find MY_TIME_T, CLOCK_TYPE, GET_TIME, etc.")
        print("- Should find time constants with time context (SECONDS_PER_MINUTE)")
        print("- Should NOT find ONE_THOUSAND (no time context)")
        print("\nNote: CI coverage lives in tests/test_define_scanner.py")


if __name__ == "__main__":
    main()
