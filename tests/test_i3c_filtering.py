#!/usr/bin/env python3
"""
Test script to verify I3C timing definitions are now filtered out.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tacs.core.define_scanner import DefineScanner

def test_i3c_filtering():
    """Test that I3C timing definitions are properly filtered out."""
    scanner = DefineScanner()
    
    # Test cases - these should be FILTERED OUT (hardware timing)
    i3c_cases = [
        "#define I3C_RENESAS_RA_OD_RISING_NS     (0U)         /* Open Drain Logic Rising Time (ns) */",
        "#define I3C_RENESAS_RA_OD_FALLING_NS    (0U)         /* Open Drain Logic Falling Time (ns) */",
        "#define I3C_RENESAS_RA_PP_RISING_NS     (0U)         /* Open Drain Logic Rising Time (ns) */",
        "#define I3C_RENESAS_RA_PP_FALLING_NS    (0U)         /* Open Drain Logic Falling Time (ns) */",
        "#define I3C_RENESAS_RA_OD_HIGH_NS       (167U)       /* Open Drain Logic High Time (ns) */",
        "#define I3C_RENESAS_RA_PP_HIGH_NS       (167U)       /* Push Pull Logic High Time (ns) */",
    ]
    
    # Test cases - these should MATCH (Y2038-relevant)
    y2038_cases = [
        "#define MY_TIME_T time_t",
        "#define SECONDS_PER_MINUTE 60",
        "#define TIMEOUT_SECONDS 30",
        "#define SLEEP_DELAY_MS 1000",
    ]
    
    print("Testing I3C timing filtering:")
    i3c_matches = 0
    for line in i3c_cases:
        matches = scanner.scan_line_for_defines(line, "test.c", 1)
        if matches:
            print(f"❌ UNEXPECTED MATCH: {line}")
            for match in matches:
                print(f"   -> {match.subcheck_type}: {match.macro_name}")
            i3c_matches += len(matches)
        else:
            print(f"✅ CORRECTLY FILTERED: {line}")
    
    print(f"\nI3C matches found: {i3c_matches} (should be 0)")
    
    print("\nTesting Y2038 cases (should still match):")
    y2038_matches = 0
    for line in y2038_cases:
        matches = scanner.scan_line_for_defines(line, "test.c", 1)
        if matches:
            print(f"✅ CORRECTLY MATCHED: {line}")
            for match in matches:
                print(f"   -> {match.subcheck_type}: {match.macro_name}")
            y2038_matches += len(matches)
        else:
            print(f"❌ UNEXPECTED FILTER: {line}")
    
    print(f"\nY2038 matches found: {y2038_matches} (should be > 0)")
    
    print(f"\nSummary:")
    print(f"  I3C filtering: {'✅ PASS' if i3c_matches == 0 else '❌ FAIL'}")
    print(f"  Y2038 detection: {'✅ PASS' if y2038_matches > 0 else '❌ FAIL'}")

if __name__ == "__main__":
    test_i3c_filtering()
