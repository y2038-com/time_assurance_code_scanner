#!/usr/bin/env python3
"""
Quick verification of the time constant fix.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tacs.core.define_scanner import DefineScanner

def quick_test():
    """Quick test of the time constant fix."""
    scanner = DefineScanner()
    
    test_cases = [
        "#define SECONDS_PER_MINUTE 60",      # Should match (has 'seconds', 'per', 'minute')
        "#define TIMEOUT_SECONDS 30",         # Should match (has 'timeout', 'seconds')
        "#define SLEEP_DELAY_MS 1000",        # Should match (has 'sleep', 'delay')
        "#define WAIT_INTERVAL 500",          # Should match (has 'wait', 'interval')
        "#define CLOCK_FREQUENCY_100MHZ 100000000",  # Should be filtered (hardware)
        "#define TIMER_PRESCALER_64 64",      # Should be filtered (hardware)
    ]
    
    print("Testing time constant patterns:")
    for line in test_cases:
        matches = scanner.scan_line_for_defines(line, "test.c", 1)
        if matches:
            print(f"✅ MATCHED: {line}")
            for match in matches:
                print(f"   -> {match.subcheck_type}: {match.macro_name}")
        else:
            print(f"❌ FILTERED: {line}")
    
    print("\nExpected results:")
    print("✅ SECONDS_PER_MINUTE should match (time_constant)")
    print("✅ TIMEOUT_SECONDS should match (time_constant)")
    print("✅ SLEEP_DELAY_MS should match (time_constant)")
    print("✅ WAIT_INTERVAL should match (time_constant)")
    print("❌ CLOCK_FREQUENCY_100MHZ should be filtered (hardware)")
    print("❌ TIMER_PRESCALER_64 should be filtered (hardware)")

if __name__ == "__main__":
    quick_test()
