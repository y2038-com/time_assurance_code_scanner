#!/usr/bin/env python3
"""
Test script for the new integrated #define scanning functionality.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tacs.core.define_scanner import DefineScanner, DefineMatch

def test_define_scanner():
    """Test the DefineScanner with various #define patterns."""
    print("Testing DefineScanner...")
    
    scanner = DefineScanner()
    
    # Test cases
    test_cases = [
        # Time type aliases (should match)
        ("#define MY_TIME_T time_t", "test.c", 10),
        ("#define CLOCK_TYPE clock_t", "test.c", 11),
        ("#define TIMER_TYPE timer_t", "test.c", 12),
        
        # Time function aliases (should match)
        ("#define MY_TIME_FUNC time", "test.c", 13),
        ("#define GET_TIME gettimeofday", "test.c", 14),
        ("#define LOCAL_TIME localtime", "test.c", 15),
        
        # Time struct aliases (should match)
        ("#define MY_TIMESPEC struct timespec", "test.c", 16),
        ("#define TIMEVAL_TYPE struct timeval", "test.c", 17),
        
        # Time constants (should match only with time context)
        ("#define SECONDS_PER_MINUTE 60", "test.c", 18),
        ("#define SECONDS_PER_HOUR 3600", "test.c", 19),
        ("#define SECONDS_PER_DAY 86400", "test.c", 20),
        
        # Non-time-related (should NOT match)
        ("#define RTC_REGISTER 0x1234", "test.c", 21),
        ("#define PORT_NUMBER 1000", "test.c", 22),
        ("#define BUFFER_SIZE 1000000", "test.c", 23),
        ("#define CTL_VALUE 0x456", "test.c", 24),
        ("#define BICR_MASK 0xFF", "test.c", 25),
        
        # Edge cases
        ("#define ONE_THOUSAND 1000", "test.c", 26),  # Should NOT match (no time context)
        ("#define TIMEOUT_MS 1000", "test.c", 27),    # Should match (time context)
    ]
    
    matches = []
    for line, file_path, line_num in test_cases:
        line_matches = scanner.scan_line_for_defines(line, file_path, line_num)
        matches.extend(line_matches)
        if line_matches:
            print(f"✓ MATCH: {line}")
            for match in line_matches:
                print(f"  -> {match.subcheck_type}: {match.macro_name} -> {match.macro_value}")
        else:
            print(f"✗ NO MATCH: {line}")
    
    print(f"\nTotal matches: {len(matches)}")
    
    # Group by subcheck type
    by_type = {}
    for match in matches:
        if match.subcheck_type not in by_type:
            by_type[match.subcheck_type] = []
        by_type[match.subcheck_type].append(match)
    
    print("\nResults by subcheck type:")
    for subcheck_type, type_matches in by_type.items():
        print(f"  {subcheck_type}: {len(type_matches)} matches")
        for match in type_matches:
            print(f"    {match.macro_name} -> {match.macro_value}")
    
    # Test follow-up rule generation
    print("\nTesting follow-up rule generation...")
    followup_rules = scanner.generate_followup_rules(matches)
    print(f"Generated {len(followup_rules)} follow-up rules:")
    for rule in followup_rules:
        print(f"  {rule['symbol']}: {rule['risk']} risk - {rule['description']}")

if __name__ == "__main__":
    test_define_scanner()
