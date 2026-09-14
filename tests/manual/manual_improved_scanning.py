#!/usr/bin/env python3
"""
Test script to verify the improved #define scanning.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_improved_scanning():
    """Test the improved scanning with a small sample."""
    print("Testing Improved #define Scanning")
    print("=" * 50)
    
    # Create a test directory with some sample files
    test_dir = "test_define_scan"
    os.makedirs(test_dir, exist_ok=True)
    
    # Create test files with various #define patterns
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
"""
    }
    
    # Write test files
    for filename, content in test_files.items():
        with open(os.path.join(test_dir, filename), 'w') as f:
            f.write(content)
    
    print(f"Created test directory: {test_dir}")
    print("Test files created with various #define patterns")
    
    # Run the scanner
    print("\nRunning scanner...")
    cmd = f"tacs scan --root {test_dir} --rules configs/example.rules.json --llm none --debug-candidates"
    print(f"Command: {cmd}")
    
    print("\nExpected results:")
    print("- Should find ~10-15 Y2038-relevant #define statements")
    print("- Should NOT find RTC_REGISTER, PORT_NUMBER, BUFFER_SIZE, CTL_VALUE, BICR_MASK")
    print("- Should find MY_TIME_T, CLOCK_TYPE, MY_TIME_FUNC, etc.")
    print("- Should find time constants with time context (SECONDS_PER_MINUTE, TIMEOUT_MS)")
    print("- Should NOT find ONE_THOUSAND (no time context)")

if __name__ == "__main__":
    test_improved_scanning()
