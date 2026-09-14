#!/usr/bin/env python3
"""
Debug script to see why I3C timing definitions are matching.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tacs.core.define_scanner import DefineScanner
import re

def debug_i3c_matches():
    """Debug why I3C timing definitions are matching."""
    scanner = DefineScanner()
    
    # The problematic line
    test_line = "#define I3C_RENESAS_RA_OD_RISING_NS     (0U)         /* Open Drain Logic Rising Time (ns) */"
    
    print("Debugging I3C timing definition:")
    print(f"Line: {test_line}")
    print()
    
    # Extract macro name and value
    define_pattern = re.compile(r'#define\s+(\w+)\s+(.*?)(?:\n|$)', re.MULTILINE)
    match = define_pattern.search(test_line)
    
    if match:
        macro_name = match.group(1)
        macro_value = match.group(2).strip()
        
        print(f"Macro name: {macro_name}")
        print(f"Macro value: {macro_value}")
        print()
        
        # Test each subcheck
        print("Testing subchecks:")
        
        # Test time type patterns
        print(f"Time type patterns: {scanner.time_type_regex.pattern}")
        if scanner.time_type_regex.search(macro_value.lower()):
            print("  ✅ Matches time type patterns")
        else:
            print("  ❌ No time type match")
        
        # Test time function patterns  
        print(f"Time function patterns: {scanner.time_function_regex.pattern}")
        if scanner.time_function_regex.search(macro_value.lower()):
            print("  ✅ Matches time function patterns")
        else:
            print("  ❌ No time function match")
        
        # Test time struct patterns
        print(f"Time struct patterns: {scanner.time_struct_regex.pattern}")
        if scanner.time_struct_regex.search(macro_value.lower()):
            print("  ✅ Matches time struct patterns")
        else:
            print("  ❌ No time struct match")
        
        # Test time constant patterns
        print(f"Time constant patterns: {scanner.time_constant_regex.pattern}")
        if scanner.time_constant_regex.search(macro_value.lower()):
            print("  ✅ Matches time constant patterns")
        else:
            print("  ❌ No time constant match")
        
        # Test hardware filtering
        print(f"\nHardware filtering:")
        if scanner._is_hardware_related(macro_name, macro_value, test_line):
            print("  ✅ Filtered as hardware-related")
        else:
            print("  ❌ NOT filtered as hardware-related")
        
        # Test the full subcheck
        print(f"\nFull subcheck result:")
        result = scanner._apply_subchecks(macro_name, macro_value, test_line)
        if result:
            print(f"  ✅ Matches: {result}")
        else:
            print("  ❌ No match")
    
    # Test the actual scan_line_for_defines method
    print(f"\nActual scan_line_for_defines result:")
    matches = scanner.scan_line_for_defines(test_line, "test.c", 1)
    if matches:
        print(f"  ✅ Found {len(matches)} matches:")
        for match in matches:
            print(f"    {match.subcheck_type}: {match.macro_name} -> {match.macro_value}")
    else:
        print("  ❌ No matches found")

if __name__ == "__main__":
    debug_i3c_matches()
