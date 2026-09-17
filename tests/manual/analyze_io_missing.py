#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Simple script to analyze why I/O candidates are missing from final findings.
Run after a scan: python3 tests/patterns/analyze_io_missing.py
"""

import json
from pathlib import Path
from collections import defaultdict

# Load final findings
findings_file = Path("test_io_results.json")
if not findings_file.exists():
    print("Error: test_io_results.json not found. Run a scan first.")
    exit(1)

with open(findings_file, 'r') as f:
    results = json.load(f)

findings = results.get('findings', [])
io_findings = [f for f in findings if f.get('io_category') is not None]
regular_findings = [f for f in findings if f.get('io_category') is None]

print("=" * 80)
print("ANALYSIS: Missing I/O Candidates")
print("=" * 80)
print(f"\nTotal findings: {len(findings)}")
print(f"  - With I/O metadata: {len(io_findings)}")
print(f"  - Without I/O metadata: {len(regular_findings)}")

# Check findings by classification
print("\n" + "=" * 80)
print("Findings by Classification")
print("=" * 80)

by_classification = defaultdict(list)
for finding in findings:
    issue = finding.get('y2038_issue', 'unknown')
    by_classification[issue].append(finding)

for issue, finds in sorted(by_classification.items()):
    io_count = sum(1 for f in finds if f.get('io_category'))
    print(f"{issue.upper()}: {len(finds)} total ({io_count} with I/O metadata)")

# Check if I/O candidates might be in NO findings
print("\n" + "=" * 80)
print("Potential Missing I/O Candidates")
print("=" * 80)

# Look for findings in the test file that might be I/O-related
test_file_findings = [f for f in findings if 'test_io_boundary_patterns.c' in f.get('file', '')]

print(f"\nFindings in test_io_boundary_patterns.c: {len(test_file_findings)}")
print(f"  - With I/O metadata: {sum(1 for f in test_file_findings if f.get('io_category'))}")
print(f"  - Without I/O metadata: {sum(1 for f in test_file_findings if not f.get('io_category'))}")

# Check NO findings that might be I/O candidates
no_findings = [f for f in test_file_findings if f.get('y2038_issue') == 'no']
print(f"\nNO findings in test file: {len(no_findings)}")
if no_findings:
    print("  These might be I/O candidates that were classified as safe:")
    for finding in no_findings[:5]:
        print(f"    - {finding['file']}:{finding['region']['start_line']} - {finding.get('symbol', 'unknown')}")
        print(f"      Reason: {finding.get('reason', 'N/A')[:80]}...")

# Check for I/O-related symbols in regular findings
io_functions = ['printf', 'scanf', 'fprintf', 'fscanf', 'sprintf', 'sscanf', 
                'snprintf', 'read', 'write', 'fread', 'fwrite', 'memcpy', 'memmove']

print("\n" + "=" * 80)
print("Regular Findings with I/O-related Symbols")
print("=" * 80)

io_related_regular = []
for finding in regular_findings:
    symbol = finding.get('symbol', '').lower()
    snippet = finding.get('source_snippet', '').lower()
    reason = finding.get('reason', '').lower()
    
    # Check if it mentions I/O functions
    for io_func in io_functions:
        if io_func in symbol or io_func in snippet or io_func in reason:
            io_related_regular.append((finding, io_func))
            break

if io_related_regular:
    print(f"\nFound {len(io_related_regular)} regular findings that mention I/O functions:")
    for finding, io_func in io_related_regular[:10]:
        print(f"  - {finding['file']}:{finding['region']['start_line']}")
        print(f"    I/O function: {io_func}")
        print(f"    Classification: {finding.get('y2038_issue')}")
        print(f"    Symbol: {finding.get('symbol')}")
        print(f"    Reason: {finding.get('reason', 'N/A')[:60]}...")
        print()
else:
    print("\nNo regular findings found that mention I/O functions")

print("\n" + "=" * 80)
print("Recommendations")
print("=" * 80)
print("""
1. Check if I/O candidates are in functions classified as NO (safe)
   - These won't appear in final findings if they're filtered out
   
2. Check if multiple I/O candidates are in the same function
   - Function-first mode may merge them into one finding
   
3. Check path matching
   - I/O metadata lookup uses file:line format
   - Path differences (absolute vs relative) might cause mismatches
   
4. Run with --debug-candidates to see detailed I/O candidate tracking
""")
