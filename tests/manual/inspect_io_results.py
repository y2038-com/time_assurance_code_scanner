#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Inspect I/O boundary findings in scan results.
Usage: python3 tests/manual/inspect_io_results.py [results_file]
"""

import json
import sys
from pathlib import Path

def main():
    results_file = sys.argv[1] if len(sys.argv) > 1 else "test_io_results.json"
    
    if not Path(results_file).exists():
        print(f"Error: Results file not found: {results_file}")
        sys.exit(1)
    
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    findings = results.get('findings', [])
    
    # Separate I/O findings from regular findings
    io_findings = [f for f in findings if f.get('io_category') is not None]
    regular_findings = [f for f in findings if f.get('io_category') is None]
    
    print("=" * 80)
    print("I/O Boundary Analysis Results")
    print("=" * 80)
    print(f"\nTotal findings: {len(findings)}")
    print(f"  - I/O-boundary findings: {len(io_findings)}")
    print(f"  - Regular findings: {len(regular_findings)}")
    
    if io_findings:
        print("\n" + "=" * 80)
        print("I/O-BOUNDARY FINDINGS")
        print("=" * 80)
        
        # Group by category
        by_category = {}
        for finding in io_findings:
            category = finding.get('io_category', 'unknown')
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(finding)
        
        for category, finds in by_category.items():
            print(f"\n{category.upper().replace('_', ' ')}: {len(finds)} findings")
            print("-" * 80)
            
            for i, finding in enumerate(finds[:10], 1):  # Show first 10
                print(f"\n{i}. {finding.get('file', 'unknown')}:{finding.get('region', {}).get('start_line', '?')}")
                print(f"   Function: {finding.get('io_function', 'unknown')}")
                print(f"   Symbol: {finding.get('symbol', 'unknown')}")
                print(f"   Classification: {finding.get('y2038_issue', 'unknown')}")
                print(f"   Confidence: {finding.get('confidence', 0.0):.2f}")
                print(f"   Remediation: {finding.get('remediation_class', 'unknown')}")
                print(f"   Reason: {finding.get('reason', 'N/A')[:100]}...")
                if finding.get('source_snippet'):
                    snippet = finding['source_snippet'].strip()[:80]
                    print(f"   Code: {snippet}...")
            
            if len(finds) > 10:
                print(f"\n   ... and {len(finds) - 10} more {category} findings")
        
        # Summary by classification
        print("\n" + "=" * 80)
        print("I/O FINDINGS BY CLASSIFICATION")
        print("=" * 80)
        yes_count = sum(1 for f in io_findings if f.get('y2038_issue') == 'yes')
        no_count = sum(1 for f in io_findings if f.get('y2038_issue') == 'no')
        abstain_count = sum(1 for f in io_findings if f.get('y2038_issue') == 'abstain')
        print(f"YES (Y2038 risk): {yes_count}")
        print(f"NO (safe): {no_count}")
        print(f"ABSTAIN (uncertain): {abstain_count}")
        
        # Summary by I/O function
        print("\n" + "=" * 80)
        print("I/O FINDINGS BY FUNCTION")
        print("=" * 80)
        by_function = {}
        for finding in io_findings:
            func = finding.get('io_function', 'unknown')
            by_function[func] = by_function.get(func, 0) + 1
        
        for func, count in sorted(by_function.items(), key=lambda x: -x[1]):
            print(f"  {func}: {count}")
    
    else:
        print("\nNo I/O-boundary findings found in results.")
        print("This could mean:")
        print("  - I/O analysis is disabled (use --io-analysis)")
        print("  - No I/O candidates passed the score threshold")
        print("  - I/O metadata wasn't preserved in findings")
    
    print("\n" + "=" * 80)

if __name__ == '__main__':
    main()
