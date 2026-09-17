#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Debug script to track I/O candidates through the pipeline.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

def main():
    # Find the latest scan session
    scan_dir = Path("results/scans")
    if not scan_dir.exists():
        print("No scan results found")
        return
    
    # Get latest scan
    scans = sorted(scan_dir.glob("*T*Z_*"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not scans:
        print("No scan sessions found")
        return
    
    latest_scan = scans[0]
    print(f"Analyzing scan: {latest_scan.name}\n")
    
    # Load I/O metadata map (if we can find it)
    # Actually, we need to check the candidates file
    
    # Load candidates
    candidates_file = latest_scan / "ir" / "candidates.jsonl"
    if not candidates_file.exists():
        print(f"Candidates file not found: {candidates_file}")
        return
    
    print("=" * 80)
    print("STEP 1: I/O Candidates from I/O Boundary Analysis")
    print("=" * 80)
    
    # Find I/O candidates (they have symbol_role starting with "io_boundary_")
    io_candidates = []
    all_candidates = []
    
    with open(candidates_file, 'r') as f:
        for line in f:
            if line.strip():
                candidate = json.loads(line)
                all_candidates.append(candidate)
                if candidate.get('symbol_role', '').startswith('io_boundary_'):
                    io_candidates.append(candidate)
    
    print(f"Total candidates: {len(all_candidates)}")
    print(f"I/O-boundary candidates: {len(io_candidates)}\n")
    
    if io_candidates:
        print("I/O candidates found:")
        for i, cand in enumerate(io_candidates, 1):
            print(f"  {i}. {cand['file']}:{cand['line']} - {cand.get('symbol_role', 'unknown')}")
            print(f"     Symbol: {cand.get('symbol', 'unknown')}")
            print(f"     Code: {cand.get('one_line_snippet', '')[:80]}...")
        print()
    else:
        print("No I/O candidates found in candidates.jsonl")
        print("This might mean they weren't saved or the symbol_role wasn't set correctly\n")
    
    # Load final findings
    findings_file = Path("test_io_results.json")
    if not findings_file.exists():
        print(f"Findings file not found: {findings_file}")
        return
    
    with open(findings_file, 'r') as f:
        results = json.load(f)
    
    findings = results.get('findings', [])
    io_findings = [f for f in findings if f.get('io_category') is not None]
    
    print("=" * 80)
    print("STEP 2: Final Findings with I/O Metadata")
    print("=" * 80)
    print(f"Total findings: {len(findings)}")
    print(f"I/O-boundary findings: {len(io_findings)}\n")
    
    if io_findings:
        print("I/O findings in final results:")
        for i, finding in enumerate(io_findings, 1):
            print(f"  {i}. {finding['file']}:{finding['region']['start_line']}")
            print(f"     I/O Category: {finding.get('io_category')}")
            print(f"     I/O Function: {finding.get('io_function')}")
            print(f"     Classification: {finding.get('y2038_issue')}")
        print()
    
    # Compare: which I/O candidates are missing?
    print("=" * 80)
    print("STEP 3: Missing I/O Candidates Analysis")
    print("=" * 80)
    
    # Build lookup maps
    io_candidate_keys = set()
    for cand in io_candidates:
        # Try different key formats
        file = cand['file']
        line = cand['line']
        io_candidate_keys.add(f"{file}:{line}")
        # Also try relative paths
        try:
            rel_file = str(Path(file).relative_to(Path.cwd()))
            io_candidate_keys.add(f"{rel_file}:{line}")
        except:
            pass
        # Try basename
        io_candidate_keys.add(f"{Path(file).name}:{line}")
    
    io_finding_keys = set()
    for finding in io_findings:
        file = finding['file']
        line = finding['region']['start_line']
        io_finding_keys.add(f"{file}:{line}")
        try:
            rel_file = str(Path(file).relative_to(Path.cwd()))
            io_finding_keys.add(f"{rel_file}:{line}")
        except:
            pass
        io_finding_keys.add(f"{Path(file).name}:{line}")
    
    missing = io_candidate_keys - io_finding_keys
    
    if missing:
        print(f"Missing I/O candidates (found in candidates but not in final findings): {len(missing)}")
        for key in sorted(missing):
            print(f"  - {key}")
        
        # Check if they're in regular findings (without I/O metadata)
        print("\nChecking if missing candidates appear as regular findings (without I/O metadata)...")
        regular_finding_keys = set()
        for finding in findings:
            if finding.get('io_category') is None:
                file = finding['file']
                line = finding['region']['start_line']
                regular_finding_keys.add(f"{file}:{line}")
                try:
                    rel_file = str(Path(file).relative_to(Path.cwd()))
                    regular_finding_keys.add(f"{rel_file}:{line}")
                except:
                    pass
                regular_finding_keys.add(f"{Path(file).name}:{line}")
        
        found_as_regular = missing & regular_finding_keys
        if found_as_regular:
            print(f"\n{len(found_as_regular)} missing I/O candidates found as regular findings (metadata not attached):")
            for key in sorted(found_as_regular):
                print(f"  - {key}")
                # Find the finding
                for finding in findings:
                    if finding.get('io_category') is None:
                        file = finding['file']
                        line = finding['region']['start_line']
                        if (f"{file}:{line}" == key or 
                            f"{Path(file).name}:{line}" == key):
                            print(f"    Classification: {finding.get('y2038_issue')}")
                            print(f"    Symbol: {finding.get('symbol')}")
                            break
        
        truly_missing = missing - regular_finding_keys
        if truly_missing:
            print(f"\n{len(truly_missing)} I/O candidates completely missing from final findings:")
            for key in sorted(truly_missing):
                print(f"  - {key}")
    else:
        print("All I/O candidates found in final findings!")
    
    print("\n" + "=" * 80)
    print("STEP 4: Path Matching Analysis")
    print("=" * 80)
    
    # Check path formats
    print("I/O candidate file paths:")
    for cand in io_candidates[:5]:  # Show first 5
        print(f"  {cand['file']}")
    
    print("\nI/O finding file paths:")
    for finding in io_findings[:5]:  # Show first 5
        print(f"  {finding['file']}")
    
    print("\n" + "=" * 80)

if __name__ == '__main__':
    main()
