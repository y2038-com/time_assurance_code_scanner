#!/usr/bin/env python3
"""
Debug script to examine intermediate files and understand ID mismatches.
"""

import json
import sys
import os
from pathlib import Path

def examine_intermediate_files():
    """Examine intermediate files to understand the ID mismatch issue."""
    print("Examining intermediate files for ID mismatch analysis...")
    
    # Check if we have any intermediate files
    results_dir = Path("results")
    if not results_dir.exists():
        print("No results directory found")
        return
    
    # Look for recent scan results
    scan_dirs = [d for d in results_dir.iterdir() if d.is_dir() and d.name.startswith("scans")]
    if not scan_dirs:
        print("No scan directories found")
        return
    
    # Get the most recent scan
    latest_scan = max(scan_dirs, key=lambda d: d.stat().st_mtime)
    print(f"Examining latest scan: {latest_scan.name}")
    
    # Check for IR candidates file
    ir_file = latest_scan / "ir" / "candidates.jsonl"
    if ir_file.exists():
        print(f"\nIR Candidates file: {ir_file}")
        with open(ir_file, 'r') as f:
            lines = f.readlines()[:5]  # First 5 lines
            for i, line in enumerate(lines):
                try:
                    data = json.loads(line.strip())
                    print(f"  Line {i+1}: {data.get('file', 'NO_FILE')}:{data.get('line', 'NO_LINE')}")
                except json.JSONDecodeError:
                    print(f"  Line {i+1}: Invalid JSON")
    
    # Check for LLM Pass 1 batches
    pass1_dir = latest_scan / "llm" / "pass1" / "batches"
    if pass1_dir.exists():
        print(f"\nLLM Pass 1 batches directory: {pass1_dir}")
        batch_files = list(pass1_dir.glob("*_input.jsonl"))
        if batch_files:
            # Examine first batch
            first_batch = batch_files[0]
            print(f"  First batch: {first_batch.name}")
            with open(first_batch, 'r') as f:
                lines = f.readlines()[:3]  # First 3 lines
                for i, line in enumerate(lines):
                    try:
                        data = json.loads(line.strip())
                        print(f"    Line {i+1}: {data.get('id', 'NO_ID')}")
                    except json.JSONDecodeError:
                        print(f"    Line {i+1}: Invalid JSON")
    
    # Check for findings file
    findings_file = latest_scan / "findings" / "findings.json"
    if findings_file.exists():
        print(f"\nFindings file: {findings_file}")
        with open(findings_file, 'r') as f:
            try:
                data = json.load(f)
                findings = data.get('findings', [])
                print(f"  Total findings: {len(findings)}")
                if findings:
                    print(f"  First finding ID: {findings[0].get('id', 'NO_ID')}")
            except json.JSONDecodeError:
                print("  Invalid JSON in findings file")

def analyze_id_patterns():
    """Analyze ID patterns to understand the mismatch."""
    print("\nAnalyzing ID patterns...")
    
    # Look for any recent JSON files that might contain candidate data
    results_dir = Path("results")
    json_files = list(results_dir.rglob("*.json"))
    
    for json_file in json_files[:3]:  # Check first 3 JSON files
        print(f"\nFile: {json_file}")
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                
            # Look for candidates or findings
            if 'findings' in data:
                findings = data['findings']
                if findings:
                    print(f"  Findings count: {len(findings)}")
                    print(f"  Sample IDs: {[f.get('id', 'NO_ID') for f in findings[:3]]}")
            
            if 'candidates' in data:
                candidates = data['candidates']
                if candidates:
                    print(f"  Candidates count: {len(candidates)}")
                    print(f"  Sample IDs: {[f'{c.get(\"file\", \"NO_FILE\")}:{c.get(\"line\", \"NO_LINE\")}' for c in candidates[:3]]}")
                    
        except (json.JSONDecodeError, Exception) as e:
            print(f"  Error reading file: {e}")

if __name__ == "__main__":
    examine_intermediate_files()
    analyze_id_patterns()
