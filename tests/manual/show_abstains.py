#!/usr/bin/env python3
"""
Script to extract and display abstain findings from test results.

Usage:
    python show_abstains.py [scan_session_dir]
    
If no directory is provided, it will show abstains from results/scans/latest
(the symlink to the most recent scan session).
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional


def find_abstains_in_findings(findings_file: Path) -> List[Dict[str, Any]]:
    """Extract all abstain findings from a findings.json file."""
    with open(findings_file, 'r') as f:
        findings = json.load(f)
    
    abstains = [f for f in findings if f.get('y2038_issue') == 'abstain']
    return abstains


def get_llm_response_for_function(scan_dir: Path, function_id: str, pass_name: str) -> Optional[Dict]:
    """Get LLM response for a specific function from a pass."""
    pass_dir = scan_dir / 'llm' / pass_name / 'batches'
    if not pass_dir.exists():
        return None
    
    # Search through all batch output files
    for batch_file in sorted(pass_dir.glob('*_output.json')):
        with open(batch_file, 'r') as f:
            batch_data = json.load(f)
        
        responses = batch_data.get('response', [])
        for response in responses:
            if response.get('function_id') == function_id or function_id.endswith(response.get('function_id', '')):
                return response
    
    return None


def display_abstain_details(abstain: Dict[str, Any], scan_dir: Path):
    """Display detailed information about an abstain finding."""
    print(f"\n{'='*80}")
    print(f"ABSTAIN Finding")
    print(f"{'='*80}")
    print(f"File: {abstain.get('file', 'unknown')}")
    print(f"Lines: {abstain.get('lines', [])}")
    print(f"Function ID: {abstain.get('function_id', 'unknown')}")
    print(f"Symbol: {abstain.get('symbol', 'unknown')}")
    print(f"Confidence: {abstain.get('confidence', 0.0)}")
    print(f"Reason: {abstain.get('reason', 'No reason provided')}")
    print(f"Final Pass: {abstain.get('final_pass', 'unknown')}")
    print(f"Iteration Count: {abstain.get('iteration_count', 0)}")
    print(f"Needs More Context: {abstain.get('needs_more_context', False)}")
    
    # Show source snippet
    if abstain.get('source_snippet'):
        print(f"\nSource Code:")
        print("-" * 80)
        print(abstain['source_snippet'])
        print("-" * 80)
    
    # Try to get LLM responses from different passes
    function_id = abstain.get('function_id', '')
    if function_id:
        print(f"\nLLM Analysis History:")
        for pass_name in ['pass_f1', 'pass_f2', 'pass_f3']:
            response = get_llm_response_for_function(scan_dir, function_id, pass_name)
            if response:
                print(f"\n  {pass_name.upper()}:")
                print(f"    Summary: {response.get('y2038_summary', 'unknown')}")
                print(f"    Confidence: {response.get('confidence', 0.0)}")
                if response.get('issues'):
                    print(f"    Issues:")
                    for issue in response['issues']:
                        print(f"      - {issue.get('type', 'unknown')}: {issue.get('description', 'No description')}")
                else:
                    print(f"    Issues: None (empty issues array)")
                if response.get('needs'):
                    print(f"    Needs: {', '.join(response.get('needs', []))}")


def find_all_abstains_in_test_run(scan_dir: Path) -> List[tuple]:
    """Find all abstains in recent scan sessions from the same date."""
    abstains = []
    
    # Get the date prefix from the scan directory name
    # Format: YYYYMMDDTHHMMSSZ_<6-hex-random>
    scan_name = scan_dir.name
    if 'T' in scan_name:
        # Extract date part (YYYYMMDD)
        date_prefix = scan_name.split('T')[0]
        
        # Find all sessions from the same date
        scans_dir = scan_dir.parent
        related_sessions = [
            d for d in scans_dir.iterdir()
            if d.is_dir() and d.name.startswith(date_prefix) and d.name != 'latest'
        ]
        
        # Sort by modification time (most recent first) and limit to last 50 sessions
        # to avoid processing too many old sessions
        related_sessions.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        related_sessions = related_sessions[:50]
        
        print(f"   Found {len(related_sessions)} session(s) from {date_prefix}")
        
        # Process all related sessions
        for session_dir in sorted(related_sessions):
            findings_file = session_dir / 'findings' / 'findings.json'
            if findings_file.exists():
                try:
                    session_abstains = find_abstains_in_findings(findings_file)
                    if session_abstains:
                        print(f"   Found {len(session_abstains)} abstain(s) in {session_dir.name}")
                    for abstain in session_abstains:
                        abstains.append((session_dir, abstain))
                except Exception as e:
                    # Skip sessions with invalid JSON or other errors
                    print(f"Warning: Could not read {session_dir.name}: {e}", file=sys.stderr)
    else:
        # Fallback: just check the single directory
        findings_file = scan_dir / 'findings' / 'findings.json'
        if findings_file.exists():
            session_abstains = find_abstains_in_findings(findings_file)
            for abstain in session_abstains:
                abstains.append((scan_dir, abstain))
    
    return abstains


def main():
    if len(sys.argv) > 1:
        scan_dir = Path(sys.argv[1])
        # Single session mode
        findings_file = scan_dir / 'findings' / 'findings.json'
        if not findings_file.exists():
            print(f"Error: Findings file not found: {findings_file}")
            sys.exit(1)
        
        abstains = find_abstains_in_findings(findings_file)
        abstain_sessions = [(scan_dir, a) for a in abstains]
    else:
        # Use the latest symlink and find all abstains from the test run
        latest_link = Path('results/scans/latest')
        if not latest_link.exists():
            print("Error: results/scans/latest symlink not found")
            print("       This usually means no scan has been run yet.")
            sys.exit(1)
        
        # Resolve the symlink to get the actual directory
        scan_dir = latest_link.resolve()
        if not scan_dir.exists():
            print(f"Error: Latest scan directory does not exist: {scan_dir}")
            sys.exit(1)
        
        print(f"Using latest scan session: {scan_dir.name}")
        date_prefix = scan_dir.name.split('T')[0]
        print(f"Searching for abstains in all sessions from {date_prefix}...")
        
        # Find all abstains from the test run
        abstain_sessions = find_all_abstains_in_test_run(scan_dir)
    
    if not abstain_sessions:
        print(f"\nNo abstain findings found.")
        if len(sys.argv) == 1:
            date_prefix = scan_dir.name.split('T')[0]
            print(f"   (Searched all sessions from {date_prefix})")
        sys.exit(0)
    
    # Group by session for better display
    sessions_with_abstains = {}
    for session_dir, abstain in abstain_sessions:
        session_name = session_dir.name
        if session_name not in sessions_with_abstains:
            sessions_with_abstains[session_name] = []
        sessions_with_abstains[session_name].append(abstain)
    
    print(f"\nFound {len(abstain_sessions)} abstain finding(s) across {len(sessions_with_abstains)} session(s)")
    
    # Display abstains grouped by session
    for session_name, session_abstains in sorted(sessions_with_abstains.items()):
        session_dir = Path('results/scans') / session_name
        print(f"\n{'='*80}")
        print(f"Session: {session_name} ({len(session_abstains)} abstain(s))")
        print(f"{'='*80}")
        
        for i, abstain in enumerate(session_abstains, 1):
            display_abstain_details(abstain, session_dir)
    
    print(f"\n{'='*80}")
    print(f"Summary: {len(abstain_sessions)} total abstain finding(s) across {len(sessions_with_abstains)} session(s)")
    print(f"{'='*80}")


if __name__ == '__main__':
    main()
