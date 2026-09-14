#!/usr/bin/env python3
"""
Validation script for pattern detection tests.

This script runs the Y2038 scanner on each test pattern file and verifies
that expected patterns are detected.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Set, Optional
from dataclasses import dataclass

# Expected patterns for each test file
# Format: {test_file: {expected_symbols: minimum_count, ...}}
# Note: These are minimum counts - actual counts may be higher due to grouping
# The scanner groups candidates by line, so one line with multiple symbols counts as one candidate
EXPECTED_PATTERNS = {
    'test_function_patterns.c': {
        'time': 1,  # At least one time() call should be detected
        'localtime': 1,
        'gmtime': 1,
        'mktime': 1,
        'clock_gettime': 1,
        'gettimeofday': 1,
        'timespec_get': 1,
        'timespec_getres': 1,
    },
    'test_type_patterns.c': {
        'time_t': 1,  # At least one time_t declaration should be detected
    },
    'test_struct_patterns.c': {
        'timespec': 1,
        'timeval': 1,
        # Note: tv_sec is not a symbol in rules, it's detected via struct access
        # The scanner detects timespec/timeval, not individual members
    },
    'test_arithmetic_patterns.c': {
        'time': 1,  # Scanner detects time() function calls and arithmetic operations
        # Note: time_t type declarations may not be detected as symbol="time_t"
        # but arithmetic operations on time_t variables are detected via arithmetic scanner
    },
    'test_embedded_time_fields.c': {
        'time': 1,  # Scanner detects time() function calls
        'timespec': 1,
        'timeval': 1,
        # Note: time_t type declarations may not be detected as symbol="time_t"
        # but structures with embedded time fields are detected via struct access patterns
    },
    'test_narrowing_patterns.c': {
        'time': 1,  # Scanner detects time() function calls and arithmetic operations
        'timespec': 1,
        'clock_gettime': 1,
        # Note: time_t type declarations may not be detected as symbol="time_t"
        # but narrowing patterns are detected via arithmetic scanner
    },
    'test_cast_patterns.c': {
        'time': 1,  # Scanner detects time() function calls in cast operations
        # Note: time_t type declarations may not be detected as symbol="time_t"
        # but cast patterns are detected via arithmetic scanner
    },
    'test_comparison_patterns.c': {
        'time': 1,  # Scanner detects time() function calls, not time_t type declarations
    },
    'test_storage_patterns.c': {
        'time': 1,  # Scanner detects time() function calls, not time_t type declarations
    },
    'test_function_definitions.c': {
        'time_t': 1,
        'time': 1,
    },
    'test_safe_patterns.c': {
        # Should have minimal or no time_t/time matches
        # Most patterns should be safe (NO classification)
    },
    'test_edge_cases.c': {
        'time': 1,  # Scanner detects time() function calls
        # Note: time_t type declarations may not be detected as symbol="time_t"
        # Edge cases include commented code, string literals, preprocessor directives
    },
    'test_macro_patterns.h': {
        # Note: #define is detected by define scanner, not IR scanner
        # Scanner detects function calls and structs in macro values
        'time': 1,
        'timespec': 1,
        'timeval': 1,
        # Note: time_t type declarations may not be detected as symbol="time_t"
        # but macro patterns are detected via define scanner
    },
    'test_cpp_patterns.cpp': {
        'time_t': 1,
        'time': 1,
        # Note: C++ file doesn't contain timespec/timeval structs
    },
    'test_io_boundary_patterns.c': {
        'time': 1,  # Scanner detects time() function calls
        'timespec': 1,
        'timeval': 1,
        'clock_gettime': 1,
        'gettimeofday': 1,
        'localtime': 1,
        'mktime': 1,
        # Note: time_t type declarations may not be detected as symbol="time_t"
        # I/O functions will be detected by I/O boundary analyzer
        # IR scanner will detect time() calls and struct usage
    },
    'test_migration_patterns.c': {
        'time': 1,  # Scanner detects time() function calls
        # Note: time_t type declarations may not be detected as symbol="time_t"
        # Migration patterns should be detected as candidates
        # They will be analyzed for migration risks in migration mode
    },
}


@dataclass
class TestResult:
    """Result of a single test file."""
    file: str
    passed: bool
    found_symbols: Dict[str, int]
    expected_symbols: Dict[str, int]
    missing_symbols: Set[str]
    extra_symbols: Set[str]
    candidates_count: int
    error: Optional[str] = None


def run_scanner(test_file: Path, rules_file: Path, output_file: Path, project_root: Path, use_llm: bool = False) -> Optional[Dict]:
    """Run the scanner on a test file and return results."""
    try:
        # Run scanner from project root so Python can find the scanner module
        cmd = [
            sys.executable, '-m', 'tacs.cli',
            '--root', str(test_file.parent),
            '--rules', str(rules_file),
            '--include', f'**/{test_file.name}',
            '--llm', 'ollama' if use_llm else 'none',
            '--out', str(output_file)
        ]
        
        result = subprocess.run(
            cmd,
            cwd=str(project_root),  # Run from project root
            capture_output=True,
            text=True,
            timeout=300 if use_llm else 60
        )
        
        if result.returncode != 0:
            return {'error': result.stderr}
        
        # Read results
        results = {}
        if output_file.exists():
            with open(output_file, 'r') as f:
                results = json.load(f)
        
        # Also read candidates from scan session if available
        # Find the latest scan session (relative to project root)
        scan_sessions_dir = project_root / 'results' / 'scans'
        if scan_sessions_dir.exists():
            sessions = sorted([d for d in scan_sessions_dir.iterdir() if d.is_dir() and d.name != 'latest'],
                            key=lambda x: x.stat().st_mtime, reverse=True)
            if sessions:
                latest_session = sessions[0]
                candidates_file = latest_session / 'ir' / 'candidates.jsonl'
                if candidates_file.exists():
                    candidates = []
                    with open(candidates_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                candidates.append(json.loads(line))
                    results['candidates'] = candidates
        
        return results if results else {'error': 'No results found'}
            
    except subprocess.TimeoutExpired:
        return {'error': 'Scanner timed out'}
    except Exception as e:
        return {'error': str(e)}


def analyze_results(results: Dict, expected: Dict[str, int], check_candidates: bool = True) -> TestResult:
    """Analyze scanner results against expected patterns."""
    found_symbols = {}
    
    # Check candidates first (IR stage detection)
    if check_candidates and 'candidates' in results:
        candidates = results['candidates']
        for candidate in candidates:
            symbol = candidate.get('symbol', '')
            if symbol:
                found_symbols[symbol] = found_symbols.get(symbol, 0) + 1
    else:
        # Fallback to findings (LLM classification results)
        findings = results.get('findings', [])
        for finding in findings:
            symbol = finding.get('symbol', '')
            if symbol:
                found_symbols[symbol] = found_symbols.get(symbol, 0) + 1
        candidates = findings
    
    # Compare with expected
    # For detection tests, we check that symbols are found (at least 1), not exact counts
    missing_symbols = set()
    extra_symbols = set()
    
    for symbol, expected_count in expected.items():
        found_count = found_symbols.get(symbol, 0)
        # For detection, we just need to verify the symbol is found (at least the minimum)
        # The exact count may vary due to grouping, so we check for minimum presence
        if found_count < expected_count:
            missing_symbols.add(f"{symbol} (expected at least {expected_count}, found {found_count})")
    
    # Check for unexpected symbols (optional - just log, don't fail)
    for symbol in found_symbols:
        if symbol not in expected and symbol not in ['', 'unknown']:
            extra_symbols.add(symbol)
    
    passed = len(missing_symbols) == 0
    
    return TestResult(
        file='',
        passed=passed,
        found_symbols=found_symbols,
        expected_symbols=expected,
        missing_symbols=missing_symbols,
        extra_symbols=extra_symbols,
        candidates_count=len(candidates) if 'candidates' in results else len(results.get('findings', []))
    )


def test_pattern_file(test_file: Path, rules_file: Path, project_root: Path, expected: Dict[str, int], use_llm: bool = False) -> TestResult:
    """Test a single pattern file."""
    # Use absolute path for output file (relative to project root for consistency)
    output_file = project_root / f"{test_file.stem}_results.json"
    
    print(f"Testing {test_file.name}...", end=' ', flush=True)
    
    # Run scanner (use --llm none for fast candidate detection testing)
    results = run_scanner(test_file, rules_file, output_file, project_root, use_llm=use_llm)
    
    if results is None or 'error' in results:
        error_msg = results.get('error', 'Unknown error') if results else 'No results'
        print(f"❌ ERROR: {error_msg}")
        return TestResult(
            file=test_file.name,
            passed=False,
            found_symbols={},
            expected_symbols=expected,
            missing_symbols=set(),
            extra_symbols=set(),
            candidates_count=0,
            error=error_msg
        )
    
    # Analyze results - check candidates (IR detection) not just LLM classification
    test_result = analyze_results(results, expected, check_candidates=True)
    test_result.file = test_file.name
    
    # Print results
    if test_result.passed:
        print(f"✅ PASS ({test_result.candidates_count} candidates detected)")
        if 'findings' in results:
            findings = results['findings']
            yes_count = sum(1 for f in findings if f.get('y2038_issue') == 'yes')
            no_count = sum(1 for f in findings if f.get('y2038_issue') == 'no')
            print(f"   LLM Classification: {yes_count} YES, {no_count} NO")
    else:
        print(f"❌ FAIL ({test_result.candidates_count} candidates detected)")
        if test_result.missing_symbols:
            print(f"   Missing symbols: {', '.join(test_result.missing_symbols)}")
    
    # Clean up
    if output_file.exists():
        output_file.unlink()
    
    return test_result


def create_test_rules_file(rules_file: Path):
    """Create a rules file for testing."""
    rules = [
        {
            "symbol": "time",
            "risk": "high",
            "category": "function",
            "description": "32-bit time function that may overflow in 2038"
        },
        {
            "symbol": "localtime",
            "risk": "medium",
            "category": "function",
            "description": "Time conversion function using time_t"
        },
        {
            "symbol": "gmtime",
            "risk": "medium",
            "category": "function",
            "description": "Time conversion function using time_t"
        },
        {
            "symbol": "mktime",
            "risk": "medium",
            "category": "function",
            "description": "Time conversion function using time_t"
        },
        {
            "symbol": "clock_gettime",
            "risk": "medium",
            "category": "function",
            "description": "Clock function using time_t"
        },
        {
            "symbol": "gettimeofday",
            "risk": "medium",
            "category": "function",
            "description": "Time function using time_t"
        },
        {
            "symbol": "timespec_get",
            "risk": "medium",
            "category": "function",
            "description": "Time function using time_t"
        },
        {
            "symbol": "timespec_getres",
            "risk": "medium",
            "category": "function",
            "description": "Time function using time_t"
        },
        {
            "symbol": "time_t",
            "risk": "high",
            "category": "type",
            "description": "32-bit time type that will overflow in 2038"
        },
        {
            "symbol": "timespec",
            "risk": "high",
            "category": "structure",
            "description": "Time structure with time_t member"
        },
        {
            "symbol": "timeval",
            "risk": "high",
            "category": "structure",
            "description": "Time structure with time_t member"
        },
        {
            "symbol": "tv_sec",
            "risk": "high",
            "category": "field",
            "description": "Time_t field in time structures"
        },
        {
            "symbol": "#define",
            "risk": "medium",
            "category": "macro",
            "description": "Macro definitions that may alias time types or functions",
            "subchecks": [
                "time_type_alias",
                "time_function_alias",
                "time_constant",
                "time_struct_alias"
            ]
        }
    ]
    
    with open(rules_file, 'w') as f:
        json.dump(rules, f, indent=2)


def main():
    """Main test runner."""
    # Get project root (parent of tests directory)
    # This script is in tests/patterns/, so project root is parent.parent.parent
    project_root = Path(__file__).parent.parent.parent
    test_dir = Path(__file__).parent
    patterns_dir = test_dir  # Test files are in the same directory as this script
    
    if not patterns_dir.exists():
        print(f"Error: Patterns directory not found: {patterns_dir}")
        sys.exit(1)
    
    if not project_root.exists():
        print(f"Error: Project root not found: {project_root}")
        sys.exit(1)
    
    # Create rules file
    rules_file = test_dir / 'test_patterns_rules.json'
    create_test_rules_file(rules_file)
    
    # Find all test files
    test_files = []
    for pattern_file, expected in EXPECTED_PATTERNS.items():
        test_file = patterns_dir / pattern_file
        if test_file.exists():
            test_files.append((test_file, expected))
        else:
            print(f"Warning: Test file not found: {test_file}")
    
    if not test_files:
        print("Error: No test files found")
        sys.exit(1)
    
    print(f"Running pattern detection tests on {len(test_files)} files...\n")
    print("Note: Tests check for candidate detection (IR stage), not LLM classification.")
    print("Most patterns will be classified as NO (Y2106, not Y2038) which is correct.\n")
    
    # Run tests (use --llm none for fast testing - we're checking detection, not classification)
    results = []
    for test_file, expected in test_files:
        result = test_pattern_file(test_file, rules_file, project_root, expected, use_llm=False)
        results.append(result)
    
    # Summary
    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)
    
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    
    print(f"Total tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    
    if passed < total:
        print("\nFailed tests:")
        for result in results:
            if not result.passed:
                print(f"  - {result.file}")
                if result.error:
                    print(f"    Error: {result.error}")
                if result.missing_symbols:
                    print(f"    Missing symbols: {', '.join(result.missing_symbols)}")
    
    # Clean up
    if rules_file.exists():
        rules_file.unlink()
    
    sys.exit(0 if passed == total else 1)


if __name__ == '__main__':
    main()
