#!/usr/bin/env python3
"""
Multi-configuration test runner for Y2038 scanner.

This test runner executes tests with different environment configurations:
- 32-bit ABI with signed 32-bit time_t
- 32-bit ABI with unsigned 32-bit time_t
- 64-bit ABI with signed time_t
- 64-bit ABI with unsigned time_t

It verifies that the scanner correctly identifies patterns and classifies them
according to the environment configuration.

When --llm is specified, it tests the full pipeline including:
- Stage 3: IR Candidate Discovery
- Stage 5: LLM Pass 1 (single-line triage)
- Stage 6: LLM Pass 2 (widened context)
- Stage 7: LLM Pass 3 (file-leading context)
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# Import from same directory
sys.path.insert(0, str(Path(__file__).parent))

from test_config_fixtures import get_all_test_configs, save_config_to_file


@dataclass
class ConfigTestResult:
    """Result of testing a pattern file with a specific configuration."""
    config_name: str
    test_file: str
    passed: bool
    candidates_found: int
    findings_count: int
    yes_count: int
    no_count: int
    abstain_count: int
    # Y2106 detection results (when enabled)
    y2106_yes_count: int = 0
    y2106_no_count: int = 0
    y2106_abstain_count: int = 0
    total_issues: int = 0  # Total unique issues (Y2038 + Y2106, avoiding double-count)
    # Pipeline stage verification
    stage3_ir_ran: bool = False
    stage5_pass1_ran: bool = False
    stage6_pass2_ran: bool = False
    stage7_pass3_ran: bool = False
    # Scan session info
    scan_session_path: Optional[str] = None
    error: Optional[str] = None


@dataclass
class PatternExpectation:
    """Expected results for a pattern in different configurations."""
    pattern_name: str
    # Expected classification for each config
    ilp32_signed_32bit: str  # "yes", "no", "abstain", or "detected" (just check detection)
    ilp32_unsigned_32bit: str
    lp64_signed_64bit: str
    lp64_unsigned_64bit: str
    # Minimum number of candidates expected
    min_candidates: int = 1


# Expected results for different patterns across configurations
PATTERN_EXPECTATIONS = {
    # Arithmetic patterns
    "test_arithmetic_patterns.c": {
        "test_signed_addition": PatternExpectation(
            "test_signed_addition",
            ilp32_signed_32bit="yes",  # Y2038 risk
            ilp32_unsigned_32bit="no",  # Y2106, not Y2038
            lp64_signed_64bit="no",  # 64-bit safe
            lp64_unsigned_64bit="no",  # 64-bit safe
            min_candidates=1
        ),
        "test_unsigned_addition": PatternExpectation(
            "test_unsigned_addition",
            ilp32_signed_32bit="no",  # Y2106, not Y2038
            ilp32_unsigned_32bit="no",  # Y2106, not Y2038
            lp64_signed_64bit="no",  # Safe
            lp64_unsigned_64bit="no",  # Safe
            min_candidates=1
        ),
    },
    # Embedded time fields
    "test_embedded_time_fields.c": {
        "test_custom_struct_signed": PatternExpectation(
            "test_custom_struct_signed",
            ilp32_signed_32bit="detected",  # Should be detected
            ilp32_unsigned_32bit="detected",
            lp64_signed_64bit="detected",
            lp64_unsigned_64bit="detected",
            min_candidates=1
        ),
        "test_timespec_signed": PatternExpectation(
            "test_timespec_signed",
            ilp32_signed_32bit="detected",
            ilp32_unsigned_32bit="detected",
            lp64_signed_64bit="detected",
            lp64_unsigned_64bit="detected",
            min_candidates=1
        ),
    },
}


def run_scanner_with_config(
    test_file: Path,
    rules_file: Path,
    env_config: Dict,
    output_dir: Path,
    use_llm: bool = False,
    model: str = "qwen3-coder:480b-cloud",
    verbose: bool = False,
    detect_y2106: bool = False
) -> Tuple[Optional[Dict], Optional[str], Optional[Path]]:
    """Run the scanner with a specific environment configuration.
    
    Returns:
        Tuple of (results_dict, error_message, scan_session_path)
    """
    # Create temporary env config file
    env_config_file = output_dir / "env_config.json"
    with open(env_config_file, 'w') as f:
        json.dump(env_config, f, indent=2)
    
    output_file = output_dir / "findings.json"
    
    # Create a temporary directory with ONLY the target test file
    # This ensures the underlying scanner script only sees the target file
    # (The IR scanner doesn't pass include/exclude patterns to the underlying script)
    # 
    # NOTE: This causes findings to show file paths in /tmp directories (e.g., /tmp/y2038_test_xxx/file.c).
    # This is intentional for test isolation - each test run gets its own isolated directory.
    # The temp directory is cleaned up after the test completes.
    import shutil
    import tempfile
    temp_scan_dir = None
    
    try:
        temp_scan_dir = tempfile.mkdtemp(prefix='y2038_test_')
        temp_test_file = Path(temp_scan_dir) / test_file.name
        shutil.copy2(test_file, temp_test_file)
        
        # Also copy the rules file to the temp directory so paths work
        temp_rules_file = Path(temp_scan_dir) / rules_file.name
        shutil.copy2(rules_file, temp_rules_file)
        
        cmd = [
            sys.executable, '-m', 'tacs.cli',
            '--root', temp_scan_dir,  # Use temp directory with only target file
            '--rules', str(temp_rules_file),
            '--include', f'**/{test_file.name}',  # Include only the target file
            '--llm', 'ollama' if use_llm else 'none',
            '--model', model,
            '--env-config', str(env_config_file),
            '--out', str(output_file)
        ]
        
        # Add Y2106 detection flag if enabled
        if detect_y2106:
            cmd.append('--detect-y2106')
        
        # Add LLM logging if using LLM
        if use_llm:
            cmd.extend(['--log-llm'])
        
        # For LLM tests, show output in real-time so user can see progress
        if use_llm and verbose:
            print("    [Running scanner - this may take a while...]")
            # Use Popen to stream output in real-time
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Combine stderr into stdout
                text=True,
                bufsize=1,  # Line buffered
                universal_newlines=True
            )
            
            # Read and print output line by line
            output_lines = []
            try:
                for line in process.stdout:
                    print(f"    {line.rstrip()}")
                    output_lines.append(line)
                process.wait()
            except Exception as e:
                process.kill()
                process.wait()
                return None, f"Scanner process error: {e}", None
            
            result = type('obj', (object,), {
                'returncode': process.returncode,
                'stdout': ''.join(output_lines),
                'stderr': ''  # Already combined into stdout
            })()
            stderr_output = ""
        else:
            # Capture output for non-verbose or IR-only tests
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800 if use_llm else 60  # 30 minutes for LLM
            )
            stderr_output = result.stderr
        
        if result.returncode != 0:
            error_msg = stderr_output if stderr_output else result.stdout if hasattr(result, 'stdout') else "Scanner failed (check output above)"
            return None, error_msg, None
        
        # Read results
        results = {}
        if output_file.exists():
            with open(output_file, 'r') as f:
                results = json.load(f)
        
        # Find the latest scan session
        scan_session_path = None
        scan_sessions_dir = Path('results/scans')
        if scan_sessions_dir.exists():
            sessions = sorted(
                [d for d in scan_sessions_dir.iterdir() if d.is_dir() and d.name != 'latest'],
                key=lambda x: x.stat().st_mtime, reverse=True
            )
            if sessions:
                latest_session = sessions[0]
                scan_session_path = latest_session
                
                # Read candidates from scan session
                candidates_file = latest_session / 'ir' / 'candidates.jsonl'
                if candidates_file.exists():
                    candidates = []
                    with open(candidates_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                candidates.append(json.loads(line))
                    results['candidates'] = candidates
        
        return results, None, scan_session_path
        
    except subprocess.TimeoutExpired:
        return None, "Scanner timed out", None
    except Exception as e:
        return None, str(e), None
    finally:
        # Clean up temporary directory
        if 'temp_scan_dir' in locals():
            import shutil
            try:
                shutil.rmtree(temp_scan_dir)
            except Exception:
                pass  # Ignore cleanup errors


def verify_pipeline_stages(scan_session_path: Path, use_llm: bool) -> Dict[str, bool]:
    """Verify which pipeline stages ran by checking scan session files."""
    stages = {
        'stage3_ir_ran': False,
        'stage5_pass1_ran': False,
        'stage6_pass2_ran': False,
        'stage7_pass3_ran': False,
    }
    
    if not scan_session_path or not scan_session_path.exists():
        return stages
    
    # Stage 3: IR Candidate Discovery
    candidates_file = scan_session_path / 'ir' / 'candidates.jsonl'
    stages['stage3_ir_ran'] = candidates_file.exists()
    
    if not use_llm:
        return stages
    
    # Check for function-first pipeline (pass_f1) or legacy pipeline (pass1)
    # Function-first is the default, so check that first
    pass_f1_dir = scan_session_path / 'llm' / 'pass_f1' / 'batches'
    pass1_dir = scan_session_path / 'llm' / 'pass1' / 'batches'
    
    # Stage 5: LLM Pass F1 (function-first) or Pass 1 (legacy)
    if pass_f1_dir.exists():
        # Function-first pipeline
        pass_f1_files = list(pass_f1_dir.glob('*_input.json'))  # Function-first uses _input.json
        stages['stage5_pass1_ran'] = len(pass_f1_files) > 0
    elif pass1_dir.exists():
        # Legacy pipeline
        pass1_files = list(pass1_dir.glob('*_output.jsonl'))
        stages['stage5_pass1_ran'] = len(pass1_files) > 0
    
    # Stage 6: LLM Pass F2 (function-first) or Pass 2 (legacy)
    pass_f2_dir = scan_session_path / 'llm' / 'pass_f2' / 'batches'
    pass2_dir = scan_session_path / 'llm' / 'pass2' / 'batches'
    if pass_f2_dir.exists():
        pass_f2_files = list(pass_f2_dir.glob('*_input.json'))
        stages['stage6_pass2_ran'] = len(pass_f2_files) > 0
    elif pass2_dir.exists():
        pass2_files = list(pass2_dir.glob('*_output.jsonl'))
        stages['stage6_pass2_ran'] = len(pass2_files) > 0
    
    # Stage 7: LLM Pass 3 (legacy only, function-first doesn't have Pass 3)
    pass3_dir = scan_session_path / 'llm' / 'pass3' / 'batches'
    if pass3_dir.exists():
        pass3_files = list(pass3_dir.glob('*_output.jsonl'))
        stages['stage7_pass3_ran'] = len(pass3_files) > 0
    
    return stages


def test_pattern_with_config(
    test_file: Path,
    rules_file: Path,
    config_name: str,
    config: Dict,
    use_llm: bool = False,
    model: str = "qwen3-coder:480b-cloud",
    verbose: bool = False,
    detect_y2106: bool = False
) -> ConfigTestResult:
    """Test a pattern file with a specific configuration."""
    with tempfile.TemporaryDirectory() as temp_dir:
        output_dir = Path(temp_dir)
        
        results, error, scan_session_path = run_scanner_with_config(
            test_file, rules_file, config, output_dir, use_llm, model, verbose, detect_y2106
        )
        
        if error or not results:
            return ConfigTestResult(
                config_name=config_name,
                test_file=test_file.name,
                passed=False,
                candidates_found=0,
                findings_count=0,
                yes_count=0,
                no_count=0,
                abstain_count=0,
                error=error or "No results"
            )
        
        candidates = results.get('candidates', [])
        findings = results.get('findings', [])
        
        yes_count = sum(1 for f in findings if f.get('y2038_issue') == 'yes')
        no_count = sum(1 for f in findings if f.get('y2038_issue') == 'no')
        abstain_count = sum(1 for f in findings if f.get('y2038_issue') == 'abstain')
        
        # Count Y2106 findings (when Y2106 detection enabled)
        y2106_yes_count = 0
        y2106_no_count = 0
        y2106_abstain_count = 0
        total_issues = 0
        
        if detect_y2106:
            from tacs.core.schema import TimeIssueType
            y2106_yes_count = sum(1 for f in findings 
                                 if f.get('issue_type') in ['y2106', 'both'])
            y2106_no_count = sum(1 for f in findings 
                                if f.get('issue_type') == 'none')
            y2106_abstain_count = sum(1 for f in findings 
                                     if f.get('issue_type') == 'abstain')
            
            # Count total unique issues (Y2038 + Y2106, avoiding double-count of 'both')
            both_count = sum(1 for f in findings if f.get('issue_type') == 'both')
            total_issues = yes_count + y2106_yes_count - both_count
        
        # Verify pipeline stages
        stages = verify_pipeline_stages(scan_session_path, use_llm)
        
        # Check that candidates were found (Stage 3)
        # Also check that we have findings (scan completed successfully)
        passed = (len(candidates) > 0 and stages['stage3_ir_ran'] and 
                 len(findings) > 0)  # Must have findings to pass
        
        # If using LLM, verify Pass F1/Pass 1 ran
        if use_llm:
            passed = passed and stages['stage5_pass1_ran']
        
        return ConfigTestResult(
            config_name=config_name,
            test_file=test_file.name,
            passed=passed,
            candidates_found=len(candidates),
            findings_count=len(findings),
            yes_count=yes_count,
            no_count=no_count,
            abstain_count=abstain_count,
            stage3_ir_ran=stages['stage3_ir_ran'],
            stage5_pass1_ran=stages['stage5_pass1_ran'],
            stage6_pass2_ran=stages['stage6_pass2_ran'],
            stage7_pass3_ran=stages['stage7_pass3_ran'],
            scan_session_path=str(scan_session_path) if scan_session_path else None
        )


def test_all_configs_for_file(
    test_file: Path,
    rules_file: Path,
    use_llm: bool = False,
    model: str = "qwen3-coder:480b-cloud",
    verbose: bool = False,
    limit_configs: Optional[int] = None,
    detect_y2106: bool = False
) -> List[ConfigTestResult]:
    """Test a pattern file with all configurations."""
    all_configs = get_all_test_configs()
    
    # Limit configurations if requested
    if limit_configs:
        configs = dict(list(all_configs.items())[:limit_configs])
        print(f"  Note: Limited to {len(configs)} configuration(s) (--limit-configs {limit_configs})")
    else:
        configs = all_configs
    
    results = []
    
    mode_str = "with LLM" if use_llm else "IR only"
    print(f"\nTesting {test_file.name} with {len(configs)} configurations ({mode_str})...")
    
    if use_llm:
        print("  Note: LLM tests may take several minutes per configuration...")
        print("  Progress will be shown in real-time.\n")
    
    for i, (config_name, config) in enumerate(configs.items(), 1):
        print(f"  [{i}/{len(configs)}] {config_name}...", end=' ', flush=True)
        if use_llm:
            print()  # New line for LLM tests so output is visible
        result = test_pattern_with_config(
            test_file, rules_file, config_name, config, use_llm, model, verbose, detect_y2106
        )
        results.append(result)
        
        # Print result on same line if not verbose, or new line if verbose
        if not verbose or not use_llm:
            # For IR-only or non-verbose, print on same line
            if result.passed:
                stage_info = []
                if result.stage3_ir_ran:
                    stage_info.append("IR✓")
                if use_llm:
                    if result.stage5_pass1_ran:
                        stage_info.append("P1✓")
                    if result.stage6_pass2_ran:
                        stage_info.append("P2✓")
                    if result.stage7_pass3_ran:
                        stage_info.append("P3✓")
                
                stage_str = " ".join(stage_info) if stage_info else ""
                print(f"✅ ({result.candidates_found} candidates, "
                      f"{result.yes_count} YES, {result.no_count} NO, "
                      f"{result.abstain_count} ABSTAIN) [{stage_str}]")
            else:
                print(f"❌ {result.error or 'Failed'}")
        else:
            # For verbose LLM tests, result was already shown, just print summary
            if result.passed:
                stage_info = []
                if result.stage3_ir_ran:
                    stage_info.append("IR✓")
                if result.stage5_pass1_ran:
                    stage_info.append("P1✓")
                if result.stage6_pass2_ran:
                    stage_info.append("P2✓")
                if result.stage7_pass3_ran:
                    stage_info.append("P3✓")
                
                stage_str = " ".join(stage_info) if stage_info else ""
                if detect_y2106:
                    print(f"  ✅ Complete: {result.candidates_found} candidates")
                    print(f"     Y2038: {result.yes_count} YES, {result.no_count} NO, {result.abstain_count} ABSTAIN")
                    print(f"     Y2106: {result.y2106_yes_count} YES, {result.y2106_no_count} NO, {result.y2106_abstain_count} ABSTAIN")
                    print(f"     Total issues: {result.total_issues} [{stage_str}]")
                else:
                    print(f"  ✅ Complete: {result.candidates_found} candidates, "
                          f"{result.yes_count} YES, {result.no_count} NO, "
                          f"{result.abstain_count} ABSTAIN [{stage_str}]")
            else:
                print(f"  ❌ Failed: {result.error or 'Unknown error'}")
    
    return results


def check_ollama_available() -> bool:
    """Check if Ollama is available and running."""
    try:
        import requests
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        return response.status_code == 200
    except Exception:
        return False


def main():
    """Main test runner."""
    parser = argparse.ArgumentParser(
        description='Multi-configuration test runner for Y2038 scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run IR-only tests (fast, no LLM)
  python test_multi_config.py

  # Run full pipeline tests with LLM
  python test_multi_config.py --llm ollama

  # Run with specific model
  python test_multi_config.py --llm ollama --model qwen3-coder:480b-cloud

  # Quick LLM test (limit to 1 config and 1 file for faster testing)
  python test_multi_config.py --llm ollama --limit-configs 1 --limit-files 1
        """
    )
    parser.add_argument(
        '--llm',
        choices=['none', 'ollama'],
        default='none',
        help='LLM type to use (default: none, IR-only testing)'
    )
    parser.add_argument(
        '--model',
        default='qwen3-coder:480b-cloud',
        help='Model name when using LLM (default: qwen3-coder:480b-cloud)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show scanner output in real-time (useful for debugging)'
    )
    parser.add_argument(
        '--limit-configs',
        type=int,
        help='Limit number of configurations to test (for faster testing)'
    )
    parser.add_argument(
        '--limit-files',
        type=int,
        help='Limit number of test files to test (for faster testing)'
    )
    
    args = parser.parse_args()
    use_llm = args.llm == 'ollama'
    verbose = args.verbose or use_llm  # Always verbose for LLM tests
    
    # Check Ollama availability if using LLM
    if use_llm:
        print("Checking Ollama availability...", end=' ', flush=True)
        if not check_ollama_available():
            print("❌")
            print("\nError: Ollama is not running or not accessible.")
            print("Please ensure Ollama is running on localhost:11434")
            print("You can start Ollama with: ollama serve")
            sys.exit(1)
        print("✅")
        print()
    
    test_dir = Path(__file__).parent
    
    # Test files to run
    all_test_files = [
        test_dir / "test_arithmetic_patterns.c",
        test_dir / "test_embedded_time_fields.c",
        test_dir / "test_narrowing_patterns.c",
    ]
    
    # Limit test files if requested
    if args.limit_files:
        test_files = all_test_files[:args.limit_files]
        print(f"Note: Limited to {len(test_files)} test file(s) (--limit-files {args.limit_files})")
    else:
        test_files = all_test_files
    
    # Create rules file
    rules_file = test_dir / 'test_patterns_rules.json'
    # Use the same rules creation as test_pattern_detection.py
    from test_pattern_detection import create_test_rules_file
    create_test_rules_file(rules_file)
    
    print("="*70)
    print("Multi-Configuration Test Runner")
    print("="*70)
    mode_str = "Full Pipeline (with LLM)" if use_llm else "IR Only (no LLM)"
    print(f"Mode: {mode_str}")
    if use_llm:
        print(f"Model: {args.model}")
    if args.detect_y2106:
        print("Y2106 Detection: ENABLED")
    print(f"Testing {len(test_files)} files with 4 environment configurations")
    print("Configurations:")
    print("  1. ILP32 signed 32-bit time_t (highest Y2038 risk)")
    print("  2. ILP32 unsigned 32-bit time_t (Y2106, not Y2038)")
    print("  3. LP64 signed 64-bit time_t (Y2038 safe)")
    print("  4. LP64 unsigned 64-bit time_t (Y2038 safe)")
    print()
    
    if use_llm:
        print("Testing pipeline stages:")
        print("  - Stage 3: IR Candidate Discovery")
        print("  - Stage 5: LLM Pass 1 (single-line triage)")
        print("  - Stage 6: LLM Pass 2 (widened context)")
        print("  - Stage 7: LLM Pass 3 (file-leading context)")
        print()
    
    all_results = []
    
    for test_file in test_files:
        if not test_file.exists():
            print(f"Warning: Test file not found: {test_file}")
            continue
        
        results = test_all_configs_for_file(
            test_file, rules_file, use_llm=use_llm, model=args.model, 
            verbose=verbose, limit_configs=args.limit_configs,
            detect_y2106=args.detect_y2106
        )
        all_results.extend(results)
    
    # Summary
    print("\n" + "="*70)
    print("Test Summary")
    print("="*70)
    
    total = len(all_results)
    passed = sum(1 for r in all_results if r.passed)
    
    print(f"Total tests: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    
    # Pipeline stage summary
    if use_llm:
        print("\nPipeline Stage Verification:")
        stage3_count = sum(1 for r in all_results if r.stage3_ir_ran)
        stage5_count = sum(1 for r in all_results if r.stage5_pass1_ran)
        stage6_count = sum(1 for r in all_results if r.stage6_pass2_ran)
        stage7_count = sum(1 for r in all_results if r.stage7_pass3_ran)
        print(f"  Stage 3 (IR): {stage3_count}/{total} ran")
        print(f"  Stage 5 (Pass 1): {stage5_count}/{total} ran")
        print(f"  Stage 6 (Pass 2): {stage6_count}/{total} ran")
        print(f"  Stage 7 (Pass 3): {stage7_count}/{total} ran")
    
    # Group by configuration
    print("\nResults by Configuration:")
    configs = get_all_test_configs()
    for config_name in configs.keys():
        config_results = [r for r in all_results if r.config_name == config_name]
        config_passed = sum(1 for r in config_results if r.passed)
        total_yes = sum(r.yes_count for r in config_results)
        total_no = sum(r.no_count for r in config_results)
        total_abstain = sum(r.abstain_count for r in config_results)
        print(f"  {config_name}: {config_passed}/{len(config_results)} passed "
              f"({total_yes} YES, {total_no} NO, {total_abstain} ABSTAIN)")
    
    # Group by test file
    print("\nResults by Test File:")
    for test_file in test_files:
        file_results = [r for r in all_results if r.test_file == test_file.name]
        file_passed = sum(1 for r in file_results if r.passed)
        print(f"  {test_file.name}: {file_passed}/{len(file_results)} passed")
    
    # Clean up
    if rules_file.exists():
        rules_file.unlink()
    
    sys.exit(0 if passed == total else 1)


if __name__ == '__main__':
    main()
