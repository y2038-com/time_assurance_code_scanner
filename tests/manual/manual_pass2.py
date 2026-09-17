#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Test script for Pass 2 implementation.
"""

import json
import sys
import tempfile
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

def test_pass2():
    """Test Pass 2 implementation."""
    print("Testing Pass 2 Implementation")
    print("=" * 30)
    
    # Create a test C file with ambiguous code
    test_code = """
#include <time.h>
#include <unistd.h>

void ambiguous_function() {
    // This should be flagged as abstain in Pass 1, then resolved in Pass 2
    time_t t = time(NULL);
    
    // Some context that might help
    if (t > 0) {
        usleep(1000);
    }
}

void clear_function() {
    // This should be clearly not a Y2038 issue
    int delay = 5000;
    usleep(delay * 1000);
}
"""
    
    # Create temporary directory and file
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = Path(temp_dir) / "test.c"
        test_file.write_text(test_code)
        
        print(f"✓ Created test file: {test_file}")
        
        # Create environment config for ILP32 (risky scenario)
        env_config = {
            "hardware_model": "ILP32",
            "time_t_size_bits": 32,
            "time_t_signed": "signed",
            "time64_functions_available": False,
            "d_time_bits_supported": False,
            "d_time_bits_setting": "not_available",
            "c_library": "glibc",
            "scenario_hint": "ILP32-32bit-signed-time64_no",
            "mitigation_path": "upgrade_env"
        }
        
        env_config_file = Path(temp_dir) / "env_config.json"
        with open(env_config_file, 'w') as f:
            json.dump(env_config, f, indent=2)
        
        print(f"✓ Created environment config: {env_config_file}")
        
        # Test Pass 2 with none LLM first
        print("\n1. Testing Pass 2 with 'none' LLM...")
        try:
            from tacs.core.pipeline import ScanningPipeline
            
            pipeline = ScanningPipeline(
                scanner_path=str(Path(__file__).resolve().parents[1] / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"),
                llm_type="none",
                environment_config_path=str(env_config_file),
                enable_discovery=False,
                batch_size_pass2=5  # Small batch for testing
            )
            
            results = pipeline.scan(
                root_path=str(temp_dir),
                rules_path="configs/example.rules.json",
                include_patterns=["**/*.c"],
                exclude_patterns=[],
                min_risk="low"
            )
            
            print(f"✓ Scan completed with {len(results.findings)} findings")
            
            # Show findings
            for i, finding in enumerate(results.findings):
                print(f"  Finding {i+1}: {finding.file}:{finding.lines[0]}")
                print(f"    Symbol: {finding.symbol}")
                print(f"    Y2038 Issue: {finding.y2038_issue}")
                print(f"    Reason: {finding.reason}")
                print(f"    Confidence: {finding.confidence}")
                print(f"    Needs More Context: {finding.needs_more_context}")
                print()
            
        except Exception as e:
            print(f"✗ Scan with 'none' LLM failed: {e}")
            import traceback
            traceback.print_exc()
            return 1
        
        # Test Pass 2 with ollama LLM (if available)
        print("\n2. Testing Pass 2 with 'ollama' LLM...")
        try:
            ollama_pipeline = ScanningPipeline(
                scanner_path=str(Path(__file__).resolve().parents[1] / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"),
                llm_type="ollama",
                model="qwen3-coder:480b-cloud",
                environment_config_path=str(env_config_file),
                enable_discovery=False,
                batch_size_pass2=3,  # Very small batch for testing
                timeout_sec=30
            )
            
            ollama_results = ollama_pipeline.scan(
                root_path=str(temp_dir),
                rules_path="configs/example.rules.json",
                include_patterns=["**/*.c"],
                exclude_patterns=[],
                min_risk="low"
            )
            
            print(f"✓ Ollama Pass 2 scan completed with {len(ollama_results.findings)} findings")
            
            # Show findings
            for i, finding in enumerate(ollama_results.findings):
                print(f"  Finding {i+1}: {finding.file}:{finding.lines[0]}")
                print(f"    Symbol: {finding.symbol}")
                print(f"    Y2038 Issue: {finding.y2038_issue}")
                print(f"    Reason: {finding.reason}")
                print(f"    Confidence: {finding.confidence}")
                print(f"    Needs More Context: {finding.needs_more_context}")
                print()
                
        except Exception as e:
            print(f"✗ Scan with 'ollama' LLM failed (expected if Ollama not running): {e}")
        
        print("\n🎉 Pass 2 implementation test completed!")
        return 0

if __name__ == '__main__':
    exit(test_pass2())
