#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Test script for LLM integration with real scanning.
"""

import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Add this script's directory to the Python path (tacs/envui come from
# the installed package)
sys.path.insert(0, str(Path(__file__).parent))

def test_llm_scan():
    """Test LLM integration with a real scan."""
    print("Testing LLM Integration with Real Scan")
    print("=" * 40)
    
    # Create a test C file
    test_code = """
#include <time.h>

void test_function() {
    time_t t = time(NULL);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    
    // This should be flagged as Y2038 issue
    if (t > 2147483647) {
        // Handle overflow
    }
}
"""
    
    # Create temporary directory and file
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = Path(temp_dir) / "test.c"
        test_file.write_text(test_code)
        
        print(f"✓ Created test file: {test_file}")
        
        # Create environment config
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
        
        # Test with none LLM first
        print("\n1. Testing with 'none' LLM...")
        try:
            from tacs.core.pipeline import ScanningPipeline
            
            pipeline = ScanningPipeline(
                scanner_path=str(Path(__file__).resolve().parents[2] / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"),
                llm_type="none",
                environment_config_path=str(env_config_file),
                enable_discovery=False  # Skip discovery for this test
            )
            
            results = pipeline.scan(
                root_path=str(temp_dir),
                rules_path=str(REPO_ROOT / "configs" / "example.rules.json"),
                include_patterns=["**/*.c"],
                exclude_patterns=[],
                min_risk="low"
            )
            
            print(f"✓ Scan completed with {len(results.findings)} findings")
            
            for i, finding in enumerate(results.findings[:3]):  # Show first 3
                print(f"  Finding {i+1}: {finding.file}:{finding.lines[0]}")
                print(f"    Symbol: {finding.symbol}")
                print(f"    Y2038 Issue: {finding.y2038_issue}")
                print(f"    Reason: {finding.reason}")
                print(f"    Confidence: {finding.confidence}")
                print()
            
        except Exception as e:
            print(f"✗ Scan with 'none' LLM failed: {e}")
            import traceback
            traceback.print_exc()
            return 1
        
        # Test with ollama LLM (if available)
        print("\n2. Testing with 'ollama' LLM...")
        try:
            ollama_pipeline = ScanningPipeline(
                scanner_path=str(Path(__file__).resolve().parents[2] / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"),
                llm_type="ollama",
                model="llama2",
                environment_config_path=str(env_config_file),
                enable_discovery=False,
                timeout_sec=30
            )
            
            ollama_results = ollama_pipeline.scan(
                root_path=str(temp_dir),
                rules_path=str(REPO_ROOT / "configs" / "example.rules.json"),
                include_patterns=["**/*.c"],
                exclude_patterns=[],
                min_risk="low"
            )
            
            print(f"✓ Ollama scan completed with {len(ollama_results.findings)} findings")
            
            for i, finding in enumerate(ollama_results.findings[:3]):  # Show first 3
                print(f"  Finding {i+1}: {finding.file}:{finding.lines[0]}")
                print(f"    Symbol: {finding.symbol}")
                print(f"    Y2038 Issue: {finding.y2038_issue}")
                print(f"    Reason: {finding.reason}")
                print(f"    Confidence: {finding.confidence}")
                print()
                
        except Exception as e:
            print(f"✗ Scan with 'ollama' LLM failed (expected if Ollama not running): {e}")
        
        print("\n🎉 LLM integration scan test completed!")
        return 0

if __name__ == '__main__':
    exit(test_llm_scan())
