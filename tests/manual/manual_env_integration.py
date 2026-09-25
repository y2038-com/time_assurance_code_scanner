#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Test script to demonstrate environment configuration integration.
"""

import json
import sys
import tempfile
from pathlib import Path

# Add this script's directory to the Python path (tacs/envui come from
# the installed package)
sys.path.insert(0, str(Path(__file__).parent))

def test_environment_integration():
    """Test the environment configuration integration."""
    print("Testing Environment Configuration Integration")
    print("=" * 50)
    
    # Test 1: Create a sample environment config
    sample_config = {
        "hardware_model": "ILP32",
        "time_t_size_bits": 32,
        "time_t_signed": "signed",
        "time64_functions_available": False,
        "d_time_bits_supported": True,
        "d_time_bits_setting": "64",
        "os_or_rtos": "Zephyr 3.7",
        "c_library": "picolibc",
        "toolchain_flags": ["-D_FILE_OFFSET_BITS=64"],
        "notes": "board XYZ",
        "scenario_hint": "ILP32-32bit-signed-time64_no",
        "mitigation_path": "upgrade_env"
    }
    
    # Write sample config. It is scratch, so it goes to a temp directory; the
    # handle stays alive for the whole function, so it is removed on return.
    tmp_config_dir = tempfile.TemporaryDirectory(prefix="y2038_env_")
    env_config_path = Path(tmp_config_dir.name) / "test_env_config.json"
    with open(env_config_path, 'w') as f:
        json.dump(sample_config, f, indent=2)
    print("✓ Created sample environment configuration")
    
    # Test 2: Test LLM client with environment config
    try:
        from tacs.core.llm_client import LLMClient
        
        llm_client = LLMClient("none", "test-model", sample_config)
        print("✓ LLM client initialized with environment config")
        
        # Test environment context building
        env_rules = llm_client._build_environment_rules()
        print("✓ Environment rules built (trusted channel):")
        print(env_rules)
        
        # Test scenario-specific examples
        examples = llm_client._get_scenario_examples()
        print(f"✓ Scenario-specific examples loaded: {len(examples)} examples")
        
    except Exception as e:
        print(f"✗ LLM client test failed: {e}")
        return 1
    
    # Test 3: Test pipeline with environment config
    try:
        from tacs.core.pipeline import ScanningPipeline
        
        pipeline = ScanningPipeline(
            scanner_path=str(Path(__file__).resolve().parents[2] / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"),
            llm_type="none",
            environment_config_path=str(env_config_path)
        )
        print("✓ Pipeline initialized with environment config")
        
        if pipeline.environment_config:
            print(f"✓ Environment config loaded: {pipeline.environment_config['scenario_hint']}")
        else:
            print("✗ Environment config not loaded")
            return 1
            
    except Exception as e:
        print(f"✗ Pipeline test failed: {e}")
        return 1
    
    print("\n🎉 All integration tests passed!")
    print("\nHow to use:")
    print("1. Create environment config: python envui/cli/env_wizard.py --out results/env_config.json")
    print("2. Run scanner with config: tacs scan --root . --rules configs/example.rules.json --env-config results/env_config.json --llm none")
    
    return 0

if __name__ == '__main__':
    exit(test_environment_integration())
