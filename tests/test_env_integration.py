#!/usr/bin/env python3
"""
Test script to demonstrate environment configuration integration.
"""

import json
import sys
from pathlib import Path

# Add the project root to the Python path
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
    
    # Write sample config
    with open('results/test_env_config.json', 'w') as f:
        json.dump(sample_config, f, indent=2)
    print("✓ Created sample environment configuration")
    
    # Test 2: Test LLM client with environment config
    try:
        from tacs.core.llm_client import LLMClient
        
        llm_client = LLMClient("none", "test-model", sample_config)
        print("✓ LLM client initialized with environment config")
        
        # Test environment context building
        env_context = llm_client._build_environment_context()
        print("✓ Environment context built:")
        print(env_context)
        
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
            scanner_path=str(Path(__file__).resolve().parents[1] / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"),
            llm_type="none",
            environment_config_path="results/test_env_config.json"
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
