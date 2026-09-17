#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Test script for LLM integration.
"""

import json
import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

def test_llm_integration():
    """Test the LLM integration."""
    print("Testing LLM Integration")
    print("=" * 30)
    
    try:
        from tacs.core.llm_client import LLMClient
        from tacs.core.schema import Candidate
        
        # Create test candidates
        candidates = [
            Candidate(
                file="test.c",
                line=10,
                col_start=5,
                col_end=15,
                symbol="time",
                one_line_snippet="time_t t = time(NULL);",
                symbol_role="function_call"
            ),
            Candidate(
                file="test.c", 
                line=20,
                col_start=1,
                col_end=20,
                symbol="clock_gettime64",
                one_line_snippet="clock_gettime64(CLOCK_REALTIME, &ts);",
                symbol_role="function_call"
            )
        ]
        
        # Test 1: None LLM (should work)
        print("\n1. Testing 'none' LLM...")
        none_client = LLMClient("none", "test-model")
        none_responses = none_client.classify_candidates(candidates)
        
        print(f"✓ None LLM returned {len(none_responses)} responses")
        for i, response in enumerate(none_responses):
            print(f"  Response {i+1}: {response.y2038_issue.value} (confidence: {response.confidence})")
        
        # Test 2: Ollama LLM (may fail if Ollama not running)
        print("\n2. Testing 'ollama' LLM...")
        try:
            ollama_client = LLMClient("ollama", "llama2", timeout_sec=10)
            ollama_responses = ollama_client.classify_candidates(candidates)
            
            print(f"✓ Ollama LLM returned {len(ollama_responses)} responses")
            for i, response in enumerate(ollama_responses):
                print(f"  Response {i+1}: {response.y2038_issue.value} (confidence: {response.confidence})")
                print(f"    Reason: {response.reason}")
                
        except Exception as e:
            print(f"✗ Ollama LLM failed (expected if Ollama not running): {e}")
        
        # Test 3: Environment-aware prompts
        print("\n3. Testing environment-aware prompts...")
        env_config = {
            "hardware_model": "ILP32",
            "time_t_size_bits": 32,
            "time_t_signed": "signed",
            "time64_functions_available": False,
            "scenario_hint": "ILP32-32bit-signed-time64_no"
        }
        
        env_client = LLMClient("none", "test-model", env_config)
        env_context = env_client._build_environment_context()
        print("✓ Environment context:")
        print(env_context)
        
        # Test 4: Scenario-specific examples
        print("\n4. Testing scenario-specific examples...")
        examples = env_client._get_scenario_examples()
        print(f"✓ Loaded {len(examples)} scenario-specific examples")
        for i, example in enumerate(examples[:2]):  # Show first 2
            print(f"  Example {i+1}: {example['code']}")
            print(f"    Response: {example['response']['y2038_issue']} - {example['response']['reason']}")
        
        print("\n🎉 LLM integration tests completed!")
        
        return 0
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    exit(test_llm_integration())
