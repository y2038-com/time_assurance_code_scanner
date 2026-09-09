#!/usr/bin/env python3
"""
Quick test to verify the LLM integration fixes.
"""

import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

def test_fixes():
    """Test the recent fixes."""
    print("Testing LLM Integration Fixes")
    print("=" * 30)
    
    try:
        from tacs.core.llm_client import LLMClient
        from tacs.core.schema import Candidate, LLMResponse
        
        # Test 1: Create LLMResponse with longer reason
        print("1. Testing longer reason field...")
        response = LLMResponse(
            id="test.c:10",
            y2038_issue="yes",
            severity="high",
            confidence=0.9,
            reason="This is a longer reason that exceeds 25 characters and should now work properly",
            needs_more_context=False,
            line=10,
            col_start=5,
            col_end=15
        )
        print(f"✓ LLMResponse created with reason length: {len(response.reason)}")
        
        # Test 2: Test local Ollama connection
        print("\n2. Testing local Ollama connection...")
        client = LLMClient("ollama", "llama2", timeout_sec=5)
        
        # Test connection without making actual request
        import requests
        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            if response.status_code == 200:
                print("✓ Local Ollama server is running")
            else:
                print(f"✗ Ollama server returned status: {response.status_code}")
        except requests.exceptions.ConnectionError:
            print("✗ Cannot connect to local Ollama server")
            print("  Make sure Ollama is running: ollama serve")
        except Exception as e:
            print(f"✗ Ollama connection test failed: {e}")
        
        print("\n🎉 Fix verification completed!")
        return 0
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    exit(test_fixes())
