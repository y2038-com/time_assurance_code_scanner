#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Debug script to investigate Pass 2 issues.
"""

import json
import sys
import tempfile
from pathlib import Path

# Add this script's directory to the Python path (tacs/envui come from
# the installed package)
sys.path.insert(0, str(Path(__file__).parent))

def debug_pass2():
    """Debug Pass 2 implementation."""
    print("Debugging Pass 2 Implementation")
    print("=" * 35)
    
    try:
        from tacs.core.llm_client import LLMClient
        from tacs.core.schema import Candidate, LLMResponse, Y2038Issue
        
        # Create test candidates
        candidates = [
            Candidate(
                file="test.c",
                line=10,
                col_start=5,
                col_end=15,
                symbol="time",
                one_line_snippet="time_t t = time(NULL);",
                risk="high",
                symbol_role="function_call"
            ),
            Candidate(
                file="test.c", 
                line=20,
                col_start=1,
                col_end=20,
                symbol="usleep",
                one_line_snippet="usleep(1000);",
                risk="medium",
                symbol_role="function_call"
            )
        ]
        
        # Create test responses
        responses = [
            LLMResponse(
                id="test.c:10",
                y2038_issue=Y2038Issue.ABSTAIN,
                severity=None,
                confidence=0.3,
                reason="Need more context to determine Y2038 risk",
                needs_more_context=True,
                line=10,
                col_start=5,
                col_end=15
            ),
            LLMResponse(
                id="test.c:20",
                y2038_issue=Y2038Issue.ABSTAIN,
                severity=None,
                confidence=0.2,
                reason="Unclear if this is time-related",
                needs_more_context=True,
                line=20,
                col_start=1,
                col_end=20
            )
        ]
        
        # Test Pass 2 with none LLM
        print("1. Testing Pass 2 with 'none' LLM...")
        none_client = LLMClient("none", "test-model", batch_size_pass2=5)
        
        context_candidates = [(responses[0], candidates[0], "test context 1"), 
                            (responses[1], candidates[1], "test context 2")]
        
        pass2_responses = none_client.classify_candidates_pass2(context_candidates)
        print(f"✓ Pass 2 returned {len(pass2_responses)} responses")
        for i, response in enumerate(pass2_responses):
            print(f"  Response {i+1}: {response.y2038_issue.value} (confidence: {response.confidence})")
            print(f"    Reason: {response.reason}")
        
        # Test Pass 2 prompt building
        print("\n2. Testing Pass 2 prompt building...")
        prompt = none_client._build_pass2_prompt(context_candidates)
        print("✓ Pass 2 prompt built successfully")
        print(f"System length: {len(prompt.system)} characters")
        print(f"Untrusted user length: {len(prompt.user)} characters")
        print("First 500 characters of each:")
        print(prompt.system[:500] + "...")
        print(prompt.user[:500] + "...")
        
        # Test context extraction
        print("\n3. Testing context extraction...")
        from tacs.core.pipeline import ScanningPipeline
        
        pipeline = ScanningPipeline(
            scanner_path=str(Path(__file__).resolve().parents[2] / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"),
            llm_type="none",
            batch_size_pass2=5
        )
        
        context = pipeline._extract_widened_context(candidates[0], context_lines=3)
        print("✓ Context extraction successful")
        print("Extracted context:")
        print(context)
        
        print("\n🎉 Pass 2 debug completed!")
        return 0
        
    except Exception as e:
        print(f"✗ Debug failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    exit(debug_pass2())
