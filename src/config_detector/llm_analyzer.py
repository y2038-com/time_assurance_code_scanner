# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""LLM-based analyzer for build system configuration detection."""

import json
import hashlib
import time
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import requests


class LLMAnalyzer:
    """LLM analyzer for build system files."""
    
    def __init__(
        self,
        llm_type: str = "ollama",
        model: str = "gpt-oss:120b-cloud",
        timeout_sec: int = 60,
        debug: bool = False
    ):
        """
        Initialize the LLM analyzer.
        
        Args:
            llm_type: Type of LLM to use (ollama, none)
            model: Model name to use
            timeout_sec: Request timeout in seconds
            debug: Enable debug output
        """
        self.llm_type = llm_type
        self.model = model
        self.timeout_sec = timeout_sec
        self.debug = debug
        self.cloud_token = None
        if llm_type == "ollama":
            from tacs.llm.env import ollama_api_key

            self.cloud_token = ollama_api_key()
    
    def analyze_build_system(
        self,
        build_files: Dict[str, str],
        keyword_hints: Dict[str, Any],
        low_confidence_fields: List[str]
    ) -> Tuple[Dict[str, Any], Dict[str, float], Dict[str, str]]:
        """
        Analyze build system files using LLM.
        
        Args:
            build_files: Dictionary mapping filename to file content
            keyword_hints: Keyword-based detection results (may be incomplete)
            low_confidence_fields: List of fields with low confidence that need analysis
        
        Returns:
            Tuple of (config_dict, confidence_dict, reasoning_dict)
        """
        if self.llm_type == "none":
            return self._analyze_none()
        
        prompt = self._build_prompt(build_files, keyword_hints, low_confidence_fields)
        
        if self.debug:
            print(f"\n=== LLM PROMPT (first 2000 chars) ===")
            print(prompt[:2000])
            print("=== END PROMPT ===\n")
        
        # Make API request with retry logic
        max_retries = 3
        retry_delay = 2
        
        for attempt in range(1, max_retries + 1):
            try:
                response_data = self._make_api_request(prompt)
                return self._parse_response(response_data)
            except Exception as e:
                if attempt < max_retries:
                    if self.debug:
                        print(f"Attempt {attempt} failed, retrying in {retry_delay}s: {e}")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                else:
                    raise RuntimeError(f"LLM analysis failed after {max_retries} attempts: {e}")
        
        # Should not reach here
        raise RuntimeError("LLM analysis failed")
    
    def _build_prompt(
        self,
        build_files: Dict[str, str],
        keyword_hints: Dict[str, Any],
        low_confidence_fields: List[str]
    ) -> str:
        """Build the LLM prompt for build system analysis."""
        
        prompt = """You are analyzing build system files to determine Y2038 environment configuration.

Your task is to extract the following information:
1. hardware_model: ILP32 (32-bit) or LP64 (64-bit)
2. time_t_size_bits: 32 or 64
3. time_t_signed: signed or unsigned
4. c_library: glibc, picolibc, newlib, musl, minimal, libstdc++, or other
5. time64_functions_available: true, false, or null when the files do not establish it
6. d_time_bits_supported: true, false, or null when the files do not establish it
7. d_time_bits_setting: not_available, not_set, 32, 64, or unknown
8. os_or_rtos: Operating system or RTOS name (if detectable, or null)
9. toolchain_flags: List of relevant compiler flags (array of strings)

Keyword-based hints (may be incomplete or incorrect):
"""
        prompt += json.dumps(keyword_hints, indent=2)
        prompt += "\n\nLow-confidence fields requiring analysis:\n"
        prompt += json.dumps(low_confidence_fields, indent=2)
        prompt += "\n\nBuild system files:\n"
        
        # Add build files (limit size to avoid token limits)
        for filename, content in list(build_files.items())[:5]:  # Limit to 5 files
            # Truncate very large files
            max_lines = 2000
            lines = content.split('\n')
            if len(lines) > max_lines:
                content = '\n'.join(lines[:max_lines]) + f"\n... (truncated, {len(lines) - max_lines} more lines)"
            
            prompt += f"\n=== {filename} ===\n{content}\n"
        
        prompt += """
Analyze these files and respond with a JSON object matching this schema:
{
  "hardware_model": "ILP32" | "LP64",
  "time_t_size_bits": 32 | 64,
  "time_t_signed": "signed" | "unsigned",
  "time64_functions_available": true | false | null,
  "d_time_bits_supported": true | false | null,
  "d_time_bits_setting": "not_available" | "not_set" | "32" | "64" | "unknown",
  "c_library": "glibc" | "picolibc" | "newlib" | "musl" | "minimal" | "libstdc++" | "other",
  "os_or_rtos": "string or null",
  "toolchain_flags": ["-D_TIME_BITS=64", ...],
  "confidence": {
    "hardware_model": 0.0-1.0,
    "time_t_size_bits": 0.0-1.0,
    "time_t_signed": 0.0-1.0,
    "c_library": 0.0-1.0,
    "time64_functions_available": 0.0-1.0,
    "d_time_bits_supported": 0.0-1.0,
    "d_time_bits_setting": 0.0-1.0
  },
  "reasoning": {
    "hardware_model": "explanation",
    "time_t_size_bits": "explanation",
    "time_t_signed": "explanation",
    "c_library": "explanation",
    ...
  }
}

CRITICAL RULES:
- For hardware_model: Look for -m32/-m64 flags, target triple, architecture defines, CMAKE_SYSTEM_PROCESSOR
- For time_t_size_bits: Look for -D_TIME_BITS=64, CONFIG_TIME_T_64BIT, architecture defaults (LP64 usually has 64-bit, ILP32 usually has 32-bit)
- For time_t_signed: Check library defaults (glibc=signed, Zephyr/picolibc=often unsigned), code patterns, CONFIG_TIME_T_UNSIGNED
- For c_library: Look for library paths, -lc flags, library names in includes, find_package() calls
- For d_time_bits_supported: Check if glibc 2.34+ (usually true for modern Linux), false for embedded libraries
- For d_time_bits_setting: Check for -D_TIME_BITS=64 or -D_TIME_BITS=32, or "not_set" if not defined
- For the two capability fields: answer false only when the files show the feature is absent, and null when they simply do not say. "not_available" likewise asserts absence, so use "unknown" when the files are silent
- Be conservative: If uncertain, use lower confidence and explain reasoning
- Validate against keyword hints: If LLM result conflicts, explain why in reasoning
- Respond with ONLY valid JSON, no markdown formatting, no code blocks
"""
        return prompt
    
    def _make_api_request(self, prompt: str) -> Dict[str, Any]:
        """Make API request to Ollama (local or cloud)."""
        from tacs.llm.env import resolve_ollama_request_target

        if self.llm_type != "ollama":
            raise ValueError(f"Unsupported LLM type: {self.llm_type}")

        url, headers, api_model, is_cloud = resolve_ollama_request_target(self.model)

        data = {
            "model": api_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,  # Low temperature for deterministic results
                "num_predict": 4000  # Enough for JSON response
            }
        }

        # For cloud models, use longer timeout
        timeout = self.timeout_sec * 2 if is_cloud else self.timeout_sec

        try:
            response = requests.post(url, json=data, headers=headers, timeout=timeout)

            if response.status_code != 200:
                error_text = response.text
                if "ollama.com" in error_text or "TLS handshake" in error_text:
                    raise RuntimeError(
                        f"Cloud model connection failed: TLS handshake timeout. "
                        f"This may be a temporary network issue. Error: {error_text[:200]}"
                    )
                where = "Ollama Cloud" if is_cloud else "Local Ollama"
                raise RuntimeError(f"{where} request failed: {response.status_code} - {error_text[:200]}")

            result = response.json()

            # Extract response text
            if "response" in result:
                response_text = result["response"]
            else:
                raise ValueError("No 'response' field in Ollama response")

            return {"response": response_text, "usage": result.get("eval_count", {})}

        except requests.exceptions.Timeout:
            raise RuntimeError(f"Request timeout after {timeout} seconds")
        except requests.exceptions.ConnectionError as e:
            raise RuntimeError(f"Failed to connect to Ollama: {e}")
    
    def _parse_response(self, response_data: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, float], Dict[str, str]]:
        """Parse LLM response and extract configuration, confidence, and reasoning."""
        response_text = response_data.get("response", "")
        
        if self.debug:
            print(f"\n=== LLM RESPONSE ===")
            print(response_text)
            print("=== END RESPONSE ===\n")
        
        # Try to extract JSON from response (may be wrapped in markdown)
        json_text = response_text.strip()
        
        # Remove markdown code blocks if present
        if json_text.startswith("```"):
            lines = json_text.split('\n')
            json_text = '\n'.join(lines[1:-1])  # Remove first and last lines
        if json_text.startswith("```json"):
            lines = json_text.split('\n')
            json_text = '\n'.join(lines[1:-1])
        
        # Try to parse JSON
        try:
            parsed = json.loads(json_text)
        except json.JSONDecodeError as e:
            # Try to find JSON object in the text
            import re
            json_match = re.search(r'\{.*\}', json_text, re.DOTALL)
            if json_match:
                try:
                    parsed = json.loads(json_match.group(0))
                except json.JSONDecodeError:
                    raise ValueError(f"Failed to parse JSON from LLM response: {e}\nResponse: {response_text[:500]}")
            else:
                raise ValueError(f"Failed to parse JSON from LLM response: {e}\nResponse: {response_text[:500]}")
        
        # Extract configuration
        config = {
            "hardware_model": parsed.get("hardware_model"),
            "time_t_size_bits": parsed.get("time_t_size_bits"),
            "time_t_signed": parsed.get("time_t_signed"),
            "c_library": parsed.get("c_library"),
            "time64_functions_available": parsed.get("time64_functions_available"),
            "d_time_bits_supported": parsed.get("d_time_bits_supported"),
            "d_time_bits_setting": parsed.get("d_time_bits_setting"),
            "os_or_rtos": parsed.get("os_or_rtos"),
            "toolchain_flags": parsed.get("toolchain_flags", [])
        }
        
        # Extract confidence scores
        confidence = parsed.get("confidence", {})
        
        # Extract reasoning
        reasoning = parsed.get("reasoning", {})
        
        return config, confidence, reasoning
    
    def _analyze_none(self) -> Tuple[Dict[str, Any], Dict[str, float], Dict[str, str]]:
        """Return empty results when LLM is disabled."""
        return {}, {}, {}
