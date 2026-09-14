from __future__ import annotations

import json
import os
import time
from typing import List, Dict, Any, Optional, Tuple
from tacs.core.schema import Candidate, LLMResponse, Y2038Issue, SeverityLevel
from tacs.core.status_logger import StatusLogger
from tacs.llm.env import (
    DEFAULT_MODEL,
    default_model_id,
    looks_like_cloud_model,
    ollama_api_key,
    resolve_ollama_request_target,
)


class LLMNonRetryableError(RuntimeError):
    """HTTP client errors where retries will not help (wrong model id, auth, bad request)."""


class LLMClient:
    """Pluggable LLM client with provider-specific HTTP adapters."""
    
    def __init__(self, llm_type: str = "none", model: Optional[str] = None, environment_config: Optional[Dict[str, Any]] = None, timeout_sec: int = 30, batch_size_pass2: int = 20, batch_size_pass3: int = 10, debug_llm_raw: bool = False, debug_pass2_prompt: bool = False, time_t_aliases: Optional[Dict[str, List[str]]] = None, io_metadata_map: Optional[Dict[str, Dict[str, Any]]] = None, migration_mode: bool = False, migration_from_config: Optional[Dict[str, Any]] = None, migration_to_config: Optional[Dict[str, Any]] = None):
        """
        Initialize the LLM client.
        
        Args:
            llm_type: Type of LLM to use (none, ollama, openai, anthropic, gemini)
            model: Model name to use
            environment_config: Environment configuration for context
            timeout_sec: Request timeout in seconds
            batch_size_pass2: Batch size for Pass 2
            time_t_aliases: Dictionary of time_t alias names to their definitions
            io_metadata_map: Mapping of candidate IDs to I/O-boundary metadata
        """
        self.llm_type = llm_type
        self.model = model or default_model_id() or DEFAULT_MODEL
        self.environment_config = environment_config
        self.timeout_sec = timeout_sec
        self.batch_size_pass2 = batch_size_pass2
        self.batch_size_pass3 = batch_size_pass3
        self.debug_llm_raw = debug_llm_raw
        self.debug_pass2_prompt = debug_pass2_prompt
        self.time_t_aliases = time_t_aliases or {}
        self.io_metadata_map = io_metadata_map or {}
        # Prefer OLLAMA_API_KEY; keep OLLAMA_CLOUD_TOKEN for existing installs (COMPAT).
        self.cloud_token = ollama_api_key()
        
        # Migration mode support
        self.migration_mode = migration_mode
        self.migration_from_config = migration_from_config
        self.migration_to_config = migration_to_config
        
        # Token usage tracking
        self.token_stats = {
            "total_prompt_tokens": 0,
            "total_completion_tokens": 0,
            "total_requests": 0,
            "by_stage": {}  # Track per stage/pass
        }
        
        self._validate_provider_allowed()
    
    def classify_candidates(self, candidates: List[Candidate], batch_size: int = 100, io_metadata_map: Optional[Dict[str, Dict[str, Any]]] = None) -> List[LLMResponse]:
        """
        Classify candidates using LLM.
        
        Args:
            candidates: List of candidates to classify
            batch_size: Number of candidates per batch
            io_metadata_map: Optional I/O metadata mapping (overrides instance variable)
            
        Returns:
            List of LLM responses
        """
        # Use provided metadata map or instance variable
        metadata_map = io_metadata_map if io_metadata_map is not None else self.io_metadata_map
        
        if self.llm_type == "none":
            return self._classify_none(candidates)
        elif self.llm_type in {"ollama", "openai", "anthropic", "gemini"}:
            return self._classify_ollama(candidates, batch_size, metadata_map)
        else:
            raise ValueError(f"Unknown LLM type: {self.llm_type}")
    
    def _classify_none(self, candidates: List[Candidate]) -> List[LLMResponse]:
        """Return abstain for all candidates when LLM is disabled."""
        responses = []
        for candidate in candidates:
            response = LLMResponse(
                id=f"{candidate.file}:{candidate.line}",
                y2038_issue=Y2038Issue.ABSTAIN,
                severity=None,
                confidence=0.0,
                reason="LLM disabled",
                needs_more_context=True,
                line=candidate.line,
                col_start=candidate.col_start,
                col_end=candidate.col_end
            )
            responses.append(response)
        return responses
    
    def _classify_ollama(self, candidates: List[Candidate], batch_size: int, io_metadata_map: Optional[Dict[str, Dict[str, Any]]] = None) -> List[LLMResponse]:
        """Classify candidates using Ollama API."""
        responses = []
        
        # Process in batches with adaptive sizing for long lines
        i = 0
        while i < len(candidates):
            # Start with requested batch size
            current_batch_size = batch_size
            batch = []
            total_chars = 0
            max_line_length = 500  # Maximum characters per line before reducing batch size
            
            # Build batch, checking for extremely long lines
            while len(batch) < current_batch_size and i < len(candidates):
                candidate = candidates[i]
                line_length = len(candidate.one_line_snippet) if candidate.one_line_snippet else 0
                
                # If line is extremely long, reduce batch size for this batch
                if line_length > max_line_length * 2:  # Very long line (>1000 chars)
                    if len(batch) > 0:
                        # Finish current batch, will process long line separately
                        break
                    # Process single long line in its own batch
                    batch = [candidate]
                    i += 1
                    break
                elif line_length > max_line_length:  # Long line (>500 chars)
                    # Reduce batch size for this batch
                    if len(batch) == 0:
                        current_batch_size = min(10, batch_size // 2)  # Smaller batch for long lines
                
                batch.append(candidate)
                total_chars += line_length
                i += 1
                
                # If batch is getting too large (char-wise), finish it
                if total_chars > 50000:  # ~50KB of text
                    break
            
            if batch:
                batch_responses = self._process_batch(batch, "S1_P1")
                responses.extend(batch_responses)
        
        return responses
    
    def _process_batch(self, candidates: List[Candidate], stage_name: str = "S1_P1") -> List[LLMResponse]:
        """Process a batch of candidates."""
        StatusLogger.timestamped_print(f"Processing batch of {len(candidates)} candidates with {self.llm_type} LLM...")
        
        # Build prompt (uses instance io_metadata_map)
        prompt = self._build_prompt(candidates, self.io_metadata_map)
        
        # Make API request with retry logic for cloud models
        max_retries = 3
        retry_delay = 2  # seconds
        
        for attempt in range(1, max_retries + 1):
            try:
                response_data = self._make_api_request(prompt)
                
                # Extract token usage from response
                prompt_tokens = 0
                completion_tokens = 0
                if "usage" in response_data:
                    prompt_tokens = response_data["usage"].get("prompt_tokens", 0)
                    completion_tokens = response_data["usage"].get("completion_tokens", 0)
                    self._track_tokens(prompt_tokens, completion_tokens, stage_name)
                
                responses = self._parse_response(response_data, candidates)
                
                # Log results
                yes_count = sum(1 for r in responses if r.y2038_issue == Y2038Issue.YES)
                no_count = sum(1 for r in responses if r.y2038_issue == Y2038Issue.NO)
                abstain_count = sum(1 for r in responses if r.y2038_issue == Y2038Issue.ABSTAIN)
                
                StatusLogger.timestamped_print(f"LLM results: {yes_count} yes, {no_count} no, {abstain_count} abstain")
                if prompt_tokens > 0 or completion_tokens > 0:
                    StatusLogger.timestamped_print(f"Token usage: {prompt_tokens} prompt + {completion_tokens} completion = {prompt_tokens + completion_tokens} total")
                
                return responses
                
            except Exception as e:
                error_str = str(e)
                # Check if this is a retryable error (TLS timeout, connection issues)
                is_retryable = (
                    "TLS handshake" in error_str or 
                    "timeout" in error_str.lower() or 
                    "connection" in error_str.lower() or
                    "cloud" in error_str.lower()
                )
                
                if is_retryable and attempt < max_retries:
                    StatusLogger.timestamped_warning(f"LLM request failed (attempt {attempt}/{max_retries}): {error_str[:100]}")
                    StatusLogger.timestamped_print(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                    continue
                else:
                    StatusLogger.timestamped_error(f"LLM request failed after {attempt} attempt(s): {error_str[:150]}")
                    # Fallback to abstain on error
                    return self._fallback_responses(candidates, error_str[:150])
    
    def classify_candidates_pass2(self, context_candidates: List[tuple]) -> List[LLMResponse]:
        """
        Classify candidates with widened context for Pass 2.
        
        Args:
            context_candidates: List of (response, candidate, context) tuples
            
        Returns:
            List of LLM responses
        """
        if self.llm_type == "none":
            return self._classify_none_pass2(context_candidates)
        elif self.llm_type in {"ollama", "openai", "anthropic", "gemini"}:
            return self._classify_ollama_pass2(context_candidates)
        else:
            raise ValueError(f"Unknown LLM type: {self.llm_type}")
    
    def _classify_none_pass2(self, context_candidates: List[tuple]) -> List[LLMResponse]:
        """Return abstain for all Pass 2 candidates when LLM is disabled."""
        responses = []
        for response, candidate, context in context_candidates:
            fallback_response = LLMResponse(
                id=response.id,
                y2038_issue=Y2038Issue.ABSTAIN,
                severity=None,
                confidence=0.0,
                reason="LLM disabled for Pass 2",
                needs_more_context=True,
                line=candidate.line if candidate else 0,
                col_start=candidate.col_start if candidate else 0,
                col_end=candidate.col_end if candidate else 0
            )
            responses.append(fallback_response)
        return responses
    
    def _classify_ollama_pass2(self, context_candidates: List[tuple]) -> List[LLMResponse]:
        """Classify Pass 2 candidates using Ollama API with widened context."""
        responses = []
        
        # Process in smaller batches for Pass 2 (more context per candidate)
        batch_size = min(self.batch_size_pass2, len(context_candidates))
        
        for i in range(0, len(context_candidates), batch_size):
            batch = context_candidates[i:i + batch_size]
            batch_responses = self._process_pass2_batch(batch)
            responses.extend(batch_responses)
        
        return responses
    
    def classify_candidates_pass3(self, file_candidates: List[tuple]) -> List[LLMResponse]:
        """
        Classify candidates with full file context for Pass 3.
        
        Args:
            file_candidates: List of (response, candidate, file_content) tuples
            
        Returns:
            List of LLM responses
        """
        if self.llm_type == "none":
            return self._classify_none_pass3(file_candidates)
        elif self.llm_type in {"ollama", "openai", "anthropic", "gemini"}:
            return self._classify_ollama_pass3(file_candidates)
        else:
            raise ValueError(f"Unknown LLM type: {self.llm_type}")
    
    def _classify_none_pass3(self, file_candidates: List[tuple]) -> List[LLMResponse]:
        """Return abstain for all Pass 3 candidates when LLM is disabled."""
        responses = []
        for response, candidate, file_content in file_candidates:
            fallback_response = LLMResponse(
                id=response.id,
                y2038_issue=Y2038Issue.ABSTAIN,
                severity=None,
                confidence=0.0,
                reason="LLM disabled for Pass 3",
                needs_more_context=False,
                line=candidate.line if candidate else 0,
                col_start=candidate.col_start if candidate else 0,
                col_end=candidate.col_end if candidate else 0
            )
            responses.append(fallback_response)
        return responses
    
    def _classify_ollama_pass3(self, file_candidates: List[tuple]) -> List[LLMResponse]:
        """Classify Pass 3 candidates using Ollama API with full file context."""
        responses = []
        
        # Process in smaller batches for Pass 3 (large file content)
        batch_size = min(self.batch_size_pass3, len(file_candidates))
        
        for i in range(0, len(file_candidates), batch_size):
            batch = file_candidates[i:i + batch_size]
            batch_responses = self._process_pass3_batch(batch)
            responses.extend(batch_responses)
        
        return responses
    
    def _process_pass3_batch(self, batch: List[tuple]) -> List[LLMResponse]:
        """Process a batch of Pass 3 candidates with full file context."""
        print(f"Processing Pass 3 batch of {len(batch)} candidates with file context...")
        
        # Build Pass 3 prompt
        prompt = self._build_pass3_prompt(batch)
        
        # Make API request with retry logic for cloud models
        max_retries = 3
        retry_delay = 2  # seconds
        
        for attempt in range(1, max_retries + 1):
            try:
                response_data = self._make_api_request(prompt)
                
                # Extract token usage from response
                prompt_tokens = 0
                completion_tokens = 0
                if "usage" in response_data:
                    prompt_tokens = response_data["usage"].get("prompt_tokens", 0)
                    completion_tokens = response_data["usage"].get("completion_tokens", 0)
                    self._track_tokens(prompt_tokens, completion_tokens, "S3_P1")
                
                responses = self._parse_response(response_data, [candidate for _, candidate, _ in batch])
                
                # Log results
                yes_count = sum(1 for r in responses if r.y2038_issue == Y2038Issue.YES)
                no_count = sum(1 for r in responses if r.y2038_issue == Y2038Issue.NO)
                abstain_count = sum(1 for r in responses if r.y2038_issue == Y2038Issue.ABSTAIN)
                
                print(f"Pass 3 LLM results: {yes_count} yes, {no_count} no, {abstain_count} abstain")
                if prompt_tokens > 0 or completion_tokens > 0:
                    StatusLogger.timestamped_print(f"Token usage: {prompt_tokens} prompt + {completion_tokens} completion = {prompt_tokens + completion_tokens} total")
                
                return responses
                
            except Exception as e:
                error_str = str(e)
                # Check if this is a retryable error (TLS timeout, connection issues)
                is_retryable = (
                    "TLS handshake" in error_str or 
                    "timeout" in error_str.lower() or 
                    ("connection" in error_str.lower() and "cloud" in error_str.lower())
                )
                
                if is_retryable and attempt < max_retries:
                    StatusLogger.timestamped_warning(f"Pass 3 LLM request failed (attempt {attempt}/{max_retries}): {error_str[:100]}")
                    StatusLogger.timestamped_print(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                    continue
                else:
                    StatusLogger.timestamped_error(f"Pass 3 LLM request failed after {attempt} attempt(s): {error_str[:150]}")
                    # Fallback to abstain on error
                    return self._fallback_responses_pass3(batch, error_str[:150])
    
    def _build_pass3_prompt(self, file_candidates: List[tuple]) -> str:
        """Build prompt for Pass 3 with full file context."""
        env_context = self._build_environment_context()
        system_prompt = (
            f"You are a C/C++ Y2038 auditor analyzing complete source files. "
            f"Use the environment context and the provided full file content "
            f"to make final decisions on Y2038 risks. The '>>>' lines mark the target code. "
            f"With complete file context, you should be able to make confident decisions. "
            f"Only answer abstain if the code is genuinely ambiguous even with full context.\n\n"
            f"Environment Context:\n{env_context}\n\n"
            f"CRITICAL FOR ILP32 WITH 64-BIT TIME_T:\n"
            f"Even if time_t is 64-bit, narrowing patterns ARE Y2038/Y2106 risks:\n"
            f"- Explicit casts: (int32_t)time_value, (int)time(NULL), (long)timestamp (if long is 32-bit) → classify as 'yes'\n"
            f"- Implicit narrowing: int32_t x = time_value; int y = time(NULL); → classify as 'yes'\n"
            f"- These patterns lose precision and can cause Y2038/Y2106 issues when the narrowed value is used\n"
        )
        
        examples = self._get_pass3_examples()
        
        # Build candidate list with full file context
        candidate_text = ""
        for i, (response, candidate, file_content) in enumerate(file_candidates):
            candidate_text += f"{i+1}. {candidate.file}:{candidate.line} - {candidate.symbol}\n"
            candidate_text += f"   Full file content:\n{file_content}\n\n"
        
        prompt = f"{system_prompt}\n\nPass 3 Examples:\n"
        for example in examples:
            prompt += f"File: {example['file']}\n"
            prompt += f"Response: {json.dumps(example['response'])}\n\n"
        
        prompt += f"Candidates to classify with full file context:\n{candidate_text}\n"
        prompt += "Respond with a JSON array of classification objects matching the schema.\n"
        prompt += "IMPORTANT: Use the exact 'file:line' format for the 'id' field (e.g., 'test.c:10'), not just numbers."
        
        return prompt
    
    def _get_pass3_examples(self) -> List[Dict[str, Any]]:
        """Get Pass 3 specific examples with full file context."""
        return [
            {
                "file": """#include <time.h>
#include <stdio.h>

void process_data() {
>>>    time_t timestamp = time(NULL);
    if (timestamp > 0) {
        printf("Processing data at %ld\\n", timestamp);
    }
}

int main() {
    process_data();
    return 0;
}""",
                "response": {
                    "id": "process.c:5",
                    "y2038_issue": "yes",
                    "severity": "high",
                    "confidence": 0.95,
                    "reason": "Direct time() call with 32-bit time_t in ILP32 environment",
                    "needs_more_context": False
                }
            },
            {
                "file": """#include <time.h>
#include <sys/time.h>

void delay_function() {
    // Sleep for 100ms
>>>    usleep(100000);
    return;
}

int main() {
    delay_function();
    return 0;
}""",
                "response": {
                    "id": "delay.c:5",
                    "y2038_issue": "no",
                    "severity": None,
                    "confidence": 0.95,
                    "reason": "usleep() uses microseconds, not time_t, no Y2038 risk",
                    "needs_more_context": False
                }
            },
            {
                "file": """#include <time.h>
#include <sys/time.h>

long get_timestamp() {
>>>    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec;
}

int main() {
    long ts = get_timestamp();
    printf("Timestamp: %ld\\n", ts);
    return 0;
}""",
                "response": {
                    "id": "timestamp.c:5",
                    "y2038_issue": "yes",
                    "severity": "high",
                    "confidence": 0.9,
                    "reason": "timeval.tv_sec is 32-bit signed, wraps in 2038",
                    "needs_more_context": False
                }
            }
        ]
    
    def _fallback_responses_pass3(self, batch: List[tuple], error_msg: str) -> List[LLMResponse]:
        """Create fallback responses for Pass 3 when LLM fails."""
        responses = []
        for response, candidate, file_content in batch:
            # Truncate reason to 200 characters (schema limit)
            full_reason = f"Pass 3 LLM error: {error_msg}"
            truncated_reason = full_reason[:197] + "..." if len(full_reason) > 200 else full_reason
            fallback_response = LLMResponse(
                id=response.id,
                y2038_issue=Y2038Issue.ABSTAIN,
                severity=None,
                confidence=0.0,
                reason=truncated_reason,
                needs_more_context=False,
                line=candidate.line if candidate else 0,
                col_start=candidate.col_start if candidate else 0,
                col_end=candidate.col_end if candidate else 0
            )
            responses.append(fallback_response)
        return responses
    
    def _process_pass2_batch(self, batch: List[tuple]) -> List[LLMResponse]:
        """Process a batch of Pass 2 candidates with widened context."""
        StatusLogger.timestamped_print(f"Processing Pass 2 batch of {len(batch)} candidates with widened context...")
        
        # Debug: Show detailed batch information
        if self.debug_llm_raw:
            StatusLogger.timestamped_print("=== PASS 2 BATCH DETAILS ===")
            for i, (response, candidate, context) in enumerate(batch):
                StatusLogger.timestamped_print(f"Batch item {i+1}:")
                StatusLogger.timestamped_print(f"  Response ID: {response.id}")
                StatusLogger.timestamped_print(f"  Candidate: {candidate.file}:{candidate.line} - {candidate.symbol}")
                StatusLogger.timestamped_print(f"  Full Context:")
                context_lines = context.split('\n')
                for line in context_lines:
                    StatusLogger.timestamped_print(f"    {line}")
                StatusLogger.timestamped_print("")
        
        # Build Pass 2 prompt
        prompt = self._build_pass2_prompt(batch)
        
        # Debug: Show complete prompt if requested
        if self.debug_pass2_prompt:
            StatusLogger.timestamped_print("=== COMPLETE LLM PASS 2 PROMPT ===")
            StatusLogger.timestamped_print(prompt)
            StatusLogger.timestamped_print("=== END COMPLETE PROMPT ===")
        
        # Debug: Show raw prompt if requested
        if self.debug_llm_raw:
            StatusLogger.timestamped_print("=== RAW LLM PROMPT (Pass 2) ===")
            StatusLogger.timestamped_print(prompt)
            StatusLogger.timestamped_print("=== END RAW PROMPT ===")
        
        # Make API request with retry logic for cloud models
        max_retries = 3
        retry_delay = 2  # seconds
        
        for attempt in range(1, max_retries + 1):
            try:
                response_data = self._make_api_request(prompt)
                
                # Extract token usage from response
                prompt_tokens = 0
                completion_tokens = 0
                if "usage" in response_data:
                    prompt_tokens = response_data["usage"].get("prompt_tokens", 0)
                    completion_tokens = response_data["usage"].get("completion_tokens", 0)
                    self._track_tokens(prompt_tokens, completion_tokens, "S2_P1")
                
                # Debug: Show raw response if requested
                if self.debug_llm_raw:
                    StatusLogger.timestamped_print("=== RAW LLM RESPONSE (Pass 2) ===")
                    StatusLogger.timestamped_print(str(response_data))
                    StatusLogger.timestamped_print("=== END RAW RESPONSE ===")
                
                # Parse responses
                responses = self._parse_response(response_data, [candidate for _, candidate, _ in batch])
                
                # Log results
                yes_count = sum(1 for r in responses if r.y2038_issue == Y2038Issue.YES)
                no_count = sum(1 for r in responses if r.y2038_issue == Y2038Issue.NO)
                abstain_count = sum(1 for r in responses if r.y2038_issue == Y2038Issue.ABSTAIN)
                
                StatusLogger.timestamped_print(f"Pass 2 LLM results: {yes_count} yes, {no_count} no, {abstain_count} abstain")
                if prompt_tokens > 0 or completion_tokens > 0:
                    StatusLogger.timestamped_print(f"Token usage: {prompt_tokens} prompt + {completion_tokens} completion = {prompt_tokens + completion_tokens} total")
                
                return responses
                
            except Exception as e:
                error_str = str(e)
                # Check if this is a retryable error (TLS timeout, connection issues)
                is_retryable = (
                    "TLS handshake" in error_str or 
                    "timeout" in error_str.lower() or 
                    ("connection" in error_str.lower() and "cloud" in error_str.lower())
                )
                
                if is_retryable and attempt < max_retries:
                    StatusLogger.timestamped_warning(f"Pass 2 LLM request failed (attempt {attempt}/{max_retries}): {error_str[:100]}")
                    StatusLogger.timestamped_print(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                    continue
                else:
                    StatusLogger.timestamped_error(f"Pass 2 LLM request failed after {attempt} attempt(s): {error_str[:150]}")
                    # Fallback to abstain on error
                    return self._fallback_responses_pass2(batch, error_str[:150])
    
    def _build_pass2_prompt(self, context_candidates: List[tuple]) -> str:
        """Build the prompt for Pass 2 LLM classification with widened context."""
        # Build environment context
        env_context = self._build_environment_context()
        
        system_prompt = (
            f"You are a C/C++ Y2038 auditor analyzing code with widened context. "
            f"Use the environment context and the provided multi-line code snippets "
            f"to decide if there is a Y2038 risk. The '>>>' lines mark the target code. "
            f"With the additional context, you should be able to make confident decisions.\n\n"
            f"DECISION CRITERIA:\n"
            f"- YES: Direct time_t usage that could overflow in 2038 (arithmetic, storage, comparison) OR narrowing patterns in ILP32 with 64-bit time_t\n"
            f"- NO: Safe usage (struct tm declarations, 64-bit platforms with no narrowing, non-time_t types)\n"
            f"- ABSTAIN: Only if genuinely ambiguous even with full function context\n\n"
            f"CRITICAL FOR ILP32 WITH 64-BIT TIME_T:\n"
            f"Even if time_t is 64-bit, narrowing patterns ARE Y2038/Y2106 risks:\n"
            f"- Explicit casts: (int32_t)time_value, (int)time(NULL), (long)timestamp (if long is 32-bit) → classify as 'yes'\n"
            f"- Implicit narrowing: int32_t x = time_value; int y = time(NULL); → classify as 'yes'\n"
            f"- These patterns lose precision and can cause Y2038/Y2106 issues when the narrowed value is used\n\n"
            f"Be decisive! Most cases should be YES or NO, not ABSTAIN.\n\n"
            f"Environment Context:\n{env_context}"
        )
        
        # Add Pass 2 specific examples
        examples = self._get_pass2_examples()
        
        # Build candidate list with widened context
        candidate_text = ""
        for i, (response, candidate, context) in enumerate(context_candidates):
            candidate_text += f"{i+1}. {candidate.file}:{candidate.line} - {candidate.symbol}\n"
            candidate_text += f"   Context:\n{context}\n\n"
        
        prompt = f"{system_prompt}\n\nPass 2 Examples:\n"
        for example in examples:
            prompt += f"Context: {example['context']}\n"
            prompt += f"Response: {json.dumps(example['response'])}\n\n"
        
        prompt += f"Candidates to classify with widened context:\n{candidate_text}\n"
        prompt += "Respond with a JSON array of classification objects matching the schema.\n"
        prompt += "IMPORTANT: Use the exact 'file:line' format for the 'id' field (e.g., 'test.c:10'), not just numbers.\n"
        prompt += "Be decisive! With full function context, you should be able to classify most cases as YES or NO.\n"
        prompt += "Only use ABSTAIN for genuinely ambiguous cases where the context doesn't clarify the usage."
        
        return prompt
    
    def _get_pass2_examples(self) -> List[Dict[str, Any]]:
        """Get Pass 2 specific examples with widened context."""
        return [
            {
                "context": """    45: #include <time.h>
    46: 
    47: void process_data() {
>>> 48:     time_t timestamp = time(NULL);
    49:     if (timestamp > 0) {
    50:         // Process data
    51:     }
    52: }""",
                "response": {
                    "id": "test.c:48",
                    "y2038_issue": "yes",
                    "severity": "high",
                    "confidence": 0.9,
                    "reason": "Direct time() call with 32-bit time_t in ILP32 environment",
                    "needs_more_context": False
                }
            },
            {
                "context": """    20: #define TIMEOUT_MS 5000
    21: 
    22: void delay_function() {
>>> 23:     usleep(TIMEOUT_MS * 1000);
    24:     return;
    25: }""",
                "response": {
                    "id": "test.c:55",
                    "y2038_issue": "no",
                    "severity": None,
                    "confidence": 0.95,
                    "reason": "usleep() uses microseconds, not time_t, no Y2038 risk",
                    "needs_more_context": False
                }
            },
            {
                "context": """    15: #include <sys/time.h>
    16: 
    17: void get_current_time() {
>>> 18:     struct timeval tv;
    19:     gettimeofday(&tv, NULL);
    20:     return tv.tv_sec;
    21: }""",
                "response": {
                    "id": "test.c:62",
                    "y2038_issue": "yes",
                    "severity": "high",
                    "confidence": 0.85,
                    "reason": "timeval.tv_sec is 32-bit signed, wraps in 2038",
                    "needs_more_context": False
                }
            }
        ]
    
    def _fallback_responses_pass2(self, context_candidates: List[tuple], reason: str) -> List[LLMResponse]:
        """Create fallback responses for Pass 2 when LLM fails."""
        # Truncate reason to 200 characters (schema limit)
        full_reason = f"Pass 2 failed: {reason}"
        truncated_reason = full_reason[:197] + "..." if len(full_reason) > 200 else full_reason
        responses = []
        for response, candidate, context in context_candidates:
            fallback_response = LLMResponse(
                id=response.id,
                y2038_issue=Y2038Issue.ABSTAIN,
                severity=None,
                confidence=0.0,
                reason=truncated_reason,
                needs_more_context=True,
                line=candidate.line if candidate else 0,
                col_start=candidate.col_start if candidate else 0,
                col_end=candidate.col_end if candidate else 0
            )
            responses.append(fallback_response)
        return responses
    
    def _build_prompt(self, candidates: List[Candidate], io_metadata_map: Optional[Dict[str, Dict[str, Any]]] = None) -> str:
        """Build the prompt for LLM classification."""
        # Build environment context
        env_context = self._build_environment_context()
        
        # Add time_t aliases information
        aliases_context = ""
        if self.time_t_aliases:
            aliases_list = list(self.time_t_aliases.keys())
            if aliases_list:
                aliases_context = f"\n\nKnown time_t aliases (these are equivalent to time_t):\n"
                # Show first 20 aliases to avoid making prompt too long
                for alias in aliases_list[:20]:
                    aliases_context += f"- {alias}\n"
                if len(aliases_list) > 20:
                    aliases_context += f"... and {len(aliases_list) - 20} more aliases\n"
                aliases_context += "\nWhen analyzing code, treat these aliases the same as time_t.\n"
        
        system_prompt = (
            f"You are a C/C++ Y2038 auditor. Use the environment context and the provided code inputs "
            f"to decide if there is a Y2038 risk. Be decisive - only answer abstain if the code is "
            f"genuinely ambiguous. Most code should be classified as either yes (Y2038 risk) or no (safe).\n\n"
            f"Environment Context:\n{env_context}{aliases_context}\n\n"
            f"CRITICAL FOR ILP32 WITH 64-BIT TIME_T:\n"
            f"Even if time_t is 64-bit, narrowing patterns ARE Y2038/Y2106 risks:\n"
            f"- Explicit casts: (int32_t)time_value, (int)time(NULL) → classify as 'yes'\n"
            f"- Implicit narrowing: int32_t x = time_value; → classify as 'yes'\n"
            f"- Casts to 32-bit types in ILP32 (where long/int are 32-bit) → classify as 'yes'\n"
        )
        
        # Add scenario-specific examples
        examples = self._get_scenario_examples()
        
        # Build candidate list
        candidate_text = ""
        for i, candidate in enumerate(candidates):
            candidate_text += f"{i+1}. {candidate.file}:{candidate.line} - {candidate.symbol}\n"
            candidate_text += f"   {candidate.one_line_snippet}\n"
            if candidate.symbol_role:
                candidate_text += f"   Role: {candidate.symbol_role}\n"
            candidate_text += "\n"
        
        prompt = f"{system_prompt}\n\nExamples:\n"
        for example in examples:
            prompt += f"Code: {example['code']}\n"
            prompt += f"Response: {json.dumps(example['response'])}\n\n"
        
        prompt += f"Candidates to classify:\n{candidate_text}\n"
        
        # Add I/O-boundary context if any candidates have I/O metadata
        metadata_map = io_metadata_map if io_metadata_map is not None else self.io_metadata_map
        io_candidates = []
        for candidate in candidates:
            candidate_id = f"{candidate.file}:{candidate.line}"
            if candidate_id in metadata_map:
                io_candidates.append((candidate, metadata_map[candidate_id]))
        
        if io_candidates:
            prompt += "\n\nI/O BOUNDARY ANALYSIS CONTEXT:\n"
            prompt += "Some candidates originate from I/O-boundary analysis.\n"
            prompt += "For these candidates, pay special attention to:\n"
            prompt += "- Width/sign assumptions in format specifiers\n"
            prompt += "- Serialization boundaries (file, network, device)\n"
            prompt += "- ABI compatibility (32-bit vs 64-bit time_t)\n"
            prompt += "- Persistence compatibility (file formats, protocols)\n"
            prompt += "- External interface compatibility (devices, firmware, APIs)\n"
            prompt += "\n"
            
            for candidate, metadata in io_candidates[:5]:  # Limit to first 5 to save tokens
                prompt += f"Candidate {candidate.file}:{candidate.line}:\n"
                prompt += f"  I/O Category: {metadata.get('io_category', 'unknown')}\n"
                prompt += f"  I/O Function: {metadata.get('io_function', 'unknown')}\n"
                prompt += f"  Confidence: {metadata.get('io_confidence', 'unknown')}\n"
                # Summarize reasoning (don't include full text to save tokens)
                reasoning = metadata.get('reasoning', '')
                reasoning_summary = reasoning[:100] + "..." if len(reasoning) > 100 else reasoning
                prompt += f"  Reasoning: {reasoning_summary}\n"
                # Only include key ABI assumptions
                abi_assumptions = metadata.get('abi_assumptions', {})
                abi_summary = {
                    'hardware_model': abi_assumptions.get('hardware_model'),
                    'time_t_size_bits': abi_assumptions.get('time_t_size_bits')
                }
                prompt += f"  ABI: {json.dumps(abi_summary)}\n"
                prompt += "\n"
            
            if len(io_candidates) > 5:
                prompt += f"... and {len(io_candidates) - 5} more I/O-boundary candidates\n\n"
        
        # Add migration context if available (before classification guidelines)
        migration_context = self._build_migration_context()
        if migration_context:
            prompt += f"\n{migration_context}\n"
        
        prompt += "Respond with a JSON array of classification objects matching the schema.\n"
        prompt += "IMPORTANT: Use the exact 'file:line' format for the 'id' field (e.g., 'test.c:10'), not just numbers.\n"
        prompt += """Classification guidelines - BE CONSERVATIVE:
- 'yes': ONLY for CLEAR Y2038 risks (32-bit SIGNED time_t that overflows before 2038) - requires VERY HIGH confidence (>=0.85)
- 'no': Safe code (64-bit time_t, Y2106 patterns when Y2106 detection is off, clearly not Y2038, unsigned time_t when unsigned)
- 'abstain': USE THIS for uncertain, ambiguous, or medium confidence cases - PREFERRED over 'yes' when unsure

CRITICAL RULES:
1. If you're not 100% certain it's a Y2038 risk (32-bit signed time_t), use 'abstain'
2. If confidence is below 0.85, use 'abstain' (not 'yes')
3. When distinguishing signed vs unsigned patterns is unclear, use 'abstain'
4. When you can't determine if time_t is signed or unsigned from the line alone, use 'abstain'
5. False positives (incorrect 'yes') are WORSE than false negatives (missed 'yes') - be conservative
6. For UNSIGNED time_t environments: patterns checking for negative values (t < 0) should be 'no', not 'yes'
7. For UNSIGNED time_t environments: arithmetic operations are Y2106 risks, not Y2038 - classify as 'no' unless Y2106 detection is on

Only classify as 'yes' when ALL of these are true:
- time_t is clearly 32-bit SIGNED (not unsigned) - verify from environment context
- The pattern could overflow before 2038 (not 2106)
- You have VERY HIGH confidence (>=0.85)
- The context clearly shows it's a Y2038 risk, not Y2106
- The code pattern is genuinely risky (not a safe operation like small constant addition)"""
        
        return prompt
    
    def _build_environment_context(self) -> str:
        """Build environment context string for LLM prompts."""
        if not self.environment_config:
            return """No environment configuration provided. 

IMPORTANT: Without specific environment details, you must be conservative in your analysis:
- If time_t usage could be problematic on ANY common platform (32-bit signed, 32-bit unsigned, or 64-bit), classify as 'yes'
- Only classify as 'no' if the usage is clearly safe across all platforms
- When in doubt about platform assumptions, err on the side of caution and classify as 'yes'

Common platform assumptions to consider:
- 32-bit signed time_t: Y2038 issue (wraps in 2038)
- 32-bit unsigned time_t: Y2106 issue (wraps in 2106) - still a time overflow issue
- 64-bit time_t: No Y2038/Y2106 issues

Be decisive but conservative in your analysis."""
        
        config = self.environment_config
        
        # Basic environment info
        hardware_model = config.get('hardware_model', 'unknown')
        time_t_size = config.get('time_t_size_bits', 0)
        time_t_signed = config.get('time_t_signed', 'unknown')
        time64_available = config.get('time64_functions_available', False)
        d_time_bits_supported = config.get('d_time_bits_supported', False)
        d_time_bits_setting = config.get('d_time_bits_setting', 'unknown')
        c_library = config.get('c_library', 'unknown')
        scenario_hint = config.get('scenario_hint', 'unknown')
        
        # Get config_id if available
        config_id = config.get('config_id')
        config_id_str = f" ({config_id})" if config_id else ""
        
        context = f"""Target Environment{config_id_str}:
- Architecture: {hardware_model}
- time_t: {time_t_size}-bit {time_t_signed}
- time64 functions: {'available' if time64_available else 'not available'}
- _TIME_BITS: {'supported' if d_time_bits_supported else 'not supported'} ({d_time_bits_setting})
- C library: {c_library}
- Scenario: {scenario_hint}

CRITICAL: time_t signedness determines Y2038 vs Y2106 issues:
- 32-bit SIGNED time_t: Y2038 issue (wraps in 2038) → classify as 'yes' for Y2038 risks
- 32-bit UNSIGNED time_t: Y2106 issue (wraps in 2106) - NOT a Y2038 issue → classify as 'no' (unless Y2106 detection is enabled)
- 64-bit time_t: No Y2038/Y2106 overflow issues, BUT narrowing patterns are still Y2038/Y2106 risks → see below

CRITICAL FOR LP64 WITH 64-BIT TIME_T:
- Arithmetic operations on 64-bit time_t are SAFE (no overflow before 2038 or 2106)
- The ONLY Y2038/Y2106 risks are NARROWING PATTERNS (see below)
- Do NOT flag arithmetic operations as Y2038 risks in LP64 configurations
- Example: `time_t t = time(NULL); t = t + 2147483648;` → SAFE, classify as 'no'

CRITICAL FOR ILP32 WITH 64-BIT TIME_T:
Even though time_t is 64-bit (no overflow risk), narrowing patterns that reduce 64-bit time_t to 32-bit types ARE Y2038/Y2106 issues:
1. **Explicit narrowing casts**: `(int32_t)time_value`, `(int)time(NULL)`, `(long)timestamp` (if long is 32-bit in ILP32)
   → These lose precision and can cause Y2038/Y2106 issues if the narrowed value is used
   → Classify as 'yes' for Y2038/Y2106 risk
2. **Implicit narrowing assignments**: `int32_t x = time_value;`, `int y = time(NULL);`
   → These implicitly cast 64-bit time_t to 32-bit, losing precision
   → Classify as 'yes' for Y2038/Y2106 risk
3. **Casts from 32-bit integers to time_t**: `time_t t = (time_t)int32_value;`
   → While not directly narrowing, this can lose precision if the 32-bit value is large
   → Evaluate based on context - if the 32-bit value could represent a time beyond 2038/2106, classify as 'yes'

CRITICAL CLASSIFICATION RULES:
1. Only classify as 'yes' if ANY of these are true:
   a) Standard overflow risk (32-bit time_t):
      - time_t is 32-bit SIGNED (not unsigned) - verify this from environment context
      - The pattern could overflow BEFORE 2038 (not 2106)
      - You have VERY HIGH confidence (>=0.85)
      - The code clearly shows signed time_t behavior (e.g., negative values, signed comparisons)
      - **ARITHMETIC RISK**: For arithmetic operations, evaluate if the addition could cause overflow:
        * Adding any positive constant N to signed 32-bit time_t could overflow if current_time + N > 2,147,483,647
        * The risk depends on the constant size AND when the operation happens
        * Large constants (>= 2^30) are high risk
        * Small constants can still overflow if used near the overflow date (2038 for signed, 2106 for unsigned)
        * Analyze context: if the code could run near 2038, even small additions can overflow
   b) Narrowing pattern risk (ILP32 with 64-bit time_t):
      - Architecture is ILP32 AND time_t is 64-bit
      - Code contains explicit narrowing casts: `(int32_t)time_value`, `(int)time(NULL)`, `(long)timestamp` (if long is 32-bit)
      - Code contains implicit narrowing: `int32_t x = time_value;`, `int y = time(NULL);`
      - These patterns lose precision and can cause Y2038/Y2106 issues when the narrowed value is used
      - Classify as 'yes' for Y2038/Y2106 risk

2. Classify as 'no' if:
   - time_t is 64-bit AND architecture is LP64 (64-bit long/pointer) AND no narrowing patterns exist
   - time_t is 32-bit UNSIGNED (Y2106, not Y2038) - when Y2106 detection is off
   - **ARITHMETIC SAFETY**: For 32-bit time_t, evaluate arithmetic operations carefully:
     * Adding any positive constant N to time_t could overflow if the result exceeds the max value
     * For signed 32-bit time_t: Max is 2,147,483,647 (INT32_MAX). Adding N seconds could overflow if current_time + N > INT32_MAX
     * For unsigned 32-bit time_t: Max is 4,294,967,295 (UINT32_MAX). Adding N seconds could overflow if current_time + N > UINT32_MAX
     * The risk depends on WHEN the addition happens - if close to the overflow date, even small additions can overflow
     * Analyze each case: if the constant is large (>= 2^30 for signed, >= 2^31 for unsigned) OR if the operation could happen near the overflow date, it's risky
     * Small constants (like +60, +3600) are generally safer but still need context - if used near overflow date, they can still overflow
   - In unsigned time_t environments: patterns checking for negative values (t < 0) are meaningless and should be 'no'
   - In unsigned time_t environments: arithmetic operations are Y2106 risks, not Y2038
   - For ILP32 with 64-bit time_t: Only if NO narrowing patterns exist (64-bit time_t used safely without narrowing)

3. Classify as 'abstain' if:
   - You cannot determine if time_t is signed or unsigned
   - Confidence is below 0.85
   - The pattern is ambiguous
   - You're uncertain about Y2038 vs Y2106
   - The line lacks sufficient context
   - The operation involves variables or complex expressions (not simple constants)

REMEMBER: 'abstain' is PREFERRED over 'yes' when uncertain. False positives are worse than false negatives.
SPECIAL NOTE: In unsigned time_t environments, negative value checks (t < 0) are always false and should be 'no', not 'yes'.

All time-related types (time_t, timeval.tv_sec, timespec.tv_sec) use the same time_t type.
"""
        
        return context
    
    def _build_migration_context(self) -> str:
        """Build migration context string for prompts."""
        if not self.migration_mode or not self.migration_from_config or not self.migration_to_config:
            return ""
        
        try:
            from tacs.core.config_validator import ConfigValidator
            from_id = ConfigValidator.get_config_id(self.migration_from_config)
            to_id = ConfigValidator.get_config_id(self.migration_to_config)
        except Exception:
            from_id = "unknown"
            to_id = "unknown"
        
        migration_context = f"""
MIGRATION ANALYSIS MODE:
You are analyzing code for migration from:
  Source: {from_id} ({self.migration_from_config.get('hardware_model')} {self.migration_from_config.get('time_t_size_bits')}bit {self.migration_from_config.get('time_t_signed')})
  Target: {to_id} ({self.migration_to_config.get('hardware_model')} {self.migration_to_config.get('time_t_size_bits')}bit {self.migration_to_config.get('time_t_signed')})

Focus on patterns that would:
1. BREAK during migration (blockers):
   - Casts assuming old width/sign: (int32_t)time_value when migrating 32→64
   - I/O format specifiers assuming old width: %d when migrating 32→64
   - Raw I/O assuming old size: read(fd, &t, 4) when migrating 32→64
   - Sign checks: if (t < 0) when migrating signed→unsigned
   - Negative constants: time_t t = -1; when migrating signed→unsigned

2. CAUSE ISSUES during migration (risks):
   - Implicit assumptions about width/sign
   - API boundaries with fixed assumptions
   - External interfaces with fixed formats

3. BE SAFE during migration:
   - Code that doesn't assume specific width/sign
   - Code that uses portable patterns
   - Code that already handles both configs

Classification in migration mode:
- 'yes': Migration blocker or high-risk pattern (would break or cause issues)
- 'no': Safe for migration (no assumptions about old config)
- 'abstain': Uncertain migration impact

"""
        return migration_context
    
    def _get_scenario_examples(self) -> List[Dict[str, Any]]:
        """Get scenario-specific examples based on environment configuration."""
        if not self.environment_config:
            return self._get_generic_examples()
        
        scenario_hint = self.environment_config.get('scenario_hint', '')
        
        if 'LP64-64bit' in scenario_hint:
            return self._get_lp64_examples()
        elif 'ILP32-32bit-signed-time64_no' in scenario_hint:
            return self._get_ilp32_risky_examples()
        elif 'ILP32-32bit-unsigned' in scenario_hint:
            return self._get_ilp32_unsigned_examples()
        else:
            return self._get_generic_examples()
    
    def _get_generic_examples(self) -> List[Dict[str, Any]]:
        """Generic examples that work across all codebases."""
        return [
            {
                "code": "time_t current_time = time(NULL);",
                "response": {
                    "id": "generic.c:10",
                    "y2038_issue": "yes",
                    "severity": "high",
                    "confidence": 0.9,
                    "reason": "Direct time() call with 32-bit time_t",
                    "needs_more_context": False
                }
            },
            {
                "code": "int counter = 0;",
                "response": {
                    "id": "generic.c:15",
                    "y2038_issue": "no",
                    "severity": None,
                    "confidence": 0.95,
                    "reason": "Not time-related",
                    "needs_more_context": False
                }
            },
            {
                "code": "struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);",
                "response": {
                    "id": "generic.c:20",
                    "y2038_issue": "yes",
                    "severity": "high",
                    "confidence": 0.9,
                    "reason": "timespec.tv_sec is 32-bit signed",
                    "needs_more_context": False
                }
            },
            {
                "code": "usleep(1000);",
                "response": {
                    "id": "generic.c:25",
                    "y2038_issue": "no",
                    "severity": None,
                    "confidence": 0.95,
                    "reason": "usleep uses microseconds, not time_t",
                    "needs_more_context": False
                }
            },
            {
                "code": "TIMEOUT_VALUE = get_config();",
                "response": {
                    "id": "generic.c:30",
                    "y2038_issue": "abstain",
                    "severity": None,
                    "confidence": 0.0,
                    "reason": "Function call indirection unclear",
                    "needs_more_context": True
                }
            }
        ]
    
    def _get_lp64_examples(self) -> List[Dict[str, Any]]:
        """Examples for LP64 environments (64-bit time_t)."""
        return [
            {
                "code": "time_t t = time(NULL);",
                "response": {
                    "id": "lp64.c:10",
                    "y2038_issue": "no",
                    "severity": None,
                    "confidence": 0.95,
                    "reason": "LP64 has 64-bit time_t, Y2038-safe",
                    "needs_more_context": False
                }
            },
            {
                "code": "long timestamp = (long)time(NULL);",
                "response": {
                    "id": "lp64.c:15",
                    "y2038_issue": "abstain",
                    "severity": None,
                    "confidence": 0.3,
                    "reason": "Cast to long may truncate in LP64",
                    "needs_more_context": True
                }
            }
        ]
    
    def _get_ilp32_risky_examples(self) -> List[Dict[str, Any]]:
        """Examples for risky ILP32 environments (32-bit signed time_t, no time64)."""
        return [
            {
                "code": "time_t t = time(NULL);",
                "response": {
                    "id": "ilp32_risky.c:10",
                    "y2038_issue": "abstain",
                    "severity": None,
                    "confidence": 0.6,
                    "reason": "Cannot determine if time_t is signed or unsigned from single line - use abstain",
                    "needs_more_context": True
                }
            },
            {
                "code": "time_t t = -1; t = t + 2147483648;",
                "response": {
                    "id": "ilp32_risky.c:12",
                    "y2038_issue": "yes",
                    "severity": "high",
                    "confidence": 0.9,
                    "reason": "32-bit signed time_t with negative value and large addition - clear Y2038 risk",
                    "needs_more_context": False
                }
            },
            {
                "code": "time_t t = time(NULL); t = t + 86400;",
                "response": {
                    "id": "ilp32_risky.c:15",
                    "y2038_issue": "abstain",
                    "severity": None,
                    "confidence": 0.5,
                    "reason": "Cannot determine if time_t is signed or unsigned - could be Y2106 (unsigned) not Y2038",
                    "needs_more_context": True
                }
            },
            {
                "code": "if (time(NULL) < 0) { /* handle negative */ }",
                "response": {
                    "id": "ilp32_risky.c:18",
                    "y2038_issue": "yes",
                    "severity": "high",
                    "confidence": 0.85,
                    "reason": "Comparison with 0 indicates signed time_t - Y2038 risk",
                    "needs_more_context": False
                }
            },
            {
                "code": "struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);",
                "response": {
                    "id": "ilp32_risky.c:20",
                    "y2038_issue": "abstain",
                    "severity": None,
                    "confidence": 0.6,
                    "reason": "Cannot determine if timespec.tv_sec is signed or unsigned from single line",
                    "needs_more_context": True
                }
            },
            {
                "code": "if (time(NULL) < 0) { /* handle negative */ }",
                "response": {
                    "id": "ilp32_risky.c:25",
                    "y2038_issue": "yes",
                    "severity": "high",
                    "confidence": 0.85,
                    "reason": "Comparison with 0 indicates signed time_t - Y2038 risk",
                    "needs_more_context": False
                }
            }
        ]
    
    def _get_ilp32_unsigned_examples(self) -> List[Dict[str, Any]]:
        """Examples for ILP32 with unsigned time_t (extends range to 2106)."""
        return [
            {
                "code": "time_t t = time(NULL);",
                "response": {
                    "id": "ilp32_unsigned.c:10",
                    "y2038_issue": "no",
                    "severity": None,
                    "confidence": 0.7,
                    "reason": "32-bit unsigned time_t wraps in 2106, not 2038 - NOT a Y2038 issue",
                    "needs_more_context": False
                }
            },
            {
                "code": "if (time(NULL) > 2147483647) { /* handle overflow */ }",
                "response": {
                    "id": "ilp32_unsigned.c:15",
                    "y2038_issue": "abstain",
                    "severity": None,
                    "confidence": 0.5,
                    "reason": "Unsigned time_t check may be incorrect",
                    "needs_more_context": True
                }
            },
            {
                "code": "struct timeval tv; gettimeofday(&tv, NULL);",
                "response": {
                    "id": "ilp32_unsigned.c:20",
                    "y2038_issue": "no",
                    "severity": None,
                    "confidence": 0.95,
                    "reason": "timeval.tv_sec uses unsigned time_t - Y2106 issue, not Y2038",
                    "needs_more_context": False
                }
            }
        ]
    
    def _make_api_request(self, prompt: str) -> Dict[str, Any]:
        """Make API request to the selected provider."""
        if self.llm_type == "ollama":
            return self._make_local_request(prompt)
        if self.llm_type == "openai":
            return self._make_openai_request(prompt)
        if self.llm_type == "anthropic":
            return self._make_anthropic_request(prompt)
        if self.llm_type == "gemini":
            return self._make_gemini_request(prompt)
        raise RuntimeError(f"Unsupported LLM type for API requests: {self.llm_type}")
    
    @staticmethod
    def _is_ollama_cloud_model(model: str) -> bool:
        return looks_like_cloud_model(model)

    def _ollama_request_target(self) -> tuple[str, dict[str, str] | None, str]:
        """
        Resolve Ollama base URL, optional auth headers, and model id.

        ``OLLAMA_HOST`` unset → Ollama Cloud (``https://ollama.com``) with API key.
        Local daemon: set ``OLLAMA_HOST=http://127.0.0.1:11434``.
        """
        url, headers, api_model, _is_cloud = resolve_ollama_request_target(self.model)
        return url, headers, api_model

    def _make_local_request(self, prompt: str) -> Dict[str, Any]:
        """Make request to local Ollama or Ollama Cloud (direct)."""
        import requests

        url, headers, model = self._ollama_request_target()
        using_cloud_api = "ollama.com" in url

        data = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 8000,  # Increased from 2000 to handle larger JSON responses
            },
        }

        try:
            # Cloud / remote hops need more headroom than a local daemon.
            timeout = self.timeout_sec * 2 if using_cloud_api or self._is_ollama_cloud_model(self.model) else self.timeout_sec

            response = requests.post(
                url,
                json=data,
                headers=headers,
                timeout=timeout,
            )

            if response.status_code != 200:
                error_text = response.text
                if response.status_code in {401, 403}:
                    raise LLMNonRetryableError(
                        "Ollama Cloud unauthorized. Set OLLAMA_API_KEY "
                        "(legacy alias: OLLAMA_CLOUD_TOKEN) — create a key at "
                        "https://ollama.com/settings/keys. "
                        f"Detail: {error_text[:150]}"
                    )
                if "ollama.com" in error_text or "TLS handshake" in error_text or "cloud" in error_text.lower():
                    raise RuntimeError(
                        f"Cloud model connection failed (status {response.status_code}): "
                        f"TLS handshake timeout. This may be a temporary network issue. "
                        f"Error: {error_text[:100]}"
                    )
                where = "Ollama Cloud" if using_cloud_api else "Local Ollama"
                raise RuntimeError(f"{where} request failed: {response.status_code} - {error_text[:150]}")


            result = response.json()

            # Convert Ollama generate format to expected chat-completions-like shape
            if "response" in result:
                prompt_tokens = result.get("prompt_eval_count", 0)
                completion_tokens = result.get("eval_count", 0)

                return {
                    "choices": [{
                        "message": {
                            "content": result["response"]
                        }
                    }],
                    "usage": {
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "total_tokens": prompt_tokens + completion_tokens
                    }
                }
            raise RuntimeError("Unexpected response format from Ollama")

        except LLMNonRetryableError:
            raise
        except requests.exceptions.ConnectionError:
            if using_cloud_api:
                raise RuntimeError("Cannot connect to Ollama Cloud (https://ollama.com). Check network/DNS.")
            raise RuntimeError("Cannot connect to local Ollama server. Is Ollama running on localhost:11434?")
        except requests.exceptions.Timeout:
            raise RuntimeError(f"Request timeout after {self.timeout_sec} seconds")
        except Exception as e:
            where = "Ollama Cloud" if using_cloud_api else "Local Ollama"
            raise RuntimeError(f"{where} request failed: {e}")
    
    def _make_openai_request(self, prompt: str) -> Dict[str, Any]:
        """Make request to OpenAI-compatible chat completions API."""
        import requests

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not set")
        base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        url = f"{base_url}/chat/completions"
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        return self._post_and_normalize(url, data, headers=headers, provider_name="OpenAI")

    def _make_anthropic_request(self, prompt: str) -> Dict[str, Any]:
        """Make request to Anthropic Messages API."""
        import requests

        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1").rstrip("/")
        url = f"{base_url}/messages"
        data = {
            "model": self.model,
            "max_tokens": 8000,
            "temperature": 0.1,
            "messages": [{"role": "user", "content": prompt}],
        }
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        raw = self._post_json(url, data, headers=headers, provider_name="Anthropic")
        text_parts = []
        for item in raw.get("content", []):
            if isinstance(item, dict) and item.get("type") == "text":
                text_parts.append(str(item.get("text", "")))
        content = "\n".join([p for p in text_parts if p]).strip()
        usage = raw.get("usage", {})
        prompt_tokens = int(usage.get("input_tokens", 0) or 0)
        completion_tokens = int(usage.get("output_tokens", 0) or 0)
        return {
            "choices": [{"message": {"content": content}}],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        }

    def _make_gemini_request(self, prompt: str) -> Dict[str, Any]:
        """Make request to Gemini generateContent API."""
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY (or GOOGLE_API_KEY) is not set")
        base_url = os.getenv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta").rstrip("/")
        # Prefer header auth (Google's documented pattern); avoids long hangs some proxies show with ?key= URLs.
        url = f"{base_url}/models/{self.model}:generateContent"
        headers = {
            "x-goog-api-key": api_key,
            "Content-Type": "application/json",
        }
        data = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                # Cap completion length for faster responses on JSON batches (raise if responses truncate).
                # Large function batches need a high ceiling or JSON is cut mid-array (default was too low for 15–20 functions).
                "maxOutputTokens": int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "32768")),
            },
        }
        # generateContent can be slow on large function-first prompts; use a longer default
        # than line-level passes unless GEMINI_TIMEOUT_SEC is set.
        gem_env = os.getenv("GEMINI_TIMEOUT_SEC")
        if gem_env is not None:
            gem_timeout = max(1, int(gem_env))
        else:
            gem_timeout = max(self.timeout_sec * 2, 600)
        # Gemini often needs a higher connect budget on WSL/slow DNS paths than other providers.
        gem_connect = float(os.getenv("GEMINI_CONNECT_TIMEOUT_SEC", "120"))
        raw = self._post_json(
            url,
            data,
            headers=headers,
            provider_name="Gemini",
            timeout_sec=gem_timeout,
            connect_timeout_sec=gem_connect,
        )
        candidates = raw.get("candidates", [])
        parts = []
        if candidates and isinstance(candidates[0], dict):
            content = candidates[0].get("content", {})
            for part in content.get("parts", []):
                if isinstance(part, dict) and "text" in part:
                    parts.append(str(part["text"]))
        usage_meta = raw.get("usageMetadata", {})
        prompt_tokens = int(usage_meta.get("promptTokenCount", 0) or 0)
        completion_tokens = int(usage_meta.get("candidatesTokenCount", 0) or 0)
        return {
            "choices": [{"message": {"content": "\n".join(parts).strip()}}],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": int(usage_meta.get("totalTokenCount", prompt_tokens + completion_tokens) or 0),
            },
        }

    def _post_and_normalize(
        self,
        url: str,
        data: Dict[str, Any],
        *,
        headers: Optional[Dict[str, str]] = None,
        provider_name: str,
    ) -> Dict[str, Any]:
        """POST JSON and return OpenAI-like response shape."""
        raw = self._post_json(url, data, headers=headers, provider_name=provider_name)
        if "choices" in raw:
            return raw
        if "response" in raw:
            prompt_tokens = int(raw.get("prompt_eval_count", 0) or 0)
            completion_tokens = int(raw.get("eval_count", 0) or 0)
            return {
                "choices": [{"message": {"content": raw.get("response", "")}}],
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens,
                },
            }
        raise RuntimeError(f"{provider_name} returned unexpected response format")

    def _requests_timeout(
        self, read_seconds: int, *, connect_seconds: Optional[float] = None
    ) -> Tuple[float, float]:
        """Connect vs read timeouts so a dead route fails fast instead of burning the full read budget."""
        if connect_seconds is not None:
            connect = float(connect_seconds)
        else:
            connect = float(os.getenv("LLM_CONNECT_TIMEOUT_SEC", "30"))
        return (connect, float(read_seconds))

    def _post_json(
        self,
        url: str,
        data: Dict[str, Any],
        *,
        headers: Optional[Dict[str, str]] = None,
        provider_name: str,
        timeout_sec: Optional[int] = None,
        connect_timeout_sec: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Make a JSON POST request and decode response."""
        import requests

        effective_timeout = self.timeout_sec if timeout_sec is None else timeout_sec
        timeouts = self._requests_timeout(int(effective_timeout), connect_seconds=connect_timeout_sec)
        try:
            response = requests.post(url, json=data, headers=headers, timeout=timeouts)
            if response.status_code != 200:
                text = response.text[:300]
                # Do not retry permanent client failures (unknown model, bad key scope, etc.).
                if response.status_code in (400, 401, 403, 404, 405, 413):
                    raise LLMNonRetryableError(
                        f"{provider_name} request failed: {response.status_code} - {text}"
                    )
                # OpenAI returns 429 for rate limits AND for exhausted billing (insufficient_quota).
                if response.status_code == 429 and provider_name == "OpenAI":
                    try:
                        payload = response.json()
                        etype = (payload.get("error") or {}).get("type")
                        if etype == "insufficient_quota":
                            raise LLMNonRetryableError(
                                f"{provider_name} 429 insufficient_quota: add billing/credits or fix plan "
                                f"(https://platform.openai.com/account/billing). {text}"
                            )
                    except LLMNonRetryableError:
                        raise
                    except Exception:
                        pass
                raise RuntimeError(f"{provider_name} request failed: {response.status_code} - {text}")
            return response.json()
        except requests.exceptions.ConnectionError:
            raise RuntimeError(f"Cannot connect to {provider_name} endpoint")
        except requests.exceptions.ConnectTimeout:
            raise RuntimeError(
                f"{provider_name} connect timeout after {timeouts[0]}s "
                f"(TCP/TLS to the API host did not finish; check WSL/VPN/firewall/DNS, "
                f"or raise LLM_CONNECT_TIMEOUT_SEC / GEMINI_CONNECT_TIMEOUT_SEC)"
            )
        except requests.exceptions.ReadTimeout:
            raise RuntimeError(
                f"{provider_name} read timeout after {timeouts[1]}s "
                f"(no response body in time; large prompts need a higher read budget or a faster model)"
            )
        except requests.exceptions.Timeout:
            raise RuntimeError(
                f"{provider_name} request timeout (connect={timeouts[0]}s, read={timeouts[1]}s)"
            )
        except ValueError as e:
            raise RuntimeError(f"{provider_name} returned invalid JSON: {e}")
        except Exception as e:
            raise RuntimeError(f"{provider_name} request failed: {e}")

    def _validate_provider_allowed(self) -> None:
        """Validate selected provider against env allowlist."""
        if self.llm_type == "none":
            return
        # OSS default: all built-in providers. Deployments (e.g. webapp) may tighten via env.
        allowed_raw = os.getenv(
            "ALLOWED_LLM_PROVIDERS", "ollama,openai,anthropic,gemini"
        )
        allowed = {item.strip().lower() for item in allowed_raw.split(",") if item.strip()}
        if self.llm_type.lower() not in allowed:
            raise RuntimeError(
                f"LLM provider '{self.llm_type}' is not allowed by ALLOWED_LLM_PROVIDERS={allowed_raw}"
            )
    
    def _parse_response(self, response_data: Dict[str, Any], candidates: List[Candidate]) -> List[LLMResponse]:
        """Parse LLM response into LLMResponse objects."""
        try:
            # Extract the response text
            content = self._extract_content(response_data)
            if not content:
                return self._fallback_responses(candidates, "Empty response from LLM")
            
            # Try to parse as JSON array
            try:
                parsed = json.loads(content)
                if not isinstance(parsed, list):
                    return self._fallback_responses(candidates, "LLM response is not a JSON array")
                
                # Validate and convert responses
                responses = []
                for i, item in enumerate(parsed):
                    try:
                        response = self._parse_single_response(item, candidates, i)
                        responses.append(response)
                    except Exception as e:
                        # If individual response fails, create fallback for that candidate
                        if i < len(candidates):
                            fallback = self._create_fallback_response(candidates[i], f"Failed to parse response {i}: {e}")
                            responses.append(fallback)
                
                # Ensure we have responses for all candidates
                while len(responses) < len(candidates):
                    fallback = self._create_fallback_response(candidates[len(responses)], "Missing response from LLM")
                    responses.append(fallback)
                
                return responses[:len(candidates)]  # Truncate if we got too many
                
            except json.JSONDecodeError as e:
                return self._fallback_responses(candidates, f"Invalid JSON response: {e}")
            
        except Exception as e:
            return self._fallback_responses(candidates, f"Response parsing error: {e}")
    
    def _extract_content(self, response_data: Dict[str, Any]) -> str:
        """Extract content from API response."""
        try:
            # Try OpenAI-style format first
            if "choices" in response_data and len(response_data["choices"]) > 0:
                choice = response_data["choices"][0]
                if "message" in choice and "content" in choice["message"]:
                    return choice["message"]["content"]
            
            # Try direct response format
            if "response" in response_data:
                return response_data["response"]
            
            # Try content field
            if "content" in response_data:
                return response_data["content"]
            
            return ""
            
        except Exception:
            return ""
    
    def _parse_single_response(self, item: Dict[str, Any], candidates: List[Candidate], index: int) -> LLMResponse:
        """Parse a single response item."""
        # Validate required fields
        required_fields = ["id", "y2038_issue", "confidence", "reason"]
        for field in required_fields:
            if field not in item:
                raise ValueError(f"Missing required field: {field}")
        
        # Validate y2038_issue
        y2038_issue_str = item["y2038_issue"]
        if y2038_issue_str not in ["yes", "no", "abstain"]:
            raise ValueError(f"Invalid y2038_issue: {y2038_issue_str}")
        
        # Validate confidence
        confidence = float(item["confidence"])
        if not 0.0 <= confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got: {confidence}")
        
        # Apply confidence threshold: if confidence < 0.85 and classified as YES, change to ABSTAIN
        # This helps avoid false positives - raised threshold from 0.8 to 0.85
        if y2038_issue_str == "yes" and confidence < 0.85:
            y2038_issue_str = "abstain"
            if "reason" in item:
                item["reason"] = f"{item['reason']} (low confidence: {confidence:.2f}, using abstain to avoid false positive)"
        
        y2038_issue = Y2038Issue(y2038_issue_str)
        
        # Validate severity (optional)
        severity = None
        if "severity" in item and item["severity"] is not None:
            severity_str = item["severity"]
            if severity_str not in ["low", "medium", "high"]:
                raise ValueError(f"Invalid severity: {severity_str}")
            severity = SeverityLevel(severity_str)
        
        # Validate needs_more_context (optional)
        needs_more_context = item.get("needs_more_context", False)
        if not isinstance(needs_more_context, bool):
            needs_more_context = False
        
        # Get candidate info for line/column data
        candidate = candidates[index] if index < len(candidates) else None
        
        return LLMResponse(
            id=item["id"],
            y2038_issue=y2038_issue,
            severity=severity,
            confidence=confidence,
            reason=item["reason"],
            needs_more_context=needs_more_context,
            line=candidate.line if candidate else 0,
            col_start=candidate.col_start if candidate else 0,
            col_end=candidate.col_end if candidate else 0
        )
    
    def _create_fallback_response(self, candidate: Candidate, reason: str) -> LLMResponse:
        """Create a fallback response for a candidate."""
        # Truncate reason to 200 characters (schema limit)
        truncated_reason = reason[:197] + "..." if len(reason) > 200 else reason
        return LLMResponse(
            id=f"{candidate.file}:{candidate.line}",
            y2038_issue=Y2038Issue.ABSTAIN,
            severity=None,
            confidence=0.0,
            reason=truncated_reason,
            needs_more_context=True,
            line=candidate.line,
            col_start=candidate.col_start,
            col_end=candidate.col_end
        )
    
    def _fallback_responses(self, candidates: List[Candidate], reason: str) -> List[LLMResponse]:
        """Create fallback responses when LLM fails."""
        # Truncate reason to 200 characters (schema limit)
        truncated_reason = reason[:197] + "..." if len(reason) > 200 else reason
        responses = []
        for candidate in candidates:
            response = LLMResponse(
                id=f"{candidate.file}:{candidate.line}",
                y2038_issue=Y2038Issue.ABSTAIN,
                severity=None,
                confidence=0.0,
                reason=truncated_reason,
                needs_more_context=True,
                line=candidate.line,
                col_start=candidate.col_start,
                col_end=candidate.col_end
            )
            responses.append(response)
        return responses
    
    def _track_tokens(self, prompt_tokens: int, completion_tokens: int, stage_name: str):
        """Track token usage statistics."""
        self.token_stats["total_prompt_tokens"] += prompt_tokens
        self.token_stats["total_completion_tokens"] += completion_tokens
        self.token_stats["total_requests"] += 1
        
        if stage_name not in self.token_stats["by_stage"]:
            self.token_stats["by_stage"][stage_name] = {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "requests": 0
            }
        
        self.token_stats["by_stage"][stage_name]["prompt_tokens"] += prompt_tokens
        self.token_stats["by_stage"][stage_name]["completion_tokens"] += completion_tokens
        self.token_stats["by_stage"][stage_name]["requests"] += 1
    
    def get_token_stats(self) -> Dict[str, Any]:
        """Get token usage statistics."""
        total_tokens = self.token_stats["total_prompt_tokens"] + self.token_stats["total_completion_tokens"]
        return {
            **self.token_stats,
            "total_tokens": total_tokens
        }
    
    def reset_token_stats(self):
        """Reset token statistics."""
        self.token_stats = {
            "total_prompt_tokens": 0,
            "total_completion_tokens": 0,
            "total_requests": 0,
            "by_stage": {}
        }