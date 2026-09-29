# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Function-first LLM client for Y2038 analysis.
"""

import json
import os
import hashlib
from typing import List, Dict, Any, Optional
from tacs.core.function_schemas import (
    FunctionBody, FunctionAnalysis, FunctionBatch, FunctionCache,
    Y2038Summary, ContextNeed, FunctionFinding, IssueSpan
)
from tacs.core.llm_client import LLMNonRetryableError, _migration_endpoint_facts
from tacs.core.llm_prompt import LLMPromptParts, format_untrusted_user_payload
from tacs.core.llm_response import strip_optional_code_fence
from tacs.core.status_logger import StatusLogger


class FunctionLLMClient:
    """LLM client specialized for function-first analysis."""

    def __init__(self, llm_type: str, model: str, environment_config: Optional[Dict[str, Any]],
                 timeout_sec: int, batch_size_func: int, confidence_floor: float,
                 debug_llm_raw: bool = False, detect_y2106: bool = False):
        """
        Initialize the function-first LLM client.

        Args:
            llm_type: Type of LLM to use (ollama, etc.)
            model: Model name
            environment_config: Environment configuration
            timeout_sec: Request timeout
            batch_size_func: Batch size for function analysis
            confidence_floor: Minimum confidence threshold, quoted in the prompts
            debug_llm_raw: Enable raw LLM debugging
            detect_y2106: Enable Y2106 detection (32-bit unsigned time_t overflow in 2106)
        """
        self.llm_type = llm_type
        self.model = model
        self.environment_config = environment_config
        self.timeout_sec = timeout_sec
        self.batch_size_func = batch_size_func
        self.confidence_floor = confidence_floor
        self.debug_llm_raw = debug_llm_raw
        self.detect_y2106 = detect_y2106

        # Migration mode (set by pipeline if enabled)
        self.migration_mode = False
        self.migration_from_config = None
        self.migration_to_config = None

        # Track batch failures across the entire run
        self.total_batch_failures = 0
        self.max_total_failures = 3  # Abort after 3 total batch failures

        # Initialize base LLM client for API calls
        from tacs.core.llm_client import LLMClient
        self.base_client = LLMClient(
            llm_type=llm_type,
            model=model,
            environment_config=environment_config,
            timeout_sec=timeout_sec,
            batch_size_pass2=10,  # Not used in function-first
            batch_size_pass3=10,  # Not used in function-first
            debug_llm_raw=debug_llm_raw,
            # The base client writes the environment rules these prompts carry,
            # and it quotes the floor, so it needs the configured one.
            confidence_floor=confidence_floor,
        )

    def analyze_functions_pass_f1(self, function_batch: FunctionBatch) -> List[FunctionAnalysis]:
        """
        Analyze functions in Pass F1 (initial function analysis).

        Args:
            function_batch: Batch of functions to analyze

        Returns:
            List of function analysis results
        """
        # Check if LLM is disabled
        if self.llm_type == "none":
            return self._fallback_pass_f1_responses(function_batch.functions, "LLM disabled (--llm none)")

        StatusLogger.timestamped_print(f"Running Stage 8, Pass 2a on {len(function_batch.functions)} functions...")

        # Build Stage 8, Pass 2a prompt
        try:
            prompt = self._build_pass_f1_prompt(function_batch)
        except Exception as e:
            error_msg = f"Failed to build prompt: {e}"
            StatusLogger.timestamped_error(error_msg)
            return self._fallback_pass_f1_responses(function_batch.functions, error_msg)

        # Debug: Show prompt if requested
        if self.debug_llm_raw:
            self.base_client._debug_print_prompt_parts("PASS P1 PROMPT", prompt)

        # Retry logic: up to 3 attempts per batch
        max_retries = 3
        last_exception = None

        for attempt in range(1, max_retries + 1):
            try:
                # Make API request
                response_data = self.base_client._make_api_request(prompt)

                # Extract and track token usage from response
                prompt_tokens = 0
                completion_tokens = 0
                if "usage" in response_data:
                    prompt_tokens = response_data["usage"].get("prompt_tokens", 0)
                    completion_tokens = response_data["usage"].get("completion_tokens", 0)
                    self.base_client._track_tokens(prompt_tokens, completion_tokens, "S2_P1")

                # Debug: Show response if requested
                if self.debug_llm_raw:
                    StatusLogger.timestamped_print("=== PASS F1 RESPONSE ===")
                    StatusLogger.timestamped_print(str(response_data))
                    StatusLogger.timestamped_print("=== END PASS F1 RESPONSE ===")

                # Parse responses
                analyses = self._parse_pass_f1_response(response_data, function_batch.functions)

                # Log results
                yes_count = sum(1 for a in analyses if a.y2038_summary == Y2038Summary.YES)
                no_count = sum(1 for a in analyses if a.y2038_summary == Y2038Summary.NO)
                abstain_count = sum(1 for a in analyses if a.y2038_summary == Y2038Summary.ABSTAIN)

                StatusLogger.timestamped_print(
                    f"Stage 8, Pass 2a function classifications: "
                    f"{yes_count} yes, {no_count} no, {abstain_count} abstain"
                )
                if prompt_tokens > 0 or completion_tokens > 0:
                    StatusLogger.timestamped_print(f"Token usage: {prompt_tokens} prompt + {completion_tokens} completion = {prompt_tokens + completion_tokens} total")

                return analyses

            except LLMNonRetryableError:
                raise
            except Exception as e:
                last_exception = e
                if attempt < max_retries:
                    StatusLogger.timestamped_warning(f"Stage 8, Pass 2a LLM request failed (attempt {attempt}/{max_retries}): {e}")
                    StatusLogger.timestamped_print(f"Retrying batch...")
                    # Wait before retrying (exponential backoff)
                    import time
                    retry_delay = min(2 ** attempt, 10)  # 2s, 4s, 8s, max 10s
                    time.sleep(retry_delay)
                else:
                    # Final attempt failed
                    StatusLogger.timestamped_error(f"Stage 8, Pass 2a LLM request failed after {max_retries} attempts: {e}")
                    self.total_batch_failures += 1
                    StatusLogger.timestamped_error(f"Total batch failures: {self.total_batch_failures}/{self.max_total_failures}")

                    # Check if we should abort
                    if self.total_batch_failures >= self.max_total_failures:
                        raise RuntimeError(
                            f"Aborting scan: {self.total_batch_failures} batch(es) failed after {max_retries} retries each. "
                            "Common causes: LLM context/size limits, rate limits, network/VPN blocking the provider, "
                            "or a bad model/API configuration (check --model and provider errors above)."
                        )

                    # Fallback to abstain on error
                    return self._fallback_pass_f1_responses(function_batch.functions, str(e))

    def analyze_functions_pass_f2(self, function_batch: FunctionBatch, iteration: int) -> List[FunctionAnalysis]:
        """
        Analyze functions in Stage 8, Pass 2b (iterative enrichment).

        Args:
            function_batch: Batch of functions to analyze (with context additions)
            iteration: Iteration number (2+)

        Returns:
            List of function analysis results
        """
        StatusLogger.timestamped_print(f"Running Stage 8, Pass 2b iteration {iteration} on {len(function_batch.functions)} functions...")

        # Check if LLM is disabled
        if self.llm_type == "none":
            return self._fallback_pass_f2_responses(function_batch.functions, "LLM disabled (--llm none)")

        # Build Stage 8, Pass 2b prompt
        prompt = self._build_pass_f2_prompt(function_batch, iteration)

        # Debug: Show prompt if requested
        if self.debug_llm_raw:
            self.base_client._debug_print_prompt_parts(
                f"PASS F2 ITERATION {iteration} PROMPT", prompt
            )

        # Retry logic: up to 3 attempts per batch
        max_retries = 3
        last_exception = None

        for attempt in range(1, max_retries + 1):
            try:
                # Make API request
                response_data = self.base_client._make_api_request(prompt)

                # Extract and track token usage from response
                prompt_tokens = 0
                completion_tokens = 0
                if "usage" in response_data:
                    prompt_tokens = response_data["usage"].get("prompt_tokens", 0)
                    completion_tokens = response_data["usage"].get("completion_tokens", 0)
                    self.base_client._track_tokens(prompt_tokens, completion_tokens, "S2_P2")

                # Debug: Show response if requested
                if self.debug_llm_raw:
                    StatusLogger.timestamped_print(f"=== PASS F2 ITERATION {iteration} RESPONSE ===")
                    StatusLogger.timestamped_print(str(response_data))
                    StatusLogger.timestamped_print(f"=== END PASS F2 ITERATION {iteration} RESPONSE ===")

                # Parse responses
                analyses = self._parse_pass_f2_response(response_data, function_batch.functions)

                # Log results
                yes_count = sum(1 for a in analyses if a.y2038_summary == Y2038Summary.YES)
                no_count = sum(1 for a in analyses if a.y2038_summary == Y2038Summary.NO)
                abstain_count = sum(1 for a in analyses if a.y2038_summary == Y2038Summary.ABSTAIN)

                StatusLogger.timestamped_print(
                    f"Stage 8, Pass 2b iteration {iteration} function classifications: "
                    f"{yes_count} yes, {no_count} no, {abstain_count} abstain"
                )
                if prompt_tokens > 0 or completion_tokens > 0:
                    StatusLogger.timestamped_print(f"Token usage: {prompt_tokens} prompt + {completion_tokens} completion = {prompt_tokens + completion_tokens} total")

                return analyses

            except LLMNonRetryableError:
                raise
            except Exception as e:
                last_exception = e
                if attempt < max_retries:
                    StatusLogger.timestamped_warning(f"Stage 8, Pass 2b iteration {iteration} LLM request failed (attempt {attempt}/{max_retries}): {e}")
                    StatusLogger.timestamped_print(f"Retrying batch...")
                else:
                    # Final attempt failed
                    StatusLogger.timestamped_error(f"Stage 8, Pass 2b iteration {iteration} LLM request failed after {max_retries} attempts: {e}")
                    self.total_batch_failures += 1
                    StatusLogger.timestamped_error(f"Total batch failures: {self.total_batch_failures}/{self.max_total_failures}")

                    # Check if we should abort
                    if self.total_batch_failures >= self.max_total_failures:
                        raise RuntimeError(
                            f"Aborting scan: {self.total_batch_failures} batch(es) failed after {max_retries} retries each. "
                            "Common causes: LLM context/size limits, rate limits, network/VPN blocking the provider, "
                            "or a bad model/API configuration (check --model and provider errors above)."
                        )

                    # Fallback to abstain on error
                    return self._fallback_pass_f2_responses(function_batch.functions, str(e))

    def analyze_functions_pass_f3(self, function_batch: FunctionBatch) -> List[FunctionAnalysis]:
        """
        Analyze functions in Stage 9, Pass 1 (file-leading context).

        Args:
            function_batch: Batch of functions to analyze

        Returns:
            List of function analysis results
        """
        StatusLogger.timestamped_print(f"Running Stage 9, Pass 1 on {len(function_batch.functions)} functions...")

        # Check if LLM is disabled
        if self.llm_type == "none":
            return self._fallback_pass_f3_responses(function_batch.functions, "LLM disabled (--llm none)")

        # Build Stage 9, Pass 1 prompt
        prompt = self._build_pass_f3_prompt(function_batch)

        # Debug: Show prompt if requested
        if self.debug_llm_raw:
            self.base_client._debug_print_prompt_parts("PASS F3 PROMPT", prompt)

        # Retry logic: up to 3 attempts per batch
        max_retries = 3
        last_exception = None

        for attempt in range(1, max_retries + 1):
            try:
                # Make API request
                response_data = self.base_client._make_api_request(prompt)

                # Extract and track token usage from response
                prompt_tokens = 0
                completion_tokens = 0
                if "usage" in response_data:
                    prompt_tokens = response_data["usage"].get("prompt_tokens", 0)
                    completion_tokens = response_data["usage"].get("completion_tokens", 0)
                    self.base_client._track_tokens(prompt_tokens, completion_tokens, "S3_P1")

                # Debug: Show response if requested
                if self.debug_llm_raw:
                    StatusLogger.timestamped_print("=== PASS F3 RESPONSE ===")
                    StatusLogger.timestamped_print(str(response_data))
                    StatusLogger.timestamped_print("=== END PASS F3 RESPONSE ===")

                # Parse responses
                analyses = self._parse_pass_f3_response(response_data, function_batch.functions)

                # Log results
                yes_count = sum(1 for a in analyses if a.y2038_summary == Y2038Summary.YES)
                no_count = sum(1 for a in analyses if a.y2038_summary == Y2038Summary.NO)
                abstain_count = sum(1 for a in analyses if a.y2038_summary == Y2038Summary.ABSTAIN)

                StatusLogger.timestamped_print(
                    f"Stage 9, Pass 1 function classifications: "
                    f"{yes_count} yes, {no_count} no, {abstain_count} abstain"
                )
                if prompt_tokens > 0 or completion_tokens > 0:
                    StatusLogger.timestamped_print(f"Token usage: {prompt_tokens} prompt + {completion_tokens} completion = {prompt_tokens + completion_tokens} total")

                return analyses

            except LLMNonRetryableError:
                raise
            except Exception as e:
                last_exception = e
                if attempt < max_retries:
                    StatusLogger.timestamped_warning(f"Stage 9, Pass 1 LLM request failed (attempt {attempt}/{max_retries}): {e}")
                    StatusLogger.timestamped_print(f"Retrying batch...")
                    # Wait before retrying (exponential backoff)
                    import time
                    retry_delay = min(2 ** attempt, 10)  # 2s, 4s, 8s, max 10s
                    time.sleep(retry_delay)
                else:
                    # Final attempt failed
                    StatusLogger.timestamped_error(f"Stage 9, Pass 1 LLM request failed after {max_retries} attempts: {e}")
                    self.total_batch_failures += 1
                    StatusLogger.timestamped_error(f"Total batch failures: {self.total_batch_failures}/{self.max_total_failures}")

                    # Check if we should abort
                    if self.total_batch_failures >= self.max_total_failures:
                        raise RuntimeError(
                            f"Aborting scan: {self.total_batch_failures} batch(es) failed after {max_retries} retries each. "
                            "Common causes: LLM context/size limits, rate limits, network/VPN blocking the provider, "
                            "or a bad model/API configuration (check --model and provider errors above)."
                        )

                    # Fallback to abstain on error
                    return self._fallback_pass_f3_responses(function_batch.functions, str(e))

    def _build_pass_f1_prompt(self, function_batch: FunctionBatch) -> LLMPromptParts:
        """Build trusted instructions and untrusted payload for Stage 8, Pass 2a."""
        # Build the static environment rules (the values themselves travel as data)
        try:
            env_rules = self.base_client._build_environment_rules()
        except Exception as e:
            StatusLogger.timestamped_warning(f"Failed to build environment rules: {e}")
            env_rules = "Environment rules unavailable"

        # Build migration rules with error handling
        try:
            migration_rules = self._build_migration_rules()
        except Exception as e:
            StatusLogger.timestamped_warning(f"Failed to build migration rules: {e}")
            migration_rules = ""

        if self.detect_y2106:
            # Y2106 detection enabled - detect both Y2038 and Y2106
            system_prompt = f"""You are a C/C++ time overflow auditor analyzing complete function bodies for Year 2038 and Year 2106 overflow risks.
{self.base_client._untrusted_data_notice()}

CRITICAL DISTINCTIONS:
- Y2038 ISSUES: Functions that will overflow BEFORE 2038 (32-bit signed time_t overflow on Jan 19, 2038)
- Y2106 ISSUES: Functions using 32-bit unsigned time_t that will overflow in 2106 (Feb 7, 2106)
- BOTH: Functions with both signed and unsigned time_t usage (rare)
- SAFE: Functions that don't use time_t or only use struct tm, hardware operations, etc.

DECISION CRITERIA:
- Y2038: Classify as YES if function contains signed time_t usage that WILL overflow BEFORE 2038 OR narrowing patterns in ILP32 with 64-bit time_t
- Y2106: Classify as YES if function contains 32-bit unsigned time_t usage that WILL overflow in 2106 OR narrowing patterns in ILP32 with 64-bit time_t
- NO: Function is safe (no time_t usage, 64-bit time_t with no narrowing, etc.)
- ABSTAIN: Function is genuinely ambiguous even with full context (rare - only use when truly unclear)

CRITICAL FOR ILP32 WITH 64-BIT TIME_T:
Even if time_t is 64-bit, narrowing patterns ARE Y2038/Y2106 risks:
- Explicit narrowing casts: (int32_t)time_value, (int)time(NULL), (long)timestamp (if long is 32-bit in ILP32) → classify as YES
- Implicit narrowing assignments: int32_t x = time_value; int y = time(NULL); → classify as YES
- These patterns lose precision and can cause Y2038/Y2106 issues when the narrowed value is used

Be decisive! Classify each issue type independently.

IMPORTANT: Analyze each function independently. Don't assume all functions in a batch have the same risk level. Each function should be evaluated on its own merits.

{env_rules}

{migration_rules}
"""
        else:
            # Y2106 detection disabled - only detect Y2038 (current behavior)
            confidence_floor = self.base_client._confidence_floor_text()
            system_prompt = f"""You are a C/C++ Y2038 auditor analyzing complete function bodies for Year 2038 overflow risks.
{self.base_client._untrusted_data_notice()}

CRITICAL: You are analyzing code for Y2038 risks. BE CONSERVATIVE - false positives are worse than false negatives.

IMPORTANT DISTINCTION:
- Y2038 ISSUES: Only functions that will overflow BEFORE 2038 (32-bit SIGNED time_t only - very rare)
- Y2106 ISSUES: Functions using 32-bit UNSIGNED time_t that will overflow in 2106 (NOT Y2038 issues)
- SAFE: Functions that don't use time_t, use 64-bit time_t, or use unsigned time_t (Y2106, not Y2038)

DECISION CRITERIA - BE CONSERVATIVE:
- YES: Function contains CLEAR Y2038 risk (32-bit SIGNED time_t) OR narrowing patterns in ILP32 with 64-bit time_t - requires VERY HIGH confidence (>={confidence_floor})
- NO: Function is safe OR uses 32-bit UNSIGNED time_t (Y2106, not Y2038) OR uses 64-bit time_t with NO narrowing patterns
- ABSTAIN: Function is ambiguous, confidence < {confidence_floor}, or you're uncertain - PREFERRED over 'yes' when unsure

CRITICAL FOR LP64 WITH 64-BIT TIME_T:
- Arithmetic operations on 64-bit time_t are SAFE (no overflow before 2038 or 2106)
- The ONLY Y2038/Y2106 risks are NARROWING PATTERNS (see below)
- Do NOT flag arithmetic operations as Y2038 risks in LP64 configurations
- Example: `time_t t = time(NULL); t = t + 2147483648;` → SAFE, classify as 'no'

CRITICAL FOR ILP32 WITH 64-BIT TIME_T:
Even if time_t is 64-bit, narrowing patterns ARE Y2038/Y2106 risks:
- Explicit narrowing casts: (int32_t)time_value, (int)time(NULL), (long)timestamp (if long is 32-bit in ILP32) → classify as YES
- Implicit narrowing assignments: int32_t x = time_value; int y = time(NULL); → classify as YES
- These patterns lose precision and can cause Y2038/Y2106 issues when the narrowed value is used

CRITICAL: CHECK THE ENVIRONMENT FACTS IN THE ANALYSIS DATA TO DETERMINE IF time_t IS SIGNED OR UNSIGNED!

RULES FOR SIGNED TIME_T ENVIRONMENTS (time_t_signed: "signed"):
- **CRITICAL PATTERN 1**: Comparison operations checking for negative values:
  * `if (t < 0)` → STRONG indicator of signed time_t → classify as 'yes' for Y2038 risk
  * `if (t <= -1)` → STRONG indicator of signed time_t → classify as 'yes' for Y2038 risk
  * `if (t < 0)` in any form → STRONG indicator of signed time_t → classify as 'yes' for Y2038 risk
  * These patterns ONLY make sense with signed time_t (unsigned time_t can never be negative)
- **CRITICAL PATTERN 2**: Functions using negative time_t values:
  * `time_t t = -1;` → STRONG indicator of signed time_t → classify as 'yes' for Y2038 risk
  * `time_t t = -1L;` → STRONG indicator of signed time_t → classify as 'yes' for Y2038 risk
  * Any negative time_t initialization → STRONG indicator of signed time_t → classify as 'yes' for Y2038 risk
- **ARITHMETIC RISK EVALUATION**: For arithmetic operations on signed 32-bit time_t:
  * Adding any positive constant N could overflow if current_time + N > 2,147,483,647 (INT32_MAX)
  * The risk depends on the constant size AND when the operation happens
  * Large constants (>= 2^30) are high risk → classify as 'yes' if risky
  * Small constants can still overflow if used near 2038 → analyze context carefully
  * Evaluate each case: if the operation could happen near 2038, even small additions can overflow

RULES FOR UNSIGNED TIME_T ENVIRONMENTS (time_t_signed: "unsigned"):
- Patterns checking for negative values (t < 0) are ALWAYS false for unsigned time_t → classify as 'no'
- Arithmetic operations on unsigned time_t are Y2106 risks, not Y2038 → classify as 'no' (unless Y2106 detection is on)
- Functions using negative time_t values are incorrect code (unsigned can't be negative) → classify as 'no' or 'abstain'

ONLY classify as 'yes' if you're 100% certain it's a signed time_t Y2038 risk with confidence >= {confidence_floor}.

Be decisive! Most functions should be NO, not YES. Only flag as YES if there's a genuine Y2038 risk (overflow before 2038).

IMPORTANT: Analyze each function independently. Don't assume all functions in a batch have the same risk level. Each function should be evaluated on its own merits.

{env_rules}

{migration_rules}
"""

        if self.detect_y2106:
            # Y2106 detection enabled - include both Y2038 and Y2106 patterns
            system_prompt += """
Y2038 RISK PATTERNS (overflow BEFORE 2038):
□ Signed time_t arithmetic that could overflow before 2038
□ Specific arithmetic operations that cause overflow before 2038
□ Comparison operations that assume signed time_t behavior
□ Functions that explicitly handle negative time_t values
□ **CRITICAL FOR ILP32 WITH 64-BIT TIME_T**: Narrowing patterns that reduce 64-bit time_t to 32-bit:
  * Explicit narrowing casts: (int32_t)time_value, (int)time(NULL), (long)timestamp (if long is 32-bit in ILP32)
  * Implicit narrowing assignments: int32_t x = time_value; int y = time(NULL);
  * These lose precision and can cause Y2038/Y2106 issues when the narrowed value is used

Y2106 RISK PATTERNS (overflow in 2106):
□ 32-bit unsigned time_t variable declarations (time_t ts, time_t now, etc.)
□ 32-bit unsigned time_t arithmetic operations (ts + 1, ts - offset, etc.)
□ 32-bit unsigned time_t comparisons (ts > 0, ts < MAX_TIME, etc.)
□ 32-bit unsigned time_t function calls (time(), mktime(), gmtime_r(), localtime_r())
□ Zephyr-specific: timeutil_timegm(), timeutil_timegm64() (return unsigned time_t)
□ 32-bit unsigned time_t storage/assignment (ts = time(NULL), *time_ptr = ts)
□ struct timespec.tv_sec or struct timeval.tv_sec usage (32-bit unsigned time_t)
□ 32-bit unsigned time_t casting or conversion operations

SAFE PATTERNS:
□ Only struct tm declarations (struct tm tm = {0})
□ Only printf/string operations with no time_t
□ Only hardware register operations
□ Only non-time-related function calls
□ Functions with no time_t variables or time-related operations
□ 64-bit time_t usage with NO narrowing patterns (no overflow issues and no precision loss)

ABSTAIN ONLY WHEN:
□ Unknown typedefs that could be time_t (need typedef context)
□ Unknown macros that could be time-related (need macro context)
□ Unknown function calls that could be time functions (need callee context)
□ Unknown struct fields that could be time_t (need struct context)

EXAMPLES:
Function: static time_t get_current_time() { return time(NULL); }
Response: {"function_id": "test.c@get_current_time:10-12", "y2038_summary": "no", "y2106_summary": "yes", "issue_type": "y2106", "confidence": 0.95, "issues": [{"type": "y2106", "line": 11, "description": "time() returns 32-bit unsigned time_t that overflows in 2106"}], "needs_more_context": false, "needs": []}

Function: static int process_timestamp(time_t ts) { return ts > 0 ? 1 : 0; }
Response: {"function_id": "test.c@process_timestamp:15-17", "y2038_summary": "no", "y2106_summary": "yes", "issue_type": "y2106", "confidence": 0.9, "issues": [{"type": "y2106", "line": 16, "description": "32-bit unsigned time_t comparison overflows in 2106"}], "needs_more_context": false, "needs": []}

Function: static void print_message() { printf("Hello world\\n"); }
Response: {"function_id": "test.c@print_message:20-22", "y2038_summary": "no", "y2106_summary": "no", "issue_type": "none", "confidence": 0.95, "issues": [], "needs_more_context": false, "needs": []}

Function: static int nanosleep_wrapper(struct timespec *ts) { return nanosleep(ts, NULL); }
Response: {"function_id": "test.c@nanosleep_wrapper:30-32", "y2038_summary": "no", "y2106_summary": "yes", "issue_type": "y2106", "confidence": 0.95, "issues": [{"type": "y2106", "line": 31, "description": "struct timespec.tv_sec is 32-bit unsigned time_t, overflows in 2106"}], "needs_more_context": false, "needs": []}
"""
        else:
            # Y2106 detection disabled - only Y2038 patterns
            system_prompt += """
Y2038 RISK PATTERNS TO FLAG AS YES (overflow BEFORE 2038):
□ **CRITICAL**: Comparison operations checking for negative values (t < 0, t <= -1, if (t < 0)) - these ONLY work with signed time_t
□ **CRITICAL**: Functions using negative time_t values (t = -1, t = -1L) - these ONLY work with signed time_t
□ Signed time_t arithmetic that could overflow before 2038 (large constants >= 2^30)
□ Specific arithmetic operations that cause overflow before 2038
□ Functions that explicitly handle negative time_t values
□ **CRITICAL FOR ILP32 WITH 64-BIT TIME_T**: Narrowing patterns that reduce 64-bit time_t to 32-bit:
  * Explicit narrowing casts: (int32_t)time_value, (int)time(NULL), (long)timestamp (if long is 32-bit in ILP32)
  * Implicit narrowing assignments: int32_t x = time_value; int y = time(NULL);
  * These lose precision and can cause Y2038/Y2106 issues when the narrowed value is used

Y2106 PATTERNS (NOT Y2038 issues - flag as NO):
□ 32-bit unsigned time_t variable declarations (time_t ts, time_t now, etc.)
□ 32-bit unsigned time_t arithmetic operations (ts + 1, ts - offset, etc.)
□ 32-bit unsigned time_t comparisons (ts > 0, ts < MAX_TIME, etc.)
□ 32-bit unsigned time_t function calls (time(), mktime(), gmtime_r(), localtime_r())
□ Zephyr-specific: timeutil_timegm(), timeutil_timegm64() (return unsigned time_t)
□ 32-bit unsigned time_t storage/assignment (ts = time(NULL), *time_ptr = ts)
□ struct timespec.tv_sec or struct timeval.tv_sec usage (32-bit unsigned time_t)
□ 32-bit unsigned time_t casting or conversion operations

SAFE PATTERNS (NO):
□ Only struct tm declarations (struct tm tm = {0})
□ Only printf/string operations with no time_t
□ Only hardware register operations
□ Only non-time-related function calls
□ Functions with no time_t variables or time-related operations

ABSTAIN ONLY WHEN:
□ Unknown typedefs that could be time_t (need typedef context)
□ Unknown macros that could be time-related (need macro context)
□ Unknown function calls that could be time functions (need callee context)
□ Unknown struct fields that could be time_t (need struct context)

EXAMPLES FOR SIGNED TIME_T ENVIRONMENTS:
Function: void test_signed_comparison() { time_t t = time(NULL); if (t < 0) { return; } }
Response: {"function_id": "test.c@test_signed_comparison:25-30", "y2038_summary": "yes", "confidence": 0.95, "issues": [{"type": "y2038_risk", "line": 27, "description": "Comparison with negative value (t < 0) indicates signed time_t behavior and potential for pre-2038 overflow"}], "needs_more_context": false, "needs": []}

Function: void test_signed_addition() { time_t t = -1; t = t + 2147483648; }
Response: {"function_id": "test.c@test_signed_addition:18-22", "y2038_summary": "yes", "confidence": 0.95, "issues": [{"type": "y2038_risk", "line": 19, "description": "Signed time_t addition of large constant (2147483648) may cause overflow before 2038 on 32-bit signed time_t systems"}], "needs_more_context": false, "needs": []}

EXAMPLES FOR UNSIGNED TIME_T ENVIRONMENTS:
Function: static time_t get_current_time() { return time(NULL); }
Response: {"function_id": "test.c@get_current_time:10-12", "y2038_summary": "no", "confidence": 0.95, "issues": [{"type": "y2106_not_y2038", "line": 11, "description": "time() returns 32-bit unsigned time_t that overflows in 2106, not 2038"}], "needs_more_context": false, "needs": []}

Function: static int process_timestamp(time_t ts) { return ts > 0 ? 1 : 0; }
Response: {"function_id": "test.c@process_timestamp:15-17", "y2038_summary": "no", "confidence": 0.9, "issues": [{"type": "y2106_not_y2038", "line": 16, "description": "32-bit unsigned time_t comparison overflows in 2106, not 2038"}], "needs_more_context": false, "needs": []}

Function: static void print_message() { printf("Hello world\\n"); }
Response: {"function_id": "test.c@print_message:20-22", "y2038_summary": "no", "confidence": 0.95, "issues": [], "needs_more_context": false, "needs": []}

Function: static void uses_custom_time_type() { MY_TIME t = read_clock(); }
Response: {"function_id": "test.c@uses_custom_time_type:40-42", "y2038_summary": "abstain", "confidence": 0.4, "issues": [], "needs_more_context": true, "needs": ["typedef"]}

Function: static int nanosleep_wrapper(struct timespec *ts) { return nanosleep(ts, NULL); }
Response: {"function_id": "test.c@nanosleep_wrapper:30-32", "y2038_summary": "no", "confidence": 0.95, "issues": [{"type": "y2106_not_y2038", "line": 31, "description": "struct timespec.tv_sec is 32-bit unsigned time_t, overflows in 2106 not 2038"}], "needs_more_context": false, "needs": []}
"""

        system_prompt += """
Analyze every entry of the analysis data's 'functions' array. Each entry gives the
function_id, the function body as written, and the absolute candidate line numbers.
"""

        if self.detect_y2106:
            system_prompt += """
Respond with a JSON array of analysis objects. Each object must have exactly these fields:
{
  "function_id": "string (exact format provided)",
  "y2038_summary": "yes|no|abstain",
  "y2106_summary": "yes|no|abstain",
  "issue_type": "y2038|y2106|both|none|abstain",
  "confidence": 0.0-1.0,
  "issues": [{"type": "y2038|y2106|both|safe|ambiguous", "line": int, "description": "string"}],
  "needs_more_context": boolean,
  "needs": ["typedef"|"struct"|"macro"|"callee"|"header"]
}

LINE NUMBER REQUIREMENTS (VERY IMPORTANT):
- When `issues` is non-empty, each `issues[].line` must be the 1-based ABSOLUTE line number in the original file.
- The first line of a function's `body` corresponds to the `<start_line>` embedded in `function_id` (format: `<relpath>@<symbol>:<start>-<end>`).
- If the issue spans a range, choose the most relevant line within that range from the function body.
- When a function's `candidate_lines` array is non-empty, each `issues[].line` MUST be one of those candidate line numbers.

CRITICAL REQUIREMENTS:
- Copy each `function_id` exactly from the analysis data (case-sensitive; no trimming, prefixes, suffixes, or aliases)
- Include exactly one result object per requested function_id; never omit an ID or invent another
- Classify Y2038 and Y2106 independently (both can be YES if applicable)
- issue_type must be exactly: "y2038" | "y2106" | "both" | "none" | "abstain"
- y2038_summary / y2106_summary must be exactly lowercase "yes" | "no" | "abstain" (no synonyms)
- confidence must be a JSON number in [0.0, 1.0] (not a string, boolean, NaN, or Infinity)
- needs_more_context must be a JSON boolean
- `issues` must be a JSON array of objects with exactly the fields type, line, and description; `[]` is valid (especially for no/abstain)
- For YES: include concrete issue objects explaining the Y2038/Y2106 risks found
- For NO / ABSTAIN: `issues` may be `[]`, or may include explanatory issue objects
- For ABSTAIN: set needs_more_context and needs to name missing context (typedef, struct, macro, callee, header)
- Return valid JSON array - no extra text or formatting"""
        else:
            system_prompt += """
Respond with a JSON array of analysis objects. Each object must have exactly these fields:
{
  "function_id": "string (exact format provided)",
  "y2038_summary": "yes|no|abstain",
  "confidence": 0.0-1.0,
  "issues": [{"type": "string", "line": int, "description": "string"}],
  "needs_more_context": boolean,
  "needs": ["typedef"|"struct"|"macro"|"callee"|"header"]
}

LINE NUMBER REQUIREMENTS (VERY IMPORTANT):
- When `issues` is non-empty, each `issues[].line` must be the 1-based ABSOLUTE line number in the original file.
- The first line of a function's `body` corresponds to the `<start_line>` embedded in `function_id` (`...:<start>-<end>`).
- If unsure, choose the closest line in the provided function body that matches the described issue.
- When a function's `candidate_lines` array is non-empty, each `issues[].line` MUST be one of those candidate line numbers.

CRITICAL REQUIREMENTS:
- Copy each `function_id` exactly from the analysis data (case-sensitive; no trimming, prefixes, suffixes, or aliases)
- Include exactly one result object per requested function_id; never omit an ID or invent another
- y2038_summary must be exactly lowercase "yes" | "no" | "abstain" (no synonyms such as safe/risky/true)
- confidence must be a JSON number in [0.0, 1.0] (not a string, boolean, NaN, or Infinity)
- needs_more_context must be a JSON boolean
- `issues` must be a JSON array of objects with exactly the fields type, line, and description; `[]` is valid (especially for no/abstain)
- Be decisive: classify as YES ONLY for genuine Y2038 risks (overflow before 2038), NO for everything else
- For YES: include concrete issue objects explaining the Y2038 risks found
- For NO / ABSTAIN: `issues` may be `[]`, or may include explanatory issue objects
- For ABSTAIN: set needs_more_context and needs to name missing context (typedef, struct, macro, callee, header)
- Return valid JSON array - no extra text or formatting"""

        system_prompt += self._function_response_format_rules()

        return LLMPromptParts(
            system=system_prompt,
            user=format_untrusted_user_payload(
                self._function_payload("function_y2038_analysis", function_batch)
            ),
        )

    def _build_pass_f2_prompt(self, function_batch: FunctionBatch, iteration: int) -> LLMPromptParts:
        """Build trusted instructions and untrusted payload for Stage 8, Pass 2b."""
        system_prompt = f"""You are a C/C++ Y2038 auditor performing iterative analysis with additional context.
{self.base_client._untrusted_data_notice()}
This is iteration {iteration} of analysis for functions that needed more context.

{self.base_client._build_environment_rules()}

{self._build_migration_rules()}

CRITICAL FOR ILP32 WITH 64-BIT TIME_T:
Even if time_t is 64-bit, narrowing patterns ARE Y2038/Y2106 risks:
- Explicit narrowing casts: (int32_t)time_value, (int)time(NULL), (long)timestamp (if long is 32-bit in ILP32) → classify as YES
- Implicit narrowing assignments: int32_t x = time_value; int y = time(NULL); → classify as YES
- These patterns lose precision and can cause Y2038/Y2106 issues when the narrowed value is used

Each entry of the analysis data's 'functions' array carries the original body, its
absolute candidate_lines, and the context_additions gathered for it.

With this additional context, provide your final analysis. Respond with a JSON array matching the same schema as Pass F1.
Be decisive - this is your final chance to classify these functions.

LINE NUMBER REQUIREMENT:
- When `issues` is non-empty, set each `issues[].line` to one of the function's `candidate_lines` (pick the most relevant match).
"""
        system_prompt += self._function_response_format_rules()

        payload = self._function_payload("function_y2038_analysis_with_added_context", function_batch)
        payload["iteration"] = iteration
        return LLMPromptParts(
            system=system_prompt,
            user=format_untrusted_user_payload(payload),
        )

    def _build_pass_f3_prompt(self, function_batch: FunctionBatch) -> LLMPromptParts:
        """Build trusted instructions and untrusted payload for Stage 9, Pass 1."""
        system_prompt = f"""You are a C/C++ Y2038 auditor performing FINAL analysis with full file context.
{self.base_client._untrusted_data_notice()}
These functions remain ambiguous after iterative analysis, but with full file context you should be able to make a definitive decision.

CRITICAL: This is the FINAL pass. You MUST make a decision - YES or NO. Only use ABSTAIN if the code is genuinely impossible to analyze even with full file context (extremely rare).

{self.base_client._build_environment_rules()}

{self._build_migration_rules()}

DECISION CRITERIA (same as Pass F1):
- YES: Function contains time_t usage that WILL overflow BEFORE 2038 (for signed time_t) OR narrowing patterns that reduce 64-bit time_t to 32-bit in ILP32 systems
- NO: Function is safe OR uses 32-bit unsigned time_t that overflows in 2106 (not a Y2038 issue) OR uses 64-bit time_t safely with NO narrowing patterns
- ABSTAIN: ONLY if genuinely impossible to determine even with full file context (should be extremely rare)

CRITICAL FOR ILP32 WITH 64-BIT TIME_T:
Even if time_t is 64-bit, narrowing patterns ARE Y2038/Y2106 risks:
- Explicit narrowing casts: (int32_t)time_value, (int)time(NULL), (long)timestamp (if long is 32-bit in ILP32) → classify as YES
- Implicit narrowing assignments: int32_t x = time_value; int y = time(NULL); → classify as YES
- These patterns lose precision and can cause Y2038/Y2106 issues when the narrowed value is used

Be DECISIVE! With full file context, you should be able to classify 99% of cases as YES or NO.

Each entry of the analysis data's 'functions' array carries the body, the absolute
candidate_lines, the leading lines of the file it came from, and every typedef,
struct and macro found anywhere in that file.
"""

        # The schema below is literal JSON, so it stays out of the f-string above.
        system_prompt += """
This is your FINAL analysis opportunity. You have full file context - make a DECISIVE decision.
Respond with a JSON array matching the same schema as Pass F1:
{
  "function_id": "string (exact format provided)",
  "y2038_summary": "yes|no|abstain",
  "confidence": 0.0-1.0,
  "issues": [{"type": "string", "line": int, "description": "string"}],
  "needs_more_context": false,
  "needs": []
}

LINE NUMBER REQUIREMENTS (VERY IMPORTANT):
- When `issues` is non-empty, each `issues[].line` must be the 1-based ABSOLUTE line number in the original file.
- The first line of a function's `body` corresponds to the `<start_line>` embedded in `function_id` (`...:<start>-<end>`).
- Prefer a line that best pinpoints the described issue in the provided function body.
- When a function's `candidate_lines` array is non-empty, each `issues[].line` MUST be one of those candidate line numbers.

IMPORTANT:
- Use "needs_more_context": false (this is the final pass)
- Use "needs": [] (no more context needed)
- `issues` may be `[]` when no concrete issue objects are needed
- Be DECISIVE - classify as YES or NO unless truly impossible
- Only use ABSTAIN if genuinely impossible to determine even with full file context"""
        system_prompt += self._function_response_format_rules()

        return LLMPromptParts(
            system=system_prompt,
            user=format_untrusted_user_payload(
                self._function_payload(
                    "function_y2038_analysis_with_file_context",
                    function_batch,
                    include_file_context=True,
                )
            ),
        )

    @staticmethod
    def _function_response_format_rules() -> str:
        """How the answer must be shaped, given nothing partial is salvaged."""
        return (
            "\n\nRESPONSE FORMAT:\n"
            "- Respond with one complete JSON array and nothing else. A single markdown "
            "fence around the whole response is tolerated; nothing else is.\n"
            "- A truncated or partial array is rejected whole and every function in the "
            "batch receives analysis_error, so answer within the batch you were given.\n"
            "- Use only the documented field names and lowercase enum values. Do not use "
            "aliases (for example classification, functionID, safe-as-verdict).\n"
            "- Match each object to a function by exact function_id only; array order is "
            "not used for binding.\n"
            "- `issues` must be present as a JSON array; `[]` is valid. Each issue object "
            "may contain only type, line, and description.\n"
        )

    def _function_payload(
        self,
        task: str,
        function_batch: FunctionBatch,
        *,
        include_file_context: bool = False,
    ) -> Dict[str, Any]:
        """The untrusted half of a function-pass prompt: environment and code facts."""
        payload: Dict[str, Any] = {
            "task": task,
            "environment_config": self.base_client._environment_facts(),
            "functions": [
                self._function_facts(func, include_file_context=include_file_context)
                for func in function_batch.functions
            ],
        }
        migration = self._migration_facts()
        if migration:
            payload["migration"] = migration
        return payload

    def _function_facts(
        self, func: FunctionBody, *, include_file_context: bool = False
    ) -> Dict[str, Any]:
        """One function as untrusted structured facts."""
        facts: Dict[str, Any] = {
            "function_id": func.function_id,
            "symbol": func.symbol,
            "start_line": func.start_line,
            "end_line": func.end_line,
            "body": func.body,
            "candidate_lines": sorted(func.candidate_lines or []),
        }
        if func.context_additions:
            facts["context_additions"] = {
                str(key): value for key, value in func.context_additions.items()
            }
        if include_file_context:
            facts["file_context"] = self._file_context_facts(func)
        return facts

    def _file_context_facts(self, func: FunctionBody) -> Dict[str, Any]:
        """File-leading lines plus every type definition in the function's file."""
        try:
            with open(func.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            return {"error": f"Error reading file - {e}"}

        # Import here to avoid circular dependency
        from tacs.core.function_analyzer import FunctionAnalyzer
        analyzer = FunctionAnalyzer()
        return {
            "leading_lines": ''.join(lines[:50]),
            "typedefs": analyzer._extract_typedefs(lines),
            "structs": analyzer._extract_structs(lines),
            "macros": analyzer._extract_macros(lines),
        }

    def _parse_pass_f1_response(self, response_data: Dict[str, Any], functions: List[FunctionBody]) -> List[FunctionAnalysis]:
        """Parse Stage 8, Pass 2a LLM response."""
        return self._parse_function_response(response_data, functions, "S2_P1")

    def _parse_pass_f2_response(self, response_data: Dict[str, Any], functions: List[FunctionBody]) -> List[FunctionAnalysis]:
        """Parse Stage 8, Pass 2b LLM response."""
        return self._parse_function_response(response_data, functions, "S2_P2")

    def _parse_pass_f3_response(self, response_data: Dict[str, Any], functions: List[FunctionBody]) -> List[FunctionAnalysis]:
        """Parse Stage 9, Pass 1 LLM response."""
        return self._parse_function_response(response_data, functions, "S3_P1")

    def _align_analyses_to_functions(
        self,
        analyses: List[FunctionAnalysis],
        functions: List[FunctionBody],
        pass_name: str,
        note: str,
    ) -> List[FunctionAnalysis]:
        """Legacy helper retained for tests: re-align pre-built analyses by exact ID.

        Prefer :meth:`_parse_function_response`, which validates the wire contract
        before constructing internal analyses. Duplicate IDs fail closed.
        """
        from tacs.core.function_analysis_response import (
            ISSUE_DUPLICATE_ID,
            ISSUE_MISSING_EXPECTED,
            _error_stub,
        )

        by_id: Dict[str, List[FunctionAnalysis]] = {}
        for analysis in analyses:
            fid = analysis.function_id
            if type(fid) is not str:
                continue
            by_id.setdefault(fid, []).append(analysis)

        out: List[FunctionAnalysis] = []
        for func in functions:
            hits = by_id.get(func.function_id) or []
            if len(hits) == 1:
                hit = hits[0]
                if hit.function_id != func.function_id:
                    out.append(
                        _error_stub(
                            func,
                            issue_type=ISSUE_MISSING_EXPECTED,
                            description=(
                                f"{pass_name}: function_id mismatch after alignment ({note})"
                            ),
                            pass_name=pass_name,
                        )
                    )
                else:
                    out.append(hit)
                continue
            if len(hits) > 1:
                out.append(
                    _error_stub(
                        func,
                        issue_type=ISSUE_DUPLICATE_ID,
                        description=(
                            f"{pass_name}: duplicate function_id in model response"
                        ),
                        pass_name=pass_name,
                    )
                )
                continue
            out.append(
                _error_stub(
                    func,
                    issue_type=ISSUE_MISSING_EXPECTED,
                    description=(
                        f"{pass_name}: no usable model item with exact function_id ({note})"
                    ),
                    pass_name=pass_name,
                )
            )
        return out

    def _parse_function_response(self, response_data: Dict[str, Any], functions: List[FunctionBody], pass_name: str) -> List[FunctionAnalysis]:
        """Parse function analysis response with exact-ID wire validation.

        The whole response must be the requested JSON array, optionally inside one
        markdown fence. Items complete only with an exact requested ``function_id``
        and canonical fields; positional binding and aliases are rejected.
        """
        from tacs.core.function_analysis_response import align_model_items_to_functions

        try:
            content = self.base_client._extract_content(response_data)
            if not content:
                return self._fallback_function_responses(
                    functions, f"Empty response from {pass_name}"
                )

            content = strip_optional_code_fence(content)

            parsed = json.loads(content)
            if not isinstance(parsed, list):
                return self._fallback_function_responses(
                    functions, f"{pass_name} response is not a JSON array"
                )

            analyses, diagnostics = align_model_items_to_functions(
                parsed,
                functions,
                pass_name=pass_name,
                detect_y2106=self.detect_y2106,
            )

            unknown = int(diagnostics.get("unknown_function_id") or 0)
            if unknown:
                StatusLogger.timestamped_warning(
                    f"{pass_name}: ignored {unknown} unknown_function_id item(s) "
                    "outside the requested batch"
                )
            duplicates = int(diagnostics.get("duplicate_function_id") or 0)
            if duplicates:
                StatusLogger.timestamped_warning(
                    f"{pass_name}: {duplicates} duplicate_function_id value(s); "
                    "affected functions marked analysis_error"
                )
            missing_ids = int(diagnostics.get("missing_function_id") or 0)
            invalid_items = int(diagnostics.get("invalid_item") or 0)
            if missing_ids or invalid_items:
                StatusLogger.timestamped_warning(
                    f"{pass_name}: skipped {missing_ids} missing_function_id and "
                    f"{invalid_items} invalid_item entr(ies) without binding"
                )

            if self.debug_llm_raw:
                for i, analysis in enumerate(analyses):
                    StatusLogger.timestamped_print(
                        f"Aligned analysis {i + 1}: {analysis.function_id} -> "
                        f"{analysis.y2038_summary.value} "
                        f"(status={analysis.execution_status.value}, "
                        f"confidence={analysis.confidence:.2f})"
                    )

            return analyses

        except json.JSONDecodeError:
            StatusLogger.timestamped_warning(
                f"{pass_name} response was not a complete JSON array "
                f"(truncated or malformed); the batch is analysis_error"
            )
            return self._fallback_function_responses(
                functions,
                f"{pass_name} JSON parsing error (truncated response)",
            )
        except Exception:
            StatusLogger.timestamped_error(f"{pass_name} parsing error")
            return self._fallback_function_responses(
                functions, f"{pass_name} parsing error"
            )

    def _fallback_function_responses(self, functions: List[FunctionBody], error_msg: str) -> List[FunctionAnalysis]:
        """Create operational stubs for function analysis (not genuine model abstentions)."""
        from tacs.core.schema import AssessmentExecutionStatus

        analyses = []
        for func in functions:
            line0 = func.start_line if getattr(func, "start_line", None) else 1
            analysis = FunctionAnalysis(
                function_id=func.function_id,
                y2038_summary=Y2038Summary.ABSTAIN,
                confidence=0.0,
                issues=[
                    {
                        "type": "analysis_error",
                        "description": error_msg,
                        "line": line0,
                    }
                ],
                needs_more_context=False,
                needs=[],
                execution_status=AssessmentExecutionStatus.ANALYSIS_ERROR,
            )
            analyses.append(analysis)
        return analyses

    def _fallback_pass_f1_responses(self, functions: List[FunctionBody], error_msg: str) -> List[FunctionAnalysis]:
        """Create fallback responses for Stage 8, Pass 2a."""
        return self._fallback_function_responses(functions, f"Stage 8, Pass 2a error: {error_msg}")

    def _fallback_pass_f2_responses(self, functions: List[FunctionBody], error_msg: str) -> List[FunctionAnalysis]:
        """Create fallback responses for Stage 8, Pass 2b."""
        return self._fallback_function_responses(functions, f"Stage 8, Pass 2b error: {error_msg}")

    def _fallback_pass_f3_responses(self, functions: List[FunctionBody], error_msg: str) -> List[FunctionAnalysis]:
        """Create fallback responses for Stage 9, Pass 1."""
        return self._fallback_function_responses(functions, f"Stage 9, Pass 1 error: {error_msg}")

    def _migration_facts(self) -> Dict[str, Any]:
        """Source and target configs as untrusted facts, or empty when not migrating."""
        if not self.migration_mode or not self.migration_from_config or not self.migration_to_config:
            return {}
        try:
            return {
                "from": _migration_endpoint_facts(self.migration_from_config),
                "to": _migration_endpoint_facts(self.migration_to_config),
            }
        except Exception:
            return {}

    def _build_migration_rules(self) -> str:
        """Static migration rules for the trusted channel, or empty when not migrating."""
        if not self.migration_mode or not self.migration_from_config or not self.migration_to_config:
            return ""

        return """
MIGRATION ANALYSIS MODE:
The analysis data's 'migration' object names the source and target configurations
you are judging the code against.

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