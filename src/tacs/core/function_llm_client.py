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
Response: {"function_id": "test.c@print_message:20-22", "y2038_summary": "no", "y2106_summary": "no", "issue_type": "none", "confidence": 0.95, "issues": [{"type": "safe", "line": 21, "description": "no time_t usage, only printf operation"}], "needs_more_context": false, "needs": []}

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
Response: {"function_id": "test.c@print_message:20-22", "y2038_summary": "no", "confidence": 0.95, "issues": [{"type": "safe", "line": 21, "description": "no time_t usage, only printf operation"}], "needs_more_context": false, "needs": []}

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
- `issues[].line` must be the 1-based ABSOLUTE line number in the original file.
- The first line of a function's `body` corresponds to the `<start_line>` embedded in `function_id` (format: `<relpath>@<symbol>:<start>-<end>`).
- If the issue spans a range, choose the most relevant line within that range from the function body.
- When a function's `candidate_lines` array is non-empty, `issues[].line` MUST be one of those candidate line numbers.

CRITICAL REQUIREMENTS:
- Use the exact function_id format provided
- Classify Y2038 and Y2106 independently (both can be YES if applicable)
- issue_type should be: "y2038" (only Y2038), "y2106" (only Y2106), "both" (both issues), "none" (safe), "abstain" (unclear)
- Provide specific issue descriptions explaining WHY for each decision
- For Y2038 YES: Explain specific Y2038 risks found (signed time_t overflow before 2038)
- For Y2106 YES: Explain specific Y2106 risks found (unsigned time_t overflow in 2106)
- For NO: Explain specific reasons (e.g., "no time_t usage", "64-bit time_t", "only struct tm", "hardware operations")
- For ABSTAIN: Explain what context is missing (typedef, struct, macro, callee, header)
- ALWAYS provide at least one issue description for every function analyzed
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
- `issues[].line` must be the 1-based ABSOLUTE line number in the original file.
- The first line of a function's `body` corresponds to the `<start_line>` embedded in `function_id` (`...:<start>-<end>`).
- If unsure, choose the closest line in the provided function body that matches the described issue.
- When a function's `candidate_lines` array is non-empty, `issues[].line` MUST be one of those candidate line numbers.

CRITICAL REQUIREMENTS:
- Use the exact function_id format provided
- Be decisive: classify as YES ONLY for genuine Y2038 risks (overflow before 2038), NO for everything else
- Provide specific issue descriptions explaining WHY for each decision
- For YES: Explain specific Y2038 risks found (extremely rare for unsigned time_t)
- For NO: Explain specific reasons (e.g., "no time_t usage", "32-bit unsigned time_t overflows in 2106 not 2038", "only struct tm", "hardware operations")
- For ABSTAIN: Explain what context is missing (typedef, struct, macro, callee, header)
- ALWAYS provide at least one issue description for every function analyzed
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
- For each issue, set `issues[].line` to one of the function's `candidate_lines` (pick the most relevant match).
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
- `issues[].line` must be the 1-based ABSOLUTE line number in the original file.
- The first line of a function's `body` corresponds to the `<start_line>` embedded in `function_id` (`...:<start>-<end>`).
- Prefer a line that best pinpoints the described issue in the provided function body.
- When a function's `candidate_lines` array is non-empty, `issues[].line` MUST be one of those candidate line numbers.

IMPORTANT:
- Use "needs_more_context": false (this is the final pass)
- Use "needs": [] (no more context needed)
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
            "batch abstains, so answer within the batch you were given.\n"
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
        """Ensure one FunctionAnalysis per input function (pipeline zips by position)."""
        from tacs.core.candidate_utils import summary_value
        from tacs.core.schema import AssessmentExecutionStatus

        by_id: Dict[str, FunctionAnalysis] = {}
        conflict_ids: set[str] = set()
        for a in analyses:
            fid = (a.function_id or "").strip()
            if not fid:
                continue
            existing = by_id.get(fid)
            if existing is None:
                by_id[fid] = a
                continue
            if summary_value(existing.y2038_summary) == summary_value(a.y2038_summary):
                # Identical duplicate verdict: keep the higher-confidence copy.
                if float(a.confidence or 0) > float(existing.confidence or 0):
                    by_id[fid] = a
                continue
            # Conflicting duplicate outputs for one function are ambiguous model
            # behavior — collapse to a single abstain rather than picking a side.
            conflict_ids.add(fid)
            line0 = 1
            for func in functions:
                if func.function_id == fid:
                    line0 = func.start_line or 1
                    break
            by_id[fid] = FunctionAnalysis(
                function_id=fid,
                y2038_summary=Y2038Summary.ABSTAIN,
                confidence=0.0,
                issues=[
                    {
                        "type": "duplicate_conflict",
                        "description": (
                            f"Model returned conflicting {pass_name} outputs for this "
                            f"function ({summary_value(existing.y2038_summary)} vs "
                            f"{summary_value(a.y2038_summary)}); treating as abstain."
                        ),
                        "line": line0,
                    }
                ],
                needs_more_context=True,
                needs=[],
                execution_status=AssessmentExecutionStatus.ANALYSIS_ERROR,
            )
        if conflict_ids:
            StatusLogger.timestamped_warning(
                f"{pass_name}: model returned conflicting duplicate outputs for "
                f"{len(conflict_ids)} function(s); collapsed each to abstain"
            )
        out: List[FunctionAnalysis] = []
        missing = 0
        for func in functions:
            hit = by_id.get(func.function_id)
            if hit is not None:
                if hit.function_id != func.function_id:
                    hit = hit.model_copy(update={"function_id": func.function_id})
                out.append(hit)
                continue
            missing += 1
            line0 = func.start_line if getattr(func, "start_line", None) else 1
            out.append(
                FunctionAnalysis(
                    function_id=func.function_id,
                    y2038_summary=Y2038Summary.ABSTAIN,
                    confidence=0.0,
                    issues=[
                        {
                            "type": "parse_gap",
                            "description": (
                                f"No usable {pass_name} model output for this function ({note}). "
                                "Try a smaller --batch-size-func or raise GEMINI_MAX_OUTPUT_TOKENS."
                            ),
                            "line": line0,
                        }
                    ],
                    needs_more_context=True,
                    needs=[],
                    execution_status=AssessmentExecutionStatus.ANALYSIS_ERROR,
                )
            )
        if missing:
            StatusLogger.timestamped_warning(
                f"{pass_name}: model returned output for {len(functions) - missing}/{len(functions)} "
                f"functions in this batch; {missing} filled as abstain ({note})"
            )
        return out

    def _parse_function_response(self, response_data: Dict[str, Any], functions: List[FunctionBody], pass_name: str) -> List[FunctionAnalysis]:
        """Parse function analysis response.

        The whole response must be the requested JSON array, optionally inside one
        markdown fence. Nothing is read out of a malformed reply: a truncation or
        an injected span would otherwise answer for functions the model never
        judged, and a partial batch is indistinguishable from a complete one once
        the leftovers are padded with abstains.
        """
        try:
            # Extract content from response
            content = self.base_client._extract_content(response_data)
            if not content:
                return self._fallback_function_responses(functions, f"Empty response from {pass_name}")

            # Unwrap one whole-response markdown fence if present
            content = strip_optional_code_fence(content)

            # Parse JSON
            parsed = json.loads(content)
            if not isinstance(parsed, list):
                return self._fallback_function_responses(functions, f"{pass_name} response is not a JSON array")

            # Convert to FunctionAnalysis objects
            analyses = []
            for i, item in enumerate(parsed):
                try:
                    # Normalize field names and convert types
                    normalized_item = self._normalize_function_analysis_item(item, functions[i] if i < len(functions) else None)
                    analysis = FunctionAnalysis(**normalized_item)
                    analyses.append(analysis)

                    # Debug: Show parsed analysis details
                    if self.debug_llm_raw:
                        StatusLogger.timestamped_print(f"Parsed analysis {i+1}: {analysis.function_id} -> {analysis.y2038_summary.value} (confidence: {analysis.confidence:.2f})")
                        if analysis.issues:
                            StatusLogger.timestamped_print(f"  Issues: {len(analysis.issues)} found")
                            for issue in analysis.issues:
                                StatusLogger.timestamped_print(f"    - {issue}")
                        else:
                            StatusLogger.timestamped_print(f"  No specific issues found")
                        if analysis.needs:
                            StatusLogger.timestamped_print(f"  Needs: {analysis.needs}")
                        if analysis.needs_more_context:
                            StatusLogger.timestamped_print(f"  Needs more context: {analysis.needs_more_context}")

                except Exception as e:
                    StatusLogger.timestamped_warning(f"Failed to parse {pass_name} analysis item: {e}")
                    StatusLogger.timestamped_warning(f"Raw item: {item}")
                    continue

            return self._align_analyses_to_functions(
                analyses, functions, pass_name, "fewer valid array entries than functions"
            )

        except json.JSONDecodeError as e:
            # A response that is not one complete JSON array is not read at all.
            StatusLogger.timestamped_warning(
                f"{pass_name} response was not a complete JSON array "
                f"(truncated or malformed): {e}; the batch abstains"
            )
            return self._fallback_function_responses(functions, f"{pass_name} JSON parsing error (truncated response): {e}")
        except Exception as e:
            StatusLogger.timestamped_error(f"{pass_name} parsing error: {e}")
            return self._fallback_function_responses(functions, f"{pass_name} parsing error: {e}")

    def _normalize_function_analysis_item(self, item: Dict[str, Any], function: Optional[FunctionBody] = None) -> Dict[str, Any]:
        """Normalize LLM response item to match FunctionAnalysis schema."""

        normalized = {}

        # Map function_id from various field names
        function_id = (
            item.get('function_id') or
            item.get('functionID') or
            item.get('function') or
            (function.function_id if function else None)
        )
        if not function_id and function:
            function_id = function.function_id
        if not function_id:
            # Try to construct from file/function/line fields
            file_path = item.get('file', '')
            func_name = item.get('function', '')
            line_start = item.get('line_start') or item.get('line', '')
            line_end = item.get('line_end', '')
            if file_path and func_name and line_start:
                function_id = f"{file_path}@{func_name}:{line_start}-{line_end}" if line_end else f"{file_path}@{func_name}:{line_start}"
        # Ensure function_id is always a non-empty string (required by FunctionAnalysis; LLM may return null/number)
        raw = function_id or 'unknown'
        normalized['function_id'] = str(raw).strip() or 'unknown'

        # Map y2038_summary from various field names and values
        y2038_summary = None
        summary_value = (
            item.get('y2038_summary') or
            item.get('y2038_status') or
            item.get('Y2038Affected') or
            item.get('y2038') or
            item.get('y2038_problem') or
            item.get('classification')
        )

        if summary_value:
            summary_str = str(summary_value).lower()
            if summary_str in ['yes', 'true', 'risky', 'risky_narrowing']:
                y2038_summary = Y2038Summary.YES
            elif summary_str in ['no', 'false', 'safe', 'y2038_safe']:
                # Check if it's actually safe or Y2106
                y2038_safe = item.get('y2038_safe', True)
                if isinstance(y2038_safe, bool) and not y2038_safe:
                    y2038_summary = Y2038Summary.YES
                else:
                    y2038_summary = Y2038Summary.NO
            elif summary_str in ['abstain', 'unknown', 'ambiguous']:
                y2038_summary = Y2038Summary.ABSTAIN

        # If still not determined, check y2038_safe field
        if y2038_summary is None:
            y2038_safe = item.get('y2038_safe')
            if isinstance(y2038_safe, bool):
                y2038_summary = Y2038Summary.NO if y2038_safe else Y2038Summary.YES
            else:
                y2038_summary = Y2038Summary.ABSTAIN

        normalized['y2038_summary'] = y2038_summary

        # Map y2106_summary (when Y2106 detection enabled)
        if self.detect_y2106:
            y2106_summary = None
            y2106_value = (
                item.get('y2106_summary') or
                item.get('y2106_status') or
                item.get('Y2106Affected') or
                item.get('y2106')
            )

            if y2106_value:
                y2106_str = str(y2106_value).lower()
                if y2106_str in ['yes', 'true', 'risky']:
                    y2106_summary = Y2038Summary.YES
                elif y2106_str in ['no', 'false', 'safe']:
                    y2106_summary = Y2038Summary.NO
                elif y2106_str in ['abstain', 'unknown', 'ambiguous']:
                    y2106_summary = Y2038Summary.ABSTAIN

            # If not explicitly provided, infer from issue_type or issues
            if y2106_summary is None:
                issue_type = item.get('issue_type', '').lower()
                issues = item.get('issues', [])

                # Check if any issues are Y2106
                has_y2106_issue = any(
                    issue.get('type', '').lower() in ['y2106', 'both']
                    for issue in issues if isinstance(issue, dict)
                )

                if issue_type in ['y2106', 'both'] or has_y2106_issue:
                    y2106_summary = Y2038Summary.YES
                elif issue_type == 'none':
                    y2106_summary = Y2038Summary.NO
                else:
                    # Default: infer from y2038_summary (if Y2038 is NO and we have Y2106 patterns, it's likely Y2106)
                    if y2038_summary == Y2038Summary.NO:
                        # Check if issues indicate Y2106
                        has_y2106_pattern = any(
                            'y2106' in str(issue.get('type', '')).lower() or
                            '2106' in str(issue.get('description', '')).lower()
                            for issue in issues if isinstance(issue, dict)
                        )
                        y2106_summary = Y2038Summary.YES if has_y2106_pattern else Y2038Summary.NO
                    else:
                        y2106_summary = Y2038Summary.NO

            normalized['y2106_summary'] = y2106_summary

            # Map issue_type
            issue_type = item.get('issue_type', '').lower()
            if issue_type:
                from tacs.core.schema import TimeIssueType
                if issue_type == 'y2038':
                    normalized['issue_type'] = TimeIssueType.Y2038
                elif issue_type == 'y2106':
                    normalized['issue_type'] = TimeIssueType.Y2106
                elif issue_type == 'both':
                    normalized['issue_type'] = TimeIssueType.BOTH
                elif issue_type == 'none':
                    normalized['issue_type'] = TimeIssueType.NONE
                elif issue_type == 'abstain':
                    normalized['issue_type'] = TimeIssueType.ABSTAIN
            else:
                # Infer issue_type from y2038_summary and y2106_summary
                from tacs.core.schema import TimeIssueType
                has_y2038 = y2038_summary == Y2038Summary.YES
                has_y2106 = normalized.get('y2106_summary') == Y2038Summary.YES

                if has_y2038 and has_y2106:
                    normalized['issue_type'] = TimeIssueType.BOTH
                elif has_y2038:
                    normalized['issue_type'] = TimeIssueType.Y2038
                elif has_y2106:
                    normalized['issue_type'] = TimeIssueType.Y2106
                elif y2038_summary == Y2038Summary.ABSTAIN:
                    normalized['issue_type'] = TimeIssueType.ABSTAIN
                else:
                    normalized['issue_type'] = TimeIssueType.NONE

        # Map confidence from various field names and convert string to float
        confidence = item.get('confidence', 0.5)
        if isinstance(confidence, str):
            confidence_str = confidence.lower()
            if confidence_str in ['high', 'h']:
                confidence = 0.9
            elif confidence_str in ['medium', 'med', 'm']:
                confidence = 0.7
            elif confidence_str in ['low', 'l']:
                confidence = 0.5
            else:
                try:
                    confidence = float(confidence)
                except (ValueError, TypeError):
                    confidence = 0.5
        else:
            try:
                confidence = float(confidence)
            except (TypeError, ValueError):
                confidence = 0.5

        normalized['confidence'] = max(0.0, min(1.0, confidence))

        # Map issues - normalize to list of dicts
        issues = item.get('issues', [])
        if not isinstance(issues, list):
            issues = []

        # Normalize issues: convert strings to dicts, ensure all are dicts
        normalized_issues = []
        for issue in issues:
            if isinstance(issue, str):
                # Convert string to dict format
                normalized_issues.append({
                    'type': issue,
                    'description': f"Issue: {issue}",
                    'line': item.get('line', item.get('line_start', function.start_line if function else 0))
                })
            elif isinstance(issue, dict):
                # Already a dict, use as-is (but ensure required fields)
                normalized_issue = {
                    'type': issue.get('type', 'unknown'),
                    'description': issue.get('description', issue.get('notes', '')),
                    'line': issue.get('line', item.get('line', item.get('line_start', function.start_line if function else 0)))
                }
                # Copy any additional fields
                for key, value in issue.items():
                    if key not in normalized_issue:
                        normalized_issue[key] = value
                normalized_issues.append(normalized_issue)
            # Skip non-string, non-dict items

        # If no issues found, try to create from other fields
        if not normalized_issues:
            if 'explanation' in item:
                normalized_issues = [{
                    'type': 'y2038_risk',
                    'description': item['explanation'],
                    'line': item.get('line', item.get('line_start', function.start_line if function else 0))
                }]
            elif 'reason' in item:
                normalized_issues = [{
                    'type': 'y2038_risk',
                    'description': item['reason'],
                    'line': item.get('line', item.get('line_start', function.start_line if function else 0))
                }]
            elif 'comment' in item:
                normalized_issues = [{
                    'type': 'y2038_risk',
                    'description': item['comment'],
                    'line': item.get('line', item.get('line_start', function.start_line if function else 0))
                }]
            elif 'notes' in item:
                normalized_issues = [{
                    'type': 'y2038_risk',
                    'description': item['notes'],
                    'line': item.get('line', item.get('line_start', function.start_line if function else 0))
                }]

        normalized['issues'] = normalized_issues

        # Map needs_more_context
        needs_more_context = item.get('needs_more_context', False)
        if not isinstance(needs_more_context, bool):
            needs_more_context = False
        normalized['needs_more_context'] = needs_more_context

        # Map needs
        needs = item.get('needs', [])
        if not isinstance(needs, list):
            needs = []
        normalized['needs'] = [ContextNeed(n) if isinstance(n, str) else n for n in needs]

        return normalized

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
                needs_more_context=True,
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