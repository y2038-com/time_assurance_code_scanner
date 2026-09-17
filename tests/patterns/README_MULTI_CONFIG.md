# Multi-Configuration Test Framework

This directory contains an extended test framework that validates the Y2038 scanner across different environment configurations.

## Overview

The multi-configuration test framework tests the scanner with all eight environment
configurations — every combination of ABI (ILP32, LP64), `time_t` width (32, 64) and
signedness. The four that carry most of the signal are:

1. **ILP32 signed 32-bit time_t** - 32-bit ABI with signed 32-bit time_t (highest Y2038 risk)
2. **ILP32 unsigned 32-bit time_t** - 32-bit ABI with unsigned 32-bit time_t (Y2106 risk, not Y2038)
3. **LP64 signed 64-bit time_t** - 64-bit ABI with signed 64-bit time_t (Y2038 safe)
4. **LP64 unsigned 64-bit time_t** - 64-bit ABI with unsigned 64-bit time_t (Y2038 safe, rare)

The remaining four (`ilp32_signed_64bit`, `ilp32_unsigned_64bit`, `lp64_signed_32bit`,
`lp64_unsigned_32bit`) are rarer pairings and are exercised too.

## Test Files

### New Test Files

- **`test_narrowing_patterns.c`** - Tests narrowing patterns that should fail even in LP64
  - Explicit casts to int32_t (should be YES even in LP64)
  - Typedef of int32_t used to hold time_t values
  - #define that creates narrow type aliases
  - Struct members (int32_t) assigned time_t values
  - Functions returning time_t stored in 32-bit members
  - Serialization/network patterns with 32-bit time fields

- **`test_embedded_time_fields.c`** - Tests structures with embedded 32-bit time fields (signed and unsigned)
  - Custom structs with time_t fields
  - Standard structures (timespec, timeval)
  - Explicit 32-bit integer time fields
  - Serialization/storage patterns
  - Edge cases and complex patterns

- **`test_arithmetic_patterns.c`** (extended) - Comprehensive time_t math operations
  - Signed time_t arithmetic (Y2038 risk)
  - Unsigned time_t arithmetic (Y2106, not Y2038)
  - Additional patterns: modulo, bitwise, shifts, compound assignments
  - Arithmetic with structs, pointers, and in various contexts

### Test Framework Files

- **`test_config_fixtures.py`** - Environment configuration fixtures
  - Pre-configured environment configs for all 8 scenarios
  - Helper functions to create and manage configs
  - Config file generation utilities

- **`../manual/manual_multi_config.py`** - Multi-configuration test runner
  - Runs tests with all 8 environment configurations
  - Validates pattern detection across configurations
  - Reports results grouped by configuration and test file

## Running the Tests

### Run Multi-Configuration Tests

#### IR-Only Testing (Fast, No LLM)

```bash
# Run tests with all configurations (IR-only, no LLM)
python tests/manual/manual_multi_config.py
```

This will:
1. Test each pattern file with all 8 environment configurations
2. Verify that patterns are detected correctly (IR candidate discovery)
3. Verify Stage 3 (IR Candidate Discovery) ran
4. Report results grouped by configuration and test file

#### Full Pipeline Testing (With LLM)

```bash
# Run tests with LLM (full pipeline)
python tests/manual/manual_multi_config.py --llm ollama

# Run with specific model
python tests/manual/manual_multi_config.py --llm ollama --model qwen3-coder:480b-cloud

# Run with verbose output (shows scanner progress in real-time)
python tests/manual/manual_multi_config.py --llm ollama --verbose
```

**Prerequisites for LLM testing:**
- Ollama must be running on `localhost:11434`
- The specified model must be available in Ollama
- The test script will check Ollama availability before starting

**Note:** LLM tests can take **10-20 minutes per configuration** (each test file has ~245 functions, processed in batches of 15). For faster testing, use `--limit-configs 1 --limit-files 1` to test just one configuration and one file.

**Performance Tips:**
- Use `--limit-configs 1` to test just one configuration first
- Use `--limit-files 1` to test just one test file
- IR-only tests (`--llm none`) are much faster (seconds instead of minutes)

This will:
1. Check that Ollama is running and accessible
2. Test each pattern file with all 8 environment configurations
3. Show scanner progress in real-time (so you can see what's happening)
4. Verify that patterns are detected correctly (IR candidate discovery)
5. Verify all pipeline stages ran:
   - Stage 3: IR Candidate Discovery
   - Stage 8, Pass 2a: function-level analysis
   - Stage 8, Pass 2b: widened context - if Pass 2a left abstains
   - Stage 9, Pass 1: file-leading context - if abstains remain
6. Report LLM classifications (yes/no/abstain) for each configuration
7. Report results grouped by configuration and test file

### Command-Line Options

- `--llm {none,ollama}` - LLM type to use (default: `none`)
  - `none`: IR-only testing, no LLM calls (fast)
  - `ollama`: Full pipeline with LLM analysis (slower, requires Ollama)
- `--model MODEL` - Model name when using LLM (default: `qwen3-coder:480b-cloud`)
- `--verbose, -v` - Show scanner output in real-time (automatically enabled for LLM tests)
- `--limit-configs N` - Limit number of configurations to test (for faster LLM testing)
- `--limit-files N` - Limit number of test files to test (for faster LLM testing)

### Troubleshooting

**If tests hang with `--llm ollama`:**
1. Check that Ollama is running: `curl http://localhost:11434/api/tags`
2. Verify the model is available: `ollama list`
3. Test the model manually: `ollama run qwen3-coder:480b-cloud`
4. Check Ollama logs for errors
5. **Note:** LLM tests are slow by design - each function batch takes 30-60 seconds

**If you see "Ollama is not running":**
- Start Ollama: `ollama serve`
- Or ensure Ollama service is running: `systemctl status ollama` (Linux)

**If tests show "Failed: Unknown error" but scan completed:**
- This was a bug that's been fixed - the test now correctly detects function-first pipeline (`pass_f1` instead of `pass1`)
- Re-run the test to see if it passes now

**For faster testing:**
```bash
# Test just one configuration and one file (much faster)
python tests/manual/manual_multi_config.py --llm ollama --limit-configs 1 --limit-files 1
```

### Generate Environment Config Files

```bash
# Generate all environment config files
python tests/patterns/test_config_fixtures.py
```

This creates one JSON file per configuration in `tests/patterns/env_configs/`:
- `ilp32_signed_32bit.json`
- `ilp32_unsigned_32bit.json`
- `ilp32_signed_64bit.json`
- `ilp32_unsigned_64bit.json`
- `lp64_signed_32bit.json`
- `lp64_unsigned_32bit.json`
- `lp64_signed_64bit.json`
- `lp64_unsigned_64bit.json`

All eight are committed, so the fixtures are reviewable and the schema-integrity
tests validate a fixed set rather than whatever happens to be on disk. If you change
a config in `test_config_fixtures.py`, regenerate and commit all eight —
`test_the_pattern_fixture_directory_matches_the_generator` fails on any drift.

### Run Standard Pattern Detection Tests

```bash
# Run standard pattern detection (uses default config)
python tests/manual/manual_pattern_detection.py
```

## Test Coverage

### Time_t Math Operations

The extended `test_arithmetic_patterns.c` covers:

- **Basic arithmetic**: addition, subtraction, multiplication, division
- **Advanced operations**: modulo, bitwise, shifts
- **Compound assignments**: +=, -=, *=, /=
- **Contexts**: expressions, conditions, returns, loops
- **With structures**: arithmetic on struct members
- **With pointers**: arithmetic via pointers
- **Edge cases**: large constants, negative constants, overflow checks

### Embedded Time Fields

The `test_embedded_time_fields.c` covers:

- **Custom structs**: structs with time_t fields (signed and unsigned)
- **Multiple fields**: structs with multiple time_t fields
- **Nested structs**: time_t in nested structures
- **Arrays**: arrays of structs with time_t
- **Pointers**: pointers to structs with time_t
- **Unions**: time_t in unions
- **Bitfields**: time_t in bitfields (if supported)
- **Standard structs**: timespec, timeval usage
- **Explicit types**: int32_t, uint32_t as time fields
- **Serialization**: network packets, file headers, database records
- **Edge cases**: static/global structs, function parameters, return values

## Expected Results by Configuration

### ILP32 Signed 32-bit time_t

- **Y2038 Risk Patterns**: Should be classified as "yes"
  - Signed time_t arithmetic that could overflow before 2038
  - Structures with signed 32-bit time_t fields
  - Casts from time_t to narrower types

- **Y2106 Patterns**: Should be classified as "no" (not Y2038)
  - Unsigned time_t arithmetic
  - Structures with unsigned 32-bit time_t fields

### ILP32 Unsigned 32-bit time_t

- **Y2038 Risk Patterns**: Should be classified as "no" (Y2106, not Y2038)
  - All patterns should be classified as "no" since unsigned time_t overflows in 2106, not 2038

### LP64 Signed 64-bit time_t

- **Most Patterns**: Should be classified as "no" (Y2038 safe)
  - 64-bit time_t is safe from Y2038 issues
- **Narrowing Patterns**: Should be classified as "yes" (Y2038 risk)
  - Explicit casts to int32_t (e.g., `(int32_t)time(NULL)`)
  - Typedef of int32_t used to hold time_t
  - #define that narrows time_t to 32-bit
  - Struct members (int32_t) assigned time_t values
  - These patterns explicitly narrow 64-bit time_t to 32-bit, which is risky

### LP64 Unsigned 64-bit time_t

- **Most Patterns**: Should be classified as "no" (Y2038 safe)
  - 64-bit time_t is safe from Y2038 issues
- **Narrowing Patterns**: Should be classified as "yes" (Y2038 risk)
  - Same narrowing patterns as LP64 signed - explicit 32-bit narrowing is risky

## Pipeline Stage Verification

When using `--llm ollama`, the test framework verifies that all pipeline stages ran correctly:

### Stage 3: IR Candidate Discovery
- Verifies `ir/candidates.jsonl` exists and contains candidates
- This stage always runs (even with `--llm none`)

### Stage 8, Pass 2a: function-level analysis
- Verifies `llm/stage_8_pass_2a/batches/*_output.json` files exist
- Checks that the pass processed candidates
- Only runs when `--llm ollama` is used

### Stage 8, Pass 2b: widened context
- Verifies `llm/stage_8_pass_2b/batches/*_output.json` files exist
- Only runs if Pass 2a left abstains to enrich

### Stage 9, Pass 1: file-leading context
- Verifies `llm/stage_9_pass_1/batches/*_output.json` files exist
- Only runs if abstains remain after Stage 8

The line-level Stage S1 pre-filter is off by default, so a default run produces no
Stage S1 artifacts at all.

## Integration with Existing Tests

The multi-configuration test framework extends the existing test framework:

- Uses the same pattern detection logic from `tests/manual/manual_pattern_detection.py`
- Reuses the same test files and rules
- Adds environment configuration support
- Validates results across different configurations
- Adds full pipeline verification when using `--llm ollama`

## Configuration Details

### ILP32 Signed 32-bit time_t

```json
{
  "hardware_model": "ILP32",
  "time_t_size_bits": 32,
  "time_t_signed": "signed",
  "time64_functions_available": false,
  "d_time_bits_supported": false,
  "d_time_bits_setting": "not_available",
  "c_library": "picolibc",
  "scenario_hint": "ILP32-32bit-signed-time64_no-N/A",
  "mitigation_path": "upgrade_env"
}
```

### ILP32 Unsigned 32-bit time_t

```json
{
  "hardware_model": "ILP32",
  "time_t_size_bits": 32,
  "time_t_signed": "unsigned",
  "time64_functions_available": false,
  "d_time_bits_supported": false,
  "d_time_bits_setting": "not_available",
  "c_library": "picolibc",
  "scenario_hint": "ILP32-32bit-unsigned-time64_no-N/A",
  "mitigation_path": null
}
```

### LP64 Signed 64-bit time_t

```json
{
  "hardware_model": "LP64",
  "time_t_size_bits": 64,
  "time_t_signed": "signed",
  "time64_functions_available": true,
  "d_time_bits_supported": true,
  "d_time_bits_setting": "64",
  "c_library": "glibc",
  "scenario_hint": "LP64-64bit-signed-time64_yes-_TIME_BITS_64",
  "mitigation_path": null
}
```

### LP64 Unsigned 64-bit time_t

```json
{
  "hardware_model": "LP64",
  "time_t_size_bits": 64,
  "time_t_signed": "unsigned",
  "time64_functions_available": true,
  "d_time_bits_supported": true,
  "d_time_bits_setting": "64",
  "c_library": "glibc",
  "scenario_hint": "LP64-64bit-unsigned-time64_yes-_TIME_BITS_64",
  "mitigation_path": null
}
```

## Future Enhancements

- Add LLM classification validation (currently only checks detection)
- Add specific pattern expectations per configuration
- Add performance benchmarks per configuration
- Add regression tests for known issues
- Add tests for edge cases in environment configuration
