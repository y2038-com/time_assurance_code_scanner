# Y2038 Pattern Detection Tests

This directory contains comprehensive test files to verify that the Y2038 scanner correctly identifies all patterns it's designed to detect.

## Test Files

### C Test Files

1. **test_function_patterns.c** - Tests various time-related function calls
   - `time()`, `localtime()`, `gmtime()`, `mktime()`, etc.
   - Function calls in different contexts (return, assignment, condition, etc.)

2. **test_type_patterns.c** - Tests time_t type declarations
   - Variable declarations, pointers, arrays
   - Typedefs and type aliases
   - Related types (clock_t, timer_t, etc.)

3. **test_struct_patterns.c** - Tests time-related struct usage
   - `struct timespec` and `struct timeval` usage
   - Member access (tv_sec)
   - Safe patterns (struct tm only)

4. **test_arithmetic_patterns.c** - Tests time_t arithmetic operations
   - Y2038 risk patterns (signed time_t)
   - Y2106 patterns (unsigned time_t - should be NO)
   - Safe arithmetic

5. **test_cast_patterns.c** - Tests casts from time_t
   - Explicit casts from functions
   - Explicit casts from variables
   - Implicit casts via assignment

6. **test_comparison_patterns.c** - Tests time_t comparison operations
   - Equality, inequality, greater/less than
   - Comparisons with constants and variables

7. **test_storage_patterns.c** - Tests time_t storage and assignment
   - Direct assignment, array assignment
   - Struct member assignment
   - Pointer assignment

8. **test_function_definitions.c** - Tests function definitions with time_t
   - Functions returning time_t
   - Functions accepting time_t
   - Functions with time_t local variables

9. **test_safe_patterns.c** - Tests patterns that should NOT be flagged
   - struct tm only (no time_t)
   - Hardware operations
   - Non-time functions
   - Safe time_t usage (Y2106, not Y2038)

10. **test_edge_cases.c** - Tests edge cases and special scenarios

11. **test_narrowing_patterns.c** - Tests narrowing patterns that should fail even in LP64
    - Explicit casts to int32_t
    - Typedef of int32_t used to hold time_t
    - #define that creates narrow type aliases
    - Struct members assigned time_t values
    - Functions returning time_t stored in 32-bit members
    - Comments and strings
    - Preprocessor directives
    - Multiple patterns in one function
    - Nested patterns

12. **test_io_boundary_patterns.c** - Tests I/O-boundary patterns for Y2038/Y2106 risks
    - Formatted I/O (printf, scanf families) with format specifier mismatches
    - Raw I/O (read, write, memcpy, etc.) with time_t serialization/deserialization
    - Struct I/O with time-bearing fields (timespec, timeval, custom structs)
    - Explicit casts at I/O boundaries
    - Safe patterns (explicit conversions, text serialization)
    - External interface patterns (ioctl, network protocols, shared memory)
    - Size patterns (sizeof(time_t), literal widths)
    - Assignment tracking (variables from time functions used in I/O)
    - Edge cases (multiple I/O operations, nested calls, conditionals, loops)

13. **test_migration_patterns.c** - Tests migration analysis patterns
    - Migration 32→64 bit: Casts, sizeof, literal I/O, format specifiers
    - Migration signed→unsigned: Sign checks, negative constants, format specifiers
    - Migration ILP32→LP64: long type assumptions, struct padding
    - Combined migration scenarios (multiple config changes)
    - I/O boundary migration risks (network protocols, file formats, shared memory)
    - Safe migration patterns (portable code that doesn't break)

### Header File

11. **test_macro_patterns.h** - Tests #define macro patterns
    - time_type_alias
    - time_function_alias
    - time_constant
    - time_struct_alias
    - Complex macro patterns

### C++ Test File

12. **test_cpp_patterns.cpp** - Tests C++ specific patterns
    - Classes and member functions
    - Templates
    - Namespaces
    - Operator overloading
    - STL containers
    - Smart pointers
    - Lambda functions
    - std::chrono
    - C++11/14/17/20 features

## Running the Tests

### Automated Testing (Recommended)

Run the validation script to test all patterns:

```bash
python tests/patterns/test_pattern_detection.py
```

The script will:
1. Run the scanner on each test file (using `--llm none` for fast testing)
2. Verify expected patterns are detected as candidates (IR stage)
3. Report pass/fail status for each test
4. Provide a summary of results

**Note**: The script checks for **candidate detection** (patterns found), not LLM classification. Most patterns will be correctly classified as NO (Y2106, not Y2038) when using LLM analysis.

### Manual Testing

You can run the scanner manually on any test file:

```bash
# Fast test (no LLM, just detection)
python -m scanner.cli \
  --root tests/patterns \
  --rules configs/example.rules.json \
  --include "test_function_patterns.c" \
  --llm none \
  --out test_results.json

# Full test (with LLM classification)
python -m scanner.cli \
  --root tests/patterns \
  --rules configs/example.rules.json \
  --include "test_function_patterns.c" \
  --llm ollama \
  --out test_results.json
```

### Understanding Test Results

When running the automated tests:
- ✅ **PASS** means expected symbols were detected as candidates
- ❌ **FAIL** means expected symbols were not found
- The candidate count shows how many candidates were detected (may be higher than expected due to grouping)

When running with LLM (`--llm ollama`):
- Most patterns will be classified as **NO** (Y2106, not Y2038) - this is correct
- Only genuine Y2038 issues (signed time_t, overflow before 2038) will be classified as **YES**
- Safe patterns will be classified as **NO**

## Expected Results

### Detection Expectations

- **Function patterns**: Should detect all time-related function calls
- **Type patterns**: Should detect all time_t type declarations
- **Struct patterns**: Should detect struct timespec/timeval usage and tv_sec access
- **Arithmetic patterns**: Should detect time_t arithmetic (Y2038 vs Y2106 distinction)
- **Cast patterns**: Should detect casts from time_t functions/variables
- **Comparison patterns**: Should detect time_t comparisons
- **Storage patterns**: Should detect time_t assignments
- **Function definitions**: Should detect time_t in function signatures
- **Safe patterns**: Should NOT flag safe patterns (or flag as NO)
- **Edge cases**: Should handle edge cases correctly
- **Macro patterns**: Should detect #define patterns with time_t
- **C++ patterns**: Should detect C++ specific time_t usage

### Classification Expectations

When using LLM analysis (not `--llm none`):

- **Y2038 issues (YES)**: Only signed time_t patterns that overflow before 2038 (rare)
- **Y2106 issues (NO)**: 32-bit unsigned time_t patterns that overflow in 2106 (not Y2038)
- **Safe patterns (NO)**: struct tm only, hardware operations, non-time functions

## Test Coverage

The test suite covers:

- ✅ All function call patterns
- ✅ All type declaration patterns
- ✅ All struct usage patterns
- ✅ All arithmetic patterns
- ✅ All cast patterns
- ✅ All comparison patterns
- ✅ All storage/assignment patterns
- ✅ All function definition patterns
- ✅ Safe patterns (should not be flagged)
- ✅ Edge cases
- ✅ Macro patterns
- ✅ C++ specific patterns
- ✅ I/O-boundary patterns (formatted I/O, raw I/O, struct I/O, external interfaces)

## Adding New Tests

To add a new test pattern:

1. Add the pattern to the appropriate test file (or create a new one)
2. Update `EXPECTED_PATTERNS` in `test_pattern_detection.py` if needed
3. Run the validation script to verify detection
4. Document the pattern in this README

## Notes

- Some test files may not compile (e.g., Zephyr-specific functions, C++20 features)
- The scanner should still detect patterns even if code doesn't compile
- The validation script uses `--llm none` for fast testing
- For full LLM analysis testing, run scans manually with `--llm ollama`

## Troubleshooting

### Test fails but pattern exists in code

- Check that the pattern matches the scanner's detection rules
- Verify the symbol is in the rules file
- Check for typos or syntax issues in the test file

### Test passes but pattern not detected in real code

- Verify the real code matches the test pattern exactly
- Check for preprocessor directives that might hide the pattern
- Verify the scanner is configured correctly

### False positives in safe patterns

- Check that the pattern is truly safe (no time_t usage)
- Verify the LLM is correctly classifying as NO
- Check for edge cases that might trigger false detection
