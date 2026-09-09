# Test Commands for Y2038/Y2106 Scanner

This document provides ready-to-use commands for testing the scanner with test patterns.

## Quick Reference

All commands should be run from the project root: `/path/to/new_scan`

## 1. Basic Pattern Detection Tests (Fast - No LLM)

### Test All Pattern Files
```bash
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_*.c" \
  --include "test_*.cpp" \
  --include "test_*.h" \
  --llm none \
  --out test_all_patterns_results.json
```

**What this tests:**
- IR candidate discovery (Stage 3)
- Structural filtering (Stage 4)
- Basic pattern matching
- Typedef/macro discovery (Stage 2)

**Expected:** Many candidates detected, all classified as "abstain" (no LLM)

### Test Specific Pattern File
```bash
# Arithmetic patterns
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_arithmetic_patterns.c" \
  --llm none \
  --out test_arithmetic_results.json

# Cast patterns
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_cast_patterns.c" \
  --llm none \
  --out test_cast_results.json

# Narrowing patterns
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_narrowing_patterns.c" \
  --llm none \
  --out test_narrowing_results.json
```

## 2. I/O Boundary Analysis Tests

### Quick I/O Test (No LLM)
```bash
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_io_boundary_patterns.c" \
  --llm none \
  --io-analysis \
  --out test_io_results.json
```

**What this tests:**
- I/O function detection
- Format string parsing
- Time-bearing variable detection
- I/O candidate scoring
- Threshold filtering

### Full I/O Test (With LLM)
```bash
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_io_boundary_patterns.c" \
  --llm ollama \
  --io-analysis \
  --io-score-threshold 6.0 \
  --out test_io_full_results.json
```

**What this tests:**
- Everything from quick test, plus:
- LLM classification of I/O candidates
- I/O-specific prompt context
- Final findings with I/O metadata

### Inspect I/O Results
```bash
python tests/patterns/inspect_io_results.py test_io_results.json
```

## 3. Migration Analysis Tests

### Migration Test (ILP32 signed 32-bit → ILP32 signed 64-bit)
```bash
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_migration_patterns.c" \
  --migration-mode \
  --migration-from tests/patterns/env_configs/ilp32_signed_32bit.json \
  --migration-to tests/patterns/env_configs/ilp32_signed_64bit.json \
  --llm ollama \
  --out migration_test_results.json
```

### Migration Test (ILP32 → LP64)
```bash
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_migration_patterns.c" \
  --migration-mode \
  --migration-from tests/patterns/env_configs/ilp32_signed_32bit.json \
  --migration-to tests/patterns/env_configs/lp64_signed_64bit.json \
  --llm ollama \
  --out migration_ilp32_to_lp64_results.json
```

### Migration Test (Signed → Unsigned)
```bash
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_migration_patterns.c" \
  --migration-mode \
  --migration-from tests/patterns/env_configs/ilp32_signed_32bit.json \
  --migration-to tests/patterns/env_configs/ilp32_unsigned_32bit.json \
  --llm ollama \
  --out migration_signed_to_unsigned_results.json
```

## 4. Configuration-Specific Tests

### Test with ILP32 Signed 32-bit Config (Classic Y2038)
```bash
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_arithmetic_patterns.c" \
  --env-config tests/patterns/env_configs/ilp32_signed_32bit.json \
  --llm ollama \
  --out test_ilp32_signed_32bit_results.json
```

### Test with LP64 Signed 64-bit Config (Modern Safe)
```bash
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_arithmetic_patterns.c" \
  --env-config tests/patterns/env_configs/lp64_signed_64bit.json \
  --llm ollama \
  --out test_lp64_signed_64bit_results.json
```

**Expected:** Fewer "yes" findings (narrowing patterns only, not overflow)

## 5. Comprehensive Test Suite

### All Patterns with Full LLM Analysis
```bash
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_*.c" \
  --include "test_*.cpp" \
  --llm ollama \
  --io-analysis \
  --out comprehensive_test_results.json
```

**Note:** This will take longer and use more tokens. Consider testing individual files first.

## 6. Automated Test Scripts

### Pattern Detection Validation
```bash
cd tests/patterns
python test_pattern_detection.py
```

**What this tests:**
- Basic symbol detection (time_t, time(), etc.)
- Pattern file coverage
- IR stage functionality

### Quick I/O Test Script
```bash
cd tests/patterns
python test_io_quick.py
```

**What this tests:**
- I/O boundary detection
- Quick validation without LLM

## 7. Testing Specific Features

### Test Typedef Discovery
```bash
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_type_patterns.c" \
  --llm none \
  --out test_typedef_results.json
```

Check `results/discovery_report.json` for discovered typedefs.

### Test Macro Discovery
```bash
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_macro_patterns.h" \
  --llm none \
  --out test_macro_results.json
```

### Test Safe Patterns (Should NOT be flagged)
```bash
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_safe_patterns.c" \
  --llm ollama \
  --out test_safe_results.json
```

**Expected:** Most findings should be "no" (Y2106, not Y2038, or safe patterns)

## 8. Performance Testing

### Large Pattern File Test
```bash
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_arithmetic_patterns.c" \
  --llm ollama \
  --batch-size-func 15 \
  --out test_performance_results.json
```

Monitor:
- Processing time per stage
- Token usage
- Memory usage

## 9. Debugging Commands

### Show All Candidates (No Filtering)
```bash
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_arithmetic_patterns.c" \
  --llm none \
  --debug-candidates \
  --out test_debug_results.json
```

### Show LLM Prompts and Responses
```bash
python -m scanner.cli \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_arithmetic_patterns.c" \
  --llm ollama \
  --log-llm \
  --debug-llm-raw \
  --out test_debug_llm_results.json
```

Check `results/scans/` directory for LLM interaction logs.

## 10. Multi-Config Testing

### Test All 8 Configurations
```bash
cd tests/patterns
python test_multi_config.py
```

**What this tests:**
- Scanner behavior across all 8 config combinations
- Config detection accuracy
- Environment-aware analysis

## Recommended Testing Sequence

1. **Start with quick tests (no LLM):**
   ```bash
   python -m scanner.cli --root tests/patterns --rules tests/patterns/test_patterns_rules.json --include "test_arithmetic_patterns.c" --llm none --out quick_test.json
   ```

2. **Test I/O boundary detection:**
   ```bash
   python -m scanner.cli --root tests/patterns --rules tests/patterns/test_patterns_rules.json --include "test_io_boundary_patterns.c" --llm none --io-analysis --out io_test.json
   ```

3. **Test with LLM on one file:**
   ```bash
   python -m scanner.cli --root tests/patterns --rules tests/patterns/test_patterns_rules.json --include "test_arithmetic_patterns.c" --llm ollama --out llm_test.json
   ```

4. **Test migration analysis:**
   ```bash
   python -m scanner.cli --root tests/patterns --rules tests/patterns/test_patterns_rules.json --include "test_migration_patterns.c" --migration-mode --migration-from tests/patterns/env_configs/ilp32_signed_32bit.json --migration-to tests/patterns/env_configs/ilp32_signed_64bit.json --llm ollama --out migration_test.json
   ```

5. **Run comprehensive test:**
   ```bash
   python -m scanner.cli --root tests/patterns --rules tests/patterns/test_patterns_rules.json --include "test_*.c" --llm ollama --io-analysis --out comprehensive_test.json
   ```

## Checking Results

### View Results Summary
```bash
# Count findings by classification
jq '[.[] | .y2038_issue] | group_by(.) | map({issue: .[0], count: length})' test_results.json

# Count I/O findings
jq '[.[] | select(.io_category != null)] | length' test_results.json

# Count migration risks
jq '[.[] | select(.migration_risk_type != null)] | length' test_results.json
```

### Inspect Specific Findings
```bash
# View all "yes" findings
jq '[.[] | select(.y2038_issue == "yes")]' test_results.json

# View I/O findings
python tests/patterns/inspect_io_results.py test_results.json
```

## Tips

1. **Start small:** Test individual pattern files before running comprehensive tests
2. **Use `--llm none` first:** Verify candidate detection before spending tokens on LLM analysis
3. **Check intermediate results:** Look in `results/scans/` for detailed logs
4. **Monitor token usage:** Use `--token-budget` to control costs
5. **Compare configs:** Run same file with different configs to see environment-aware differences
