# Running I/O Boundary Tests

This guide explains how to test the I/O-boundary analyzer with the test patterns.

## Quick Test (Fast - No LLM)

Test I/O boundary detection without LLM classification:

```bash
cd /path/to/time_assurance_code_scanner
tacs scan \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_io_boundary_patterns.c" \
  --llm none \
  --io-analysis \
  --out test_io_results.json
```

**What this tests:**
- I/O function detection (printf, scanf, read, write, etc.)
- Time-bearing variable detection
- Format string parsing
- Raw I/O pattern matching
- Scoring and filtering

**Expected output:**
- Status messages showing "Stage 5: I/O boundary analysis..."
- Number of I/O-boundary candidates found
- Candidates above the score threshold

## Full Test (With LLM Classification)

Test with full LLM analysis to see how I/O candidates are classified:

```bash
tacs scan \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_io_boundary_patterns.c" \
  --llm ollama \
  --model gpt-oss:120b-cloud \
  --io-analysis \
  --io-score-threshold 6.0 \
  --out test_io_results.json
```

**What this tests:**
- Everything from quick test, plus:
- LLM classification of I/O-boundary candidates
- I/O-specific prompt context
- Final findings with I/O metadata

## Using the Automated Test Script

The automated test script will include the I/O test file, but it uses `--llm none`:

```bash
cd tests/patterns
python test_pattern_detection.py
```

**Note:** The automated script checks for basic symbol detection (time_t, time(), etc.) but doesn't specifically verify I/O-boundary candidates. For I/O-specific testing, use the manual commands above.

## Verifying I/O Candidates

After running a scan, check the results:

### 1. Check Console Output

Look for these messages:
```
Stage 5: I/O boundary analysis...
Found X files with I/O function calls
Found Y I/O-boundary candidates
I/O boundary analysis: Y candidates found, Z above threshold (6.0)
```

### 2. Check Results JSON

```bash
# View results
cat test_io_results.json | python -m json.tool | less

# Or use jq if available
cat test_io_results.json | jq '.findings[] | select(.io_category != null)'
```

Look for findings with:
- `io_category`: "formatted_io_mismatch", "raw_representation_risk", or "external_interface_risk"
- `io_function`: "printf", "scanf", "write", "read", etc.
- `remediation_class`: "manual_code_review" or "manual_interface_review_required"
- `io_score`: Score value (should be >= threshold)

### 3. Check Intermediate Results

The scanner saves intermediate results in the scan session folder:

```bash
# Find the latest scan session
ls -lt results/scan_*/

# Check candidates (includes I/O candidates)
cat results/scan_*/ir/candidates.jsonl | grep -i "io_boundary"

# Check LLM logs (if --log-llm was used)
cat results/scan_*/llm_logs/*.json | grep -i "io"
```

## Testing Specific Patterns

### Test Only Formatted I/O

Create a minimal test file with just formatted I/O patterns:

```c
// test_io_formatted.c
#include <time.h>
#include <stdio.h>

void test_printf_mismatch(void) {
    time_t t = time(NULL);
    printf("%d", t);  // Should flag
}
```

```bash
tacs scan \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_io_formatted.c" \
  --llm none \
  --io-analysis \
  --out test_formatted_results.json
```

### Test Only Raw I/O

Create a minimal test file with just raw I/O patterns:

```c
// test_io_raw.c
#include <time.h>
#include <unistd.h>

void test_write_time_t(void) {
    time_t t = time(NULL);
    write(1, &t, sizeof(t));  // Should flag
}
```

```bash
tacs scan \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_io_raw.c" \
  --llm none \
  --io-analysis \
  --out test_raw_results.json
```

## Adjusting Test Parameters

### Lower Score Threshold (More Candidates)

```bash
tacs scan \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_io_boundary_patterns.c" \
  --llm none \
  --io-analysis \
  --io-score-threshold 3.0 \  # Lower threshold
  --out test_io_results.json
```

### Disable Literal Width Checking

```bash
tacs scan \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_io_boundary_patterns.c" \
  --llm none \
  --io-analysis \
  --no-io-check-literal-widths \  # Disable literal width checks
  --out test_io_results.json
```

### Disable I/O Analysis (Baseline)

```bash
tacs scan \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_io_boundary_patterns.c" \
  --llm none \
  --no-io-analysis \  # Disable I/O analysis
  --out test_baseline_results.json
```

## Expected Results

### High Confidence Findings (Score >= 8.0)

- Format specifier mismatches with time-bearing arguments
- Raw I/O with `sizeof(time_t)` or `sizeof(time_t variable)`
- Raw I/O with literal widths matching time_t size
- I/O on structs containing time_t fields
- External interface boundaries (ioctl, network protocols)

### Medium Confidence Findings (Score 5.0-7.9)

- Variable format strings with time-bearing arguments
- Raw I/O with time-bearing variables (without explicit sizeof)
- I/O operations with explicit casts

### Should NOT Flag (Negative Score)

- Explicit safe conversions (int64_t, uint64_t)
- Text serialization (ISO-8601, explicit string formatting)
- Non-time data I/O
- I/O operations without time context

## Troubleshooting

### No I/O Candidates Found

1. **Check I/O analysis is enabled:**
   ```bash
   # Should see "Stage 5: I/O boundary analysis..." in output
   ```

2. **Check files contain I/O functions:**
   ```bash
   grep -E "(printf|scanf|read|write|memcpy)" tests/patterns/test_io_boundary_patterns.c
   ```

3. **Check time-bearing context:**
   - I/O analyzer requires time context (time_t, time(), etc.)
   - Without time context, candidates get negative scores and are filtered

4. **Lower score threshold:**
   ```bash
   --io-score-threshold 1.0  # Very low threshold for testing
   ```

### Too Many False Positives

1. **Raise score threshold:**
   ```bash
   --io-score-threshold 8.0  # Higher threshold
   ```

2. **Check time context:**
   - False positives often come from non-time I/O
   - Verify time-bearing detection is working

3. **Review scoring:**
   - Check `io_score` in results
   - Patterns without time context should have negative scores

### I/O Candidates Not Reaching LLM

1. **Check score threshold:**
   - Candidates below threshold are filtered before LLM
   - Lower threshold or check candidate scores

2. **Check LLM is enabled:**
   ```bash
   --llm ollama  # Not --llm none
   ```

3. **Check candidate count:**
   - Look for "X above threshold" message
   - If 0, no candidates passed threshold

## Example Test Session

```bash
# 1. Quick test (fast)
tacs scan \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_io_boundary_patterns.c" \
  --llm none \
  --io-analysis \
  --out test_io_quick.json

# 2. Check results
cat test_io_quick.json | jq '.findings | length'
cat test_io_quick.json | jq '.findings[] | select(.io_category != null) | {file, line, io_category, io_function, io_score}'

# 3. Full test with LLM (slower)
tacs scan \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_io_boundary_patterns.c" \
  --llm ollama \
  --io-analysis \
  --out test_io_full.json

# 4. Compare results
echo "Quick test findings:"
cat test_io_quick.json | jq '.findings | length'
echo "Full test findings:"
cat test_io_full.json | jq '.findings | length'
```

## Next Steps

After verifying basic functionality:

1. **Test with real codebases** - Run on actual projects with I/O operations
2. **Tune score thresholds** - Adjust based on false positive/negative rates
3. **Review LLM classifications** - Verify I/O candidates are correctly classified
4. **Check remediation guidance** - Ensure findings include helpful remediation info
