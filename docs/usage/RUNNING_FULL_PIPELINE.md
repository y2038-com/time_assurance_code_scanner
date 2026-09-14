# Running the Full Analysis Pipeline

Current CLI entrypoint: **`tacs scan`**. For a first local run without an LLM, see
[QUICK_START.md](../../QUICK_START.md).

## Overview

`tacs` supports two analysis approaches:

1. **Function-First Pipeline** (default): Analyzes complete functions with Stage S2 (function-level) Pass P1/P2 and Stage S3 (file-level) Pass P1
2. **Legacy Pipeline with Stage S1**: Single-line triage (Stage S1, Pass P1) followed by widened context (Stage S2, Pass P1) and file context (Stage S3, Pass P1)

LLM providers are **opt-in** (`--llm none` by default). Examples below that use
`--llm ollama` assume you have configured `OLLAMA_API_KEY` (and left `OLLAMA_HOST`
unset for Ollama Cloud) or set `OLLAMA_HOST` for a local daemon.

## Y2106 Detection

The scanner can detect both Y2038 and Y2106 issues when the `--detect-y2106` flag is enabled:

- **Y2038 issues**: 32-bit signed `time_t` overflow on January 19, 2038
- **Y2106 issues**: 32-bit unsigned `time_t` overflow on February 7, 2106

By default, only Y2038 issues are detected. When `--detect-y2106` is enabled:
- The scanner classifies findings with `issue_type` (y2038, y2106, both, none, abstain)
- Summary statistics show both Y2038 and Y2106 counts
- Findings include both `y2038_issue` and `y2106_issue` classifications

**Example with Y2106 detection:**
```bash
tacs scan \
  --root ~/git/wolfssl \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --llm ollama \
  --detect-y2106 \
  --env-config results/env_config.json \
  --out findings.json
```

**Output when Y2106 detection is enabled:**
```
Scan complete: 31 findings
  Y2038: 1 yes, 28 no, 0 abstain
  Y2106: 5 yes, 24 no, 0 abstain
  Total issues: 6 (1 Y2038, 5 Y2106)
```

**When to use Y2106 detection:**
- When your codebase uses 32-bit unsigned `time_t` (common in embedded systems)
- When you need to identify all time overflow issues, not just Y2038
- When fixing Y2038 by switching to unsigned `time_t` is a viable mitigation strategy
- Note: Enabling Y2106 detection will identify more issues, as unsigned `time_t` usage is common

## Running Function-First Pipeline (Default)

This is the default and recommended approach:

```bash
tacs scan \
  --root ~/git/wolfssl \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --include "**/*.c" \
  --include "**/*.h" \
  --exclude "**/doc/**" \
  --llm ollama \
  --model qwen3-coder:480b-cloud \
  --env-config results/env_config.json \
  --batch-size-func 10 \
  --confidence-floor 0.7 \
  --log-llm \
  --out findings.json
```

**Pipeline stages:**
- Stage 0: Environment Configuration
- Stage 1: Code Metrics
- Stage 2: Typedef/Macro Discovery
- Stage 3: IR Candidate Discovery
- Stage 4: Structural Filter
- Functionization (preparation)
- **Stage S2 (function-level), Pass P1**: Initial function analysis
- **Stage S2 (function-level), Pass P2**: Iterative enrichment
- **Stage S3 (file-level), Pass P1**: File-leading context

## Running Legacy Pipeline with Pass 1 (Single-Line Triage)

To enable the legacy pipeline with single-line Pass 1 analysis:

```bash
tacs scan \
  --root ~/git/wolfssl \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --include "**/*.c" \
  --include "**/*.h" \
  --exclude "**/doc/**" \
  --llm ollama \
  --model qwen3-coder:480b-cloud \
  --env-config results/env_config.json \
  --batch-size-stage1 100 \
  --confidence-floor 0.7 \
  --enable-stage1 \
  --no-function-first \
  --log-llm \
  --out findings.json
```

**Key flags:**
- `--enable-stage1`: Enables Stage S1 (single-line line-level analysis)
- `--no-function-first`: Disables function-first pipeline (uses legacy pipeline)
- `--batch-size-stage1 100`: Sets batch size to 100 candidates per Stage S1 request (default: 100)

**Pipeline stages:**
- Stage 0: Environment Configuration
- Stage 1: Code Metrics
- Stage 2: Typedef/Macro Discovery (time_t aliases passed to Stage S1, Pass P1)
- Stage 3: IR Candidate Discovery
- Stage 4: Structural Filter
- **Stage S1 (line-level), Pass P1**: Single-line triage
- **Stage S2 (function-level), Pass P1**: Widened context
- **Stage S3 (file-level), Pass P1**: File context

## Stage S1, Pass P1 Features

### Time_t Aliases

Stage S1, Pass P1 automatically receives all discovered time_t aliases from Stage 2 (typedef discovery). These are included in the LLM prompt so the model knows which types are equivalent to `time_t`.

**Example aliases that will be passed:**
- `wc_time_cb`
- `timestamp_t`
- `my_time_t`
- etc.

### Adaptive Batch Sizing

Stage S1, Pass P1 uses adaptive batch sizing to handle extremely long lines:

- **Default batch size**: 100 candidates
- **Long lines (>500 chars)**: Batch size reduced to 10-50 candidates
- **Very long lines (>1000 chars)**: Processed individually
- **Batch size limit**: Maximum ~50KB of text per batch

This ensures the LLM context window isn't exceeded even with very long lines.

### Batch Size Configuration

You can adjust the batch size:

```bash
--batch-size-stage1 100  # Default: 100 candidates per Stage S1 batch
--batch-size-stage1 50   # Smaller batches (more requests, less context per request)
--batch-size-stage1 150  # Larger batches (fewer requests, more context per request)
```

**Note:** The scanner will automatically reduce batch size if lines are extremely long to avoid context window errors.

## Verification

To verify that time_t aliases are being passed to Stage S1, Pass P1:

1. **Check discovery output:**
   ```
   [timestamp] Found 125 typedef aliases
   [timestamp] Passed 125 time_t aliases to LLM client for Stage S1, Pass P1
   ```

2. **Check Stage S1, Pass P1 prompt** (with `--debug-llm-raw`):
   ```bash
   --debug-llm-raw
   ```
   Look for "Known time_t aliases" section in the prompt.

3. **Check scan session logs:**
   ```bash
   cat results/scans/latest/scan_metadata.json | jq '.time_t_aliases'
   ```

## Performance Considerations

### Function-First vs Legacy Pipeline

- **Function-First**: Better for codebases with well-structured functions, provides more context
- **Legacy with Pass 1**: Better for quick triage, processes candidates line-by-line first

### Batch Size Trade-offs

- **Larger batches (100-150)**: Fewer LLM requests, faster overall, but higher risk of context window errors
- **Smaller batches (50-75)**: More LLM requests, slower overall, but safer for very long lines

### Recommended Settings

For most codebases:
```bash
--batch-size-stage1 100  # Good balance
```

For codebases with very long lines:
```bash
--batch-size-stage1 50   # More conservative
```

## Example: Full Pipeline with Pass 1

```bash
# Full analysis with Pass 1 enabled
tacs scan \
  --root ~/git/wolfssl \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --include "**/*.c" \
  --include "**/*.h" \
  --exclude "**/doc/**" \
  --llm ollama \
  --model qwen3-coder:480b-cloud \
  --env-config results/env_config.json \
  --batch-size-stage1 100 \
  --confidence-floor 0.7 \
  --enable-stage1 \
  --no-function-first \
  --log-llm \
  --out wolfssl_findings.json
```

**Expected output:**
```
[timestamp] Stage 2: Discovering typedefs and macros...
[timestamp] Found 125 typedef aliases
[timestamp] Passed 125 time_t aliases to LLM client for Stage S1, Pass P1
[timestamp] Running Stage S1 (line-level), Pass P1...
[timestamp] Processing batch of 100 candidates with ollama LLM...
[timestamp] LLM results: 5 yes, 90 no, 5 abstain
[timestamp] Stage S1, Pass P1: 10 survivors, 90 dropped
[timestamp] Running Stage S2 (function-level), Pass P1 (widened context)...
```

## Troubleshooting

### Stage S1 Not Running

If Stage S1 doesn't run, check:
1. `--enable-stage1` flag is set
2. `--no-function-first` flag is set (or `--function-first` is NOT set)
3. `--llm` is not set to `none`

### Time_t Aliases Not Appearing

If aliases aren't being passed:
1. Check that `--no-enable-discovery` is NOT set
2. Check discovery output for "Found X typedef aliases"
3. Look for "Passed X time_t aliases to LLM client for Pass 1" message

### Context Window Errors

If you see "prompt too long" errors:
1. Reduce `--batch-size-stage1` (e.g., to 50)
2. The scanner will automatically reduce batch size for long lines, but you can be more conservative
