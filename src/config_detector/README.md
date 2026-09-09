# Configuration Detector

A separate Python utility that analyzes build systems and outputs likelihood scores for all eight possible environment configurations.

## Overview

Instead of enumerating all board/library combinations (which could be hundreds for complex RTOS projects), this utility:
- Analyzes build system files (Makefiles, CMakeLists.txt)
- Detects architecture (ILP32 vs LP64), time_t size (32-bit vs 64-bit), and time_t signedness (signed vs unsigned)
- Outputs likelihood scores (0.0-1.0) for each of the 8 possible configurations
- Rules out configurations that are clearly not applicable

## The Eight Possible Configurations

1. **ilp32_signed_32bit** - 32-bit architecture, 32-bit signed time_t (highest Y2038 risk)
2. **ilp32_signed_64bit** - 32-bit architecture, 64-bit signed time_t (Y2038 safe, but uncommon)
3. **ilp32_unsigned_32bit** - 32-bit architecture, 32-bit unsigned time_t (Y2106 risk)
4. **ilp32_unsigned_64bit** - 32-bit architecture, 64-bit unsigned time_t (Y2106 safe, but uncommon)
5. **lp64_signed_32bit** - 64-bit architecture, 32-bit signed time_t (Y2038 risk, but uncommon)
6. **lp64_signed_64bit** - 64-bit architecture, 64-bit signed time_t (Y2038 safe, most common for LP64)
7. **lp64_unsigned_32bit** - 64-bit architecture, 32-bit unsigned time_t (Y2106 risk, but uncommon)
8. **lp64_unsigned_64bit** - 64-bit architecture, 64-bit unsigned time_t (Y2106 risk)

## Usage

### Basic Usage (Keyword-Based Only)

```bash
# Human-readable output (keyword-based detection)
python -m config_detector.cli /path/to/project

# JSON output
python -m config_detector.cli /path/to/project --format json

# Save to file
python -m config_detector.cli /path/to/project --out results/config_likelihoods.json
```

### Hybrid Detection (Keyword + LLM)

```bash
# Enable LLM analysis (automatically triggered if confidence < 0.7)
python -m config_detector.cli /path/to/project --llm ollama --model qwen3-coder:480b-cloud

# Force LLM analysis even if confidence is high
python -m config_detector.cli /path/to/project --llm ollama --force-llm

# Keyword-only (disable LLM)
python -m config_detector.cli /path/to/project --keyword-only

# Non-interactive mode (auto-accept if high confidence)
python -m config_detector.cli /path/to/project --llm ollama --non-interactive

# Adjust confidence threshold for LLM triggering
python -m config_detector.cli /path/to/project --llm ollama --confidence-threshold 0.8

# Disable caching
python -m config_detector.cli /path/to/project --llm ollama --no-cache

# Debug mode (show LLM prompts/responses)
python -m config_detector.cli /path/to/project --llm ollama --debug
```

### Example Output

```
Configuration Detection Results
==================================================

Project: /path/to/project
Detected: 2026-02-25 23:31:25 UTC

Likelihood Scores:
  ✓ ilp32_signed_32bit     85% (High confidence)
  ⚠ ilp32_signed_64bit     12.5% (Low confidence)
  ⚠ ilp32_unsigned_32bit   15% (Medium confidence)
  ⚠ ilp32_unsigned_64bit   12.5% (Low confidence)
  ✗ lp64_signed_32bit        0% (Ruled out: Architecture is ILP32, not LP64)
  ✗ lp64_signed_64bit        0% (Ruled out: Architecture is ILP32, not LP64)
  ✗ lp64_unsigned_32bit      0% (Ruled out: Architecture is ILP32, not LP64)
  ✗ lp64_unsigned_64bit      0% (Ruled out: Architecture is ILP32, not LP64)

Recommendation: Use ilp32_signed_32bit configuration

Evidence:
  - cmake: CMAKE_SYSTEM_PROCESSOR=arm (supports ilp32_signed_32bit, ilp32_unsigned_32bit)
  - compiler_flag: -m32 (supports ilp32_signed_32bit, ilp32_unsigned_32bit)
```

## Phase 1 Features (Completed)

- ✅ Makefile parser (basic flag extraction)
- ✅ CMake parser (basic variable extraction)
- ✅ Architecture detection (ILP32 vs LP64 from flags, toolchain, processor)
- ✅ time_t size detection (explicit flags and architecture inference)
- ✅ time_t signedness detection (explicit flags and library defaults)
- ✅ Likelihood scoring for all 8 configurations
- ✅ Human-readable and JSON output formats

## Phase 2 Features (Completed)

- ✅ LLM-based analysis for complex build systems
- ✅ Hybrid approach: keyword-based first, LLM when needed
- ✅ Automatic LLM triggering based on confidence thresholds
- ✅ Caching of LLM results to avoid redundant analysis
- ✅ Validation of LLM responses against environment schema
- ✅ User review workflow (interactive and non-interactive modes)
- ✅ Full environment configuration detection (not just likelihoods)

## Future Enhancements

- **Phase 3**: Code pattern analysis, conditional build analysis, hardware/chip knowledge database

## Integration with Scanner

The scanner can use this utility:

```bash
# Auto-detect and use most likely config
python -m scanner.cli \
  --root /path/to/code \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --auto-detect-config
```

## Architecture

```
config_detector/
├── cli.py                    # CLI entry point
├── detector.py               # Phase 1: Keyword-based detection orchestrator
├── hybrid_detector.py         # Phase 2: Hybrid detector (keyword + LLM)
├── llm_analyzer.py          # Phase 2: LLM-based build file analysis
├── validator.py              # Phase 2: Configuration validation
├── cache.py                  # Phase 2: LLM result caching
├── build_parsers/            # Build system parsers
│   ├── base.py
│   ├── makefile.py
│   └── cmake.py
├── analyzers/                # Detection analyzers
│   ├── architecture.py       # ILP32 vs LP64 detection
│   └── time_t_config.py     # time_t size detection
└── output/                   # Output formatting
    └── likelihood.py         # Likelihood scoring and formatting
```
