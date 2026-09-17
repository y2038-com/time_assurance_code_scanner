# Configuration Detector Usage Guide

**Experimental.** Prefer an explicit `--env-config` for production scans. Auto-detect
is best-effort and often low-confidence.

## Overview

`tacs detect` (and the underlying `config_detector` package) analyzes build systems
(Makefiles, CMakeLists.txt) and scores likelihoods among the eight ABI/`time_t`
configurations.

## Quick Start

```bash
# Preferred public CLI
tacs detect /path/to/project
tacs detect /path/to/project --format text
tacs detect /path/to/project --out results/config_likelihoods.json

# Equivalent module entry (advanced / scripting)
python -m config_detector.cli /path/to/project --format json
```

## Example: Simple Embedded Project

Create a test Makefile:

```makefile
CC = arm-none-eabi-gcc
CFLAGS = -m32 -D_TIME_BITS=32 -Os
ARCH = arm
```

Run detection:

```bash
python -m config_detector.cli /path/to/project
```

Expected output:

```
Configuration Detection Results
==================================================

Project: /path/to/project
Detected: 2026-02-25 23:31:25 UTC

Likelihood Scores:
  ✓ ilp32_signed_32bit     85% (High confidence)
  ⚠ ilp32_unsigned_32bit   15% (Medium confidence)
  ✗ lp64_signed_64bit        0% (Ruled out: Architecture is ILP32, not LP64)
  ✗ lp64_unsigned_64bit      0% (Ruled out: Architecture is ILP32, not LP64)

Recommendation: Use ilp32_signed_32bit configuration

Evidence:
  - compiler_flag: -m32 (supports ilp32_signed_32bit, ilp32_unsigned_32bit)
  - compiler_flag: -D_TIME_BITS=32 (supports ilp32_signed_32bit, ilp32_unsigned_32bit)
  - toolchain: arm-none-eabi (supports ilp32_signed_32bit, ilp32_unsigned_32bit)
```

## Example: CMake Project

Create a test CMakeLists.txt:

```cmake
set(CMAKE_SYSTEM_PROCESSOR "aarch64")
set(CMAKE_C_FLAGS "-m64 -D_TIME_BITS=64")
```

Run detection:

```bash
python -m config_detector.cli /path/to/project
```

Expected output:

```
Configuration Detection Results
==================================================

Project: /path/to/project
Detected: 2026-02-25 23:31:25 UTC

Likelihood Scores:
  ✗ ilp32_signed_32bit        0% (Ruled out: Architecture is LP64, not ILP32)
  ✗ ilp32_unsigned_32bit      0% (Ruled out: Architecture is LP64, not ILP32)
  ✓ lp64_signed_64bit        90% (High confidence)
  ⚠ lp64_unsigned_64bit     10% (Low confidence)

Recommendation: Use lp64_signed_64bit configuration
```

## Integration with Scanner

Auto-detected configs are a convenience only — validate before trusting them.

```bash
# Step 1: Detect configuration (experimental)
tacs detect /path/to/project --out results/detected_config.json

# Step 2: Prefer converting / mapping to a real env_config JSON, then:
tacs scan \
  --root /path/to/code \
  --rules src/tacs/rules/y2038_sample_rules.json \
  --env-config configs/example.env_config.json \
  --llm none \
  --out findings.json
```

## What Gets Detected

### Architecture (ILP32 vs LP64)

**High Confidence Indicators:**
- `-m32` or `-m64` compiler flags
- `CMAKE_SYSTEM_PROCESSOR` variable

**Medium Confidence Indicators:**
- Toolchain names (`arm-none-eabi-*` → ILP32, `aarch64-*` → LP64)
- `-march=` flags (`armv7*` → ILP32, `x86_64` → LP64)

### time_t Size (32 vs 64 bits)

**High Confidence Indicators:**
- `-D_TIME_BITS=32` or `-D_TIME_BITS=64`

**Medium Confidence Indicators:**
- `-D_FILE_OFFSET_BITS=64` (hint for 64-bit)
- Architecture inference (LP64 → 64-bit, ILP32 → 32-bit)

## Limitations

- **time_t signedness**: Detected only from explicit defines and cflags such as
  `-D_TIME_T_UNSIGNED`; nothing is inferred from the architecture, so most
  projects leave it undetermined
- **C library**: Not detected from build files; supply it in an env config
- **Complex build systems**: Basic parsing only (Meson, Bazel not supported yet)
- **Conditional builds**: Not analyzed

## Troubleshooting

### "No build files found"

The detector couldn't find any Makefiles or CMakeLists.txt files. This could mean:
- The project uses a different build system (not yet supported)
- Build files are in a non-standard location
- The project path is incorrect

**Solution**: Manually create an environment config with `python scripts/run_env_wizard.py`,
or copy and edit one of the examples in `configs/`

### Low confidence scores

If all configurations show low confidence (25%), it means:
- No explicit architecture flags found
- No explicit time_t configuration found
- Detection is falling back to equal probability

**Solution**: The detector needs more explicit indicators. Check if your build files have:
- `-m32` or `-m64` flags
- `-D_TIME_BITS=32` or `-D_TIME_BITS=64` defines
- `CMAKE_SYSTEM_PROCESSOR` variable (for CMake)

## Possible future work

- Zephyr-specific parsing and C library detection from build files
- Signedness heuristics beyond explicit defines
- Code pattern analysis and a hardware/chip knowledge database

None of these are scheduled; prefer an explicit `--env-config` when the target is known.
