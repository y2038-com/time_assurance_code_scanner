# Configuration Detector Usage Guide

## Overview

The `config_detector` utility automatically analyzes build systems (Makefiles, CMakeLists.txt) to determine the likelihood of each of the four main environment configurations.

## Quick Start

```bash
# Basic usage - analyze a project
python -m config_detector.cli /path/to/project

# JSON output
python -m config_detector.cli /path/to/project --format json

# Save results to file
python -m config_detector.cli /path/to/project --out results/config_likelihoods.json
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

The scanner can use auto-detected configurations:

```bash
# Step 1: Detect configuration
python -m config_detector.cli /path/to/project --out results/detected_config.json

# Step 2: Use detected config with scanner
python -m scanner.cli \
  --root /path/to/code \
  --rules scanner/rules/y2038_sample_rules.json \
  --env-config results/detected_config.json \
  --llm ollama \
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

## Limitations (Phase 1)

- **time_t signedness**: Not detected in Phase 1 (requires Phase 2)
- **C library**: Not detected in Phase 1 (requires Phase 2)
- **Complex build systems**: Basic parsing only (Meson, Bazel not supported yet)
- **Conditional builds**: Not analyzed (Phase 3)

## Troubleshooting

### "No build files found"

The detector couldn't find any Makefiles or CMakeLists.txt files. This could mean:
- The project uses a different build system (not yet supported)
- Build files are in a non-standard location
- The project path is incorrect

**Solution**: Manually create an environment config using `envui/cli/env_wizard.py`

### Low confidence scores

If all configurations show low confidence (25%), it means:
- No explicit architecture flags found
- No explicit time_t configuration found
- Detection is falling back to equal probability

**Solution**: The detector needs more explicit indicators. Check if your build files have:
- `-m32` or `-m64` flags
- `-D_TIME_BITS=32` or `-D_TIME_BITS=64` defines
- `CMAKE_SYSTEM_PROCESSOR` variable (for CMake)

## Next Steps

- **Phase 2**: Will add Zephyr-specific parsing, C library detection, and time_t signedness heuristics
- **Phase 3**: Will add code pattern analysis and hardware/chip knowledge database
