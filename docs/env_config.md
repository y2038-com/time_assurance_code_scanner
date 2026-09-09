# Y2038 Environment Configuration

This document explains the environment configuration fields used by the Y2038 vulnerability scanner and how they influence the scanning process.

## Overview

The Y2038 scanner requires detailed environment configuration to make accurate assessments about potential Year 2038 issues. The environment configuration determines:

- **Scenario-specific rule application**: Different architectures and time_t configurations require different detection rules
- **LLM prompt context**: The scanner provides environment details to LLM models for better context
- **Mitigation path requirements**: Some configurations require explicit mitigation strategies

## Configuration Fields

### Required Fields

#### `hardware_model`
- **Type**: `enum("ILP32", "LP64")`
- **Description**: Hardware architecture model
- **Examples**: 
  - `"ILP32"`: 32-bit int, long, pointer (common in embedded systems)
  - `"LP64"`: 32-bit int, 64-bit long, pointer (common in 64-bit Unix systems)

#### `time_t_size_bits`
- **Type**: `enum(32, 64)`
- **Description**: Size of time_t in bits
- **Examples**:
  - `32`: Standard 32-bit time_t (vulnerable to Y2038)
  - `64`: 64-bit time_t (Y2038-safe)

#### `time_t_signed`
- **Type**: `enum("signed", "unsigned")`
- **Description**: Whether time_t is signed or unsigned
- **Examples**:
  - `"signed"`: Most common, wraps around in 2038
  - `"unsigned"`: Less common, wraps around in 2106

#### `time64_functions_available`
- **Type**: `boolean`
- **Description**: Whether time64 functions (like `time64_t`, `clock_gettime64`) are available
- **Examples**:
  - `true`: Modern glibc with time64 support
  - `false`: Older systems or embedded libraries without time64

#### `d_time_bits_supported`
- **Type**: `boolean`
- **Description**: Whether `_TIME_BITS` macro is supported
- **Examples**:
  - `true`: glibc 2.34+ supports `_TIME_BITS=64`
  - `false`: Older glibc or other C libraries

#### `d_time_bits_setting`
- **Type**: `enum("not_available", "not_set", "32", "64")`
- **Description**: Current `_TIME_BITS` setting
- **Examples**:
  - `"not_available"`: When `d_time_bits_supported=false`
  - `"not_set"`: `_TIME_BITS` not defined
  - `"64"`: `_TIME_BITS=64` defined

#### `c_library`
- **Type**: `enum("glibc", "newlib", "picolibc", "musl", "minimal", "libstdc++", "other")`
- **Description**: C library implementation
- **Examples**:
  - `"glibc"`: GNU C Library (Linux)
  - `"picolibc"`: Lightweight C library (embedded)
  - `"musl"`: Musl libc (Alpine Linux)

### Optional Fields

#### `os_or_rtos`
- **Type**: `string`
- **Description**: Operating system or RTOS name and version
- **Examples**: `"Zephyr 3.7"`, `"Linux 5.4"`, `"FreeRTOS 10.0"`

#### `c_library_other_text`
- **Type**: `string`
- **Description**: Description when `c_library="other"`
- **Examples**: `"Custom embedded C library"`

#### `toolchain_flags`
- **Type**: `string[]`
- **Description**: Toolchain compilation flags
- **Examples**: `["-D_FILE_OFFSET_BITS=64", "-D_TIME_BITS=64"]`

#### `notes`
- **Type**: `string`
- **Description**: Additional notes about the environment
- **Examples**: `"board XYZ"`, `"specific configuration notes"`

### Derived Fields

#### `scenario_hint`
- **Type**: `enum(...)`
- **Description**: Automatically derived scenario identifier
- **Values**:
  - `"LP64-64bit-N/A"`: LP64 with 64-bit time_t
  - `"ILP32-64bit-N/A"`: ILP32 with 64-bit time_t
  - `"ILP32-32bit-unsigned-time64_yes"`: ILP32, 32-bit unsigned time_t, time64 available
  - `"ILP32-32bit-unsigned-time64_no"`: ILP32, 32-bit unsigned time_t, no time64
  - `"ILP32-32bit-signed-time64_yes"`: ILP32, 32-bit signed time_t, time64 available
  - `"ILP32-32bit-signed-time64_no"`: ILP32, 32-bit signed time_t, no time64

#### `mitigation_path`
- **Type**: `enum("upgrade_env", "stay_and_patch") | null`
- **Description**: Required mitigation strategy for risky scenarios
- **Values**:
  - `"upgrade_env"`: Upgrade to 64-bit time_t environment
  - `"stay_and_patch"`: Stay with 32-bit time_t but patch code
  - `null`: No mitigation required

## Validation Rules

The configuration must satisfy these business rules:

1. **`_TIME_BITS` consistency**: If `d_time_bits_supported=false`, then `d_time_bits_setting` must be `"not_available"`
2. **`_TIME_BITS` availability**: If `d_time_bits_supported=true`, then `d_time_bits_setting` cannot be `"not_available"`
3. **C library other**: If `c_library="other"`, then `c_library_other_text` must be non-empty
4. **Mitigation requirement**: If `scenario_hint="ILP32-32bit-signed-time64_no"`, then `mitigation_path` is required
5. **Toolchain flags format**: Must match pattern `^(-{1,2}[A-Za-z0-9_][A-Za-z0-9_-]*(=.+)?|-[DU][A-Za-z0-9_]+(=.+)?)$`

## How the Scanner Uses Configuration

### LLM Prompt Context

The scanner includes environment details in LLM prompts to provide context:

```
Environment: ILP32, time_t=32 signed, time64=no, _TIME_BITS=supported:64, c_lib=picolibc
```

### Deterministic Rule Application

Different scenarios trigger different detection rules:

- **LP64-64bit-N/A**: Focus on legacy code patterns, less strict about time_t usage
- **ILP32-32bit-signed-time64_no**: Most strict, requires mitigation path
- **ILP32-32bit-unsigned-time64_***: Moderate strictness, unsigned time_t extends range

### Mitigation Path Enforcement

For the risky `ILP32-32bit-signed-time64_no` scenario, the scanner:

1. Requires explicit `mitigation_path` configuration
2. Applies stricter detection rules
3. Flags findings that require immediate attention
4. Provides mitigation-specific recommendations

## CLI Usage

### Interactive Mode

```bash
python envui/cli/env_wizard.py --out results/env_config.json --print-summary
```

This walks through prompts for each field and writes a validated configuration.

### Non-Interactive Mode

```bash
python envui/cli/env_wizard.py --non-interactive envui/examples/env_config.sample.json --out results/env_config.json --print-summary --log-cli
```

This validates and normalizes an existing JSON configuration.

### Example Output

```
Summary: ILP32, time_t=32 signed, time64=no, _TIME_BITS=supported:64, c_lib=picolibc
```

## Integration with Scanner

The scanner reads the environment configuration and:

1. **Stage 0**: Validates scenario and applies mitigation requirements
2. **Stage 1-3**: Uses environment context for candidate discovery
3. **Stage 4**: Applies scenario-specific structural filtering
4. **Stage 5-7**: Includes environment details in LLM prompts
5. **Stage 8-11**: Uses scenario context for final assessment

This ensures that Y2038 detection is accurate and actionable for the specific target environment.
