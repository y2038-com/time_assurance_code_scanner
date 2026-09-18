# Environment configuration (`--env-config`)

This document explains the environment configuration fields used by **TACS**
(`tacs scan --env-config …`) and how they influence time-assurance analysis
(Y2038 / Y2106 class risks).

## Overview

Scans are only as meaningful as the assumed ABI/`time_t` model. The environment configuration determines:

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
- **Type**: `boolean | null`
- **Description**: Whether time64 functions (like `time64_t`, `clock_gettime64`) are available
- **Examples**:
  - `true`: Modern glibc with time64 support
  - `false`: Known to be absent, e.g. an embedded library you have inspected
  - `null`: Unknown — nothing in the available evidence settles it

#### `d_time_bits_supported`
- **Type**: `boolean | null`
- **Description**: Whether `_TIME_BITS` macro is supported
- **Examples**:
  - `true`: glibc 2.34+ supports `_TIME_BITS=64`
  - `false`: Known to be absent, e.g. an older glibc or a C library you have inspected
  - `null`: Unknown — nothing in the available evidence settles it

#### `d_time_bits_setting`
- **Type**: `enum("unknown", "not_available", "not_set", "32", "64")`
- **Description**: Current `_TIME_BITS` setting
- **Examples**:
  - `"unknown"`: Not established; use this when `d_time_bits_supported` is `null`
  - `"not_available"`: When `d_time_bits_supported=false`
  - `"not_set"`: `_TIME_BITS` not defined
  - `"64"`: `_TIME_BITS=64` defined

##### Unknown vs. unavailable

The two capability fields are tri-state, because an ABI does not imply what a C
library ships. A 64-bit `time_t` does not put time64 entry points in the library,
and no `time_t` width implies `_TIME_BITS` support. `false` and `"not_available"`
are claims that a feature is absent; write them only when you know. When you do
not, write `null` and `"unknown"` — a scan reasons differently about a feature
that is missing than about one nobody checked, and the LLM prompt says which it
is. Omitting a capability field is read the same way as `null`.

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
- **Type**: `string` matching
  `^(ILP32|LP64)-(32|64)bit(-(signed|unsigned))?(-time64_(yes|no|unknown))?(-(N/A|_TIME_BITS_(32|64|not_set|unknown)))?$`
- **Description**: Automatically derived scenario identifier, composed left to
  right from the dimensions the config already carries:
  `<hardware_model>-<time_t bits>bit[-<signedness>][-time64_<yes|no|unknown>][-<N/A|_TIME_BITS_<setting>>]`.
  The schema constrains the shape with a pattern rather than listing the
  products, because the hint is assembled by several generators and a
  hand-maintained list drifts from them.
- **Examples**:
  - `"LP64-64bit-N/A"`: LP64 with 64-bit time_t
  - `"ILP32-64bit-N/A"`: ILP32 with 64-bit time_t
  - `"ILP32-32bit-unsigned-time64_yes"`: ILP32, 32-bit unsigned time_t, time64 available
  - `"ILP32-32bit-signed-time64_no"`: ILP32, 32-bit signed time_t, no time64
  - `"ILP32-32bit-signed-time64_unknown"`: ILP32, 32-bit signed time_t, time64 availability not established
  - `"LP64-64bit-signed-time64_yes-_TIME_BITS_64"`: with the optional `_TIME_BITS` tail

The hint is a label. Scan logic reads the structured ABI fields
(`hardware_model`, `time_t_size_bits`, `time_t_signed`,
`time64_functions_available`) rather than parsing this string.

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
2. **`_TIME_BITS` availability**: If `d_time_bits_supported=true`, then `d_time_bits_setting` cannot be `"not_available"` (`"unknown"` is allowed: support can be known while the build's setting is not)
3. **`_TIME_BITS` unknown**: If `d_time_bits_supported` is `null` or omitted, then `d_time_bits_setting` cannot be `"not_available"`; use `"unknown"`
4. **C library other**: If `c_library="other"`, then `c_library_other_text` must be non-empty
5. **Mitigation requirement**: If `scenario_hint` begins with `"ILP32-32bit-signed-time64_no"` or `"ILP32-32bit-signed-time64_unknown"` (any trailing `_TIME_BITS` segment included), then `mitigation_path` is required and cannot be `null`. Unknown time64 availability counts here because the risk a mitigation would address has not been ruled out
6. **Toolchain flags format**: Must match pattern `^(-{1,2}[A-Za-z0-9_][A-Za-z0-9_-]*(=.+)?|-[DU][A-Za-z0-9_]+(=.+)?)$`

## How the Scanner Uses Configuration

### LLM Prompt Context

The scanner includes environment details in LLM prompts to provide context:

```
- time64 functions: not available
- _TIME_BITS: supported (setting: 64)
```

Each capability reaches the model in its own state, and the prompt tells the
model that an unknown is undetermined rather than absent:

```
- time64 functions: unknown (not established by the environment evidence)
- _TIME_BITS: support unknown (not established by the environment evidence) (setting: unknown)
```

### Deterministic Rule Application

Different scenarios trigger different detection rules:

- **LP64-64bit-N/A**: Focus on legacy code patterns, less strict about time_t usage
- **ILP32-32bit-signed-time64_no** and **ILP32-32bit-signed-time64_unknown**: Most strict, requires mitigation path
- **ILP32-32bit-unsigned-time64_***: Moderate strictness, unsigned time_t extends range

### Mitigation Path Enforcement

For the risky `ILP32-32bit-signed-time64_no` and `ILP32-32bit-signed-time64_unknown`
scenarios, the scanner:

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

This keeps Y2038 detection grounded in the declared target environment so
results are more actionable for that ABI / `time_t` model.

## Failure behavior

`--env-config` is optional to supply, but not optional to get right. A config that
cannot be read, is not valid JSON, or does not describe one of the supported target
environments fails the scan with a message naming the file. No findings are written.

The alternative would be worse: since `time_t` width and signedness decide whether an
expression overflows at all, continuing without the requested environment would report
findings for a different target than the one asked for. Omitting `--env-config`
entirely remains valid and scans with no declared environment.

`tacs repos` resolves a config per repository and records it in the run's
`env_config.json`, so the same contract applies there.
