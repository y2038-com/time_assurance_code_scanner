# Migration Test Patterns

This document describes the migration test patterns in `test_migration_patterns.c`.

## Overview

The migration test patterns cover scenarios where code would break or cause issues when migrating from one environment configuration to another. These patterns are detected by the migration analyzer when `--migration-mode` is enabled.

## Test Categories

### 1. Migration: 32-Bit → 64-Bit time_t

These patterns assume 32-bit time_t and would break when migrating to 64-bit time_t:

- **Explicit casts to 32-bit types**: `(int32_t)time_value`, `(int)time_value`
- **sizeof() assumptions**: `sizeof(int32_t)` used for time_t
- **Literal 4-byte I/O**: `read(fd, &t, 4)`, `write(fd, &t, 4)`
- **Format specifier mismatches**: `printf("%d", t)`, `scanf("%d", &t)`
- **Raw struct I/O**: Structs with time_t fields written with fixed-size assumptions
- **memcpy with fixed size**: `memcpy(buf, &t, 4)`

### 2. Migration: Signed → Unsigned time_t

These patterns assume signed time_t and would break when migrating to unsigned time_t:

- **Sign checks**: `if (t < 0)`, `if (t <= -1)`, `if (t == -1)`
- **Negative constants**: `time_t t = -1;`, `time_t error = -1L;`
- **Format specifier sign mismatches**: `printf("%d", t)` vs `printf("%u", t)`
- **Comparisons with negative values**: `if (t > -1)`, `if (t != -1)`

### 3. Migration: ILP32 → LP64 (Architecture Change)

These patterns assume ILP32 architecture and would change behavior in LP64:

- **long type assumptions**: `long x = (long)t;` (32-bit in ILP32, 64-bit in LP64)
- **Format specifier width changes**: `printf("%ld", t)` (width changes)
- **Struct padding changes**: Structs with time_t fields may have different padding

### 4. Combined Migration Scenarios

These patterns test multiple config changes at once:

- **ILP32 signed 32-bit → ILP32 signed 64-bit**: Width change only
- **ILP32 signed 32-bit → ILP32 unsigned 32-bit**: Signedness change only
- **ILP32 signed 32-bit → LP64 signed 64-bit**: Architecture + width change
- **LP64 signed 64-bit → ILP32 signed 64-bit**: Architecture change (rare)

### 5. I/O Boundary Migration Risks

These patterns test I/O operations that would break during migration:

- **Network protocols**: Fixed-width time_t in network packets
- **File formats**: Fixed-width time_t in binary file formats
- **Shared memory**: Fixed-width time_t in shared memory structures
- **Device I/O**: Fixed-width time_t in device I/O operations

### 6. Safe Migration Patterns

These patterns should NOT be flagged as migration risks:

- **Uses sizeof(time_t)**: Portable code that uses `sizeof(time_t)`
- **Explicit conversion to fixed-width**: `int64_t wire_value = (int64_t)t;`
- **Text serialization**: ISO-8601, strftime, etc.
- **No assumptions**: Code that doesn't assume specific width/sign
- **Portable format specifiers**: Using `%lld` with explicit `long long` cast

## Expected Results

When running with `--migration-mode`:

- **Migration blockers** (severity: blocker): Would prevent migration
  - Explicit casts to old width/sign
  - Sign checks assuming old signedness
  - Literal I/O sizes assuming old width

- **Migration risks** (severity: high_risk/medium_risk): Would cause issues
  - Format specifier mismatches
  - Struct layout changes
  - Architecture assumptions

- **Safe patterns**: Should NOT be flagged
  - Portable code using sizeof(time_t)
  - Explicit conversions to fixed-width types
  - Text serialization

## Usage

To test migration patterns:

```bash
# Create migration config files
python3 tests/patterns/test_config_fixtures.py

# Run migration analysis
tacs scan \
  --root tests/patterns \
  --rules tests/patterns/test_patterns_rules.json \
  --include "test_migration_patterns.c" \
  --migration-mode \
  --migration-from tests/patterns/env_configs/ilp32_signed_32bit.json \
  --migration-to tests/patterns/env_configs/ilp32_signed_64bit.json \
  --llm ollama \
  --out migration_results.json
```

## Test Coverage

The migration test patterns cover:

- ✅ Width assumption patterns (32→64 bit)
- ✅ Signedness assumption patterns (signed→unsigned)
- ✅ Architecture assumption patterns (ILP32→LP64)
- ✅ I/O boundary migration risks
- ✅ Combined migration scenarios
- ✅ Safe migration patterns (should not be flagged)
