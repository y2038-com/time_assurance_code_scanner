# Narrowing Patterns Test

## Overview

The `test_narrowing_patterns.c` file contains test cases for patterns that should be classified as **YES (Y2038 risk)** even in LP64 configurations (64-bit systems). These patterns explicitly narrow 64-bit `time_t` values to 32-bit, which is a Y2038 risk regardless of the underlying system architecture.

## Why These Patterns Should Fail in LP64

Even though LP64 systems have 64-bit `time_t` (Y2038-safe), code that explicitly narrows `time_t` to 32-bit types is still risky because:

1. **Explicit narrowing loses precision** - Casting 64-bit `time_t` to `int32_t` truncates values
2. **Portability issues** - Code may be compiled on ILP32 systems where narrowing is even more dangerous
3. **Storage limitations** - Storing `time_t` in 32-bit fields will overflow in 2038
4. **Serialization risks** - Network/file formats using 32-bit time fields will break

## Test Patterns

### 1. Explicit Casts to int32_t

```c
// Should be YES in all configurations
int32_t narrow = (int32_t)time(NULL);
int32_t narrow = (int32_t)ts.tv_sec;
```

**Expected**: YES in all configurations (ILP32 and LP64)

### 2. Typedef of int32_t Used to Hold time_t

```c
typedef int32_t narrow_time_t;
narrow_time_t narrow = time(NULL);  // Should be YES
```

**Expected**: YES in all configurations

### 3. #define That Creates Narrow Type Alias

```c
#define NARROW_TIME_TYPE int32_t
NARROW_TIME_TYPE narrow = time(NULL);  // Should be YES
```

**Expected**: YES in all configurations

### 4. Struct Member Assigned time_t Value

```c
struct time_record {
    int32_t timestamp;  // 32-bit member
};
record.timestamp = time(NULL);  // Should be YES
```

**Expected**: YES in all configurations

### 5. Function Returning time_t Stored in 32-bit Member

```c
struct time_storage {
    int32_t stored_time;
};
storage.stored_time = time(NULL);  // Should be YES
return storage.stored_time;  // Should be YES
```

**Expected**: YES in all configurations

## Expected Results by Configuration

| Pattern | ILP32 Signed | ILP32 Unsigned | LP64 Signed | LP64 Unsigned |
|---------|--------------|----------------|-------------|---------------|
| Cast to int32_t | YES | YES | **YES** | **YES** |
| Typedef narrowing | YES | YES | **YES** | **YES** |
| #define narrowing | YES | YES | **YES** | **YES** |
| Struct member | YES | YES | **YES** | **YES** |
| Return narrowing | YES | YES | **YES** | **YES** |

**Key Point**: All narrowing patterns should be **YES** in **all** configurations, including LP64.

## Why This Matters

These tests verify that the scanner correctly identifies **explicit narrowing** as a Y2038 risk, even when the underlying system has 64-bit `time_t`. This is important because:

1. **Code portability** - Code may be compiled on different architectures
2. **Storage formats** - Network protocols, file formats, databases often use 32-bit time
3. **Explicit intent** - The code explicitly chooses 32-bit storage, which is risky
4. **Future-proofing** - Even if safe today, narrowing will fail in 2038

## Integration with Test Framework

The narrowing patterns are included in the multi-configuration test framework:

```bash
# Test narrowing patterns with all configurations
python tests/manual/manual_multi_config.py --llm ollama

# Quick test (one config, one file)
python tests/manual/manual_multi_config.py --llm ollama --limit-configs 1 --limit-files 1
```

The test framework will verify that:
- Patterns are detected (IR stage)
- Patterns are classified as YES in all configurations (LLM stage)
- LP64 configurations correctly identify narrowing as risky
