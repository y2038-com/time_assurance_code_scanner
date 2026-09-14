# I/O Boundary Test Patterns

This document describes the I/O-boundary test patterns in `test_io_boundary_patterns.c` and what they test.

## Overview

The I/O-boundary analyzer detects Y2038/Y2106 risks at I/O interfaces, including:
- Format specifier mismatches in printf/scanf families
- Raw binary serialization/deserialization of time_t
- I/O operations on structs containing time-bearing fields
- External interface boundaries (devices, protocols, shared memory)

## Test Categories

### 1. Formatted I/O Patterns (Format Specifier Mismatches)

These tests verify detection of format specifier mismatches that could cause Y2038/Y2106 issues:

- **`test_printf_d_mismatch`**: `printf("%d", time_t)` - 32-bit signed specifier on potentially 64-bit time_t
- **`test_printf_u_mismatch`**: `printf("%u", time_t)` - 32-bit unsigned specifier on signed time_t
- **`test_printf_ld_potential`**: `printf("%ld", time_t)` - Long specifier (32-bit in ILP32, 64-bit in LP64)
- **`test_printf_lld_mismatch`**: `printf("%lld", time_t)` - 64-bit specifier on potentially 32-bit time_t
- **`test_fprintf_mismatch`**: `fprintf(fp, "%d", time_t)` - Format mismatch in fprintf
- **`test_sprintf_mismatch`**: `sprintf(buf, "%u", time_t)` - Format mismatch in sprintf
- **`test_snprintf_mismatch`**: `snprintf(buf, size, "%d", time_t)` - Format mismatch in snprintf
- **`test_scanf_d_mismatch`**: `scanf("%d", &time_t)` - Format mismatch in scanf
- **`test_fscanf_mismatch`**: `fscanf(fp, "%u", &time_t)` - Format mismatch in fscanf
- **`test_sscanf_mismatch`**: `sscanf(str, "%d", &time_t)` - Format mismatch in sscanf
- **`test_printf_correct_format`**: Correct format specifier (should have lower confidence)
- **`test_printf_variable_format`**: Variable format string (should have lower confidence)

### 2. Raw I/O Patterns (Binary Serialization Risks)

These tests verify detection of raw binary I/O operations that could break with ABI changes:

- **`test_write_sizeof_time_t`**: `write(fd, &t, sizeof(t))` - Raw serialization of time_t
- **`test_write_sizeof_explicit`**: `write(fd, &t, sizeof(time_t))` - Explicit sizeof(time_t)
- **`test_read_sizeof_time_t`**: `read(fd, &t, sizeof(t))` - Raw deserialization into time_t
- **`test_read_literal_4`**: `read(fd, &t, 4)` - Fixed 4-byte assumption (32-bit)
- **`test_read_literal_8`**: `read(fd, &t, 8)` - Fixed 8-byte assumption (64-bit)
- **`test_fwrite_time_t`**: `fwrite(&t, sizeof(t), 1, fp)` - File write of time_t
- **`test_fread_time_t`**: `fread(&t, sizeof(t), 1, fp)` - File read into time_t
- **`test_memcpy_time_t`**: `memcpy(buf, &t, sizeof(t))` - Memory copy of time_t
- **`test_memcpy_into_time_t`**: `memcpy(&t, buf, sizeof(t))` - Memory copy into time_t
- **`test_memmove_time_t`**: `memmove(buf, &t, sizeof(t))` - Memory move of time_t
- **`test_send_time_t`**: `send(sock, &t, sizeof(t), 0)` - Network send of time_t
- **`test_recv_time_t`**: `recv(sock, &t, sizeof(t), 0)` - Network receive into time_t
- **`test_pread_time_t`**: `pread(fd, &t, sizeof(t), 0)` - Positional read into time_t
- **`test_pwrite_time_t`**: `pwrite(fd, &t, sizeof(t), 0)` - Positional write of time_t

### 3. Struct Patterns (Time-bearing Structs in I/O)

These tests verify detection of I/O operations on structs containing time_t fields:

- **`test_fwrite_struct_with_time`**: `fwrite(&record, sizeof(record), 1, fp)` where record contains time_t
- **`test_fread_struct_with_time`**: `fread(&record, sizeof(record), 1, fp)` where record contains time_t
- **`test_write_timespec`**: `write(fd, &ts, sizeof(ts))` where ts is struct timespec
- **`test_read_timespec`**: `read(fd, &ts, sizeof(ts))` where ts is struct timespec
- **`test_memcpy_timeval`**: `memcpy(buf, &tv, sizeof(tv))` where tv is struct timeval

### 4. Explicit Cast Patterns (Casts at I/O Boundary)

These tests verify detection of explicit casts that increase risk:

- **`test_write_with_cast`**: Explicit cast before write (increases risk)
- **`test_read_with_cast`**: Explicit cast to narrow type before read (high risk)

### 5. Safe Patterns (Should NOT be flagged)

These tests verify that safe patterns are not flagged (or flagged with low confidence):

- **`test_safe_int64_conversion`**: Explicit conversion to int64_t before I/O (safe)
- **`test_safe_text_serialization`**: Text serialization with ISO-8601 format (safe)
- **`test_safe_decimal_string`**: Explicit decimal string conversion (safe)
- **`test_io_non_time_data`**: I/O on non-time data (should not flag)
- **`test_printf_non_time`**: printf with non-time integer (should not flag)

### 6. External Interface Patterns (Device/Protocol Boundaries)

These tests verify detection of external interface boundaries:

- **`test_ioctl_time_t`**: ioctl() with time_t (device I/O - high risk)
- **`test_network_protocol_time`**: Network protocol struct with time_t (protocol boundary)
- **`test_shm_time_t`**: Shared memory with time_t (shared memory boundary)

### 7. Size Patterns (Suspicious Size Arguments)

These tests verify detection of sizeof() patterns:

- **`test_sizeof_time_t_var`**: `sizeof(t)` where t is time_t variable
- **`test_sizeof_time_t_type`**: `sizeof(time_t)` explicit type
- **`test_sizeof_typedef_alias`**: `sizeof(alias)` where alias is time_t typedef

### 8. Assignment Tracking Patterns (Time Function Assignments)

These tests verify enhanced detection of variables assigned from time functions:

- **`test_time_assignment_io`**: Variable assigned from `time()` then used in I/O
- **`test_gettimeofday_assignment_printf`**: Variable from `gettimeofday()` then used in printf
- **`test_localtime_assignment_io`**: Variable from `localtime()`/`mktime()` then used in I/O

### 9. Edge Cases

These tests verify handling of edge cases:

- **`test_multiple_io_operations`**: Multiple I/O operations with same time_t
- **`test_nested_io_calls`**: Nested I/O calls
- **`test_io_in_conditional`**: I/O in conditional statement
- **`test_io_in_loop`**: I/O in loop

## Expected Detection Behavior

### High Confidence Findings

- Format specifier mismatches (width or sign) with time-bearing arguments
- Raw I/O with `sizeof(time_t)` or `sizeof(time_t variable)`
- Raw I/O with literal widths (4 or 8) matching time_t size
- I/O on structs containing time_t fields
- External interface boundaries (ioctl, network protocols)

### Medium Confidence Findings

- Variable format strings with time-bearing arguments
- Raw I/O with time-bearing variables (without explicit sizeof)
- I/O operations with explicit casts

### Low Confidence / Should NOT Flag

- Explicit safe conversions (int64_t, uint64_t with documented schema)
- Text serialization (ISO-8601, explicit string formatting)
- Non-time data I/O
- I/O operations without time context

## Testing

Run the test file with the scanner:

```bash
# Fast test (no LLM, just detection)
tacs scan \
  --root tests/patterns \
  --rules configs/example.rules.json \
  --include "test_io_boundary_patterns.c" \
  --llm none \
  --io-analysis \
  --out test_io_results.json

# Full test (with LLM classification)
tacs scan \
  --root tests/patterns \
  --rules configs/example.rules.json \
  --include "test_io_boundary_patterns.c" \
  --llm ollama \
  --io-analysis \
  --io-score-threshold 6.0 \
  --out test_io_results.json
```

## Notes

- The I/O-boundary analyzer requires `--io-analysis` flag (enabled by default)
- Score threshold can be adjusted with `--io-score-threshold` (default: 6.0)
- I/O findings are merged with regular candidates and sent to LLM escalation
- I/O metadata is preserved separately and included in LLM prompts for enhanced analysis
