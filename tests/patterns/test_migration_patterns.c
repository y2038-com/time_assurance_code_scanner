// Test file for migration analysis patterns
// This file tests patterns that would break or cause issues during config migration
// Migration scenarios: 32→64 bit, signed→unsigned, ILP32→LP64

#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>

// ============================================================================
// MIGRATION: 32-BIT → 64-BIT TIME_T
// ============================================================================

// Migration blocker: Explicit cast to 32-bit type
void migration_32_to_64_cast_blocker(void) {
    time_t t = time(NULL);
    int32_t x = (int32_t)t;  // MIGRATION BLOCKER: Assumes 32-bit time_t
    int y = (int)t;           // MIGRATION BLOCKER: Assumes 32-bit time_t
    long z = (long)t;         // MIGRATION BLOCKER: In ILP32, long is 32-bit
}

// Migration blocker: sizeof() assumption
void migration_32_to_64_sizeof_blocker(void) {
    time_t t = time(NULL);
    char buf[4];  // MIGRATION BLOCKER: Assumes 4-byte time_t
    memcpy(buf, &t, sizeof(int32_t));  // MIGRATION BLOCKER: Assumes 32-bit
}

// Migration blocker: Literal 4-byte I/O
void migration_32_to_64_literal_io_blocker(void) {
    time_t t = time(NULL);
    int fd = 1;
    write(fd, &t, 4);  // MIGRATION BLOCKER: Assumes 4-byte time_t
    read(fd, &t, 4);   // MIGRATION BLOCKER: Assumes 4-byte time_t
}

// Migration risk: Format specifier mismatch
void migration_32_to_64_format_risk(void) {
    time_t t = time(NULL);
    printf("%d", t);   // MIGRATION RISK: %d assumes 32-bit
    printf("%u", t);  // MIGRATION RISK: %u assumes 32-bit unsigned
    printf("%ld", t); // MIGRATION RISK: %ld assumes 32-bit long in ILP32
}

// Migration risk: scanf format mismatch
void migration_32_to_64_scanf_risk(void) {
    time_t t;
    scanf("%d", &t);   // MIGRATION RISK: %d assumes 32-bit
    scanf("%u", &t);   // MIGRATION RISK: %u assumes 32-bit unsigned
    scanf("%ld", &t);  // MIGRATION RISK: %ld assumes 32-bit long in ILP32
}

// Migration risk: sprintf/snprintf format mismatch
void migration_32_to_64_sprintf_risk(void) {
    time_t t = time(NULL);
    char buf[64];
    sprintf(buf, "%d", t);    // MIGRATION RISK: %d assumes 32-bit
    snprintf(buf, 64, "%u", t); // MIGRATION RISK: %u assumes 32-bit unsigned
}

// Migration risk: Raw struct I/O
void migration_32_to_64_struct_io_risk(void) {
    struct {
        time_t timestamp;
        int value;
    } record;
    
    record.timestamp = time(NULL);
    int fd = 1;
    write(fd, &record, sizeof(record));  // MIGRATION RISK: Struct size changes
    read(fd, &record, sizeof(record));   // MIGRATION RISK: Struct size changes
}

// Migration risk: memcpy with fixed size
void migration_32_to_64_memcpy_risk(void) {
    time_t t = time(NULL);
    char buf[8];
    memcpy(buf, &t, 4);  // MIGRATION RISK: Assumes 4-byte time_t
    memcpy(&t, buf, 4);  // MIGRATION RISK: Assumes 4-byte time_t
}

// ============================================================================
// MIGRATION: SIGNED → UNSIGNED TIME_T
// ============================================================================

// Migration blocker: Sign check
void migration_signed_to_unsigned_sign_check_blocker(void) {
    time_t t = time(NULL);
    if (t < 0) {  // MIGRATION BLOCKER: Assumes signed time_t
        // ...
    }
    if (t <= -1) {  // MIGRATION BLOCKER: Assumes signed time_t
        // ...
    }
    if (t == -1) {  // MIGRATION BLOCKER: Assumes signed time_t
        // ...
    }
}

// Migration blocker: Negative constant
void migration_signed_to_unsigned_negative_blocker(void) {
    time_t t = -1;      // MIGRATION BLOCKER: Assumes signed time_t
    time_t t2 = -1L;    // MIGRATION BLOCKER: Assumes signed time_t
    time_t error = -1; // MIGRATION BLOCKER: Common error value pattern
}

// Migration risk: Format specifier sign mismatch
void migration_signed_to_unsigned_format_risk(void) {
    time_t t = time(NULL);
    printf("%d", t);  // MIGRATION RISK: %d assumes signed
    printf("%u", t);  // MIGRATION RISK: %u assumes unsigned (if migrating signed→unsigned)
    scanf("%d", &t);  // MIGRATION RISK: %d assumes signed
    scanf("%u", &t);  // MIGRATION RISK: %u assumes unsigned
}

// Migration risk: Comparison with negative values
void migration_signed_to_unsigned_comparison_risk(void) {
    time_t t = time(NULL);
    if (t > -1) {  // MIGRATION RISK: Comparison with negative value
        // ...
    }
    if (t != -1) {  // MIGRATION RISK: Comparison with negative value
        // ...
    }
}

// ============================================================================
// MIGRATION: ILP32 → LP64 (ARCHITECTURE CHANGE)
// ============================================================================

// Migration risk: long type assumption
void migration_ilp32_to_lp64_long_risk(void) {
    time_t t = time(NULL);
    long x = (long)t;  // MIGRATION RISK: long is 32-bit in ILP32, 64-bit in LP64
    printf("%ld", t);  // MIGRATION RISK: %ld width changes between ILP32 and LP64
}

// Migration risk: Pointer size assumption (implicit in some patterns)
void migration_ilp32_to_lp64_pointer_risk(void) {
    time_t *t_ptr = NULL;
    // Some patterns implicitly assume pointer size
    // This is less common but can occur in serialization code
}

// Migration risk: Struct padding changes
void migration_ilp32_to_lp64_struct_padding_risk(void) {
    struct {
        int32_t a;
        time_t t;  // Size changes: 4 bytes in ILP32-32bit, 8 bytes in LP64-64bit
        int32_t b;
    } s;
    
    // Struct size and padding may change
    int fd = 1;
    write(fd, &s, sizeof(s));  // MIGRATION RISK: Struct layout changes
}

// ============================================================================
// COMBINED MIGRATION SCENARIOS
// ============================================================================

// Migration: ILP32 signed 32-bit → ILP32 signed 64-bit
void migration_ilp32_32s_to_ilp32_64s(void) {
    time_t t = time(NULL);
    int32_t x = (int32_t)t;  // BLOCKER: Width assumption
    printf("%d", t);          // RISK: Format specifier
    write(1, &t, 4);          // BLOCKER: Literal size
}

// Migration: ILP32 signed 32-bit → ILP32 unsigned 32-bit
void migration_ilp32_32s_to_ilp32_32u(void) {
    time_t t = time(NULL);
    if (t < 0) {              // BLOCKER: Sign check
        // ...
    }
    time_t error = -1;        // BLOCKER: Negative constant
    printf("%d", t);          // RISK: Format specifier sign
}

// Migration: ILP32 signed 32-bit → LP64 signed 64-bit
void migration_ilp32_32s_to_lp64_64s(void) {
    time_t t = time(NULL);
    int32_t x = (int32_t)t;  // BLOCKER: Width assumption
    long y = (long)t;         // RISK: Architecture assumption (long size changes)
    printf("%d", t);          // RISK: Format specifier
    write(1, &t, 4);          // BLOCKER: Literal size
}

// Migration: LP64 signed 64-bit → ILP32 signed 64-bit (rare but possible)
void migration_lp64_64s_to_ilp32_64s(void) {
    time_t t = time(NULL);
    long long x = (long long)t;  // RISK: long long assumption (64-bit in both, but different semantics)
    printf("%lld", t);           // RISK: Format specifier (may work but verify)
}

// ============================================================================
// I/O BOUNDARY MIGRATION RISKS
// ============================================================================

// Migration: Network protocol with fixed-width time_t
void migration_network_protocol_risk(void) {
    struct {
        uint32_t magic;
        time_t timestamp;  // Size changes in migration
        uint32_t checksum;
    } packet;
    
    packet.timestamp = time(NULL);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    send(sock, &packet, sizeof(packet), 0);  // MIGRATION RISK: Protocol breaks
    recv(sock, &packet, sizeof(packet), 0);  // MIGRATION RISK: Protocol breaks
}

// Migration: File format with fixed-width time_t
void migration_file_format_risk(void) {
    struct {
        char header[4];
        time_t timestamp;  // Size changes in migration
        uint32_t data;
    } file_record;
    
    file_record.timestamp = time(NULL);
    FILE *fp = fopen("data.bin", "wb");
    fwrite(&file_record, sizeof(file_record), 1, fp);  // MIGRATION RISK: File format breaks
    fclose(fp);
    
    fp = fopen("data.bin", "rb");
    fread(&file_record, sizeof(file_record), 1, fp);  // MIGRATION RISK: File format breaks
    fclose(fp);
}

// Migration: Shared memory with fixed-width time_t
void migration_shared_memory_risk(void) {
    struct {
        time_t last_update;  // Size changes in migration
        int counter;
    } *shared_data;
    
    shared_data->last_update = time(NULL);
    // MIGRATION RISK: Shared memory layout breaks if other process uses different config
}

// Migration: Device I/O with fixed-width time_t
void migration_device_io_risk(void) {
    time_t t = time(NULL);
    int fd = open("/dev/timer", O_RDWR);
    ioctl(fd, SET_TIME, &t);  // MIGRATION RISK: Device expects specific width
    ioctl(fd, GET_TIME, &t);  // MIGRATION RISK: Device expects specific width
    close(fd);
}

// ============================================================================
// SAFE MIGRATION PATTERNS (Should NOT be flagged)
// ============================================================================

// Safe: Uses sizeof(time_t) - portable
void migration_safe_sizeof(void) {
    time_t t = time(NULL);
    char buf[sizeof(time_t)];
    memcpy(buf, &t, sizeof(time_t));  // SAFE: Uses sizeof(time_t)
    write(1, &t, sizeof(time_t));     // SAFE: Uses sizeof(time_t)
}

// Safe: Explicit conversion to fixed-width type
void migration_safe_explicit_conversion(void) {
    time_t t = time(NULL);
    int64_t wire_value = (int64_t)t;  // SAFE: Explicit conversion to fixed-width
    printf("%lld", wire_value);        // SAFE: Matches fixed-width type
}

// Safe: Text serialization (ISO-8601, etc.)
void migration_safe_text_serialization(void) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char buf[64];
    strftime(buf, 64, "%Y-%m-%dT%H:%M:%S", tm_info);  // SAFE: Text format
    printf("%s", buf);  // SAFE: Text format
}

// Safe: No assumptions about width/sign
void migration_safe_no_assumptions(void) {
    time_t t = time(NULL);
    time_t t2 = t + 3600;  // SAFE: No width/sign assumptions
    if (t2 > t) {          // SAFE: No sign assumptions
        // ...
    }
}

// Safe: Uses portable format specifiers
void migration_safe_portable_format(void) {
    time_t t = time(NULL);
    // Using %lld with explicit cast to long long is safer
    long long t_ll = (long long)t;
    printf("%lld", t_ll);  // SAFE: Explicit cast + matching format
}
