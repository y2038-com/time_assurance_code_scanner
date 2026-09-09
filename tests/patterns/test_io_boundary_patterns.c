// Test file for I/O-boundary patterns
// This file tests various I/O operations with time_t that the scanner should detect
// for Y2038/Y2106 risks at I/O boundaries

#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>

// ============================================================================
// FORMATTED I/O PATTERNS - Format Specifier Mismatches
// ============================================================================

// Test: printf with %d (32-bit signed) on 64-bit time_t - MISMATCH
void test_printf_d_mismatch(void) {
    time_t t = time(NULL);
    printf("%d", t);  // Should flag: width mismatch if time_t is 64-bit
}

// Test: printf with %u (32-bit unsigned) on signed time_t - MISMATCH
void test_printf_u_mismatch(void) {
    time_t t = time(NULL);
    printf("%u", t);  // Should flag: sign mismatch if time_t is signed
}

// Test: printf with %ld (32-bit long in ILP32, 64-bit in LP64) - POTENTIAL MISMATCH
void test_printf_ld_potential(void) {
    time_t t = time(NULL);
    printf("%ld", t);  // Should flag: width mismatch in ILP32 if time_t is 64-bit
}

// Test: printf with %lld (64-bit) on 32-bit time_t - MISMATCH
void test_printf_lld_mismatch(void) {
    time_t t = time(NULL);
    printf("%lld", t);  // Should flag: width mismatch if time_t is 32-bit
}

// Test: fprintf with format mismatch
void test_fprintf_mismatch(void) {
    time_t t = time(NULL);
    FILE *fp = stdout;
    fprintf(fp, "%d", t);  // Should flag: width mismatch
}

// Test: sprintf with format mismatch
void test_sprintf_mismatch(void) {
    time_t t = time(NULL);
    char buf[64];
    sprintf(buf, "%u", t);  // Should flag: sign mismatch if time_t is signed
}

// Test: snprintf with format mismatch
void test_snprintf_mismatch(void) {
    time_t t = time(NULL);
    char buf[64];
    snprintf(buf, sizeof(buf), "%d", t);  // Should flag: width mismatch
}

// Test: scanf with %d into time_t - MISMATCH
void test_scanf_d_mismatch(void) {
    time_t t;
    scanf("%d", &t);  // Should flag: width mismatch
}

// Test: fscanf with format mismatch
void test_fscanf_mismatch(void) {
    time_t t;
    FILE *fp = stdin;
    fscanf(fp, "%u", &t);  // Should flag: sign mismatch if time_t is signed
}

// Test: sscanf with format mismatch
void test_sscanf_mismatch(void) {
    time_t t;
    const char *str = "1234567890";
    sscanf(str, "%d", &t);  // Should flag: width mismatch
}

// Test: Correct format specifier (should be lower confidence or safe)
void test_printf_correct_format(void) {
    time_t t = time(NULL);
    // Using %lld for 64-bit time_t (LP64) - may still flag but lower confidence
    printf("%lld", t);
}

// Test: Variable format string (lower confidence)
void test_printf_variable_format(void) {
    time_t t = time(NULL);
    const char *fmt = "%d";
    printf(fmt, t);  // Should flag but lower confidence (variable format)
}

// ============================================================================
// RAW I/O PATTERNS - Binary Serialization Risks
// ============================================================================

// Test: write() with sizeof(time_t) - RISK
void test_write_sizeof_time_t(void) {
    time_t t = time(NULL);
    int fd = 1;  // stdout
    write(fd, &t, sizeof(t));  // Should flag: raw serialization of time_t
}

// Test: write() with sizeof(time_t) explicit
void test_write_sizeof_explicit(void) {
    time_t t = time(NULL);
    int fd = 1;
    write(fd, &t, sizeof(time_t));  // Should flag: raw serialization
}

// Test: read() into time_t with sizeof - RISK
void test_read_sizeof_time_t(void) {
    time_t t;
    int fd = 0;  // stdin
    read(fd, &t, sizeof(t));  // Should flag: raw deserialization
}

// Test: read() with literal 4 bytes (32-bit assumption) - RISK
void test_read_literal_4(void) {
    time_t t;
    int fd = 0;
    read(fd, &t, 4);  // Should flag: fixed 4-byte assumption
}

// Test: read() with literal 8 bytes (64-bit assumption) - RISK
void test_read_literal_8(void) {
    time_t t;
    int fd = 0;
    read(fd, &t, 8);  // Should flag: fixed 8-byte assumption
}

// Test: fwrite() with time_t
void test_fwrite_time_t(void) {
    time_t t = time(NULL);
    FILE *fp = stdout;
    fwrite(&t, sizeof(t), 1, fp);  // Should flag: raw serialization
}

// Test: fread() into time_t
void test_fread_time_t(void) {
    time_t t;
    FILE *fp = stdin;
    fread(&t, sizeof(t), 1, fp);  // Should flag: raw deserialization
}

// Test: memcpy() with time_t - RISK
void test_memcpy_time_t(void) {
    time_t t = time(NULL);
    char buf[64];
    memcpy(buf, &t, sizeof(t));  // Should flag: raw serialization
}

// Test: memcpy() into time_t - RISK
void test_memcpy_into_time_t(void) {
    time_t t;
    char buf[64] = {0};
    memcpy(&t, buf, sizeof(t));  // Should flag: raw deserialization
}

// Test: memmove() with time_t - RISK
void test_memmove_time_t(void) {
    time_t t = time(NULL);
    char buf[64];
    memmove(buf, &t, sizeof(t));  // Should flag: raw serialization
}

// Test: send() with time_t (network I/O) - RISK
void test_send_time_t(void) {
    time_t t = time(NULL);
    int sock = 0;
    send(sock, &t, sizeof(t), 0);  // Should flag: network serialization
}

// Test: recv() into time_t (network I/O) - RISK
void test_recv_time_t(void) {
    time_t t;
    int sock = 0;
    recv(sock, &t, sizeof(t), 0);  // Should flag: network deserialization
}

// Test: pread() with time_t - RISK
void test_pread_time_t(void) {
    time_t t;
    int fd = 0;
    pread(fd, &t, sizeof(t), 0);  // Should flag: raw deserialization
}

// Test: pwrite() with time_t - RISK
void test_pwrite_time_t(void) {
    time_t t = time(NULL);
    int fd = 1;
    pwrite(fd, &t, sizeof(t), 0);  // Should flag: raw serialization
}

// ============================================================================
// STRUCT PATTERNS - Time-bearing Structs in I/O
// ============================================================================

// Test: fwrite() with struct containing time_t field
void test_fwrite_struct_with_time(void) {
    struct {
        int id;
        time_t timestamp;
        char name[32];
    } record = {0};
    record.timestamp = time(NULL);
    
    FILE *fp = stdout;
    fwrite(&record, sizeof(record), 1, fp);  // Should flag: struct with time_t field
}

// Test: fread() into struct with time_t field
void test_fread_struct_with_time(void) {
    struct {
        int id;
        time_t timestamp;
        char name[32];
    } record;
    
    FILE *fp = stdin;
    fread(&record, sizeof(record), 1, fp);  // Should flag: struct with time_t field
}

// Test: write() with struct timespec
void test_write_timespec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int fd = 1;
    write(fd, &ts, sizeof(ts));  // Should flag: struct timespec contains tv_sec (time_t)
}

// Test: read() into struct timespec
void test_read_timespec(void) {
    struct timespec ts;
    int fd = 0;
    read(fd, &ts, sizeof(ts));  // Should flag: struct timespec contains tv_sec
}

// Test: memcpy() with struct timeval
void test_memcpy_timeval(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    char buf[64];
    memcpy(buf, &tv, sizeof(tv));  // Should flag: struct timeval contains tv_sec
}

// ============================================================================
// EXPLICIT CAST PATTERNS - Casts at I/O Boundary
// ============================================================================

// Test: Explicit cast before write()
void test_write_with_cast(void) {
    time_t t = time(NULL);
    int fd = 1;
    write(fd, &t, sizeof(t));  // Should flag: explicit cast increases risk
    // Note: cast would be: write(fd, (int32_t*)&t, sizeof(int32_t))
}

// Test: Explicit cast before read()
void test_read_with_cast(void) {
    time_t t;
    int fd = 0;
    read(fd, (int32_t*)&t, sizeof(int32_t));  // Should flag: explicit cast to narrow type
}

// ============================================================================
// SAFE PATTERNS - Should NOT be flagged (or low confidence)
// ============================================================================

// Test: Explicit conversion to int64_t before I/O (safe pattern)
void test_safe_int64_conversion(void) {
    time_t t = time(NULL);
    int64_t ts = (int64_t)t;  // Explicit conversion
    int fd = 1;
    write(fd, &ts, sizeof(ts));  // Should NOT flag: explicit safe conversion
}

// Test: Text serialization with ISO-8601 format (safe)
void test_safe_text_serialization(void) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm_info);
    printf("%s", buf);  // Should NOT flag: text serialization
}

// Test: Explicit decimal string conversion (safe)
void test_safe_decimal_string(void) {
    time_t t = time(NULL);
    char buf[64];
    snprintf(buf, sizeof(buf), "%lld", (long long)t);  // Explicit cast to long long
    printf("%s", buf);  // Should NOT flag: explicit safe conversion
}

// Test: I/O on non-time data (should not flag)
void test_io_non_time_data(void) {
    int x = 42;
    int fd = 1;
    write(fd, &x, sizeof(x));  // Should NOT flag: not time-bearing
}

// Test: printf with non-time integer (should not flag)
void test_printf_non_time(void) {
    int x = 42;
    printf("%d", x);  // Should NOT flag: not time-bearing
}

// ============================================================================
// EXTERNAL INTERFACE PATTERNS - Device/Protocol Boundaries
// ============================================================================

// Test: ioctl() with time_t (device I/O) - HIGH RISK
void test_ioctl_time_t(void) {
    time_t t = time(NULL);
    int fd = 0;
    // Note: ioctl typically uses struct, but showing time_t in payload
    // Should flag: external interface risk
    (void)fd;
    (void)t;
}

// Test: Network protocol struct with time_t
void test_network_protocol_time(void) {
    struct {
        uint16_t version;
        time_t timestamp;  // Protocol field
        uint32_t data;
    } packet = {0};
    packet.timestamp = time(NULL);
    
    int sock = 0;
    send(sock, &packet, sizeof(packet), 0);  // Should flag: protocol boundary
}

// Test: Shared memory with time_t
void test_shm_time_t(void) {
    time_t t = time(NULL);
    // Simulating shared memory write
    // Should flag: shared memory boundary
    (void)t;
}

// ============================================================================
// SIZE PATTERNS - Suspicious Size Arguments
// ============================================================================

// Test: sizeof() with time_t variable
void test_sizeof_time_t_var(void) {
    time_t t = time(NULL);
    int fd = 1;
    write(fd, &t, sizeof(t));  // Should flag: sizeof(time_t variable)
}

// Test: sizeof() with time_t type
void test_sizeof_time_t_type(void) {
    time_t t = time(NULL);
    int fd = 1;
    write(fd, &t, sizeof(time_t));  // Should flag: sizeof(time_t type)
}

// Test: sizeof() with typedef alias
void test_sizeof_typedef_alias(void) {
    typedef time_t my_time_t;
    my_time_t t = time(NULL);
    int fd = 1;
    write(fd, &t, sizeof(my_time_t));  // Should flag: sizeof(alias)
}

// ============================================================================
// ASSIGNMENT TRACKING PATTERNS - Time Function Assignments
// ============================================================================

// Test: Variable assigned from time() then used in I/O
void test_time_assignment_io(void) {
    time_t t = time(NULL);  // Assignment from time function
    int fd = 1;
    write(fd, &t, sizeof(t));  // Should flag: time-bearing variable from assignment
}

// Test: Variable assigned from gettimeofday() then used in printf
void test_gettimeofday_assignment_printf(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t t = tv.tv_sec;  // Assignment from time-bearing struct
    printf("%d", t);  // Should flag: format mismatch with time-bearing variable
}

// Test: Variable assigned from localtime() result
void test_localtime_assignment_io(void) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    time_t t2 = mktime(tm_info);  // Assignment from time function
    int fd = 1;
    write(fd, &t2, sizeof(t2));  // Should flag: time-bearing variable
}

// ============================================================================
// EDGE CASES
// ============================================================================

// Test: Multiple I/O operations with same time_t
void test_multiple_io_operations(void) {
    time_t t = time(NULL);
    int fd = 1;
    write(fd, &t, sizeof(t));  // First I/O
    printf("%d", t);  // Second I/O - format mismatch
    memcpy(&t, &t, sizeof(t));  // Third I/O - memcpy
    // Should flag all three
}

// Test: Nested I/O calls
void test_nested_io_calls(void) {
    time_t t = time(NULL);
    char buf[64];
    snprintf(buf, sizeof(buf), "%d", t);  // Format mismatch
    write(1, buf, strlen(buf));  // Should flag the printf family call
}

// Test: I/O in conditional
void test_io_in_conditional(void) {
    time_t t = time(NULL);
    if (t > 0) {
        printf("%d", t);  // Should flag: format mismatch
    }
}

// Test: I/O in loop
void test_io_in_loop(void) {
    time_t t = time(NULL);
    for (int i = 0; i < 10; i++) {
        printf("%d", t);  // Should flag: format mismatch
    }
}
