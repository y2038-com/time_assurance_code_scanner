// Test file for safe patterns
// This file tests patterns that should NOT be flagged as Y2038 issues
// These should be classified as NO (safe)

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// struct tm Only (No time_t) - Should be NO

// Test: struct tm declaration only
void test_tm_declaration_only(void) {
    struct tm tm = {0};
    (void)tm;
}

// Test: struct tm member access
void test_tm_member_access(void) {
    struct tm tm;
    tm.tm_year = 2024;
    tm.tm_mon = 1;
    tm.tm_mday = 15;
    (void)tm;
}

// Test: struct tm in function
void test_tm_in_function(struct tm *tm) {
    tm->tm_year = 2024;
}

// Test: struct tm initialization
void test_tm_initialization(void) {
    struct tm tm = {
        .tm_year = 2024,
        .tm_mon = 1,
        .tm_mday = 15,
        .tm_hour = 12,
        .tm_min = 30,
        .tm_sec = 0
    };
    (void)tm;
}

// Test: struct tm array
void test_tm_array(void) {
    struct tm tm_array[10];
    tm_array[0].tm_year = 2024;
}

// Hardware Operations - Should be NO

// Test: Hardware register read
void test_hardware_register_read(void) {
    volatile uint32_t reg = 0x12345678;  // Simulated register
    (void)reg;
}

// Test: Hardware register write
void test_hardware_register_write(void) {
    volatile uint32_t *reg = (volatile uint32_t *)0x40000000;
    *reg = 0x12345678;
}

// Test: Hardware timer operations
void test_hardware_timer(void) {
    volatile uint32_t timer_value = 1000;  // Hardware timer
    (void)timer_value;
}

// Test: Clock frequency (not time_t)
void test_clock_frequency(void) {
    uint32_t frequency = 1000000;  // 1 MHz clock
    (void)frequency;
}

// Non-Time Functions - Should be NO

// Test: Integer arithmetic only
void test_integer_arithmetic(void) {
    int x = 1;
    int y = 2;
    int z = x + y;
    (void)z;
}

// Test: Float arithmetic
void test_float_arithmetic(void) {
    float f1 = 1.0;
    float f2 = 2.0;
    float f3 = f1 + f2;
    (void)f3;
}

// Test: String operations
void test_string_operations(void) {
    char str[] = "time";
    char *copy = strdup(str);
    (void)copy;
}

// Test: Memory operations
void test_memory_operations(void) {
    void *ptr = malloc(100);
    memset(ptr, 0, 100);
    free(ptr);
}

// Test: File operations
void test_file_operations(void) {
    FILE *f = fopen("test.txt", "r");
    if (f) {
        fclose(f);
    }
}

// Test: Network operations (simulated)
void test_network_operations(void) {
    int socket_fd = 0;  // Simulated
    (void)socket_fd;
}

// Test: Printf operations
void test_printf_operations(void) {
    printf("Hello world\n");
    printf("Value: %d\n", 42);
}

// Test: Math operations
#include <math.h>
void test_math_operations(void) {
    double result = sin(3.14159 / 2);
    (void)result;
}

// Functions with No time_t - Should be NO

// Test: Function with no time_t
void test_no_time_t(void) {
    int x = 1;
    int y = 2;
    int z = x + y;
    (void)z;
}

// Test: Function with only integers
int test_only_integers(int a, int b) {
    return a + b;
}

// Test: Function with only strings
void test_only_strings(const char *str) {
    printf("%s\n", str);
}

// Test: Function with only pointers (non-time_t)
void test_only_pointers(void *ptr) {
    (void)ptr;
}

// Test: Function with only struct (non-time_t)
struct non_time_struct {
    int value;
    char name[32];
};
void test_only_non_time_struct(struct non_time_struct *s) {
    s->value = 42;
}

// Safe time_t Usage Patterns - Should be NO (Y2106, not Y2038)

// Test: Simple time_t declaration (Y2106, not Y2038)
void test_simple_time_t_declaration(void) {
    time_t t;  // Y2106 issue, not Y2038
    (void)t;
}

// Test: time_t assignment (Y2106, not Y2038)
void test_simple_time_t_assignment(void) {
    time_t t = time(NULL);  // Y2106 issue, not Y2038
    (void)t;
}

// Test: time_t comparison (Y2106, not Y2038)
void test_simple_time_t_comparison(void) {
    time_t t = time(NULL);
    if (t > 0) {  // Y2106 issue, not Y2038
        return;
    }
}

// Test: struct timespec usage (Y2106, not Y2038)
void test_timespec_usage(void) {
    struct timespec ts;
    ts.tv_sec = time(NULL);  // Y2106 issue, not Y2038
    (void)ts;
}

// Test: struct timeval usage (Y2106, not Y2038)
void test_timeval_usage(void) {
    struct timeval tv;
    tv.tv_sec = time(NULL);  // Y2106 issue, not Y2038
    (void)tv;
}

// Comments and Documentation - Should be NO

// Test: Commented out time_t code
void test_commented_code(void) {
    // time_t t = time(NULL);
    // struct timespec ts;
    int x = 1;
    (void)x;
}

// Test: Documentation comment
/**
 * Function that would use time_t
 * time_t t = time(NULL);
 */
void test_documentation_comment(void) {
    int x = 1;
    (void)x;
}

// Test: String literal with "time_t"
void test_string_literal(void) {
    char *str = "time_t t = time(NULL);";
    printf("%s\n", str);
}

// Test: Character literal
void test_character_literal(void) {
    char c = 't';  // Not time_t
    (void)c;
}

// Preprocessor - Should be NO (or handled separately)

// Test: #ifdef with time_t
#ifdef TIME_FEATURE
void test_ifdef_time_feature(void) {
    time_t t = time(NULL);
    (void)t;
}
#endif

// Test: #if with time_t
#if TIME_ENABLED
void test_if_time_enabled(void) {
    time_t t = time(NULL);
    (void)t;
}
#endif

// Test: #define (not time_t related)
#define MAX_VALUE 100
void test_define_not_time(void) {
    int x = MAX_VALUE;
    (void)x;
}
