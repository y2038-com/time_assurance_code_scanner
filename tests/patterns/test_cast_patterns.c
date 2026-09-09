// Test file for cast patterns
// This file tests various casts from time_t that the scanner should detect

#include <time.h>
#include <stdint.h>

// Explicit Casts from time_t Functions

// Test: Cast to int
void test_cast_to_int(void) {
    int i = (int)time(NULL);
    (void)i;
}

// Test: Cast to long
void test_cast_to_long(void) {
    long l = (long)time(NULL);
    (void)l;
}

// Test: Cast to unsigned int
void test_cast_to_unsigned_int(void) {
    unsigned int ui = (unsigned int)time(NULL);
    (void)ui;
}

// Test: Cast to uint32_t
void test_cast_to_uint32_t(void) {
    uint32_t u32 = (uint32_t)time(NULL);
    (void)u32;
}

// Test: Cast to int64_t
void test_cast_to_int64_t(void) {
    int64_t i64 = (int64_t)time(NULL);
    (void)i64;
}

// Test: Cast to uint64_t
void test_cast_to_uint64_t(void) {
    uint64_t u64 = (uint64_t)time(NULL);
    (void)u64;
}

// Test: Cast to short
void test_cast_to_short(void) {
    short s = (short)time(NULL);
    (void)s;
}

// Test: Cast to char
void test_cast_to_char(void) {
    char c = (char)time(NULL);
    (void)c;
}

// Explicit Casts from time_t Variables

// Test: Cast from time_t variable to int
void test_cast_var_to_int(void) {
    time_t t = time(NULL);
    int i = (int)t;
    (void)i;
}

// Test: Cast from time_t variable to long
void test_cast_var_to_long(void) {
    time_t t = time(NULL);
    long l = (long)t;
    (void)l;
}

// Test: Cast from time_t variable to uint32_t
void test_cast_var_to_uint32_t(void) {
    time_t t = time(NULL);
    uint32_t u = (uint32_t)t;
    (void)u;
}

// Test: Cast with typedef alias
typedef time_t time;
void test_cast_with_typedef(void) {
    time_t t = time(NULL);
    time alias = (time)t;  // Cast using typedef alias
    (void)alias;
}

// Test: Cast from time_t variable declared on same line
void test_cast_same_line_declaration(void) {
    time_t timestamp = time(NULL);
    int i = (int)timestamp;
    (void)i;
}

// Test: Cast from time_t pointer
void test_cast_from_pointer(void) {
    time_t t = time(NULL);
    time_t *tp = &t;
    int i = (int)*tp;
    (void)i;
}

// Implicit Casts via Assignment

// Test: Implicit cast to int
void test_implicit_cast_to_int(void) {
    int i = time(NULL);  // Implicit cast
    (void)i;
}

// Test: Implicit cast to long
void test_implicit_cast_to_long(void) {
    long l = time(NULL);  // Implicit cast
    (void)l;
}

// Test: Implicit cast to uint32_t
void test_implicit_cast_to_uint32_t(void) {
    uint32_t u = time(NULL);  // Implicit cast
    (void)u;
}

// Test: Implicit cast from variable
void test_implicit_cast_from_var(void) {
    time_t t = time(NULL);
    int i = t;  // Implicit cast from variable
    (void)i;
}

// Test: Implicit cast to short
void test_implicit_cast_to_short(void) {
    short s = time(NULL);  // Implicit cast
    (void)s;
}

// Casts in Expressions

// Test: Cast in expression
void test_cast_in_expression(void) {
    int result = (int)time(NULL) + 1;
    (void)result;
}

// Test: Cast in condition
void test_cast_in_condition(void) {
    if ((int)time(NULL) > 0) {
        return;
    }
}

// Test: Cast in return
int test_cast_in_return(void) {
    return (int)time(NULL);
}

// Test: Cast in function argument
void process_int(int i);
void test_cast_in_function_arg(void) {
    process_int((int)time(NULL));
}

// Test: Multiple casts
void test_multiple_casts(void) {
    time_t t = time(NULL);
    int i = (int)t;
    long l = (long)i;
    (void)l;
}

// Test: Cast with arithmetic
void test_cast_with_arithmetic(void) {
    time_t t = time(NULL);
    int i = (int)(t + 1);
    (void)i;
}

// Test: Nested casts
void test_nested_casts(void) {
    time_t t = time(NULL);
    int i = (int)(long)t;
    (void)i;
}

// Test: Cast to pointer (should not be detected as time_t cast)
void test_cast_to_pointer(void) {
    time_t t = time(NULL);
    void *ptr = (void *)&t;  // Pointer cast, not time_t cast
    (void)ptr;
}

// Test: Cast from time_t with variable name heuristic
void test_cast_time_variable(void) {
    time_t timestamp = time(NULL);
    int i = (int)timestamp;  // Variable name suggests time_t
    (void)i;
}

// Test: Cast from time_t with tick variable
void test_cast_tick_variable(void) {
    time_t tick = time(NULL);
    int i = (int)tick;  // Variable name suggests time_t
    (void)i;
}

// Test: Cast from time_t with epoch variable
void test_cast_epoch_variable(void) {
    time_t epoch = time(NULL);
    int i = (int)epoch;  // Variable name suggests time_t
    (void)i;
}

// Test: Cast from time_t with unix_time variable
void test_cast_unix_time_variable(void) {
    time_t unix_time = time(NULL);
    int i = (int)unix_time;  // Variable name suggests time_t
    (void)i;
}
