// Mini test file for arithmetic patterns (~1/10th size of full test)
// This file tests key time_t arithmetic operations

#include <time.h>
#include <stdint.h>

// First-level typedefs (directly aliasing time_t)
typedef time_t my_time_t;
typedef time_t timestamp_t;

// First-level #defines (directly aliasing time_t)
#define MY_TIME_T time_t
#define TIMESTAMP_TYPE time_t

// Y2038 Risk Patterns (Should be YES - signed time_t)

// Test: Signed time_t addition that could overflow
void test_signed_addition(void) {
    time_t t = -1;
    t = t + 2147483648;  // Could overflow if signed
    (void)t;
}

// Test: Comparison assuming signed
void test_signed_comparison(void) {
    time_t t = time(NULL);
    if (t < 0) {  // Assumes signed behavior
        return;
    }
}

// Y2106 Patterns (Should be NO - not Y2038, overflow in 2106)

// Test: Unsigned time_t addition
void test_unsigned_addition(void) {
    time_t t = time(NULL);
    t = t + 86400;  // Add one day
    (void)t;
}

// Test: time_t addition with small constant (Should be NO - safe)
void test_addition_constant(void) {
    time_t t = time(NULL);
    t = t + 60;  // Add 60 seconds - safe
    (void)t;
}

// ============================================================================
// Narrowing Patterns (Should be YES for ILP32 with 64-bit time_t)
// These patterns reduce 64-bit time_t to 32-bit, causing precision loss
// ============================================================================

// Case 1: Explicit narrowing casts
// Test: Cast time_t to int32_t
void test_narrowing_cast_int32_t(void) {
    time_t t = time(NULL);
    int32_t narrow = (int32_t)t;  // Explicit narrowing - Y2038/Y2106 risk
    (void)narrow;
}

// Test: Cast time() return to int
void test_narrowing_cast_int(void) {
    int narrow = (int)time(NULL);  // Direct cast - Y2038/Y2106 risk
    (void)narrow;
}

// Test: Cast to long (32-bit in ILP32)
void test_narrowing_cast_long(void) {
    time_t t = time(NULL);
    long narrow = (long)t;  // Cast to long (32-bit in ILP32) - Y2038/Y2106 risk
    (void)narrow;
}

// Case 2: Implicit narrowing assignments
// Test: Implicit cast via assignment to int32_t
void test_implicit_narrowing_int32_t(void) {
    time_t t = time(NULL);
    int32_t narrow = t;  // Implicit narrowing - Y2038/Y2106 risk
    (void)narrow;
}

// Test: Implicit cast via assignment to int
void test_implicit_narrowing_int(void) {
    int narrow = time(NULL);  // Implicit narrowing - Y2038/Y2106 risk
    (void)narrow;
}

// Case 3: Casts from 32-bit integers to time_t (precision loss risk)
// Test: Cast from int32_t to time_t
void test_widening_cast_from_int32_t(void) {
    int32_t int_val = 2147483647;  // Max 32-bit signed
    time_t t = (time_t)int_val;  // Cast from 32-bit - potential precision loss
    (void)t;
}
