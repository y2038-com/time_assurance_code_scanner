// Copyright (c) 2026 Y2038.com LLC
// SPDX-License-Identifier: Apache-2.0

// Test file for function call patterns
// This file tests various time-related function calls that the scanner should detect

#include <time.h>
#include <sys/time.h>

// Test: Basic time() call
time_t test_time_basic(void) {
    return time(NULL);
}

// Test: time() with pointer
time_t test_time_pointer(void) {
    time_t t;
    time(&t);
    return t;
}

// Test: time() in expression
time_t test_time_expression(void) {
    time_t now = time(NULL);
    return now;
}

// Test: time() in comparison
int test_time_comparison(void) {
    if (time(NULL) > 0) {
        return 1;
    }
    return 0;
}

// Test: time() in arithmetic
time_t test_time_arithmetic(void) {
    time_t future = time(NULL) + 86400;
    return future;
}

// Test: localtime() call
struct tm* test_localtime(void) {
    time_t t = time(NULL);
    return localtime(&t);
}

// Test: localtime_r() call
int test_localtime_r(void) {
    time_t t = time(NULL);
    struct tm tm;
    return localtime_r(&t, &tm) != NULL;
}

// Test: gmtime() call
struct tm* test_gmtime(void) {
    time_t t = time(NULL);
    return gmtime(&t);
}

// Test: gmtime_r() call
int test_gmtime_r(void) {
    time_t t = time(NULL);
    struct tm tm;
    return gmtime_r(&t, &tm) != NULL;
}

// Test: mktime() call
time_t test_mktime(void) {
    struct tm tm = {0};
    return mktime(&tm);
}

// Test: clock_gettime() call
int test_clock_gettime(void) {
    struct timespec ts;
    return clock_gettime(CLOCK_REALTIME, &ts);
}

// Test: gettimeofday() call
int test_gettimeofday(void) {
    struct timeval tv;
    return gettimeofday(&tv, NULL);
}

// Test: timespec_get() call
int test_timespec_get(void) {
    struct timespec ts;
    return timespec_get(&ts, TIME_UTC);
}

// Test: timespec_getres() call
int test_timespec_getres(void) {
    struct timespec ts;
    return timespec_getres(&ts, TIME_UTC);
}

// Test: Function call in return statement
time_t test_return_time(void) {
    return time(NULL);
}

// Test: Function call in assignment
time_t test_assignment_time(void) {
    time_t t;
    t = time(NULL);
    return t;
}

// Test: Function call in condition
int test_condition_time(void) {
    time_t threshold = 1000;
    if (time(NULL) > threshold) {
        return 1;
    }
    return 0;
}

// Test: Function call in arithmetic
time_t test_arithmetic_time(void) {
    time_t offset = 3600;
    time_t delay = time(NULL) + offset;
    return delay;
}

// Test: Function call in function argument
void process_time(time_t t);
void test_function_arg_time(void) {
    process_time(time(NULL));
}

// Test: Nested function calls
struct tm* test_nested_calls(void) {
    return localtime(time(NULL));
}

// Test: Zephyr-specific timeutil_timegm()
// Note: This may not compile without Zephyr headers, but scanner should detect it
#ifdef ZEPHYR
time_t test_timeutil_timegm(void) {
    struct tm tm = {0};
    return timeutil_timegm(&tm);
}
#endif

// Test: Zephyr-specific timeutil_timegm64()
#ifdef ZEPHYR
int64_t test_timeutil_timegm64(void) {
    struct tm tm = {0};
    return timeutil_timegm64(&tm);
}
#endif
