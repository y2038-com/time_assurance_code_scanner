// Copyright (c) 2026 Y2038.com LLC
// SPDX-License-Identifier: Apache-2.0

// Test file for struct patterns
// This file tests various time-related struct usage that the scanner should detect

#include <time.h>
#include <sys/time.h>

// Test: timespec declaration
void test_timespec_declaration(void) {
    struct timespec ts;
    (void)ts;
}

// Test: timespec member access (write)
void test_timespec_member_write(void) {
    struct timespec ts;
    ts.tv_sec = time(NULL);
}

// Test: timespec member access (read)
void test_timespec_member_read(void) {
    struct timespec ts;
    time_t t = ts.tv_sec;
    (void)t;
}

// Test: timespec pointer access (write)
void test_timespec_pointer_write(void) {
    struct timespec ts;
    struct timespec *tsp = &ts;
    tsp->tv_sec = time(NULL);
}

// Test: timespec pointer access (read)
void test_timespec_pointer_read(void) {
    struct timespec ts;
    struct timespec *tsp = &ts;
    time_t t = tsp->tv_sec;
    (void)t;
}

// Test: timespec in function parameter
void test_timespec_function_param(struct timespec *ts) {
    ts->tv_sec = time(NULL);
}

// Test: timespec array
void test_timespec_array(void) {
    struct timespec ts_array[10];
    ts_array[0].tv_sec = time(NULL);
}

// Test: timeval declaration
void test_timeval_declaration(void) {
    struct timeval tv;
    (void)tv;
}

// Test: timeval member access (write)
void test_timeval_member_write(void) {
    struct timeval tv;
    tv.tv_sec = time(NULL);
}

// Test: timeval member access (read)
void test_timeval_member_read(void) {
    struct timeval tv;
    time_t t = tv.tv_sec;
    (void)t;
}

// Test: timeval pointer access (write)
void test_timeval_pointer_write(void) {
    struct timeval tv;
    struct timeval *tvp = &tv;
    tvp->tv_sec = time(NULL);
}

// Test: timeval pointer access (read)
void test_timeval_pointer_read(void) {
    struct timeval tv;
    struct timeval *tvp = &tv;
    time_t t = tvp->tv_sec;
    (void)t;
}

// Test: timeval in function parameter
void test_timeval_function_param(struct timeval *tv) {
    tv->tv_sec = time(NULL);
}

// Test: tm declaration (safe - should be NO)
void test_tm_declaration(void) {
    struct tm tm;
    (void)tm;
}

// Test: tm member access (safe - should be NO)
void test_tm_member_access(void) {
    struct tm tm;
    tm.tm_year = 2024;
}

// Test: tm in function parameter (safe - should be NO)
void test_tm_function_param(struct tm *tm) {
    tm->tm_year = 2024;
}

// Test: itimerspec declaration
void test_itimerspec_declaration(void) {
    struct itimerspec its;
    its.it_value.tv_sec = time(NULL);
    (void)its;
}

// Test: itimerval declaration
void test_itimerval_declaration(void) {
    struct itimerval itv;
    itv.it_value.tv_sec = time(NULL);
    (void)itv;
}

// Test: Nested struct access
void test_nested_struct_access(void) {
    struct timespec ts;
    struct timespec *tsp = &ts;
    time_t t = tsp->tv_sec;
    (void)t;
}

// Test: Struct with multiple time_t members
struct multi_time_struct {
    time_t start_time;
    time_t end_time;
    struct timespec interval;
};

// Test: Struct initialization
void test_struct_initialization(void) {
    struct timespec ts = {.tv_sec = time(NULL), .tv_nsec = 0};
    (void)ts;
}

// Test: Struct in array
void test_struct_array(void) {
    struct timespec ts_array[5];
    for (int i = 0; i < 5; i++) {
        ts_array[i].tv_sec = time(NULL);
    }
}
