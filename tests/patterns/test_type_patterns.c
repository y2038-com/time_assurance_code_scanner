// Copyright (c) 2026 Y2038.com LLC
// SPDX-License-Identifier: Apache-2.0

// Test file for type declaration patterns
// This file tests various time_t type declarations that the scanner should detect

#include <time.h>

// Test: Variable declaration
void test_variable_declaration(void) {
    time_t t;
}

// Test: Initialized declaration
void test_initialized_declaration(void) {
    time_t t = 0;
}

// Test: Pointer declaration
void test_pointer_declaration(void) {
    time_t *tp;
}

// Test: Array declaration
void test_array_declaration(void) {
    time_t times[10];
}

// Test: Function parameter
void test_function_parameter(time_t t) {
    (void)t;
}

// Test: Function return type
time_t test_function_return_type(void) {
    return 0;
}

// Test: Struct member
struct test_struct {
    time_t timestamp;
};

// Test: Typedef
typedef time_t my_time_t;

// Test: Typedef alias (simple)
typedef time_t time;

// Test: Typedef alias (nested)
typedef time_t base_time;
typedef base_time my_time;

// Test: Function pointer typedef
typedef time_t (*time_func_t)(void);

// Test: Array typedef
typedef time_t time_array[10];

// Test: clock_t type
void test_clock_t(void) {
    clock_t c;
    (void)c;
}

// Test: timer_t type
void test_timer_t(void) {
    timer_t timer;
    (void)timer;
}

// Test: suseconds_t type
void test_suseconds_t(void) {
    suseconds_t s;
    (void)s;
}

// Test: useconds_t type
void test_useconds_t(void) {
    useconds_t u;
    (void)u;
}

// Test: Multiple time_t declarations
void test_multiple_declarations(void) {
    time_t t1, t2, t3;
    time_t *p1, *p2;
}

// Test: time_t with const
void test_const_time_t(void) {
    const time_t t = 0;
    (void)t;
}

// Test: time_t with volatile
void test_volatile_time_t(void) {
    volatile time_t t = 0;
    (void)t;
}

// Test: time_t with static
void test_static_time_t(void) {
    static time_t t = 0;
    (void)t;
}

// Test: time_t with extern
extern time_t global_time;

// Test: time_t in union
union test_union {
    time_t timestamp;
    int value;
};

// Test: time_t in enum (not valid, but test scanner doesn't false positive)
enum test_enum {
    VALUE1,
    VALUE2
};
