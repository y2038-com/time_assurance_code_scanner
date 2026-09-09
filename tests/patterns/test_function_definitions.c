// Test file for function definition patterns
// This file tests various function definitions involving time_t

#include <time.h>

// Functions Returning time_t

// Test: Function returning time_t
time_t test_return_time_t(void) {
    return time(NULL);
}

// Test: Function returning time_t with variable
time_t test_return_time_t_variable(void) {
    time_t t;
    return time(&t);
}

// Test: Static function returning time_t
static time_t test_static_return_time_t(void) {
    return time(NULL);
}

// Test: Inline function returning time_t
inline time_t test_inline_return_time_t(void) {
    return time(NULL);
}

// Test: Function returning time_t with arithmetic
time_t test_return_time_t_arithmetic(void) {
    time_t t = time(NULL);
    return t + 3600;
}

// Functions Accepting time_t

// Test: Function accepting time_t parameter
void test_accept_time_t(time_t t) {
    (void)t;
}

// Test: Function accepting time_t pointer
void test_accept_time_t_pointer(time_t *t) {
    *t = time(NULL);
}

// Test: Function accepting multiple time_t parameters
void test_accept_multiple_time_t(time_t t1, time_t t2) {
    (void)t1;
    (void)t2;
}

// Test: Function accepting time_t and returning int
int test_accept_time_t_return_int(time_t t) {
    return t > 0 ? 1 : 0;
}

// Test: Function accepting const time_t
void test_accept_const_time_t(const time_t t) {
    (void)t;
}

// Test: Function accepting time_t reference (C++ style, but test in C)
void test_accept_time_t_reference(time_t *t) {
    (void)t;
}

// Functions with time_t Local Variables

// Test: Function with time_t local variable
void test_local_time_t(void) {
    time_t t = time(NULL);
    (void)t;
}

// Test: Function with time_t local variable separate declaration
void test_local_time_t_separate(void) {
    time_t t;
    t = time(NULL);
    (void)t;
}

// Test: Function with multiple time_t local variables
void test_multiple_local_time_t(void) {
    time_t t1 = time(NULL);
    time_t t2 = time(NULL);
    time_t t3 = t1 + t2;
    (void)t3;
}

// Test: Function with time_t pointer local variable
void test_local_time_t_pointer(void) {
    time_t t;
    time_t *tp = &t;
    *tp = time(NULL);
}

// Test: Function with time_t array local variable
void test_local_time_t_array(void) {
    time_t times[10];
    times[0] = time(NULL);
}

// Test: Function with static time_t local variable
void test_static_local_time_t(void) {
    static time_t t = 0;
    t = time(NULL);
    (void)t;
}

// Complex Function Patterns

// Test: Function with time_t parameter and return
time_t test_time_t_param_and_return(time_t input) {
    return input + 3600;
}

// Test: Function with time_t in struct parameter
void test_time_t_in_struct_param(struct timespec *ts) {
    ts->tv_sec = time(NULL);
}

// Test: Function with time_t in multiple contexts
time_t test_time_t_multiple_contexts(time_t input) {
    time_t local = time(NULL);
    time_t result = input + local;
    return result;
}

// Test: Recursive function with time_t
time_t test_recursive_time_t(int depth) {
    if (depth <= 0) {
        return time(NULL);
    }
    return test_recursive_time_t(depth - 1);
}

// Test: Function pointer with time_t
typedef time_t (*time_func_t)(void);
void test_function_pointer_time_t(time_func_t func) {
    time_t t = func();
    (void)t;
}

// Test: Variadic function with time_t
#include <stdarg.h>
void test_variadic_time_t(int count, ...) {
    va_list args;
    va_start(args, count);
    for (int i = 0; i < count; i++) {
        time_t t = va_arg(args, time_t);
        (void)t;
    }
    va_end(args);
}

// Test: Function with time_t in nested scope
void test_nested_scope_time_t(void) {
    {
        time_t t = time(NULL);
        (void)t;
    }
    {
        time_t t = time(NULL);
        (void)t;
    }
}

// Test: Function with time_t in switch case
void test_switch_time_t(int choice) {
    time_t t;
    switch (choice) {
        case 1:
            t = time(NULL);
            break;
        case 2:
            t = time(NULL) + 3600;
            break;
        default:
            t = 0;
            break;
    }
    (void)t;
}

// Test: Function with time_t in if-else
void test_if_else_time_t(int condition) {
    time_t t;
    if (condition) {
        t = time(NULL);
    } else {
        t = time(NULL) + 3600;
    }
    (void)t;
}

// Test: Function with time_t in loop
void test_loop_time_t(void) {
    time_t times[10];
    for (int i = 0; i < 10; i++) {
        times[i] = time(NULL);
    }
}

// Test: Function with time_t in while loop
void test_while_loop_time_t(void) {
    time_t t = time(NULL);
    while (t > 0) {
        t = t - 1;
    }
}

// Test: Function with time_t in do-while loop
void test_do_while_loop_time_t(void) {
    time_t t = time(NULL);
    do {
        t = t - 1;
    } while (t > 0);
}
