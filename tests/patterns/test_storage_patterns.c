// Test file for storage/assignment patterns
// This file tests various time_t storage and assignment operations

#include <time.h>
#include <stdlib.h>

// Direct Assignment

// Test: Direct assignment with initialization
void test_direct_assignment_init(void) {
    time_t t = time(NULL);
    (void)t;
}

// Test: Direct assignment separate
void test_direct_assignment_separate(void) {
    time_t t;
    t = time(NULL);
    (void)t;
}

// Test: Assignment to pointer
void test_assignment_to_pointer(void) {
    time_t t;
    time_t *tp = &t;
    *tp = time(NULL);
}

// Test: Assignment from function result
void test_assignment_from_function(void) {
    time_t t = time(NULL);
    (void)t;
}

// Array Assignment

// Test: Array assignment
void test_array_assignment(void) {
    time_t times[10];
    times[0] = time(NULL);
}

// Test: Array initialization
void test_array_initialization(void) {
    time_t times[10] = {time(NULL), 0, time(NULL)};
    (void)times;
}

// Test: Array assignment with index
void test_array_assignment_index(void) {
    time_t times[10];
    for (int i = 0; i < 10; i++) {
        times[i] = time(NULL);
    }
}

// Test: Array of pointers
void test_array_of_pointers(void) {
    time_t t1, t2, t3;
    time_t *times[3] = {&t1, &t2, &t3};
    *times[0] = time(NULL);
}

// Struct Member Assignment

// Test: Struct member assignment
void test_struct_member_assignment(void) {
    struct {
        time_t ts;
    } s;
    s.ts = time(NULL);
}

// Test: timespec member assignment
void test_timespec_member_assignment(void) {
    struct timespec ts;
    ts.tv_sec = time(NULL);
}

// Test: timeval member assignment
void test_timeval_member_assignment(void) {
    struct timeval tv;
    tv.tv_sec = time(NULL);
}

// Test: Struct pointer member assignment
void test_struct_pointer_member_assignment(void) {
    struct timespec ts;
    struct timespec *tsp = &ts;
    tsp->tv_sec = time(NULL);
}

// Test: Nested struct member assignment
void test_nested_struct_member_assignment(void) {
    struct {
        struct timespec interval;
    } s;
    s.interval.tv_sec = time(NULL);
}

// Pointer Assignment

// Test: Pointer assignment with malloc
void test_pointer_assignment_malloc(void) {
    time_t *tp = malloc(sizeof(time_t));
    if (tp) {
        *tp = time(NULL);
        free(tp);
    }
}

// Test: Pointer assignment with address-of
void test_pointer_assignment_address(void) {
    time_t t;
    time_t *tp = &t;
    *tp = time(NULL);
}

// Test: Double pointer assignment
void test_double_pointer_assignment(void) {
    time_t t;
    time_t *tp = &t;
    time_t **tpp = &tp;
    **tpp = time(NULL);
}

// Test: Pointer arithmetic assignment
void test_pointer_arithmetic_assignment(void) {
    time_t times[10];
    time_t *tp = times;
    *tp = time(NULL);
    *(tp + 1) = time(NULL);
}

// Multiple Assignments

// Test: Multiple assignments
void test_multiple_assignments(void) {
    time_t t1, t2, t3;
    t1 = t2 = t3 = time(NULL);
}

// Test: Assignment in expression
void test_assignment_in_expression(void) {
    time_t t;
    int result = (t = time(NULL)) > 0 ? 1 : 0;
    (void)result;
}

// Test: Assignment with arithmetic
void test_assignment_with_arithmetic(void) {
    time_t t = time(NULL);
    t = t + 3600;
    (void)t;
}

// Test: Assignment from another variable
void test_assignment_from_variable(void) {
    time_t t1 = time(NULL);
    time_t t2;
    t2 = t1;
    (void)t2;
}

// Test: Assignment in loop
void test_assignment_in_loop(void) {
    time_t times[10];
    for (int i = 0; i < 10; i++) {
        times[i] = time(NULL);
    }
}

// Test: Assignment in condition
void test_assignment_in_condition(void) {
    time_t t;
    if ((t = time(NULL)) > 0) {
        return;
    }
}

// Test: Assignment in return
time_t test_assignment_in_return(void) {
    time_t t;
    return t = time(NULL);
}

// Test: Assignment with cast
void test_assignment_with_cast(void) {
    time_t t = time(NULL);
    int i = (int)t;
    (void)i;
}

// Test: Assignment from struct member
void test_assignment_from_struct_member(void) {
    struct timespec ts;
    ts.tv_sec = time(NULL);
    time_t t = ts.tv_sec;
    (void)t;
}

// Test: Assignment to struct member from variable
void test_assignment_to_struct_from_var(void) {
    struct timespec ts;
    time_t t = time(NULL);
    ts.tv_sec = t;
}
