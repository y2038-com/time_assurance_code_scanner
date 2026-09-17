// Copyright (c) 2026 Y2038.com LLC
// SPDX-License-Identifier: Apache-2.0

// Test file for narrowing patterns that should fail even in LP64 configurations
// These patterns explicitly narrow 64-bit time_t to 32-bit, which is a Y2038 risk
// even on systems with 64-bit time_t

#include <time.h>
#include <stdint.h>
#include <sys/time.h>

// ============================================================================
// Pattern 1: Explicit casts to 32-bit signed integers (int32_t)
// ============================================================================

// Test: Cast time_t to int32_t (should be YES even in LP64)
void test_cast_to_int32_t(void) {
    time_t t = time(NULL);
    int32_t narrow = (int32_t)t;  // Explicit narrowing - Y2038 risk
    (void)narrow;
}

// Test: Cast time() return to int32_t
void test_cast_time_to_int32_t(void) {
    int32_t narrow = (int32_t)time(NULL);  // Direct cast - Y2038 risk
    (void)narrow;
}

// Test: Cast timespec.tv_sec to int32_t
void test_cast_timespec_to_int32_t(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int32_t narrow = (int32_t)ts.tv_sec;  // Narrowing struct member - Y2038 risk
    (void)narrow;
}

// Test: Implicit cast via assignment to int32_t
void test_implicit_cast_to_int32_t(void) {
    time_t t = time(NULL);
    int32_t narrow = t;  // Implicit narrowing - Y2038 risk
    (void)narrow;
}

// Test: Cast in expression
void test_cast_in_expression(void) {
    time_t t = time(NULL);
    if ((int32_t)t > 0) {  // Cast in condition - Y2038 risk
        return;
    }
}

// Test: Cast in return statement
int32_t test_cast_in_return(void) {
    time_t t = time(NULL);
    return (int32_t)t;  // Cast in return - Y2038 risk
}

// ============================================================================
// Pattern 2: Typedef of int32_t used to hold time_t values
// ============================================================================

// Typedef that looks like it might be time-related but is actually int32_t
typedef int32_t narrow_time_t;

// Test: Typedef used to store time_t
void test_typedef_narrow_time_t(void) {
    time_t t = time(NULL);
    narrow_time_t narrow = t;  // Typedef narrowing - Y2038 risk
    (void)narrow;
}

// Test: Typedef used in struct
struct event_record_narrow {
    narrow_time_t timestamp;  // Typedef in struct - Y2038 risk
    int value;
};

void test_typedef_in_struct(void) {
    struct event_record_narrow event;
    event.timestamp = time(NULL);  // Assignment to typedef member - Y2038 risk
    (void)event;
}

// Test: Typedef used in function parameter
void test_typedef_function_param(narrow_time_t t) {
    (void)t;
}

void test_typedef_function_call(void) {
    time_t t = time(NULL);
    test_typedef_function_param(t);  // Passing time_t to narrow typedef - Y2038 risk
}

// Test: Typedef used in function return
narrow_time_t test_typedef_return(void) {
    time_t t = time(NULL);
    return t;  // Returning time_t as narrow typedef - Y2038 risk
}

// ============================================================================
// Pattern 3: #define that creates a narrow type alias
// ============================================================================

// #define that aliases to int32_t
#define NARROW_TIME_TYPE int32_t

// Test: #define used to store time_t
void test_define_narrow_type(void) {
    time_t t = time(NULL);
    NARROW_TIME_TYPE narrow = t;  // #define narrowing - Y2038 risk
    (void)narrow;
}

// Test: #define used in struct
struct event_record_define {
    NARROW_TIME_TYPE timestamp;  // #define in struct - Y2038 risk
    int value;
};

void test_define_in_struct(void) {
    struct event_record_define event;
    event.timestamp = time(NULL);  // Assignment to #define member - Y2038 risk
    (void)event;
}

// #define that casts to int32_t
#define NARROW_TIME(t) ((int32_t)(t))

// Test: #define used as cast
void test_define_cast(void) {
    time_t t = time(NULL);
    int32_t narrow = NARROW_TIME(t);  // #define cast - Y2038 risk
    (void)narrow;
}

// ============================================================================
// Pattern 4: Struct member assigned time_t value directly
// ============================================================================

// Struct with int32_t member
struct time_record {
    int32_t timestamp;  // 32-bit member
    int value;
};

// Test: Direct assignment to 32-bit struct member
void test_struct_member_assignment(void) {
    struct time_record record;
    record.timestamp = time(NULL);  // Direct assignment - Y2038 risk
    (void)record;
}

// Test: Assignment via pointer
void test_struct_pointer_assignment(void) {
    struct time_record record;
    struct time_record *ptr = &record;
    ptr->timestamp = time(NULL);  // Pointer assignment - Y2038 risk
    (void)record;
}

// Test: Assignment in initialization
void test_struct_initialization(void) {
    struct time_record record = {
        .timestamp = time(NULL),  // Initialization - Y2038 risk
        .value = 0
    };
    (void)record;
}

// Test: Assignment from timespec
void test_struct_from_timespec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct time_record record;
    record.timestamp = ts.tv_sec;  // From struct member - Y2038 risk
    (void)record;
}

// ============================================================================
// Pattern 5: Struct member returned from function that returns time_t
// ============================================================================

// Struct with int32_t member
struct time_storage {
    int32_t stored_time;  // 32-bit storage
    int flags;
};

// Test: Function returns time_t, stored in 32-bit member
time_t test_return_time_t_to_struct(void) {
    struct time_storage storage;
    storage.stored_time = time(NULL);  // Storing in 32-bit member - Y2038 risk
    return storage.stored_time;  // Returning from 32-bit member - Y2038 risk
}

// Test: Function that takes time_t and stores in struct
void test_store_time_t_in_struct(time_t t) {
    struct time_storage storage;
    storage.stored_time = t;  // Storing time_t in 32-bit member - Y2038 risk
    (void)storage;
}

// Test: Function that returns struct member as time_t
time_t test_return_struct_member(void) {
    struct time_storage storage;
    storage.stored_time = time(NULL);
    return storage.stored_time;  // Returning 32-bit as time_t - Y2038 risk
}

// Test: Nested struct with narrowing
struct outer_time {
    struct time_storage inner;  // Nested struct with 32-bit member
    int id;
};

void test_nested_struct_narrowing(void) {
    struct outer_time outer;
    outer.inner.stored_time = time(NULL);  // Nested assignment - Y2038 risk
    (void)outer;
}

// ============================================================================
// Pattern 6: Array of 32-bit integers storing time_t values
// ============================================================================

// Test: Array of int32_t storing time_t
void test_array_narrowing(void) {
    int32_t timestamps[10];
    timestamps[0] = time(NULL);  // Array assignment - Y2038 risk
    (void)timestamps;
}

// Test: Array in struct
struct time_array {
    int32_t timestamps[10];  // Array of 32-bit
    int count;
};

void test_struct_array_narrowing(void) {
    struct time_array arr;
    arr.timestamps[0] = time(NULL);  // Struct array assignment - Y2038 risk
    (void)arr;
}

// ============================================================================
// Pattern 7: Serialization/Network patterns (common narrowing scenarios)
// ============================================================================

// Network packet with 32-bit time field
struct __attribute__((packed)) network_packet {
    uint16_t version;
    int32_t timestamp;  // 32-bit in network format - Y2038 risk
    uint16_t flags;
};

void test_network_serialization(void) {
    struct network_packet packet;
    packet.timestamp = (int32_t)time(NULL);  // Network serialization - Y2038 risk
    (void)packet;
}

// File header with 32-bit time
struct file_header {
    char magic[4];
    int32_t timestamp;  // 32-bit in file - Y2038 risk
    uint32_t size;
};

void test_file_storage(void) {
    struct file_header header;
    header.timestamp = (int32_t)time(NULL);  // File storage - Y2038 risk
    (void)header;
}

// Database record with 32-bit time
struct db_record {
    int64_t id;
    int32_t created_at;  // 32-bit in database - Y2038 risk
    int32_t updated_at;  // 32-bit in database - Y2038 risk
};

void test_database_record(void) {
    struct db_record record;
    record.created_at = (int32_t)time(NULL);  // Database storage - Y2038 risk
    record.updated_at = (int32_t)time(NULL);  // Database storage - Y2038 risk
    (void)record;
}

// ============================================================================
// Pattern 8: Complex narrowing scenarios
// ============================================================================

// Test: Multiple narrowing operations
void test_multiple_narrowing(void) {
    time_t t1 = time(NULL);
    time_t t2 = time(NULL);
    int32_t diff = (int32_t)(t2 - t1);  // Arithmetic then narrowing - Y2038 risk
    (void)diff;
}

// Test: Narrowing in comparison
void test_narrowing_comparison(void) {
    time_t t = time(NULL);
    int32_t threshold = 2147483647;  // Max int32_t
    if ((int32_t)t > threshold) {  // Narrowing in comparison - Y2038 risk
        return;
    }
}

// Test: Narrowing in loop
void test_narrowing_loop(void) {
    int32_t timestamps[10];
    for (int i = 0; i < 10; i++) {
        timestamps[i] = (int32_t)time(NULL);  // Loop narrowing - Y2038 risk
    }
    (void)timestamps;
}

// Test: Function that narrows and returns
int32_t test_narrowing_function(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int32_t)ts.tv_sec;  // Function narrowing - Y2038 risk
}

// Test: Narrowing via function call
void test_narrowing_via_function(void) {
    int32_t narrow = test_narrowing_function();  // Getting narrowed value - Y2038 risk
    (void)narrow;
}
