// Test file for macro patterns
// This file tests various #define patterns that the scanner should detect

#ifndef TEST_MACRO_PATTERNS_H
#define TEST_MACRO_PATTERNS_H

#include <time.h>

// time_type_alias patterns

// Test: Simple time_t alias
#define TIME_TYPE time_t

// Test: time_t alias with different name
#define MY_TIME time_t

// Test: time_t alias with prefix
#define SYS_TIME_T time_t

// Test: time_t alias with suffix
#define TIME_T_ALIAS time_t

// Test: time_t alias in typedef style
#define TIME_TYPEDEF time_t

// time_function_alias patterns

// Test: Simple time function alias
#define GET_TIME time

// Test: Function alias with parentheses
#define CURRENT_TIME() time(NULL)

// Test: Function alias without parentheses
#define MY_TIME_FUNC time

// Test: Function alias with parameters
#define GET_CURRENT_TIME() time(NULL)

// Test: Multiple function aliases
#define GET_TIME_FUNC time
#define SET_TIME_FUNC time

// time_constant patterns

// Test: Seconds per minute
#define SECONDS_PER_MINUTE 60

// Test: Seconds per hour
#define SECONDS_PER_HOUR 3600

// Test: Seconds per day
#define SECONDS_PER_DAY 86400

// Test: Seconds per week
#define SECONDS_PER_WEEK 604800

// Test: Seconds per month (30 days)
#define SECONDS_PER_MONTH 2592000

// Test: Seconds per year (365 days)
#define SECONDS_PER_YEAR 31536000

// Test: Seconds per year (365.25 days)
#define SECONDS_PER_YEAR_LEAP 31557600

// Test: Minutes per hour
#define MINUTES_PER_HOUR 60

// Test: Hours per day
#define HOURS_PER_DAY 24

// Test: Days per week
#define DAYS_PER_WEEK 7

// time_struct_alias patterns

// Test: timespec alias
#define TIME_SPEC struct timespec

// Test: timeval alias
#define TIME_VAL struct timeval

// Test: timespec alias with different name
#define TIME_STRUCT struct timespec

// Test: timeval alias with different name
#define TIME_VALUE struct timeval

// Test: timespec pointer alias
#define TIME_SPEC_PTR struct timespec *

// Test: timeval pointer alias
#define TIME_VAL_PTR struct timeval *

// Test: SELECT_TYPE_ARG5 pattern (from real code)
#define SELECT_TYPE_ARG5 (struct timeval *)

// Complex Macro Patterns

// Test: TIME_MAX pattern (from real code)
#define TIME_MAX ((((time_t)1 << (8 * sizeof(time_t) - 2)) - 1) * 2 + 1)

// Test: TIME_MAX variant
#define SYS_TIME_T_MAX ((((time_t)1 << (8 * sizeof(time_t) - 2)) - 1) * 2 + 1)

// Test: TIME_MIN pattern
#define TIME_MIN 0

// Test: Time arithmetic macro
#define TIME_ADD(a, b) ((time_t)((a) + (b)))

// Test: Time subtraction macro
#define TIME_SUB(a, b) ((time_t)((a) - (b)))

// Test: Time comparison macro
#define TIME_COMPARE(t1, t2) ((t1) > (t2))

// Test: Time equality macro
#define TIME_EQUAL(t1, t2) ((t1) == (t2))

// Test: Time conversion macro
#define TIME_TO_SECONDS(t) ((t))

// Test: Seconds to time macro
#define SECONDS_TO_TIME(s) ((time_t)(s))

// Test: Time validation macro
#define IS_VALID_TIME(t) ((t) > 0)

// Test: Time clamp macro
#define CLAMP_TIME(t, min, max) (((t) < (min)) ? (min) : (((t) > (max)) ? (max) : (t)))

// Test: Time delta macro
#define TIME_DELTA(t1, t2) ((time_t)((t1) - (t2)))

// Test: Time absolute difference macro
#define TIME_ABS_DIFF(t1, t2) ((time_t)(((t1) > (t2)) ? ((t1) - (t2)) : ((t2) - (t1))))

// Nested Macro Patterns

// Test: Nested time_t macros
#define TIME_TYPE_BASE time_t
#define TIME_TYPE_ALIAS TIME_TYPE_BASE

// Test: Nested function macros
#define TIME_FUNC time
#define CALL_TIME_FUNC() TIME_FUNC(NULL)

// Test: Nested constant macros
#define SECONDS_PER_MINUTE_BASE 60
#define SECONDS_PER_HOUR_BASE (SECONDS_PER_MINUTE_BASE * 60)

// Test: Nested struct macros
#define TIME_STRUCT_BASE struct timespec
#define TIME_STRUCT_PTR_BASE TIME_STRUCT_BASE *

// Multi-line Macro Patterns

// Test: Multi-line time_t macro
#define TIME_MACRO_MULTILINE \
    time_t t = time(NULL); \
    return t;

// Test: Multi-line function macro
#define GET_TIME_MULTILINE() \
    do { \
        time_t t = time(NULL); \
        return t; \
    } while(0)

// Test: Multi-line struct macro
#define INIT_TIMESPEC(ts, sec, nsec) \
    do { \
        (ts)->tv_sec = (sec); \
        (ts)->tv_nsec = (nsec); \
    } while(0)

// Conditional Macro Patterns

// Test: Conditional time_t macro
#ifdef USE_TIME_T
#define MY_TIME_TYPE time_t
#else
#define MY_TIME_TYPE int64_t
#endif

// Test: Conditional function macro
#if TIME_FEATURE_ENABLED
#define GET_TIME_FUNC() time(NULL)
#else
#define GET_TIME_FUNC() 0
#endif

// Test: Conditional struct macro
#if defined(HAVE_TIMESPEC)
#define TIME_STRUCT_TYPE struct timespec
#elif defined(HAVE_TIMEVAL)
#define TIME_STRUCT_TYPE struct timeval
#else
#define TIME_STRUCT_TYPE struct tm
#endif

// Macro with Parameters

// Test: Macro function with time_t parameter
#define PROCESS_TIME(t) do { time_t _t = (t); (void)_t; } while(0)

// Test: Macro function with time_t return
#define GET_TIME_VALUE() time(NULL)

// Test: Macro function with multiple time_t parameters
#define COMPARE_TIMES(t1, t2) ((t1) > (t2) ? (t1) : (t2))

// Test: Macro function with time_t arithmetic
#define ADD_SECONDS(t, s) ((time_t)((t) + (s)))

// Test: Macro function with time_t cast
#define TIME_TO_INT(t) ((int)(t))

// Test: Macro function with time_t validation
#define VALIDATE_TIME(t) (((t) > 0) && ((t) < TIME_MAX))

// Stringification and Concatenation

// Test: Stringification of time_t
#define TIME_T_STR "time_t"

// Test: Concatenation with time_t
#define TIME_PREFIX "time_"
#define TIME_SUFFIX "_t"
#define TIME_FULL TIME_PREFIX "value" TIME_SUFFIX

// Variadic Macro Patterns

// Test: Variadic macro with time_t (C99)
#define TIME_LOG(fmt, ...) printf(fmt, __VA_ARGS__)

// Test: Variadic macro with time_t (GNU extension)
#define TIME_LOG_GNU(fmt, args...) printf(fmt, ##args)

// Macro with typeof (GNU extension)

// Test: typeof with time_t
#define TIME_T_TYPE typeof(time_t)

// Test: typeof with time() result
#define TIME_RESULT_TYPE typeof(time(NULL))

// Macro with sizeof

// Test: sizeof time_t
#define TIME_T_SIZE sizeof(time_t)

// Test: sizeof time_t pointer
#define TIME_T_PTR_SIZE sizeof(time_t *)

// Macro with offsetof

// Test: offsetof with time_t member
#include <stddef.h>
struct test_time_struct {
    int x;
    time_t t;
};
#define TIME_OFFSET offsetof(struct test_time_struct, t)

// Macro with _Generic (C11)

// Test: _Generic with time_t
#define TIME_TYPE_NAME(t) _Generic((t), \
    time_t: "time_t", \
    default: "unknown" \
)

#endif // TEST_MACRO_PATTERNS_H
