
#include <time.h>

// Time type aliases (should match)
#define MY_TIME_T time_t
#define CLOCK_TYPE clock_t
#define TIMER_TYPE timer_t

// Time function aliases (should match)
#define MY_TIME_FUNC time
#define GET_TIME gettimeofday
#define LOCAL_TIME localtime

// Time struct aliases (should match)
#define MY_TIMESPEC struct timespec
#define TIMEVAL_TYPE struct timeval

// Time constants (should match with time context)
#define SECONDS_PER_MINUTE 60
#define SECONDS_PER_HOUR 3600
#define SECONDS_PER_DAY 86400
#define TIMEOUT_MS 1000

// Non-time-related (should NOT match)
#define RTC_REGISTER 0x1234
#define PORT_NUMBER 1000
#define BUFFER_SIZE 1000000
#define CTL_VALUE 0x456
#define BICR_MASK 0xFF
#define ONE_THOUSAND 1000

// Edge cases
#define LFCLK_FREQ 32768
#define SLEEP_DELAY 100
