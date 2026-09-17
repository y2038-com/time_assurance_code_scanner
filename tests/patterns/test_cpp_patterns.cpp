// Copyright (c) 2026 Y2038.com LLC
// SPDX-License-Identifier: Apache-2.0

// Test file for C++ specific patterns
// This file tests various C++ features involving time_t

#include <time.h>
#include <vector>
#include <memory>
#include <map>
#include <set>
#include <array>
#include <deque>
#include <list>
#include <chrono>
#include <iostream>
#include <algorithm>
#include <functional>

// Classes and Member Functions

// Test: Class with time_t member variable
class Timer {
    time_t start_time;
public:
    Timer() : start_time(time(NULL)) {}
    time_t get_time() const { return start_time; }
};

// Test: Class with time_t member function
class TimeManager {
public:
    time_t get_current_time() { return time(NULL); }
};

// Test: Class with time_t in constructor
class TimeContainer {
    time_t timestamp;
public:
    TimeContainer() : timestamp(time(NULL)) {}
};

// Test: Class with time_t in destructor
class TimeGuard {
    time_t start_time;
public:
    TimeGuard() : start_time(time(NULL)) {}
    ~TimeGuard() {
        time_t end_time = time(NULL);
        (void)end_time;
    }
};

// Test: Static member function
class TimeUtils {
public:
    static time_t get_global_time() { return time(NULL); }
};

// Test: Const member function
class TimeReader {
    time_t stored_time;
public:
    TimeReader() : stored_time(time(NULL)) {}
    time_t get_time() const { return stored_time; }
};

// Test: Member function with time_t parameter
class TimeSetter {
    time_t value;
public:
    void set_time(time_t t) { value = t; }
};

// Test: Member function returning time_t
class TimeGetter {
    time_t value;
public:
    time_t get_value() { return value; }
};

// Test: Protected/private time_t members
class TimeBase {
protected:
    time_t protected_time;
private:
    time_t private_time;
public:
    time_t get_protected() { return protected_time; }
};

// Test: Inheritance with time_t
class BaseTime {
protected:
    time_t base_time;
};

class DerivedTime : public BaseTime {
public:
    time_t get_base() { return base_time; }
};

// Templates

// Test: Template function with time_t
template<typename T>
T get_time_value() {
    return static_cast<T>(time(NULL));
}

// Test: Template class with time_t
template<typename T>
class TimeContainer {
    time_t timestamp;
public:
    TimeContainer() : timestamp(time(NULL)) {}
    time_t get_timestamp() { return timestamp; }
};

// Test: Template specialization
template<>
class TimeContainer<int> {
    time_t timestamp;
public:
    TimeContainer() : timestamp(time(NULL)) {}
};

// Test: Template with time_t parameter
template<time_t Default>
class Timer {
    time_t value;
public:
    Timer() : value(Default) {}
};

// Test: Variadic templates
template<typename... Args>
void process_time(time_t t, Args... args) {
    (void)t;
    (void)args...;
}

// Namespaces

// Test: time_t in namespace
namespace myns {
    time_t get_time() { return time(NULL); }
}

// Test: Nested namespaces
namespace outer {
    namespace inner {
        time_t t = time(NULL);
    }
}

// Test: Anonymous namespace
namespace {
    time_t internal_time = time(NULL);
}

// Test: Using declaration
using std::time_t;

// Test: Namespace alias
namespace ts = myns;
void test_namespace_alias() {
    time_t t = ts::get_time();
    (void)t;
}

// Operator Overloading

// Test: Overloaded operator with time_t
class TimeValue {
    time_t value;
public:
    TimeValue(time_t v) : value(v) {}
    time_t operator+(const TimeValue& other) const {
        return value + other.value;
    }
    bool operator<(const TimeValue& other) const {
        return value < other.value;
    }
    TimeValue& operator=(time_t t) {
        value = t;
        return *this;
    }
    operator time_t() const {
        return value;
    }
};

// Test: Stream operators
std::ostream& operator<<(std::ostream& os, time_t t) {
    return os << t;
}

// STL Containers

// Test: vector<time_t>
void test_vector_time_t() {
    std::vector<time_t> times;
    times.push_back(time(NULL));
}

// Test: map with time_t values
void test_map_time_t_value() {
    std::map<std::string, time_t> time_map;
    time_map["start"] = time(NULL);
}

// Test: map with time_t keys
void test_map_time_t_key() {
    std::map<time_t, std::string> time_map;
    time_map[time(NULL)] = "start";
}

// Test: set<time_t>
void test_set_time_t() {
    std::set<time_t> time_set;
    time_set.insert(time(NULL));
}

// Test: array<time_t>
void test_array_time_t() {
    std::array<time_t, 10> times;
    times[0] = time(NULL);
}

// Test: deque<time_t>
void test_deque_time_t() {
    std::deque<time_t> times;
    times.push_back(time(NULL));
}

// Test: list<time_t>
void test_list_time_t() {
    std::list<time_t> times;
    times.push_back(time(NULL));
}

// Test: pair with time_t
void test_pair_time_t() {
    std::pair<time_t, int> p(time(NULL), 42);
    (void)p;
}

// Test: tuple with time_t
void test_tuple_time_t() {
    std::tuple<time_t, int, std::string> t(time(NULL), 42, "test");
    (void)t;
}

// Test: STL algorithms
void test_stl_algorithms() {
    std::vector<time_t> times;
    times.push_back(time(NULL));
    std::sort(times.begin(), times.end());
}

// Test: Range-based for
void test_range_based_for() {
    std::vector<time_t> times;
    times.push_back(time(NULL));
    for (time_t t : times) {
        (void)t;
    }
}

// Smart Pointers

// Test: unique_ptr<time_t>
void test_unique_ptr_time_t() {
    auto ptr = std::make_unique<time_t>(time(NULL));
    *ptr = time(NULL);
}

// Test: shared_ptr<time_t>
void test_shared_ptr_time_t() {
    auto ptr = std::make_shared<time_t>(time(NULL));
    *ptr = time(NULL);
}

// Test: weak_ptr<time_t>
void test_weak_ptr_time_t() {
    auto shared = std::make_shared<time_t>(time(NULL));
    std::weak_ptr<time_t> weak = shared;
}

// Lambda Functions

// Test: Lambda capturing time_t
void test_lambda_capture_time_t() {
    time_t t = time(NULL);
    auto f = [t]() { return t; };
    (void)f;
}

// Test: Lambda calling time()
void test_lambda_call_time() {
    auto f = []() { return time(NULL); };
    (void)f;
}

// Test: Lambda with time_t parameter
void test_lambda_time_t_param() {
    auto f = [](time_t t) { return t + 1; };
    (void)f;
}

// Test: Lambda in STL
void test_lambda_in_stl() {
    std::vector<time_t> times;
    times.push_back(time(NULL));
    std::for_each(times.begin(), times.end(), [](time_t t) {
        (void)t;
    });
}

// Test: Generic lambda
void test_generic_lambda() {
    auto f = [](auto t) { return t; };
    time_t t = time(NULL);
    (void)f(t);
}

// RAII Patterns

// Test: RAII class with time_t
class TimeRAII {
    time_t start;
public:
    TimeRAII() : start(time(NULL)) {}
    ~TimeRAII() {
        time_t end = time(NULL);
        (void)end;
    }
};

// Test: Smart pointer RAII
class TimeManagerRAII {
    std::unique_ptr<time_t> time_ptr;
public:
    TimeManagerRAII() : time_ptr(std::make_unique<time_t>(time(NULL))) {}
};

// std::chrono (C++11+)

// Test: chrono time_point
void test_chrono_time_point() {
    auto now = std::chrono::system_clock::now();
    time_t t = std::chrono::system_clock::to_time_t(now);
    (void)t;
}

// Test: chrono conversion from time_t
void test_chrono_from_time_t() {
    time_t t = time(NULL);
    auto tp = std::chrono::system_clock::from_time_t(t);
    (void)tp;
}

// Test: chrono duration arithmetic
void test_chrono_duration() {
    auto now = std::chrono::system_clock::now();
    auto future = now + std::chrono::hours(24);
    (void)future;
}

// Test: chrono seconds
void test_chrono_seconds() {
    std::chrono::seconds s(3600);
    (void)s;
}

// Test: chrono milliseconds
void test_chrono_milliseconds() {
    std::chrono::milliseconds ms(1000);
    (void)ms;
}

// C++11/14/17/20 Features

// Test: auto keyword
void test_auto_time_t() {
    auto t = time(NULL);
    (void)t;
}

// Test: decltype
void test_decltype_time_t() {
    decltype(time(NULL)) t = time(NULL);
    (void)t;
}

// Test: nullptr
void test_nullptr_time_t() {
    time_t* ptr = nullptr;
    (void)ptr;
}

// Test: Initializer lists
void test_initializer_list_time_t() {
    std::vector<time_t> times = {time(NULL), 0, time(NULL)};
    (void)times;
}

// Test: Range-based for with auto
void test_range_for_auto() {
    std::vector<time_t> times;
    times.push_back(time(NULL));
    for (auto t : times) {
        (void)t;
    }
}

// Test: Structured bindings (C++17)
void test_structured_bindings() {
    auto pair = std::make_pair(time(NULL), time(NULL));
    auto [t1, t2] = pair;
    (void)t1;
    (void)t2;
}

// Function Overloading

// Test: Overloaded functions
void process_time(time_t t) {
    (void)t;
}

void process_time(int i) {
    (void)i;
}

// Test: Overloaded operators
TimeValue operator+(const TimeValue& t1, time_t t2) {
    return TimeValue(t1.get_value() + t2);
}

TimeValue operator+(time_t t1, const TimeValue& t2) {
    return TimeValue(t1 + t2.get_value());
}

// Default Arguments

// Test: Default time_t argument
void func_with_default_time(time_t t = time(NULL)) {
    (void)t;
}

// Test: Default with nullptr
void func_with_nullptr_default(time_t* t = nullptr) {
    (void)t;
}

// Test: Default with constant
void func_with_constant_default(time_t t = 0) {
    (void)t;
}

// Method Chaining

// Test: Fluent interface
class FluentTimer {
    time_t start_time;
public:
    FluentTimer& set_time(time_t t) {
        start_time = t;
        return *this;
    }
    FluentTimer& start() {
        start_time = time(NULL);
        return *this;
    }
    void wait() {
        (void)start_time;
    }
};

// Exception Handling

// Test: time_t in try block
void test_try_time_t() {
    try {
        time_t t = time(NULL);
        (void)t;
    } catch (...) {
    }
}

// Test: time_t in catch
void test_catch_time_t() {
    try {
        throw std::runtime_error("error");
    } catch (const std::exception& e) {
        time_t t = time(NULL);
        (void)t;
        (void)e;
    }
}

// Move Semantics (C++11+)

// Test: Move constructor
class MoveableTimer {
    time_t value;
public:
    MoveableTimer(time_t v) : value(v) {}
    MoveableTimer(MoveableTimer&& other) : value(other.value) {
        other.value = 0;
    }
    MoveableTimer& operator=(MoveableTimer&& other) {
        value = other.value;
        other.value = 0;
        return *this;
    }
};

// References vs Pointers

// Test: Reference parameter
void func_time_t_ref(time_t& t) {
    t = time(NULL);
}

// Test: Const reference
void func_time_t_const_ref(const time_t& t) {
    (void)t;
}

// Test: Rvalue reference
void func_time_t_rvalue_ref(time_t&& t) {
    (void)t;
}

// Friend Functions

// Test: Friend function
class FriendTimer {
    time_t value;
    friend time_t get_friend_time(const FriendTimer& t);
};

time_t get_friend_time(const FriendTimer& t) {
    return t.value;
}

// Virtual Functions

// Test: Virtual function with time_t
class VirtualTimeBase {
public:
    virtual time_t get_time() { return time(NULL); }
};

class VirtualTimeDerived : public VirtualTimeBase {
public:
    time_t get_time() override { return time(NULL); }
};

// Static Members

// Test: Static member variable
class StaticTimer {
public:
    static time_t global_time;
};

time_t StaticTimer::global_time = time(NULL);

// Test: Static member function
class StaticTimeUtils {
public:
    static time_t get_global() {
        return StaticTimer::global_time;
    }
};

// Inline Functions

// Test: Inline function
inline time_t get_inline_time() {
    return time(NULL);
}

// Test: Inline member function
class InlineTimer {
    time_t value;
public:
    inline time_t get() { return value; }
};

// C++ Casts

// Test: static_cast<time_t>
void test_static_cast_time_t() {
    int i = 42;
    time_t t = static_cast<time_t>(i);
    (void)t;
}

// Test: reinterpret_cast<time_t*>
void test_reinterpret_cast_time_t() {
    void* ptr = malloc(sizeof(time_t));
    time_t* tp = reinterpret_cast<time_t*>(ptr);
    (void)tp;
    free(ptr);
}

// Test: const_cast<time_t*>
void test_const_cast_time_t() {
    const time_t* ct = nullptr;
    time_t* t = const_cast<time_t*>(ct);
    (void)t;
}

// C++ Attributes (C++11+)

// Test: [[nodiscard]]
[[nodiscard]] time_t get_nodiscard_time() {
    return time(NULL);
}

// Test: [[maybe_unused]]
void test_maybe_unused_time_t() {
    [[maybe_unused]] time_t unused_time = time(NULL);
}

// C++ Standard Library Time Functions

// Test: std::time()
void test_std_time() {
    time_t t = std::time(nullptr);
    (void)t;
}

// Test: std::localtime()
void test_std_localtime() {
    time_t t = time(NULL);
    std::tm* tm = std::localtime(&t);
    (void)tm;
}

// Test: std::gmtime()
void test_std_gmtime() {
    time_t t = time(NULL);
    std::tm* tm = std::gmtime(&t);
    (void)tm;
}

// Test: std::mktime()
void test_std_mktime() {
    std::tm tm = {};
    time_t t = std::mktime(&tm);
    (void)t;
}

// C++ vs C Compatibility

// Test: C-style cast in C++
void test_c_style_cast_cpp() {
    int i = (int)time(NULL);
    (void)i;
}

// Test: C++ cast from C function
void test_cpp_cast_from_c() {
    int i = static_cast<int>(time(NULL));
    (void)i;
}

// Test: Mixing C and C++
extern "C" {
    time_t c_get_time();
}

void test_mix_c_cpp() {
    time_t t = c_get_time();
    (void)t;
}

// Test: C linkage
extern "C" time_t c_linkage_get_time() {
    return time(NULL);
}
