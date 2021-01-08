// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#define NANO_IN_SECOND 1000000000
#define SGX_TARGET "sgx"

static int is_sgx_target()
{
    char* target = getenv("MYST_TARGET");
    if (target != NULL && !strcmp(SGX_TARGET, target))
        return 1;
    else
        return 0;
}

static int test_clock_get_time(long reference)
{
    struct timespec tp = {0};
    long tolerance = NANO_IN_SECOND * 2; // 2s
    long timestamp = 0, prev_timestamp = 0;

    // Check if the current time is close to the time passed from command line
    assert(clock_gettime(CLOCK_REALTIME, &tp) == 0);
    timestamp = tp.tv_sec * NANO_IN_SECOND + tp.tv_nsec;
    long diff = timestamp - reference;
    printf("Time spent on booting myst = %ld ms\n", diff / 1000000);
    assert(diff > 0 && diff < tolerance);

    // Check if the monotonic clock goes backward
    for (int i = 1; i < 1000000000; i++)
    {
        if ((i % 100000000) == 0)
        {
            assert(clock_gettime(CLOCK_MONOTONIC, &tp) == 0);
            timestamp = tp.tv_sec * NANO_IN_SECOND + tp.tv_nsec;
            printf(
                "monotonic clock: prev %ld, now %ld\n",
                prev_timestamp,
                timestamp);

            // No backward clock
            assert(timestamp > prev_timestamp);
            prev_timestamp = timestamp;
        }
    }

    // Check if montonic clock is close to boottime clock
    struct timespec mono_tp = {0};
    struct timespec boot_tp = {0};
    assert(clock_gettime(CLOCK_MONOTONIC, &mono_tp) == 0);
    assert(clock_gettime(CLOCK_BOOTTIME, &boot_tp) == 0);
    long mono_timestamp = mono_tp.tv_sec * NANO_IN_SECOND + mono_tp.tv_nsec;
    long boot_timestamp = boot_tp.tv_sec * NANO_IN_SECOND + boot_tp.tv_nsec;
    long mono_boot_diff = boot_timestamp - mono_timestamp;
    long mono_boot_tolerance = 60000; // in nanoseconds
    printf(
        "Diff between mono and boot = %ld ns (expected  %ld ns)\n",
        mono_boot_diff,
        mono_boot_tolerance);
    assert(mono_boot_diff >= 0 && mono_boot_diff < mono_boot_tolerance);

    // Check coarse clocks
    assert(clock_gettime(CLOCK_REALTIME_COARSE, &tp) == 0);
    assert(clock_gettime(CLOCK_MONOTONIC_COARSE, &tp) == 0);

    // Check process and thread cputime clocks
    assert(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp) == 0);
    assert(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tp) == 0);

    if (is_sgx_target())
    {
        // No support for the following clock ids, yet.
        assert(clock_gettime(CLOCK_REALTIME_ALARM, &tp) == -1);
        assert(clock_gettime(CLOCK_TAI, &tp) == -1);
        assert(clock_gettime(CLOCK_MONOTONIC_RAW, &tp) == -1);
        assert(clock_gettime(CLOCK_BOOTTIME_ALARM, &tp) == -1);
        // ATTN: compare realtime timestamp with a reply from icanhazepoch.com
    }

    return 0;
}

static int test_clock_set_time()
{
    struct timespec tp0 = {0}, tp1 = {0}, tp2 = {0}, update_tp = {0};
    long tolerance = NANO_IN_SECOND / 10; // 0.1s
    long timestamp0 = 0, timestamp1 = 0, timestamp2 = 0;
    const long adjust = 10; // 10 seconds

    assert(clock_gettime(CLOCK_REALTIME, &tp0) == 0);
    timestamp0 = tp0.tv_sec * NANO_IN_SECOND + tp0.tv_nsec;

    update_tp = tp0;
    update_tp.tv_sec -= adjust; // move clock back by `adjust` seconds
    assert(clock_settime(CLOCK_REALTIME, &update_tp) == 0);

    // Validate we can't set the realtime clock backward in the sgx target
    // As only the sgx target maintains the monotonicity of the realtime clock
    assert(clock_gettime(CLOCK_REALTIME, &tp1) == 0);
    timestamp1 = tp1.tv_sec * NANO_IN_SECOND + tp1.tv_nsec;

    assert(timestamp1 > timestamp0);

    update_tp = tp1;
    update_tp.tv_sec += adjust; // move clock forward by `adjust` seconds
    assert(clock_settime(CLOCK_REALTIME, &update_tp) == 0);

    // Validate we can set the realtime clock forward
    assert(clock_gettime(CLOCK_REALTIME, &tp2) == 0);
    timestamp2 = tp2.tv_sec * NANO_IN_SECOND + tp2.tv_nsec;
    long diff = timestamp2 - timestamp1;
    printf(
        "Diff between tp1 and tp2  = %ld ms (expected %ld ms)\n",
        diff / 1000000,
        adjust * 1000);
    assert(diff > 0 && diff < tolerance + adjust * NANO_IN_SECOND);

    // Setting the following clocks is expected to fail
    assert(clock_settime(CLOCK_REALTIME_ALARM, &update_tp) == -1);
    assert(clock_settime(CLOCK_REALTIME_COARSE, &update_tp) == -1);
    assert(clock_settime(CLOCK_TAI, &update_tp) == -1);
    assert(clock_settime(CLOCK_MONOTONIC_COARSE, &update_tp) == -1);
    assert(clock_settime(CLOCK_MONOTONIC, &update_tp) == -1);
    assert(clock_settime(CLOCK_MONOTONIC_RAW, &update_tp) == -1);
    assert(clock_settime(CLOCK_BOOTTIME, &update_tp) == -1);
    assert(clock_settime(CLOCK_BOOTTIME_ALARM, &update_tp) == -1);
    assert(clock_settime(CLOCK_PROCESS_CPUTIME_ID, &update_tp) == -1);
    assert(clock_settime(CLOCK_THREAD_CPUTIME_ID, &update_tp) == -1);

    return 0;
}

static int test_diff_precisions()
{
    struct timespec tp = {0};
    struct timeval tv = {0};
    time_t t = 0;
    long tolerance = 1; // 1 second

    assert(clock_gettime(CLOCK_REALTIME, &tp) == 0);
    assert(gettimeofday(&tv, NULL) == 0);
    t = time(NULL);
    assert(t > 0);

    assert(t >= tp.tv_sec && t - tp.tv_sec <= tolerance);
    assert(t >= tv.tv_sec && t - tv.tv_sec <= tolerance);

    return 0;
}

int main(int argc, const char* argv[])
{
    assert(argc == 3);

    long now_from_cmdline = atol(argv[1]) * NANO_IN_SECOND + atol(argv[2]);

    assert(test_clock_get_time(now_from_cmdline) == 0);

    if (is_sgx_target())
    {
        assert(test_clock_set_time() == 0);
    }

    assert(test_diff_precisions() == 0);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
