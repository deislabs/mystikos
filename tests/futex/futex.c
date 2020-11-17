// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#define FUTEX_WAIT 0

/* get the timestamp in nanoseconds */
uint64_t timestamp_nsec(void)
{
    struct timeval tv = {0L, 0L};
    assert(gettimeofday(&tv, NULL) == 0);
    return 1000 * (tv.tv_sec * 1000000 + tv.tv_usec);
}

void test_double_wait(void)
{
    const uint64_t nsec = 1000000000;
    const uint64_t timeout = nsec / 10;
    const uint64_t slop = 500000;
    const uint64_t lo = timeout - slop;
    const uint64_t hi = timeout + slop;
    uint64_t delta;
    struct timespec tp = {.tv_sec = 0, timeout};
    int futex_word = 0;

    const uint64_t t0 = timestamp_nsec();
    syscall(SYS_futex, &futex_word, FUTEX_WAIT, futex_word, &tp, NULL, 0);

    const uint64_t t1 = timestamp_nsec();
    delta = t1 - t0;
    assert(delta >= lo && delta <= hi);

    printf("delta=%zu lo=%zu hi=%zu tenth=%zu\n", delta, lo, hi, timeout);

    const uint64_t t3 = timestamp_nsec();

    syscall(SYS_futex, &futex_word, FUTEX_WAIT, futex_word, &tp, NULL, 0);

    const uint64_t t4 = timestamp_nsec();
    delta = t4 - t3;
    assert(delta >= lo && delta <= hi);

    printf("delta=%zu lo=%zu hi=%zu tenth=%zu\n", delta, lo, hi, timeout);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    test_double_wait();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
