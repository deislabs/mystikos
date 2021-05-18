// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>
#include "../utils/utils.h"

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

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
    const uint64_t slop = 5000000;
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

static int _uaddr = 0;

static void* _wait_thread(void* arg)
{
    long r = syscall(SYS_futex, &_uaddr, FUTEX_WAIT, 1, NULL, NULL, 0);
    assert(r == 0);
    return NULL;
}

static void test_wait_and_wake(void)
{
    pthread_t t1;

    _uaddr = 1;
    assert(pthread_create(&t1, NULL, _wait_thread, NULL) == 0);

    /* wait until thread is asleep */
    sleep_msec(50);

    _uaddr = 0;
    long r = syscall(SYS_futex, &_uaddr, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    assert(r == 1);
    assert(pthread_join(t1, NULL) == 0);
}

static void test_wait_and_wake_n(void)
{
    static const size_t nthreads = 16;
    pthread_t t[nthreads];
    _uaddr = 1;

    for (size_t i = 0; i < nthreads; i++)
        assert(pthread_create(&t[i], NULL, _wait_thread, NULL) == 0);

    /* wait until thread is asleep */
    sleep_msec(50);

    long r = syscall(SYS_futex, &_uaddr, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    assert(r == 16);

    for (size_t i = 0; i < nthreads; i++)
        assert(pthread_join(t[i], NULL) == 0);
}

int main(int argc, const char* argv[])
{
    test_double_wait();
    test_wait_and_wake();
    test_wait_and_wake_n();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
