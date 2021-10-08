// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>
#include "../utils/utils.h"

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAKE_BITSET 10
#define FUTEX_CLOCK_REALTIME 256
#define FUTEX_BITSET_MATCH_ANY 0xffffffff

/* get the timestamp in nanoseconds */
uint64_t timestamp_nsec(void)
{
    struct timeval tv = {0L, 0L};
    assert(gettimeofday(&tv, NULL) == 0);
    return 1000 * (tv.tv_sec * 1000000 + tv.tv_usec);
}

void test_double_wait(void)
{
    static uint64_t nanos = 1000000000; /* nanos in one second */
    const uint64_t timeout = nanos;     /* timeout in nanoseconds */
    const uint64_t slop = timeout / 4;  /* 25% tolerance */
    const uint64_t lo = timeout - slop;
    const uint64_t hi = timeout + slop;
    uint64_t delta;
    struct timespec tp = {.tv_sec = timeout / nanos, timeout % nanos};
    int futex_word = 0;

    printf("=== start test (%s)\n", __FUNCTION__);

    const uint64_t t0 = timestamp_nsec();
    syscall(SYS_futex, &futex_word, FUTEX_WAIT, futex_word, &tp, NULL, 0);

    const uint64_t t1 = timestamp_nsec();
    delta = t1 - t0;

    printf("delta=%zu lo=%zu hi=%zu tenth=%zu\n", delta, lo, hi, timeout);
    assert(delta >= lo && delta <= hi);

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
    long r = syscall(SYS_futex, &_uaddr, FUTEX_WAIT, 1, NULL, NULL, 1);
    assert(r == 0);
    return NULL;
}

static void* _wait_thread_bitset(void* arg)
{
    long r = syscall(SYS_futex, &_uaddr, FUTEX_WAIT_BITSET, 1, NULL, NULL, 1);
    assert(r == 0);
    return NULL;
}

static void test_wait_and_wake(void)
{
    pthread_t t1;

    printf("=== start test (%s)\n", __FUNCTION__);

    _uaddr = 1;
    assert(pthread_create(&t1, NULL, _wait_thread, NULL) == 0);

    /* wait until thread is asleep */
    sleep_msec(50);

    _uaddr = 0;
    long r = syscall(SYS_futex, &_uaddr, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    assert(r == 1);
    assert(pthread_join(t1, NULL) == 0);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

static void test_wait_and_wake_n(void)
{
    static const size_t nthreads = 16;
    pthread_t t[nthreads];
    _uaddr = 1;

    printf("=== start test (%s)\n", __FUNCTION__);

    for (size_t i = 0; i < nthreads; i++)
        assert(pthread_create(&t[i], NULL, _wait_thread, NULL) == 0);

    /* wait until all threads are asleep */
    sleep_msec(1000);

    long r = syscall(SYS_futex, &_uaddr, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    assert(r == nthreads);

    for (size_t i = 0; i < nthreads; i++)
        assert(pthread_join(t[i], NULL) == 0);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_wait_realtime(void)
{
    static uint64_t nanos = 1000000000; /* nanos in one second */
    const uint64_t timeout = nanos;     /* timeout in nanoseconds */
    const uint64_t slop = timeout / 4;  /* 25% tolerance */
    const uint64_t lo = timeout - slop;
    const uint64_t hi = timeout + slop;
    uint64_t delta;
    struct timespec tp;
    int futex_word = 0;

    printf("=== start test (%s)\n", __FUNCTION__);

    const uint64_t now = timestamp_nsec();
    const uint64_t then = (now + timeout);
    tp.tv_sec = then / nanos;
    tp.tv_nsec = then % nanos;

#if 0
    struct timespec timenow;
    clock_gettime(CLOCK_REALTIME, &timenow);
    tp.tv_sec = timenow.tv_sec;
    tp.tv_nsec = timenow.tv_nsec + timeout;
#else
#endif

    const uint64_t t0 = timestamp_nsec();
    syscall(
        SYS_futex,
        &futex_word,
        FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME,
        futex_word,
        &tp,
        NULL,
        1);

    const uint64_t t1 = timestamp_nsec();
    delta = t1 - t0;
    assert(delta >= lo && delta <= hi);

    printf("delta=%zu lo=%zu hi=%zu tenth=%zu\n", delta, lo, hi, timeout);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

static void test_wait_and_wake_bitset(void)
{
    pthread_t t1;

    printf("=== start test (%s)\n", __FUNCTION__);

    _uaddr = 1;
    assert(pthread_create(&t1, NULL, _wait_thread_bitset, NULL) == 0);

    /* wait until thread is asleep */
    sleep_msec(100);

    _uaddr = 0;

    /* wait should fail as 1 & 2 == 0 */
    long r =
        syscall(SYS_futex, &_uaddr, FUTEX_WAKE_BITSET, INT_MAX, NULL, NULL, 2);
    assert(r == 0);

    /* wait should pass as 1 & 1 == 1 */
    r = syscall(SYS_futex, &_uaddr, FUTEX_WAKE_BITSET, INT_MAX, NULL, NULL, 1);
    assert(r == 1);

    assert(pthread_join(t1, NULL) == 0);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

static void test_wait_and_wake_n_bitset(void)
{
    static const size_t nthreads = 16;
    pthread_t t[nthreads];
    _uaddr = 1;

    printf("=== start test (%s)\n", __FUNCTION__);

    for (size_t i = 0; i < nthreads; i++)
        assert(pthread_create(&t[i], NULL, _wait_thread_bitset, NULL) == 0);

    /* wait until thread is asleep */
    sleep_msec(1000);

    long r =
        syscall(SYS_futex, &_uaddr, FUTEX_WAKE_BITSET, INT_MAX, NULL, NULL, 1);
    assert(r == 16);

    for (size_t i = 0; i < nthreads; i++)
        assert(pthread_join(t[i], NULL) == 0);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    unsigned long count = 1;

    /* check command-line arguments */
    if (argc != 1 && argc != 2)
    {
        fprintf(stderr, "Usage: %s <count>\n", argv[0]);
        exit(1);
    }

    /* get the count argument if any */
    if (argc == 2)
    {
        char* end = NULL;
        count = strtoul(argv[1], &end, 10);

        if (!end || *end || count == 0)
        {
            fprintf(stderr, "%s: bad count argument: %s\n", argv[0], argv[1]);
            exit(1);
        }
    }

    /* run the tests 1 or more times */
    for (size_t i = 0; i < count; i++)
    {
        test_double_wait();
        test_wait_and_wake();
        test_wait_and_wake_n();
        test_wait_realtime();
        test_wait_and_wake_bitset();
        test_wait_and_wake_n_bitset();
    }

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
