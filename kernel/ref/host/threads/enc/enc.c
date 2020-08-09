// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include <unistd.h>
#include <openenclave/internal/backtrace.h>
#include "posix_t.h"
#include "../../../../3rdparty/libc/musl/src/posix/posix_ocalls.h"

#define NUM_THREADS 6

void posix_init(struct posix_shared_block* shared_block, int tid);

extern bool oe_disable_debug_malloc_check;

extern int posix_gettid(void);

void sleep_msec(uint64_t milliseconds)
{
    struct timespec ts;
    const struct timespec* req = &ts;
    struct timespec rem = {0, 0};
    static const uint64_t _SEC_TO_MSEC = 1000UL;
    static const uint64_t _MSEC_TO_NSEC = 1000000UL;

    ts.tv_sec = (time_t)(milliseconds / _SEC_TO_MSEC);
    ts.tv_nsec = (long)((milliseconds % _SEC_TO_MSEC) * _MSEC_TO_NSEC);

    while (nanosleep(req, &rem) != 0 && errno == EINTR)
    {
        req = &rem;
    }
}

static void* _thread_func(void* arg)
{
    uint64_t secs = (size_t)arg;
    uint64_t msecs = secs * 1000;

    oe_host_printf("_thread_func()\n");
    sleep_msec(msecs / 10);

    return arg;
}

void test_create_thread(void)
{
    pthread_t threads[NUM_THREADS];

    printf("=== %s()\n", __FUNCTION__);

    /* Create threads */
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        if (pthread_create(&threads[i], NULL, _thread_func, (void*)i) != 0)
        {
            fprintf(stderr, "pthread_create() failed\n");
            abort();
        }
    }

    /* Join threads */
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        void* retval;

        if (pthread_join(threads[i], &retval) != 0)
        {
            fprintf(stderr, "pthread_join() failed\n");
            abort();
        }

        oe_host_printf("joined...\n");

        OE_TEST((uint64_t)retval == i);
    }
}

static uint64_t _shared_integer = 0;
static pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;
const size_t N = 100;

static void* _test_mutex_thread(void* arg)
{
    size_t n = (uint64_t)arg;

    for (size_t i = 0; i < n*N; i++)
    {
        pthread_mutex_lock(&_mutex);
        _shared_integer++;
        pthread_mutex_unlock(&_mutex);
    }

    return arg;
}

void test_mutexes(void)
{
    pthread_t threads[NUM_THREADS];
    size_t integer = 0;

    printf("=== %s()\n", __FUNCTION__);

    /* Create threads */
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        void* arg = (void*)i;

        if (pthread_create(&threads[i], NULL, _test_mutex_thread, arg) != 0)
        {
            fprintf(stderr, "pthread_create() failed\n");
            abort();
        }

        integer += i * N;
    }

    /* Join threads */
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        void* retval;
        OE_TEST(pthread_join(threads[i], &retval) == 0);
        OE_TEST((uint64_t)retval == i);
        printf("joined...\n");
    }

    OE_TEST(integer == _shared_integer);
}

static pthread_mutex_t _timed_mutex = PTHREAD_MUTEX_INITIALIZER;

static __int128 _time(void)
{
    const __int128 BILLION = 1000000000;
    struct timespec now;

    clock_gettime(CLOCK_REALTIME, &now);

    return (__int128)now.tv_sec * BILLION + (__int128)now.tv_nsec;
}

static void* _test_timedlock(void* arg)
{
    (void)arg;
    const uint64_t TIMEOUT_SEC = 3;
    const __int128 BILLION = 1000000000;
    const __int128 LO = (TIMEOUT_SEC * BILLION) - (BILLION / 5);
    const __int128 HI = (TIMEOUT_SEC * BILLION) + (BILLION / 5);

    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += TIMEOUT_SEC;

    __int128 t1 = _time();

    int r = pthread_mutex_timedlock(&_timed_mutex, &timeout);
    OE_TEST(r == ETIMEDOUT);

    __int128 t2 = _time();
    __int128 delta = t2 - t1;
    OE_TEST(delta >= LO && delta <= HI);

    return NULL;
}

void test_timedlock(void)
{
    pthread_t thread;

    printf("=== %s()\n", __FUNCTION__);

    pthread_mutex_lock(&_timed_mutex);

    if (pthread_create(&thread, NULL, _test_timedlock, NULL) != 0)
    {
        fprintf(stderr, "pthread_create() failed\n");
        abort();
    }

    for (size_t i = 0; i < 6; i++)
    {
        printf("sleeping...\n");
        sleep(1);
    }

    if (pthread_join(thread, NULL) != 0)
    {
        fprintf(stderr, "pthread_create() failed\n");
        abort();
    }

    pthread_mutex_unlock(&_timed_mutex);
}

struct test_cond_arg
{
    pthread_cond_t c;
    pthread_mutex_t m;
    size_t n;
};

static void* _test_cond(void* arg_)
{
    struct test_cond_arg* arg = (struct test_cond_arg*)arg_;

    pthread_mutex_lock(&arg->m);
    printf("wait: %p\n", pthread_self());
    pthread_cond_wait(&arg->c, &arg->m);
    arg->n++;
    pthread_mutex_unlock(&arg->m);

    return pthread_self();
}

void test_cond_signal(void)
{
    pthread_t threads[NUM_THREADS];

    printf("=== %s()\n", __FUNCTION__);

    struct test_cond_arg arg;

    OE_TEST(pthread_cond_init(&arg.c, NULL) == 0);
    OE_TEST(pthread_mutex_init(&arg.m, NULL) == 0);
    arg.n = 0;

    OE_TEST(pthread_mutex_lock(&arg.m) == 0);

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        OE_TEST(pthread_create(&threads[i], NULL, _test_cond, &arg) == 0);
    }

    OE_TEST(pthread_mutex_unlock(&arg.m) == 0);

    sleep_msec(100);

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        pthread_mutex_lock(&arg.m);
        printf("signal...\n");
        pthread_cond_signal(&arg.c);
        pthread_mutex_unlock(&arg.m);
        sleep_msec(50);
    }

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        void* retval = NULL;
        OE_TEST(pthread_join(threads[i], &retval) == 0);
        oe_host_printf("joined:%p\n", retval);
    }

    OE_TEST(arg.n == NUM_THREADS);
    pthread_mutex_destroy(&arg.m);
    pthread_cond_destroy(&arg.c);
}

void test_cond_broadcast(void)
{
    pthread_t threads[NUM_THREADS];

    printf("=== %s()\n", __FUNCTION__);

    struct test_cond_arg arg;

    OE_TEST(pthread_cond_init(&arg.c, NULL) == 0);
    OE_TEST(pthread_mutex_init(&arg.m, NULL) == 0);
    arg.n = 0;

    OE_TEST(pthread_mutex_lock(&arg.m) == 0);

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        OE_TEST(pthread_create(&threads[i], NULL, _test_cond, &arg) == 0);
    }

    OE_TEST(pthread_mutex_unlock(&arg.m) == 0);

    sleep_msec(100);
    pthread_mutex_lock(&arg.m);
    printf("broadcast...\n");
    pthread_cond_broadcast(&arg.c);
    pthread_mutex_unlock(&arg.m);

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        void* retval = NULL;
        OE_TEST(pthread_join(threads[i], &retval) == 0);
        oe_host_printf("joined:%p\n", retval);
    }

    OE_TEST(arg.n == NUM_THREADS);
    pthread_mutex_destroy(&arg.m);
    pthread_cond_destroy(&arg.c);
}

void posix_test_ecall(struct posix_shared_block* shared_block, int tid)
{
    oe_disable_debug_malloc_check = true;

    posix_init(shared_block, tid);

#if 0
    {
        extern int test_pthread_cancel1(void);
        OE_TEST(test_pthread_cancel1() == 0);
    }
#endif

#if 0
    {
        extern int test_pthread_cancel2(void);
        OE_TEST(test_pthread_cancel2() == 0);
    }
#endif

#if 1
    for (size_t i = 0; i < 1000; i++)
    {
        extern int test_pthread_cancel3(void);
        OE_TEST(test_pthread_cancel3() == 0);
    }
#endif

#if 0
    for (size_t i = 0; i < 100; i++)
    {
        extern int test_pthread_cancel4(void);
        OE_TEST(test_pthread_cancel4() == 0);
    }
#endif

#if 0
    test_create_thread();
    test_mutexes();
    test_timedlock();
    test_cond_signal();
    test_cond_broadcast();
#endif

#if 0
    extern void test_functional(void);
    test_functional();

    extern void test_regression(void);
    test_regression();
#endif

    // Requires FUTEX_LOCK_PI implementation
    // RUN_LIBC_TEST(pthread_robust_main);

    // Requires FUTEX_LOCK_PI implementation
    // RUN_LIBC_TEST(pthread_mutex_pi_main);

    printf("=== %s() passed all tests\n", __FUNCTION__);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    4096, /* HeapPageCount */
    1024, /* StackPageCount */
    17);   /* TCSCount */
