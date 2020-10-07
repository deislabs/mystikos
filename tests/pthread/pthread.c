#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <unistd.h>

#define NUM_THREADS 8

#if 0
#define TRACE
#endif

#ifdef TRACE
#define T(EXPR) EXPR
#else
#define T(EXPR)
#endif

static size_t _get_max_threads(void)
{
    const long SYS_libos_max_threads = 1014;

    long n = syscall(SYS_libos_max_threads);

    if (n < 0)
    {
        fprintf(stderr, "_get_max_threads() failed\n");
        assert(0);
    }

    return (size_t)n;
}

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

/*
**==============================================================================
**
** test_create_thread()
**
**==============================================================================
*/

static void* _thread_func(void* arg)
{
    uint64_t secs = (size_t)arg;
    uint64_t msecs = secs * 1000;

    T(printf("_thread_func()\n");)
    sleep_msec(msecs / 10);

    return arg;
}

void test_create_thread(void)
{
    pthread_t threads[NUM_THREADS];

    printf("=== start test (%s)\n", __FUNCTION__);

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

        T(printf("joined...\n");)

        assert((uint64_t)retval == i);
    }

    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
**==============================================================================
**
** test_create_thread()
**
**==============================================================================
*/

static uint64_t _shared_integer = 0;
static pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;
const size_t N = 100;

static void* _test_mutex_thread(void* arg)
{
    size_t n = (uint64_t)arg;

    for (size_t i = 0; i < n * N; i++)
    {
        pthread_mutex_lock(&_mutex);
        int local = _shared_integer;

        /* introduce some delay to amplify the race condition */
        for (int j = 0; j < 10000; j++)
            ;

        _shared_integer = local + 1;
        pthread_mutex_unlock(&_mutex);
    }
    T(printf("child %zu done with mutex\n", n);)

    return arg;
}

void test_mutexes(int mutex_type)
{
    pthread_t threads[NUM_THREADS];
    uint64_t integer = 0;
    _shared_integer = 0;

    printf("=== start test (%s:%d)\n", __FUNCTION__, mutex_type);

    pthread_mutexattr_t Attr;
    pthread_mutexattr_init(&Attr);
    pthread_mutexattr_settype(&Attr, mutex_type);
    pthread_mutex_init(&_mutex, &Attr);

    pthread_mutex_lock(&_mutex);
    T(printf("mutex taken by main thread\n");)

    /* Create threads */
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        void* arg = (void*)(i + 1);

        if (pthread_create(&threads[i], NULL, _test_mutex_thread, arg) != 0)
        {
            fprintf(stderr, "pthread_create() failed\n");
            abort();
        }

        integer += (i + 1) * N;
    }

    pthread_mutex_unlock(&_mutex);
    T(printf("mutex released by main thread; now starting children.\n");)

    /* Join threads */
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        void* retval;
        assert(pthread_join(threads[i], &retval) == 0);
        assert((uint64_t)retval == i + 1);
        T(printf("joined...\n");)
    }

    if (integer != _shared_integer)
    {
        fprintf(stderr, "Expected: %ld, Got: %ld\n", integer, _shared_integer);
        abort();
    }

    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
**==============================================================================
**
** test_timedlock()
**
**==============================================================================
*/

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
    const uint64_t TIMEOUT_SEC = 1;
    const __int128 BILLION = 1000000000;
    const __int128 LO = (TIMEOUT_SEC * BILLION) - (BILLION / 5);
    const __int128 HI = (TIMEOUT_SEC * BILLION) + (BILLION / 5);

    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += TIMEOUT_SEC;

    __int128 t1 = _time();

    int r = pthread_mutex_timedlock(&_timed_mutex, &timeout);
    assert(r == ETIMEDOUT);

    __int128 t2 = _time();
    __int128 delta = t2 - t1;
    assert(delta >= LO && delta <= HI);

    return NULL;
}

void test_timedlock(void)
{
    pthread_t thread;

    printf("=== start test (%s)\n", __FUNCTION__);

    pthread_mutex_lock(&_timed_mutex);

    if (pthread_create(&thread, NULL, _test_timedlock, NULL) != 0)
    {
        fprintf(stderr, "pthread_create() failed\n");
        abort();
    }

    for (size_t i = 0; i < 2; i++)
    {
        T(printf("sleeping...\n");)
        sleep(1);
    }

    if (pthread_join(thread, NULL) != 0)
    {
        fprintf(stderr, "pthread_create() failed\n");
        abort();
    }

    pthread_mutex_unlock(&_timed_mutex);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
**==============================================================================
**
** test_cond_signal()
**
**==============================================================================
*/

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
    T(printf("wait: %p\n", pthread_self());)
    pthread_cond_wait(&arg->c, &arg->m);
    arg->n++;
    pthread_mutex_unlock(&arg->m);

    return pthread_self();
}

void test_cond_signal(void)
{
    pthread_t threads[NUM_THREADS];

    printf("=== start test (%s)\n", __FUNCTION__);

    struct test_cond_arg arg;

    assert(pthread_cond_init(&arg.c, NULL) == 0);
    assert(pthread_mutex_init(&arg.m, NULL) == 0);
    arg.n = 0;

    assert(pthread_mutex_lock(&arg.m) == 0);

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        assert(pthread_create(&threads[i], NULL, _test_cond, &arg) == 0);
    }

    assert(pthread_mutex_unlock(&arg.m) == 0);

    sleep_msec(100);

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        pthread_mutex_lock(&arg.m);
        T(printf("signal...\n");)
        pthread_cond_signal(&arg.c);
        pthread_mutex_unlock(&arg.m);
        sleep_msec(50);
    }

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        void* retval = NULL;
        assert(pthread_join(threads[i], &retval) == 0);
        T(printf("joined:%p\n", retval);)
    }

    assert(arg.n == NUM_THREADS);
    pthread_mutex_destroy(&arg.m);
    pthread_cond_destroy(&arg.c);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
**==============================================================================
**
** test_cond_broadcast()
**
**==============================================================================
*/

void test_cond_broadcast(void)
{
    pthread_t threads[NUM_THREADS];

    printf("=== start test (%s)\n", __FUNCTION__);

    struct test_cond_arg arg;

    assert(pthread_cond_init(&arg.c, NULL) == 0);
    assert(pthread_mutex_init(&arg.m, NULL) == 0);
    arg.n = 0;

    assert(pthread_mutex_lock(&arg.m) == 0);

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        assert(pthread_create(&threads[i], NULL, _test_cond, &arg) == 0);
    }

    assert(pthread_mutex_unlock(&arg.m) == 0);

    sleep_msec(100);
    pthread_mutex_lock(&arg.m);
    T(printf("broadcast...\n");)
    pthread_cond_broadcast(&arg.c);
    pthread_mutex_unlock(&arg.m);

    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        void* retval = NULL;
        assert(pthread_join(threads[i], &retval) == 0);
        T(printf("joined:%p\n", retval);)
    }

    assert(arg.n == NUM_THREADS);
    pthread_mutex_destroy(&arg.m);
    pthread_cond_destroy(&arg.c);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
**==============================================================================
**
** test_exhaust_threads()
**
**==============================================================================
*/

static void* _exhaust_thread(void* arg)
{
    sleep(1);
    return arg;
}

void test_exhaust_threads(void)
{
    const size_t max_threads = _get_max_threads();
    pthread_t threads[max_threads];

    printf("=== start test (%s)\n", __FUNCTION__);

    /* Create threads until exhausted (last iteration fails with EAGAIN) */
    for (size_t i = 0; i < max_threads; i++)
    {
        int r = pthread_create(&threads[i], NULL, _exhaust_thread, (void*)i);

        if (i + 1 == max_threads)
            assert(r == EAGAIN);
        else
            assert(r == 0);
    }

    /* Join threads except for the last one that failed */
    for (size_t i = 0; i < max_threads - 1; i++)
    {
        void* retval;

        if (pthread_join(threads[i], &retval) != 0)
        {
            fprintf(stderr, "pthread_join() failed\n");
            abort();
        }

        T(printf("joined...\n");)

        assert((uint64_t)retval == i);
    }

    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
**==============================================================================
**
** main()
**
**==============================================================================
*/

int main(int argc, const char* argv[])
{
    unsigned long n = 1;

    printf("=== start test (%s)\n", argv[0]);

    if (argc > 2)
    {
        fprintf(stderr, "Usage: %s [<count>]\n", argv[0]);
        exit(1);
    }

    if (argc == 2)
    {
        char* end = NULL;
        n = strtoul(argv[1], &end, 0);

        if (!end || *end)
        {
            fprintf(stderr, "%s: bad count argument: %s\n", argv[0], argv[1]);
            exit(1);
        }
    }

    for (size_t i = 0; i < n; i++)
    {
        test_create_thread();
        test_mutexes(PTHREAD_MUTEX_NORMAL);
        test_mutexes(PTHREAD_MUTEX_RECURSIVE);
        test_timedlock();
        test_cond_signal();
        test_cond_broadcast();
        test_exhaust_threads();
    }

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
