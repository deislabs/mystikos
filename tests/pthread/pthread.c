// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <myst/tee.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/times.h>
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

static int _host_nprocs = -1;

__attribute__((format(printf, 3, 4))) static int _err(
    const char* file,
    unsigned int line,
    const char* fmt,
    ...)
{
    va_list ap;

    fprintf(stderr, "%s(%u): ", file, line);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(1);
}

#define PUTERR(FMT, ...) _err(__FILE__, __LINE__, FMT, ##__VA_ARGS__)

static size_t _get_max_threads(void)
{
    long n = syscall(SYS_myst_max_threads);

    if (n < 0)
    {
        PUTERR("_get_max_threads() failed");
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

/* pthread_create() wrapper with retry on EAGAIN */
static int _pthread_create(
    pthread_t* thread,
    const pthread_attr_t* attr,
    void* (*start_routine)(void*),
    void* arg)
{
    int ret = 0;
    size_t i;
    const size_t retries = 3;

    for (i = 0; i < retries; i++)
    {
        ret = pthread_create(thread, attr, start_routine, arg);

        if (ret == EAGAIN)
            continue;

        break;
    }

#if 0
    if (i != 0 && ret == 0)
        assert("unexpected" == NULL);
#endif

    return ret;
}

/*
**==============================================================================
**
** test_create_thread()
**
**==============================================================================
*/

static int _gettid()
{
    return (int)syscall(SYS_gettid);
}

static void* _thread_func(void* arg)
{
    uint64_t secs = (size_t)arg;
    uint64_t msecs = secs * 1000;
    pid_t ppid = getppid();
    pid_t pid = getpid();
    pid_t tid = _gettid();

    T(printf("_thread_func(): ppid=%d pid=%d tid=%d\n", ppid, pid, tid));
    (void)ppid;
    (void)pid;
    (void)tid;
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
        int r;

        if ((r = _pthread_create(&threads[i], NULL, _thread_func, (void*)i)))
        {
            PUTERR("pthread_create() failed: %d", r);
            abort();
        }
    }

    /* Join threads */
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        void* retval;

        if (pthread_join(threads[i], &retval) != 0)
        {
            PUTERR("pthread_join() failed");
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
        {
            if ((j % 3000) == 0)
                sched_yield();
        }

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
        int r;
        void* arg = (void*)(i + 1);

        if ((r = _pthread_create(&threads[i], NULL, _test_mutex_thread, arg)))
        {
            PUTERR("pthread_create() failed: %d", r);
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
        PUTERR("Expected: %ld, Got: %ld", integer, _shared_integer);
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
    int r;

    printf("=== start test (%s)\n", __FUNCTION__);

    pthread_mutex_lock(&_timed_mutex);

    if ((r = _pthread_create(&thread, NULL, _test_timedlock, NULL)))
    {
        PUTERR("pthread_create() failed: %d", r);
        abort();
    }

    for (size_t i = 0; i < 2; i++)
    {
        T(printf("sleeping...\n");)
        sleep(1);
    }

    if (pthread_join(thread, NULL) != 0)
    {
        PUTERR("pthread_join() failed");
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
    T(printf("wait: %p\n", (void*)pthread_self());)
    pthread_cond_wait(&arg->c, &arg->m);
    arg->n++;
    pthread_mutex_unlock(&arg->m);

    return (void*)pthread_self();
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
        assert(_pthread_create(&threads[i], NULL, _test_cond, &arg) == 0);
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
        assert(_pthread_create(&threads[i], NULL, _test_cond, &arg) == 0);
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

static _Atomic(int) _wait;

static void* _exhaust_thread(void* arg)
{
    /* wait here until main thread clears this atomic variable */
    while (_wait)
        sleep_msec(500);

    return arg;
}

void test_exhaust_threads(void)
{
    const size_t max_threads = _get_max_threads();
    pthread_t threads[max_threads];

    printf("=== start test (%s)\n", __FUNCTION__);

    _wait = 1;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);

    /* Create threads until exhausted (last iteration fails with EAGAIN) */
    for (size_t i = 0; i < max_threads; i++)
    {
        if (i % 100 == 0)
            printf("====== creating thread %ld\n", i);

        int r = _pthread_create(&threads[i], &attr, _exhaust_thread, (void*)i);

        if (i + 1 == max_threads)
            assert(r == EAGAIN);
        else
            assert(r == 0);
    }

    pthread_attr_destroy(&attr);

    _wait = 0;

    /* Join threads except for the last one that failed */
    for (size_t i = 0; i < max_threads - 1; i++)
    {
        void* retval;

        if (i % 100 == 0)
            printf("====== joining thread %ld\n", i);

        if (pthread_join(threads[i], &retval) != 0)
        {
            PUTERR("pthread_join() failed");
            abort();
        }

        assert((uint64_t)retval == i);
    }

    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
**==============================================================================
**
** test_affinity()
**
**==============================================================================
*/

static pid_t _child_tid;

static sem_t _terminate_sem;

static void* _affinity_thread_func(void* arg)
{
    sem_t* sem = (sem_t*)arg;

    _child_tid = _gettid();
    sem_post(sem);

    /* wait for the parent thread to signal the terminate semaphore */
    while (sem_wait(&_terminate_sem))
        ;

    return NULL;
}

void test_affinity(void)
{
    pthread_t thread;
    int r;
    cpu_set_t main_mask;
    size_t max_cpu = 0;
    pthread_attr_t attr;
    static sem_t sem1;
    static sem_t sem2;

    printf("=== start test (%s)\n", __FUNCTION__);

    _child_tid = 0;
    assert(sem_init(&sem1, 0, 0) == 0);
    assert(sem_init(&_terminate_sem, 0, 0) == 0);

    /* Create one thread */
    if ((r = _pthread_create(&thread, NULL, _affinity_thread_func, &sem1)))
    {
        PUTERR("pthread_create() failed: %d", r);
        abort();
    }

    /* wait for the child to set _child_tid */
    while (sem_wait(&sem1))
        ;

    /* get the affinity of main thread */
    {
        size_t n = 0;
        pid_t pid = 0;
        cpu_set_t mask;

        CPU_ZERO(&mask);
        r = sched_getaffinity(pid, sizeof(mask), &mask);
        assert(r == 0);

        /* save so it can be restored below */
        memcpy(&main_mask, &mask, sizeof(main_mask));

        for (size_t cpu = 0; cpu < sizeof(mask) * 8; cpu++)
        {
            if (CPU_ISSET(cpu, &mask))
            {
                max_cpu = n;
                n++;
            }
        }

        printf("main thread has %zu affinities\n", n);
        assert(n > 0);
    }

    /* set the affinity of the main thread to CPU 0 and verify */
    {
        cpu_set_t mask;
        const pid_t pid = 0;

        CPU_ZERO(&mask);
        CPU_SET(0, &mask);
        r = sched_setaffinity(pid, sizeof(mask), &mask);
        assert(r == 0);

        CPU_ZERO(&mask);
        r = sched_getaffinity(pid, sizeof(mask), &mask);
        assert(r == 0);

        /* verify that processor zero is set */
        assert(CPU_ISSET(0, &mask));

        /* verify that no other processors are set */
        for (size_t cpu = 1; cpu < sizeof(mask) * 8; cpu++)
            assert(!CPU_ISSET(cpu, &mask));

        printf("main thread has 1 affinity\n");
    }

    /* verify that the main thread is now running on CPU 0 */
    {
        unsigned cpu = UINT_MAX;
        unsigned node = UINT_MAX;

        /* final null argument is unused since Linux 2.6.24 */
        long ret = syscall(SYS_getcpu, &cpu, &node, NULL);
        assert(ret == 0);
        assert(cpu == 0);

        printf("main thread now running on CPU 0\n");
    }

    /* set the affinity of the main thread to the max cpu and verify */
    {
        cpu_set_t mask;
        const pid_t pid = 0;

        CPU_ZERO(&mask);
        CPU_SET(max_cpu, &mask);
        r = sched_setaffinity(pid, sizeof(mask), &mask);
        assert(r == 0);

        CPU_ZERO(&mask);
        r = sched_getaffinity(pid, sizeof(mask), &mask);
        assert(r == 0);

        /* verify that processor zero is set */
        assert(CPU_ISSET(max_cpu, &mask));

        /* verify that no other processors are set */
        for (size_t cpu = 0; cpu < sizeof(mask) * 8; cpu++)
        {
            if (cpu != max_cpu)
                assert(!CPU_ISSET(cpu, &mask));
        }

        printf("main thread has 1 affinity\n");
    }

    /* verify that the main thread is now running on the max cpu */
    {
        unsigned cpu = UINT_MAX;
        unsigned node = UINT_MAX;
        uint64_t tcache[16];

        long ret = syscall(SYS_getcpu, &cpu, &node, tcache);
        assert(ret == 0);
        assert(cpu == max_cpu);

        printf("main thread now running on CPU %zu\n", max_cpu);
    }

    /* verify that the child thread has one or more affinities */
    {
        size_t n = 0;
        cpu_set_t mask;

        CPU_ZERO(&mask);
        r = sched_getaffinity(_child_tid, sizeof(mask), &mask);
        assert(r == 0);

        for (size_t cpu = 0; cpu < sizeof(mask) * 8; cpu++)
        {
            if (CPU_ISSET(cpu, &mask))
                n++;
        }

        printf("child thread has %zu affinities\n", n);
        assert(n > 0);
    }

    /* set the affinity for the child thread to CPU 0 and verify */
    {
        cpu_set_t mask;

        CPU_ZERO(&mask);
        CPU_SET(0, &mask);
        r = sched_setaffinity(_child_tid, sizeof(mask), &mask);
        assert(r == 0);

        CPU_ZERO(&mask);
        r = sched_getaffinity(_child_tid, sizeof(mask), &mask);
        assert(r == 0);

        /* verify that processor zero is set */
        assert(CPU_ISSET(0, &mask));

        /* verify that no other processors are set */
        for (size_t cpu = 1; cpu < sizeof(mask) * 8; cpu++)
            assert(!CPU_ISSET(cpu, &mask));

        printf("main thread has 1 affinity\n");
    }

    /* restore the original affinity of the main thread */
    r = sched_setaffinity(0, sizeof(main_mask), &main_mask);
    assert(r == 0);

    /* terminate the child waiting on the semaphore */
    assert(sem_post(&_terminate_sem) == 0);

    if (pthread_join(thread, NULL) != 0)
    {
        PUTERR("pthread_join() failed");
        abort();
    }

    r = pthread_attr_init(&attr);
    assert(r == 0);

#ifdef ATTR_AFFINITY_NP
    {
        cpu_set_t mask;

        /* Set child's affinity to the original main thread affinity*/
        r = pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &main_mask);
        assert(r == 0);

        CPU_ZERO(&mask);
        r = pthread_attr_getaffinity_np(&attr, sizeof(cpu_set_t), &mask);
        assert(r == 0);

        /* compare returned mask and mask set */
        for (size_t cpu = 0; cpu < sizeof(cpu_set_t) * 8; cpu++)
        {
            assert(CPU_ISSET(cpu, &mask) == CPU_ISSET(cpu, &main_mask));
        }

        printf("pthread_attr_setaffinity/getaffinity_np matches\n");
    }
#endif

    /* clear the tid */
    _child_tid = 0;
    assert(sem_init(&sem2, 0, 0) == 0);

    /* Create one child thread with attr */
    if ((r = _pthread_create(&thread, &attr, _affinity_thread_func, &sem2)))
    {
        PUTERR("pthread_create() with attr failed: %d", r);
        abort();
    }

    /* wait for the child to set _child_tid */
    while (sem_wait(&sem2))
        ;

    r = pthread_attr_destroy(&attr);
    assert(r == 0);
    printf("pthread_attr_destroy() succeeded\n");

#ifdef ATTR_AFFINITY_NP
    {
        cpu_set_t mask;
        CPU_ZERO(&mask);
        r = sched_getaffinity(_child_tid, sizeof(mask), &mask);
        assert(r == 0);

        for (size_t cpu = 0; cpu < sizeof(cpu_set_t) * 8; cpu++)
        {
            assert(CPU_ISSET(cpu, &mask) == CPU_ISSET(cpu, &main_mask));
        }
        printf("affinity matches what's set in pthread_create(attr)\n");
    }
#endif

    /* terminate the child waiting on the semaphore */
    assert(sem_post(&_terminate_sem) == 0);

    if (pthread_join(thread, NULL) != 0)
    {
        PUTERR("pthread_join() failed");
        abort();
    }

    T(printf("joined...\n");)

    sem_destroy(&sem1);
    sem_destroy(&sem2);

    /* test against overwrites of the CPU set beyond cpusetsize */
    {
        assert(sizeof(cpu_set_t) == 128);

        /* case 1: 8 bytes */
        {
            cpu_set_t mask;
            const size_t size = 8; /* must be >= kernel affinity mask size */

            CPU_ZERO(&mask);
            memset((uint8_t*)&mask + size, 0xab, sizeof(mask) - size);

            for (size_t i = 0; i < size; i++)
                assert(((uint8_t*)&mask)[i] == 0);

            for (size_t i = size; i < sizeof(mask); i++)
                assert(((uint8_t*)&mask)[i] == 0xab);

            assert(sched_getaffinity(0, size, &mask) == 0);

            for (size_t i = size; i < sizeof(mask); i++)
                assert(((uint8_t*)&mask)[i] == 0xab);
        }
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

    if (argc > 3)
    {
        fprintf(stderr, "Usage: %s [<nprocs> [<count>]]\n", argv[0]);
        exit(1);
    }

    if (argc == 3)
    {
        char* end = NULL;
        n = strtoul(argv[2], &end, 0);

        if (!end || *end)
        {
            fprintf(stderr, "%s: bad count argument: %s\n", argv[0], argv[1]);
            exit(1);
        }
    }

    if (argc >= 2)
    {
        char* end = NULL;
        _host_nprocs = strtoul(argv[1], &end, 0);

        if (!end || *end)
        {
            fprintf(stderr, "%s: bad count argument: %s\n", argv[0], argv[1]);
            exit(1);
        }
    }

    int nprocs = get_nprocs();
    printf("Number of processors is %d\n", nprocs);

    if (_host_nprocs != -1)
    {
        if (_host_nprocs != nprocs)
        {
            PUTERR("nprocs mismatch %d != %d\n", _host_nprocs, nprocs);
        }
    }

    for (size_t i = 0; i < n; i++)
    {
        printf("=== pass %zu\n", i);
        test_affinity();
        test_create_thread();
        test_mutexes(PTHREAD_MUTEX_NORMAL);
        test_mutexes(PTHREAD_MUTEX_RECURSIVE);
        test_timedlock();
        test_cond_signal();
        test_cond_broadcast();
        if (_get_max_threads() != LONG_MAX)
            test_exhaust_threads();
    }

    struct tms tms;
    assert(times(&tms) != -1);
    printf("System time: %ld, user time: %ld\n", tms.tms_stime, tms.tms_utime);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
