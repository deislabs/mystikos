// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define NUM_THREADS 8

// #define TRACE
static _Atomic(int) counter = 0;

static void _sleep_msec(uint64_t milliseconds)
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

#ifdef TRACE
    printf("_thread_func()\n");
#endif
    _sleep_msec(msecs / 10);

    counter++;
    return arg;
}

void test_create_thread(void)
{
    pthread_t threads[NUM_THREADS];

#ifdef TRACE
    printf("=== %s()\n", __FUNCTION__);
#endif

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

#ifdef TRACE
        printf("joined...\n");
#endif

        assert((uint64_t)retval == i);
    }

    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_detach_thread(void)
{
    pthread_t threads[NUM_THREADS];
    counter = 0;

#ifdef TRACE
    printf("=== %s()\n", __FUNCTION__);
#endif

    /* Create threads */
    for (size_t i = 0; i < NUM_THREADS; i++)
    {
        if (pthread_create(&threads[i], NULL, _thread_func, (void*)i) != 0)
        {
            fprintf(stderr, "pthread_create() failed\n");
            abort();
        }

        if (pthread_detach(threads[i]) != 0)
        {
            fprintf(stderr, "pthread_detach() failed\n");
            abort();
        }
    }

    while (counter != NUM_THREADS)
    {
      ; // wait until all children are done.
    }

    printf("=== passed test (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    test_create_thread();
    test_detach_thread();
    return 0;
}
