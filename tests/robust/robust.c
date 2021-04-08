// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <unistd.h>

#include "../utils/utils.h"

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
** test_robust_mutex()
**
**==============================================================================
*/

static pthread_mutex_t _mutex;

static void* _thread_func(void* arg)
{
    pthread_mutex_lock(&_mutex);

    /* exit without releasing the mutex */
    pthread_exit(NULL);
    return NULL;
}

void test_robust_mutex(void)
{
    pthread_t thread;
    int r;

    printf("=== start test (%s)\n", __FUNCTION__);

    pthread_mutexattr_t mattr;
    r = pthread_mutexattr_init(&mattr);
    assert(r == 0);
    pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
    assert(r == 0);
    pthread_mutex_init(&_mutex, &mattr);
    assert(r == 0);

    {
        int r = pthread_mutex_lock(&_mutex);
        assert(r == 0);

        r = pthread_mutex_unlock(&_mutex);
        assert(r == 0);
    }

    /* create a thread that locks but does not unlock mutex */
    if ((r = _pthread_create(&thread, NULL, _thread_func, NULL)))
    {
        PUTERR("pthread_create() failed: %d", r);
        abort();
    }

    /* give the thread time to exit */
    sleep_msec(100);

    /* this should fail since the child thread has it locked */
    r = pthread_mutex_unlock(&_mutex);
    assert(r == EPERM);

    /* try to lock the mutex that is already locked by the child */
    r = pthread_mutex_lock(&_mutex);
    assert(r == EOWNERDEAD);

    /* make the mutex consistent */
    r = pthread_mutex_consistent(&_mutex);
    assert(r == 0);

    /* unlock the mutex */
    r = pthread_mutex_unlock(&_mutex);
    assert(r == 0);

    /* Join threads */
    r = pthread_join(thread, NULL);
    assert(r == 0);

    pthread_mutex_destroy(&_mutex);

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
    printf("=== start test (%s)\n", argv[0]);
    test_robust_mutex();
    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
