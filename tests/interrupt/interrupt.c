// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <myst/syscallext.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <syscall.h>
#include <unistd.h>

#include "../utils/utils.h"

#define NSEC_PER_SEC 1000000000UL

/*
**==============================================================================
**
** _test_nanosleep()
**
**==============================================================================
*/

struct test_nanosleep_arg
{
    _Atomic(pid_t) tid;
    size_t num_interruptions;
};

static __inline__ int64_t ts2nano(const struct timespec* tp)
{
    return (tp->tv_sec * NSEC_PER_SEC) + tp->tv_nsec;
}

static void* _test_nanosleep_thread(void* arg_)
{
    struct test_nanosleep_arg* arg = (struct test_nanosleep_arg*)arg_;
    static time_t sec = 3;
    struct timespec req = {.tv_sec = sec, .tv_nsec = 0};
    struct timespec ts0;
    struct timespec ts1;

    /* unblock the parent thread that is waiting on the tid */
    arg->tid = syscall(SYS_gettid);

    printf("=== thread %d sleeping...\n", arg->tid);

    /* get the start time */
    clock_gettime(CLOCK_REALTIME, &ts0);

    while (req.tv_sec > 0 || req.tv_nsec > 0)
    {
        struct timespec rem;

        memset(&rem, 0, sizeof(rem));

        int r = nanosleep(&req, &rem);

        if (r < 0)
        {
            if (errno == EINTR)
            {
                arg->num_interruptions++;
                req = rem;
            }
            else
            {
                assert(0);
            }
        }
        else
        {
            break;
        }
    }

    /* get the end time */
    clock_gettime(CLOCK_REALTIME, &ts1);

    /* this should have run in roughly N seconds, where N == sec */
    const long delta = ts2nano(&ts1) - ts2nano(&ts0);
    const long nsec = sec * NSEC_PER_SEC;
    const long fuzz = NSEC_PER_SEC / 10;
    assert(delta >= (nsec - fuzz) && delta <= (nsec + fuzz));

    return arg;
}

static void _test_nanosleep(void)
{
    pthread_t th;
    struct test_nanosleep_arg arg;
    const size_t num_interruptions = 50;

    memset(&arg, 0, sizeof(arg));
    int ret = pthread_create(&th, NULL, _test_nanosleep_thread, &arg);
    assert(ret == 0);

    /* wait until the tid has been set by the thread */
    while (arg.tid == 0)
        __asm__ __volatile__("pause" : : : "memory");

    sleep_msec(10);

    /* interrupt the thread multiple times */
    for (size_t i = 0; i < num_interruptions; i++)
    {
        sleep_msec(10);
        printf("=== thread %d interrupting...\n", arg.tid);
        syscall(SYS_myst_interrupt_thread, arg.tid);
    }

    /* join the thread */
    pthread_join(th, NULL);

    assert(arg.num_interruptions > 0);
    assert(arg.num_interruptions <= num_interruptions);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
**==============================================================================
**
** _test_epoll_wait()
**
**==============================================================================
*/

struct test_epoll_wait_arg
{
    _Atomic(pid_t) tid;
    size_t num_interruptions;
    size_t max_interruptions;
};

static void* _test_epoll_wait_thread(void* arg_)
{
    struct test_epoll_wait_arg* arg = (struct test_epoll_wait_arg*)arg_;
    static time_t sec = 1;
    struct timespec req = {.tv_sec = sec, .tv_nsec = 0};
    struct timespec ts0;
    struct timespec ts1;
    int epfd;
    size_t n = 0;

    /* unblock the parent thread that is waiting on the tid */
    arg->tid = syscall(SYS_gettid);

    printf("=== thread sleeping...\n");

    assert((epfd = epoll_create1(0)) >= 0);

    for (size_t i = 0; i < arg->max_interruptions; i++)
    {
        const static int maxevents = 1;
        struct epoll_event events[maxevents];
        const int timeout = 2000;

        assert(epoll_wait(epfd, events, maxevents, timeout) == -1);

        if (errno == EINTR)
        {
            arg->num_interruptions++;
        }
        else
        {
            printf("eeeeeeeeeeeeeeeeeeeeeee=%d: %s\n", errno, strerror(errno));
            assert(0);
        }
    }

    assert(close(epfd) == 0);

    return arg;
}

static void _test_epoll_wait(void)
{
    pthread_t th;
    struct test_epoll_wait_arg arg;
    const size_t num_interruptions = 100;

    memset(&arg, 0, sizeof(arg));
    arg.max_interruptions = num_interruptions;

    int ret = pthread_create(&th, NULL, _test_epoll_wait_thread, &arg);
    assert(ret == 0);

    /* wait until the tid has been set by the thread */
    while (arg.tid == 0)
        __asm__ __volatile__("pause" : : : "memory");

    /* interrupt the thread multiple times */
    for (size_t i = 0; i < num_interruptions; i++)
    {
        sleep_msec(10);
        syscall(SYS_myst_interrupt_thread, arg.tid);
    }

    /* join the thread */
    pthread_join(th, NULL);

    assert(arg.num_interruptions > 0);
    assert(arg.num_interruptions <= num_interruptions);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

/*
**==============================================================================
**
** _test_poll()
**
**==============================================================================
*/

struct test_poll_arg
{
    _Atomic(pid_t) tid;
    size_t num_interruptions;
    size_t max_interruptions;
};

static void* _test_poll_thread(void* arg_)
{
    struct test_poll_arg* arg = (struct test_poll_arg*)arg_;
    static time_t sec = 1;
    struct timespec req = {.tv_sec = sec, .tv_nsec = 0};
    struct timespec ts0;
    struct timespec ts1;
    size_t n = 0;

    /* unblock the parent thread that is waiting on the tid */
    arg->tid = syscall(SYS_gettid);

    printf("=== thread sleeping...\n");

    for (size_t i = 0; i < arg->max_interruptions; i++)
    {
        assert(poll(NULL, 0, 5000) == -1);

        if (errno == EINTR)
        {
            arg->num_interruptions++;
        }
        else
        {
            assert(0);
        }
    }

    return arg;
}

static void _test_poll(void)
{
    pthread_t th;
    struct test_poll_arg arg;
    const size_t num_interruptions = 100;

    memset(&arg, 0, sizeof(arg));
    arg.max_interruptions = num_interruptions;

    int ret = pthread_create(&th, NULL, _test_poll_thread, &arg);
    assert(ret == 0);

    /* wait until the tid has been set by the thread */
    while (arg.tid == 0)
        __asm__ __volatile__("pause" : : : "memory");

    /* interrupt the thread multiple times */
    for (size_t i = 0; i < num_interruptions; i++)
    {
        sleep_msec(10);
        syscall(SYS_myst_interrupt_thread, arg.tid);
    }

    /* join the thread */
    pthread_join(th, NULL);

    assert(arg.num_interruptions > 0);
    assert(arg.num_interruptions <= num_interruptions);

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
    _test_nanosleep();
    _test_epoll_wait();
    _test_poll();

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
