// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <syscall.h>
#include <unistd.h>

#include <myst/config.h>
#include <myst/syscallext.h>

#include "../utils/utils.h"

#define NSEC_PER_SEC 1000000000UL

/*
**==============================================================================
**
** _test_nanosleep()
**
**==============================================================================
*/

#if (MYST_INTERRUPT_NANOSLEEP_WITH_SIGNAL == 1)

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
    static time_t sec = 1;
    struct timespec req = {.tv_sec = sec, .tv_nsec = 0};
    struct timespec ts0;
    struct timespec ts1;

    /* unblock the parent thread that is waiting on the tid */
    arg->tid = syscall(SYS_gettid);

    printf("=== thread sleeping...\n");

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

#endif

/*
**==============================================================================
**
** _test_epoll_wait()
**
**==============================================================================
*/

#if (MYST_INTERRUPT_EPOLL_WITH_SIGNAL == 1)

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

#endif

/*
**==============================================================================
**
** _test_poll()
**
**==============================================================================
*/

#if (MYST_INTERRUPT_POLL_WITH_SIGNAL == 1)

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

#endif

/*
**==============================================================================
**
** _test_accept()
**
**==============================================================================
*/

static const uint16_t port = 14321;

struct test_pipe_read_arg
{
    _Atomic(pid_t) tid;
    size_t num_interruptions;
    size_t max_interruptions;
};

static void* _test_accept_thread(void* arg_)
{
    struct test_pipe_read_arg* arg = (struct test_pipe_read_arg*)arg_;
    static time_t sec = 1;
    struct timespec req = {.tv_sec = sec, .tv_nsec = 0};
    struct timespec ts0;
    struct timespec ts1;
    size_t n = 0;
    int fds[2];
    int lsock;

    (void)arg;

    assert(pipe(fds) == 0);

    /* unblock the parent thread that is waiting on the tid */
    arg->tid = syscall(SYS_gettid);

    assert((lsock = socket(AF_INET, SOCK_STREAM, 0)) >= 0);

    /* reuse the server address */
    {
        const int opt = 1;
        const socklen_t len = sizeof(opt);
        int r = setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (void*)&opt, len);
        assert(r == 0);
    }

    {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);
        assert(bind(lsock, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    }

    assert(listen(lsock, 10) == 0);

    printf("=== thread sleeping...\n");

    for (size_t i = 0; i < arg->max_interruptions; i++)
    {
        char buf[16];
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        assert(accept4(lsock, (struct sockaddr*)NULL, &addrlen, 0) == -1);

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

static void _test_accept(void)
{
    pthread_t th;
    struct test_pipe_read_arg arg;
    const size_t num_interruptions = 100;

    memset(&arg, 0, sizeof(arg));
    arg.max_interruptions = num_interruptions;

    int ret = pthread_create(&th, NULL, _test_accept_thread, &arg);
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

static pid_t _parent_tid;
static pid_t _child_tid;
static int _child_thread_lock;
static int _parent_thread_lock;

static void _parent_signal_handler(
    int signum,
    siginfo_t* siginfo,
    void* context)
{
    printf("=== parent receives signal=%d\n", signum);

    (void)siginfo;
    (void)context;

    assert(signum == SIGUSR2);

    _parent_thread_lock = 0;
}

static void _child_signal_handler(int signum, siginfo_t* siginfo, void* context)
{
    printf("=== child receives signal=%d\n", signum);

    (void)siginfo;
    (void)context;

    assert(signum == SIGUSR1);

    _child_thread_lock = 0;
}

static void* _child_func(void* arg)
{
    struct sigaction act = {0};

    act.sa_sigaction = _child_signal_handler;
    act.sa_flags = SA_SIGINFO;

    (void)arg;

    if (sigaction(SIGUSR1, &act, NULL) < 0)
    {
        return NULL;
    }

    _child_tid = syscall(SYS_gettid);

    printf("=== sending interrupt to parent tid=%d\n", _parent_tid);
    syscall(SYS_tkill, _parent_tid, SIGUSR2);

    _child_thread_lock = 1;
    while (_child_thread_lock != 0)
        asm volatile("pause" ::: "memory");
}

static void _test_tkill(void)
{
    pthread_t thread;
    struct sigaction act = {0};

    act.sa_sigaction = _parent_signal_handler;
    act.sa_flags = SA_SIGINFO;

    if (sigaction(SIGUSR2, &act, NULL) < 0)
    {
        return;
    }

    _parent_tid = syscall(SYS_gettid);

    pthread_create(&thread, NULL, _child_func, NULL);

    _parent_thread_lock = 1;
    while (_parent_thread_lock != 0)
        asm volatile("pause" ::: "memory");

    sleep_msec(30);

    printf("=== sending interrupt to child tid=%d\n", _child_tid);
    syscall(SYS_tkill, _child_tid, SIGUSR1);

    pthread_join(thread, NULL);

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
#if (MYST_INTERRUPT_NANOSLEEP_WITH_SIGNAL == 1)
    _test_nanosleep();
#endif

#if (MYST_INTERRUPT_EPOLL_WITH_SIGNAL == 1)
    _test_epoll_wait();
#endif

#if (MYST_INTERRUPT_POLL_WITH_SIGNAL == 1)
    _test_poll();
#endif

#ifdef MYST_INTERRUPT_USER_WITH_TKILL
    _test_tkill();
#endif

    _test_accept();

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
