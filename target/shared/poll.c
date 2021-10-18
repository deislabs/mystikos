// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <syscall.h>
#include <unistd.h>

#include <myst/config.h>
#include <myst/tcall.h>

#if (MYST_INTERRUPT_POLL_WITH_SIGNAL == 1)

long myst_tcall_poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
    long ret;
    sigset_t sigmask;
    struct timespec ts;

    ts.tv_sec = timeout / 1000;
    ts.tv_nsec = (timeout % 1000) * 1000000;

    /* Temporarily unblock signals */
    sigemptyset(&sigmask);

    if ((ret = ppoll(fds, nfds, &ts, &sigmask)) < 0)
        ret = -errno;

#ifdef MYST_TRACE_THREAD_INTERRUPTIONS
    if (ret == -EINTR)
    {
        pid_t tid = (pid_t)syscall(SYS_gettid);
        printf(">>>>>>>> poll() interrupted: tid=%d\n", tid);
        fflush(stdout);
    }
#endif

    return ret;
}

long myst_tcall_poll_wake(void)
{
    return 0;
}

#elif (MYST_INTERRUPT_POLL_WITH_SIGNAL == -1)

#define WAKE_MAGIC 0x617eafc2e697492c

/* wake pipes */
struct waker
{
    struct waker* next;
    pid_t tid;
    int pipefd[2];
};

struct waker* _wakers;
static pthread_mutex_t _wakers_mutex = PTHREAD_MUTEX_INITIALIZER;
static int _initialized = 0;

static void _free_wakers(void)
{
    for (struct waker* p = _wakers; p;)
    {
        struct waker* next = p->next;
        free(p);
        p = next;
    }
}

static pid_t _gettid(void)
{
    return (pid_t)syscall(SYS_gettid);
}

static int _set_nonblock(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
        return -1;

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        return -1;

    return 0;
}

static struct waker* _new_waker(void)
{
    struct waker* ret = NULL;
    struct waker* waker;

    if (!(waker = malloc(sizeof(struct waker))))
        goto done;

    waker->next = NULL;
    waker->tid = _gettid();

    if (pipe(waker->pipefd) == -1)
        goto done;

    if (_set_nonblock(waker->pipefd[0]) != 0)
        goto done;

    if (_set_nonblock(waker->pipefd[1]) != 0)
        goto done;

    ret = waker;
    waker = NULL;

done:

    if (waker)
        free(waker);

    return ret;
}

long myst_tcall_poll_wake(void)
{
    /* wake up all waiters */
    pthread_mutex_lock(&_wakers_mutex);
    {
        const uint64_t x = WAKE_MAGIC;

        for (struct waker* p = _wakers; p; p = p->next)
        {
            if (write(p->pipefd[1], &x, sizeof(x)) != sizeof(x))
            {
                // the write may fail if  the pipe is full, but the failure
                // may safely be ignored since the thread will be awoken under
                // this failure condition (since the pipe is ready for read).
            }
        }
    }
    pthread_mutex_unlock(&_wakers_mutex);

    return 0;
}

struct waker* _get_waker(void)
{
    struct waker* ret = NULL;

    pthread_mutex_lock(&_wakers_mutex);

    /* search the wakers list */
    for (struct waker* p = _wakers; p; p = p->next)
    {
        if (p->tid == _gettid())
        {
            ret = p;
            goto done;
        }
    }

    /* create a new waker for this thread */
    {
        struct waker* waker;

        if (!(waker = _new_waker()))
            goto done;

        waker->next = _wakers;
        _wakers = waker;
        ret = waker;
    }

    /* install at exit handler on first call */
    if (_initialized == 0)
    {
        atexit(_free_wakers);
        _initialized = 1;
    }

done:
    pthread_mutex_unlock(&_wakers_mutex);
    return ret;
}

long myst_tcall_poll(struct pollfd* lfds, unsigned long nfds, int timeout)
{
    long ret = 0;
    long r;
    struct pollfd* fds = NULL;
    struct waker* waker;
    int woken_by_waker = 0;

    if (!(waker = _get_waker()))
    {
        ret = -ENOSYS;
        goto done;
    }

    /* Make a copy of the fds[] array and append the waker */
    {
        if (!(fds = calloc(nfds + 1, sizeof(struct pollfd))))
        {
            ret = -ENOMEM;
            goto done;
        }

        if (lfds)
            memcpy(fds, lfds, nfds * sizeof(struct pollfd));

        /* watch for reads on the read-end of the waker */
        fds[nfds].fd = waker->pipefd[0];
        fds[nfds].events = POLLIN;
    }

    /* Wait for events */
    if ((r = poll((struct pollfd*)fds, nfds + 1, timeout)) < 0)
    {
        ret = -errno;
        goto done;
    }

    /* Check whether there were any writes to the waker pipe */
    if (fds[nfds].revents & POLLIN)
    {
        uint64_t x;
        ssize_t n;

        /* consume all words written to the pipe */
        while ((n = read(waker->pipefd[0], &x, sizeof(x))) == sizeof(x))
        {
            if (x != WAKE_MAGIC)
            {
                ret = -EINVAL;
                goto done;
            }
        }

        if (n == -1 && errno != EWOULDBLOCK)
        {
            ret = -EINVAL;
            goto done;
        }
        woken_by_waker = 1;
        /* don't return a value that includes this waker */
        r--;
    }

    /* Copy back the array */
    if (lfds)
        memcpy(lfds, fds, nfds * sizeof(struct pollfd));

    ret = r;

    if ((ret == 0) && woken_by_waker)
        ret = -EINTR;

done:

    if (fds)
        free(fds);
    return ret;
}

#else
#error "MYST_INTERRUPT_POLL_WITH_SIGNAL undefined"
#endif
