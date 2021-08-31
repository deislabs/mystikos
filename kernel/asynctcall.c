#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <myst/asynctcall.h>
#include <myst/mutex.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/syscall.h>
#include <myst/tcall.h>

#define PIPE_MAGIC_WORD 0x77d377455afc4838

#define MAX_WAKERS 16384

static myst_mutex_t _mutex;

MYST_INLINE long _sys_fcntl(int fd, int cmd, long arg)
{
    long params[6] = {fd, cmd, arg};
    return myst_tcall(SYS_fcntl, params);
}

MYST_INLINE long _sys_write(int fd, const void* buf, size_t count)
{
    long params[6] = {fd, (long)buf, count};
    return myst_tcall(SYS_write, params);
}

MYST_INLINE long _sys_pipe2(int pipefd[2], int flags)
{
    long params[6] = {(long)pipefd, flags};
    return myst_tcall(SYS_pipe2, params);
}

MYST_INLINE long _sys_poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
    long params[6] = {(long)fds, nfds, timeout};
    return myst_tcall(SYS_poll, params);
}

typedef struct waker
{
    int pipefd[2];
} waker_t;

static waker_t _wakers[MAX_WAKERS];

static int _set_nonblock(int fd)
{
    int flags;

    if ((flags = _sys_fcntl(fd, F_GETFL, 0)) == -1)
        return -1;

    if (_sys_fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        return -1;

    return 0;
}

static int _set_block(int fd)
{
    int flags;

    if ((flags = _sys_fcntl(fd, F_GETFL, 0)) == -1)
        return -1;

    if (_sys_fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1)
        return -1;

    return 0;
}

static int _is_nonblock(int fd)
{
    int flags;

    if ((flags = _sys_fcntl(fd, F_GETFL, 0)) == -1)
        return -1;

    return (flags & O_NONBLOCK) ? 0 : -1;
}

static int _init_once_waker(waker_t* waker)
{
    int ret = 0;

    myst_mutex_lock(&_mutex);

    /* if not initialized yet */
    if (waker->pipefd[0] == 0 && waker->pipefd[1] == 0)
    {
        if (_sys_pipe2(waker->pipefd, 0) < 0)
        {
            ret = -1;
            goto done;
        }

        if (_set_nonblock(waker->pipefd[0]) != 0 ||
            _set_nonblock(waker->pipefd[1]) != 0)
        {
            close(waker->pipefd[0]);
            close(waker->pipefd[1]);
            waker->pipefd[0] = 0;
            waker->pipefd[1] = 0;
            ret = -1;
            goto done;
        }
    }

done:
    myst_mutex_unlock(&_mutex);
    return ret;
}

long myst_async_tcall(long num, int poll_flags, int fd, ...)
{
    long ret = 0;
    bool reset_to_blocking = false;
    waker_t* waker;

    va_list ap;
    va_start(ap, fd);
    long x2 = va_arg(ap, long);
    long x3 = va_arg(ap, long);
    long x4 = va_arg(ap, long);
    long x5 = va_arg(ap, long);
    long x6 = va_arg(ap, long);
    va_end(ap);

    if (_is_nonblock(fd) == 0)
    {
        long params[6] = {fd, x2, x3, x4, x5, x6};
        ret = myst_tcall(num, params);
        goto done;
    }

    if (fd >= (int)MYST_COUNTOF(_wakers))
    {
        assert("unexpected" == NULL);
        ret = -ENOSYS;
        goto done;
    }

    _set_nonblock(fd);
    reset_to_blocking = true;
    waker = &_wakers[fd];

    /* Try to perform the operation up front */
    {
        long params[6] = {fd, x2, x3, x4, x5, x6};
        long r = myst_tcall(num, params);

        if (r >= 0)
        {
            ret = r;
            goto done;
        }
    }

    if (_init_once_waker(waker) != 0)
    {
        assert("unexpected" == NULL);
        ret = -ENOSYS;
        goto done;
    }

    /* Wait for events */
    for (;;)
    {
        struct pollfd fds[2];
        long r;

        memset(fds, 0, sizeof(fds));
        fds[0].fd = fd;
        fds[0].events = poll_flags;
        fds[1].fd = waker->pipefd[0];
        fds[1].events = POLLIN;

        if ((r = _sys_poll(fds, 2, -1)) < 0)
        {
            ret = r;
            goto done;
        }

        if (r > 0)
        {
            if (fds[0].revents & poll_flags)
            {
                long params[6] = {fd, x2, x3, x4, x5, x6};
                r = myst_tcall(num, params);

                if (r >= 0)
                {
                    ret = r;
                    goto done;
                }

                if (errno != EWOULDBLOCK)
                {
                    ret = -errno;
                    goto done;
                }
            }
            else if (fds[1].revents & POLLIN)
            {
                ssize_t n;
                uint64_t x;

                while ((n = read(waker->pipefd[0], &x, sizeof(x))) == sizeof(x))
                {
                    if (x != PIPE_MAGIC_WORD)
                    {
                        ret = -EINTR;
                        goto done;
                    }
                }

                if (n == -1 && errno != EWOULDBLOCK)
                {
                    ret = -EINTR;
                    goto done;
                }

                /* operation was interrupted so return -EINTR */
                ret = -EINTR;
                goto done;
            }
        }
    }

done:

    if (reset_to_blocking)
        _set_block(fd);

    return ret;
}

long myst_interrupt_async_tcall(int fd)
{
    const uint64_t x = PIPE_MAGIC_WORD;
    waker_t* waker;

    if (fd >= (int)MYST_COUNTOF(_wakers))
    {
        assert("unexpected" == NULL);
        return -EINVAL;
    }

    waker = &_wakers[fd];

    if (_init_once_waker(waker) != 0)
        return -ENOSYS;

    if (_sys_write(waker->pipefd[1], &x, sizeof(x)) != sizeof(x))
    {
        // the write may fail if  the pipe is full, but the failure
        // may safely be ignored since the thread will be awoken under
        // this failure condition (since the pipe is ready for read).
    }

    return 0;
}
