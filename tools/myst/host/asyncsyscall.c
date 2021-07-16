#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <myst/asyncsyscall.h>
#include <myst/defs.h>

#define PIPE_MAGIC_WORD 0x77d377455afc4838

static pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;

static int _set_nonblock(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
        return -1;

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        return -1;

    return 0;
}

static int _set_block(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
        return -1;

    if (fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == -1)
        return -1;

    return 0;
}

static int _is_nonblock(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
        return -1;

    return (flags & O_NONBLOCK) ? 0 : -1;
}

static int _init_nonblocking_pipe(int pipefd[2])
{
    int ret = 0;

    pthread_mutex_lock(&_mutex);

    /* if not initialized yet */
    if (pipefd[0] == 0 && pipefd[1] == 0)
    {
        if (pipe(pipefd) < 0)
        {
            ret = -1;
            goto done;
        }

        if (_set_nonblock(pipefd[0]) != 0)
        {
            close(pipefd[0]);
            close(pipefd[1]);
            pipefd[0] = 0;
            pipefd[1] = 0;
            ret = -1;
            goto done;
        }

        if (_set_nonblock(pipefd[1]) != 0)
        {
            close(pipefd[0]);
            close(pipefd[1]);
            pipefd[0] = 0;
            pipefd[1] = 0;
            ret = -1;
            goto done;
        }
    }

done:
    pthread_mutex_unlock(&_mutex);
    return ret;
}

typedef struct waker
{
    int pipefd[2];
} waker_t;

#define MAX_WAKERS 16384
static waker_t _wakers[MAX_WAKERS];

long myst_async_syscall(long num, int poll_flags, int fd, ...)
{
    long ret = 0;
    struct pollfd fds[2];
    bool reset_to_blocking = false;
    int* pipefd;

    va_list ap;
    va_start(ap, fd);
    long x2 = va_arg(ap, long);
    long x3 = va_arg(ap, long);
    long x4 = va_arg(ap, long);
    long x5 = va_arg(ap, long);
    long x6 = va_arg(ap, long);
    va_end(ap);

    if (fd >= MYST_COUNTOF(_wakers))
    {
        assert("unexpected" == NULL);
        ret = -ENOSYS;
        goto done;
    }

    pipefd = _wakers[fd].pipefd;

    if (_is_nonblock(fd) == 0)
    {
        ret = syscall(num, fd, x2, x3, x4, x5, x6);
        goto done;
    }

    _set_nonblock(fd);
    reset_to_blocking = true;

    if (_init_nonblocking_pipe(pipefd) != 0)
    {
        ret = -ENOSYS;
        goto done;
    }

    /* Wait for events */
    for (;;)
    {
        int r;

        memset(fds, 0, sizeof(fds));
        fds[0].fd = fd;
        fds[0].events = poll_flags;
        fds[1].fd = pipefd[0];
        fds[1].events = POLLIN;

        if ((r = poll(fds, 2, 0)) < 0)
        {
            ret = -ENOSYS;
            goto done;
        }

        if (r > 0)
        {
            if (fds[0].revents & poll_flags)
            {
                r = syscall(num, fd, x2, x3, x4, x5, x6);

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
            else if (fds[1].revents & poll_flags)
            {
                ssize_t n;
                uint64_t x;

                while ((n = read(pipefd[0], &x, sizeof(x))) == sizeof(x))
                {
                    if (x != PIPE_MAGIC_WORD)
                    {
                        ret = -ENOSYS;
                        goto done;
                    }
                }

                if (n == -1 && errno != EWOULDBLOCK)
                {
                    ret = -ENOSYS;
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

long myst_interrupt_async_syscall(int fd)
{
    const uint64_t x = PIPE_MAGIC_WORD;
    int* pipefd;

    if (fd >= MYST_COUNTOF(_wakers))
    {
        assert("unexpected" == NULL);
        return -EINVAL;
    }

    pipefd = _wakers[fd].pipefd;

    if (_init_nonblocking_pipe(pipefd) != 0)
        return -ENOSYS;

    if (write(pipefd[1], &x, sizeof(x)) != sizeof(x))
    {
        // the write may fail if  the pipe is full, but the failure
        // may safely be ignored since the thread will be awoken under
        // this failure condition (since the pipe is ready for read).
    }

    return 0;
}
