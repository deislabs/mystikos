// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <myst/asynctcall.h>
#include <myst/buf.h>
#include <myst/defs.h>
#include <myst/eraise.h>
#include <myst/mutex.h>
#include <myst/pipedev.h>
#include <myst/printf.h>
#include <myst/process.h>
#include <myst/round.h>
#include <myst/syscall.h>
#include <myst/time.h>

#define MAGIC 0x9906acdc

#define USE_ASYNC_TCALL

#if 0
#define T(EXPR) EXPR
#else
#define T(EXPR)
#endif

/* Limit the number of pipes */
#define MAX_PIPES 256
#define DEFAULT_PIPE_SIZE (64 * 1024)

/*
**==============================================================================
**
** Payload layout:
**
**     [header][packets...][trailer]
**
**
** Read-write enablements states (2 half-pages)
**
**                              Write-Enabled   Read-Enabled    State
**     +--------+--------+      -----------------------------------------
**     |        |        |      Yes             No              WR_ENABLED
**     +--------+--------+
**
**     +--------+--------+
**     |XXXXXXXX|        |      Yes             Yes             RDWR_ENABLED
**     +--------+--------+
**
**     +--------+--------+
**     |XXXXXXXX|XXXXXXXX|      No              Yes             RD_ENABLED
**     +--------+--------+
**
**==============================================================================
*/

static _Atomic(size_t) _num_pipes;

typedef enum state
{
    STATE_WR_ENABLED,
    STATE_RDWR_ENABLED,
    STATE_RD_ENABLED,
} state_t;

/* this structure is shared by the pipe */
typedef struct shared
{
    myst_mutex_t lock;
    int flags; /* O_NONBLOCK */
    size_t nreaders;
    size_t nwriters;
    size_t pipesz; /* capacity of pipe (F_SETPIPE_SZ/F_GETPIPE_SZ) */
    state_t state; /* read-write enablement state */
    myst_buf_t buf;
} shared_t;

struct myst_pipe
{
    uint32_t magic; /* MAGIC */
    int fd;         /* host file descriptor */
    int mode;       /* O_RDONLY or O_WRONLY */
    shared_t* shared;
};

MYST_INLINE size_t _min(size_t x, size_t y)
{
    return (x < y) ? x : y;
}

MYST_INLINE long _sys_close(int fd)
{
    long params[6] = {fd};
    return myst_tcall(SYS_close, params);
}

MYST_INLINE long _sys_pipe2(int pipefd[2], int flags)
{
    long params[6] = {(long)pipefd, flags};
    return myst_tcall(SYS_pipe2, params);
}

MYST_INLINE long _sys_read(int fd, void* buf, size_t count)
{
#ifdef USE_ASYNC_TCALL
    int poll_flags = POLLIN | POLLHUP;
    return myst_async_tcall(SYS_read, poll_flags, fd, buf, count);
#else
    long params[6] = {fd, (long)buf, count};
    return myst_tcall(SYS_read, params);
#endif
}

MYST_INLINE long _sys_write(int fd, const void* buf, size_t count)
{
#ifdef USE_ASYNC_TCALL
    return myst_async_tcall(SYS_write, POLLOUT, fd, buf, count);
#else
    long params[6] = {fd, (long)buf, count};
    return myst_tcall(SYS_write, params);
#endif
}

MYST_INLINE long _sys_fstat(int fd, struct stat* statbuf)
{
    long params[6] = {fd, (long)statbuf};
    return myst_tcall(SYS_fstat, params);
}

MYST_INLINE long _sys_fcntl(int fd, int cmd, long arg)
{
    long params[6] = {fd, cmd, arg};
    return myst_tcall(SYS_fcntl, params);
}

MYST_INLINE long _sys_ioctl(int fd, unsigned long request, long arg)
{
    long params[6] = {fd, request, arg};
    return myst_tcall(SYS_ioctl, params);
}

MYST_INLINE long _sys_dup(int oldfd)
{
    long params[6] = {oldfd};
    return myst_tcall(SYS_dup, params);
}

MYST_INLINE long _sys_poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
    long params[6] = {(long)fds, nfds, timeout};
    return myst_tcall(SYS_poll, params);
}

MYST_INLINE bool _valid_pipe(const myst_pipe_t* pipe)
{
    return pipe && pipe->magic == MAGIC;
}

MYST_INLINE size_t _nbytes(const shared_t* shared)
{
    return shared->buf.size;
}

MYST_INLINE size_t _space(const shared_t* shared)
{
    return shared->pipesz - shared->buf.size;
}

static int _pd_pipe2(myst_pipedev_t* pipedev, myst_pipe_t* pipe[2], int flags)
{
    int ret = 0;
    myst_pipe_t* rdpipe = NULL;
    myst_pipe_t* wrpipe = NULL;
    shared_t* shared = NULL;
    int fds[2] = {-1, -1};

    if (!pipedev || !pipe || (flags & ~(O_CLOEXEC | O_DIRECT | O_NONBLOCK)))
        ERAISE(-EINVAL);

    if (++_num_pipes == MAX_PIPES)
    {
        _num_pipes--;
        ERAISE(-EMFILE);
    }

    /* Create the pipe descriptors on the host */
    ECHECK(_sys_pipe2(fds, flags));

    /* Set the pipe buffer size to PIPE_BUF */
    ECHECK(_sys_fcntl(fds[0], F_SETPIPE_SZ, PIPE_BUF));

    /* Create the shared structure */
    {
        if (!(shared = calloc(1, sizeof(shared_t))))
            ERAISE(-ENOMEM);

        /* initially there is one reader and one writer */
        shared->nreaders = 1;
        shared->nwriters = 1;

        /* Set initial pipe capacity; may be updated by fcntl(F_SETPIPE_SZ) */
        shared->pipesz = DEFAULT_PIPE_SIZE;

        /* Set the state */
        shared->state = STATE_WR_ENABLED;

        /* Set the non-blocking flag */
        shared->flags = flags;
    }

    /* Create the read pipe */
    {
        if (!(rdpipe = calloc(1, sizeof(myst_pipe_t))))
            ERAISE(-ENOMEM);

        rdpipe->magic = MAGIC;
        rdpipe->fd = fds[0];
        rdpipe->mode = O_RDONLY;
        rdpipe->shared = shared;
    }

    /* Create the write pipe */
    {
        if (!(wrpipe = calloc(1, sizeof(myst_pipe_t))))
            ERAISE(-ENOMEM);

        wrpipe->magic = MAGIC;
        wrpipe->fd = fds[1];
        wrpipe->mode = O_WRONLY;
        wrpipe->shared = shared;
    }

    T(printf(
          "_pd_pipe2(): fds[%d:%d] pid=%d\n", fds[0], fds[1], myst_getpid());)

    pipe[0] = rdpipe;
    pipe[1] = wrpipe;
    rdpipe = NULL;
    wrpipe = NULL;
    fds[0] = -1;
    fds[1] = -1;

done:

    if (rdpipe)
        free(rdpipe);

    if (wrpipe)
        free(wrpipe);

    if (fds[0] >= 0)
        _sys_close(fds[0]);

    if (fds[1] >= 0)
        _sys_close(fds[1]);

    return ret;
}

static ssize_t _pd_read(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    void* buf,
    size_t count)
{
    ssize_t ret = 0;
    ssize_t nread = 0;
    shared_t* shared;
    struct locals
    {
        uint8_t zeros[PIPE_BUF];
    };
    struct locals* locals = NULL;
    bool locked = false;

    T(printf("=== _pd_read(): count=%zu\n", count));

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    shared = pipe->shared;

    if (!buf && count)
        ERAISE(-EINVAL);

    if (count == 0)
        goto done;

    if (pipe->mode == O_WRONLY)
        ERAISE(-EBADF);

    if (!(locals = calloc(1, sizeof(struct locals))))
        ERAISE(-ENOMEM);

    myst_mutex_lock(&shared->lock);
    locked = true;

    if (shared->flags == O_NONBLOCK) /* handle non-blocking write */
    {
        /* ATTN */
        assert(false);
    }
    else /* handle blocking read */
    {
        uint8_t* ptr = buf;
        size_t rem = count;

        while (rem > 0)
        {
            size_t min = _min(rem, _nbytes(shared));

            if (min) /* there is data in the buffer */
            {
                memcpy(ptr, shared->buf.data, min);
                ECHECK(myst_buf_remove(&shared->buf, 0, min));
                rem -= min;
                ptr += min;
                nread += min;

                switch (shared->state)
                {
                    case STATE_RD_ENABLED:
                    {
                        if (_space(shared))
                        {
                            const size_t n = PIPE_BUF / 2;
                            ECHECK(_sys_read(pipe->fd, locals->zeros, n));
                            shared->state = STATE_RDWR_ENABLED;
                        }
                        else
                        {
                            const size_t n = PIPE_BUF;
                            ECHECK(_sys_read(pipe->fd, locals->zeros, n));
                            shared->state = STATE_WR_ENABLED;
                        }
                        break;
                    }
                    case STATE_RDWR_ENABLED:
                    {
                        if (_space(shared))
                        {
                            const size_t n = PIPE_BUF / 2;
                            ECHECK(_sys_read(pipe->fd, locals->zeros, n));
                            shared->state = STATE_WR_ENABLED;
                        }
                        break;
                    }
                    case STATE_WR_ENABLED:
                    {
                        /* ATTN: what do we do here */
                        break;
                    }
                }
            }
            else /* the buffer is empty */
            {
                struct pollfd fds[1];
                fds[0].fd = pipe->fd;
                fds[0].events = POLLIN;

                /* block here until pipe becomes write enabled */
                myst_mutex_unlock(&shared->lock);
                // printf("read.poll: rem=%zu\n", rem);
                _sys_poll(fds, MYST_COUNTOF(fds), -1);
                // printf("read.poll>>>>>>>>>>\n");
                myst_mutex_lock(&shared->lock);
            }
        }
    }

    ret = nread;

done:

    if (locals)
        free(locals);

    if (locked)
        myst_mutex_unlock(&shared->lock);

    T(printf("_pd_read(): ret=%zd\n", ret));

    return ret;
}

static ssize_t _pd_write(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    const void* buf,
    size_t count)
{
    ssize_t ret = 0;
    myst_buf_t out = MYST_BUF_INITIALIZER;
    bool locked = false;
    shared_t* shared;
    struct locals
    {
        uint8_t zeros[PIPE_BUF];
    };
    struct locals* locals = NULL;
    size_t nwritten = 0;

    T(printf("=== _pd_write(): count=%zu\n", count));

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    shared = pipe->shared;

    if (!buf && count)
        ERAISE(-EINVAL);

    if (pipe->mode == O_RDONLY)
        ERAISE(-EBADF);

    if (count == 0)
        goto done;

    if (!(locals = calloc(1, sizeof(struct locals))))
        ERAISE(-ENOMEM);

    myst_mutex_lock(&shared->lock);
    locked = true;

    /* if there are no readers, then raise EPIPE */
    if (shared->nreaders == 0)
    {
        myst_syscall_kill(myst_getpid(), SIGPIPE);
        ERAISE(-EPIPE);
    }

    if (shared->flags == O_NONBLOCK) /* handle non-blocking write */
    {
        /* ATTN */
        assert(false);
    }
    else /* handle blocking write */
    {
        const uint8_t* ptr = buf;
        size_t rem = count;

        while (rem > 0)
        {
            size_t space = shared->pipesz - _nbytes(shared);
            size_t min = _min(rem, space);

            if (min) /* there is space in the buffer */
            {
                ECHECK(myst_buf_append(&shared->buf, ptr, min));
                rem -= min;
                ptr += min;
                nwritten += min;

                switch (shared->state)
                {
                    case STATE_WR_ENABLED:
                    {
                        if (_space(shared))
                        {
                            const size_t n = PIPE_BUF / 2;
                            ECHECK(_sys_write(pipe->fd, locals->zeros, n));
                            shared->state = STATE_RDWR_ENABLED;
                        }
                        else
                        {
                            const size_t n = PIPE_BUF;
                            ECHECK(_sys_write(pipe->fd, locals->zeros, n));
                            shared->state = STATE_RD_ENABLED;
                        }
                        break;
                    }
                    case STATE_RDWR_ENABLED:
                    {
                        if (_space(shared) == 0)
                        {
                            const size_t n = PIPE_BUF / 2;
                            ECHECK(_sys_write(pipe->fd, locals->zeros, n));
                            shared->state = STATE_RD_ENABLED;
                        }
                        break;
                    }
                    case STATE_RD_ENABLED:
                    {
                        assert(false);
                        break;
                    }
                }
            }
            else /* the buffer is full */
            {
                struct pollfd fds[1];
                fds[0].fd = pipe->fd;
                fds[0].events = POLLOUT;

                /* block here until pipe becomes write enabled */
                myst_mutex_unlock(&shared->lock);
                _sys_poll(fds, MYST_COUNTOF(fds), -1);
                myst_mutex_lock(&shared->lock);
            }
        }
    }

    ret = nwritten;

done:

    if (locked)
        myst_mutex_unlock(&shared->lock);

    if (out.data)
        free(out.data);

    if (locals)
        free(locals);

    T(printf("_pd_write(): ret=%ld\n", ret));

    return ret;
}

static ssize_t _pd_readv(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EINVAL);

    ret = myst_fdops_readv(&pipedev->fdops, pipe, iov, iovcnt);
    ECHECK(ret);

done:

    return ret;
}

static ssize_t _pd_writev(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EINVAL);

    ret = myst_fdops_writev(&pipedev->fdops, pipe, iov, iovcnt);
    ECHECK(ret);

done:

    return ret;
}

static int _pd_fstat(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    struct stat* statbuf)
{
    int ret = 0;

    if (!pipedev || !_valid_pipe(pipe) || !statbuf)
        ERAISE(-EINVAL);

    ECHECK(_sys_fstat(pipe->fd, statbuf));

done:
    return ret;
}

static int _pd_fcntl(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    int cmd,
    long arg)
{
    int ret = 0;
    long r;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EINVAL);

    switch (cmd)
    {
        case F_SETPIPE_SZ:
        {
            if (arg < PIPE_BUF)
                arg = PIPE_BUF;

            arg = (arg + (PIPE_BUF - 1)) / PIPE_BUF * PIPE_BUF;

            pipe->shared->pipesz = arg;
            goto done;
        }
        case F_GETPIPE_SZ:
        {
            ret = pipe->shared->pipesz;
            goto done;
        }
    }

    ECHECK((r = _sys_fcntl(pipe->fd, cmd, arg)));

    switch (cmd)
    {
        case F_SETFL:
        {
            pipe->shared->flags |= arg;
            break;
        }
    }

    ret = r;

done:

    return ret;
}

static int _pd_ioctl(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    unsigned long request,
    long arg)
{
    int ret = 0;

    (void)arg;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    if (request == TIOCGWINSZ)
        ERAISE(-EINVAL);

    ERAISE(-ENOTSUP);

done:

    return ret;
}

static int _pd_dup(
    myst_pipedev_t* pipedev,
    const myst_pipe_t* pipe,
    myst_pipe_t** pipe_out)
{
    int ret = 0;
    myst_pipe_t* new_pipe = NULL;

    if (pipe_out)
        *pipe_out = NULL;

    if (!pipedev || !_valid_pipe(pipe) || !pipe_out)
        ERAISE(-EINVAL);

    if (!(new_pipe = calloc(1, sizeof(myst_pipe_t))))
        ERAISE(-ENOMEM);

    *new_pipe = *pipe;

    /* perform syscall */
    ECHECK(new_pipe->fd = _sys_dup(pipe->fd));

    if (new_pipe->mode == O_RDONLY)
        new_pipe->shared->nreaders++;
    else
        new_pipe->shared->nwriters++;

    T(printf(
          "_pd_dup(): oldfd=%d newfd=%d pid=%d\n",
          pipe->fd,
          new_pipe->fd,
          myst_getpid());)

    *pipe_out = new_pipe;
    new_pipe = NULL;

done:
    T(printf("_pd_dup(): done\n");)

    if (new_pipe)
        free(new_pipe);

    return ret;
}

static int _pd_interrupt(myst_pipedev_t* pipedev, myst_pipe_t* pipe)
{
    int ret = 0;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    T(printf("_pd_interrupt(): fd=%d pid=%d\n", pipe->fd, myst_getpid());)
    myst_interrupt_async_tcall(pipe->fd);

done:
    T(printf("_pd_interrupt(): done\n");)
    return ret;
}

static int _pd_close(myst_pipedev_t* pipedev, myst_pipe_t* pipe)
{
    int ret = 0;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    if (!pipe->shared->nreaders && !pipe->shared->nwriters)
    {
        ERAISE(-EBADF);
    }

    T(printf("_pd_close(): fd=%d pid=%d\n", pipe->fd, myst_getpid());)
    ECHECK(_sys_close(pipe->fd));

    if (pipe->mode == O_RDONLY)
        pipe->shared->nreaders--;
    else if (pipe->mode == O_WRONLY)
        pipe->shared->nwriters--;

    if (pipe->shared->nreaders == 0 && pipe->shared->nwriters == 0)
        free(pipe->shared);

    memset(pipe, 0, sizeof(myst_pipe_t));
    free(pipe);

    _num_pipes--;

done:
    T(printf("_pd_close(): done\n");)

    return ret;
}

static int _pd_target_fd(myst_pipedev_t* pipedev, myst_pipe_t* pipe)
{
    int ret = 0;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EINVAL);

    ret = pipe->fd;

done:
    return ret;
}

static int _pd_get_events(myst_pipedev_t* pipedev, myst_pipe_t* pipe)
{
    int ret = 0;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

extern myst_pipedev_t* myst_pipedev_get(void)
{
    // clang-format-off
    static myst_pipedev_t _pipdev = {
        {
            .fd_read = (void*)_pd_read,
            .fd_write = (void*)_pd_write,
            .fd_readv = (void*)_pd_readv,
            .fd_writev = (void*)_pd_writev,
            .fd_fstat = (void*)_pd_fstat,
            .fd_fcntl = (void*)_pd_fcntl,
            .fd_ioctl = (void*)_pd_ioctl,
            .fd_dup = (void*)_pd_dup,
            .fd_close = (void*)_pd_close,
            .fd_interrupt = (void*)_pd_interrupt,
            .fd_target_fd = (void*)_pd_target_fd,
            .fd_get_events = (void*)_pd_get_events,
        },
        .pd_pipe2 = _pd_pipe2,
        .pd_read = _pd_read,
        .pd_write = _pd_write,
        .pd_readv = _pd_readv,
        .pd_writev = _pd_writev,
        .pd_fstat = _pd_fstat,
        .pd_fcntl = _pd_fcntl,
        .pd_ioctl = _pd_ioctl,
        .pd_dup = _pd_dup,
        .pd_close = _pd_close,
        .pd_target_fd = _pd_target_fd,
        .pd_get_events = _pd_get_events,
    };
    // clang-format-on

    return &_pipdev;
}
