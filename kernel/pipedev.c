// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <myst/cond.h>
#include <myst/defs.h>
#include <myst/eraise.h>
#include <myst/id.h>
#include <myst/panic.h>
#include <myst/pipedev.h>
#include <myst/process.h>
#include <myst/round.h>
#include <myst/syscall.h>

#define MAGIC 0x9906acdc

#define SCRATCH_BUF_SIZE 256

typedef struct pipe_impl
{
    myst_cond_t cond;
    myst_mutex_t mutex;
    char* data; /* points to buf or heap-allocated memory */
    size_t pipesz;
    char buf[PIPE_BUF];
    size_t nbytes;
    size_t nreaders;
    size_t nwriters;
    size_t wrsize; /* set by write(), decremented by read() */
} pipe_impl_t;

struct myst_pipe
{
    uint32_t magic;
    int mode;    /* O_RDONLY or O_WRONLY */
    int flags;   /* (O_NONBLOCK | O_CLOEXEC | O_DIRECT) */
    int fdflags; /* FD_CLOEXEC */
    pipe_impl_t* impl;
};

MYST_INLINE bool _valid_pipe(const myst_pipe_t* pipe)
{
    return pipe && pipe->magic == MAGIC && pipe->impl;
}

static void _lock(myst_pipe_t* pipe)
{
    myst_assume(_valid_pipe(pipe));
    myst_mutex_lock(&pipe->impl->mutex);
}

static void _unlock(myst_pipe_t* pipe)
{
    myst_assume(_valid_pipe(pipe));
    myst_mutex_unlock(&pipe->impl->mutex);
}

static int _pd_pipe2(myst_pipedev_t* pipedev, myst_pipe_t* pipe[2], int flags)
{
    int ret = 0;
    myst_pipe_t* rdpipe = NULL;
    myst_pipe_t* wrpipe = NULL;
    pipe_impl_t* impl = NULL;

    if (!pipedev || !pipe || (flags & ~(O_CLOEXEC | O_DIRECT | O_NONBLOCK)))
        ERAISE(-EINVAL);

    /* Create the shared pipe implementation structure */
    {
        if (!(impl = calloc(1, sizeof(pipe_impl_t))))
            ERAISE(-ENOMEM);

        /* initially there is one read and one writer */
        impl->nreaders = 1;
        impl->nwriters = 1;

        /* setup the default pipe buffer */
        impl->data = impl->buf;
        impl->pipesz = PIPE_BUF;
    }

    /* Create the read pipe */
    {
        if (!(rdpipe = calloc(1, sizeof(myst_pipe_t))))
            ERAISE(-ENOMEM);

        rdpipe->magic = MAGIC;
        rdpipe->mode = O_RDONLY;
        rdpipe->flags = flags;
        rdpipe->impl = impl;

        if (flags & O_CLOEXEC)
            rdpipe->fdflags = FD_CLOEXEC;
    }

    /* Create the write pipe */
    {
        if (!(wrpipe = calloc(1, sizeof(myst_pipe_t))))
            ERAISE(-ENOMEM);

        wrpipe->magic = MAGIC;
        wrpipe->mode = O_WRONLY;
        wrpipe->flags = flags;
        wrpipe->impl = impl;

        if (flags & O_CLOEXEC)
            wrpipe->fdflags = FD_CLOEXEC;
    }

    pipe[0] = rdpipe;
    pipe[1] = wrpipe;
    rdpipe = NULL;
    wrpipe = NULL;
    impl = NULL;

done:

    if (rdpipe)
        free(rdpipe);

    if (wrpipe)
        free(wrpipe);

    if (impl)
        free(impl);

    return ret;
}

static ssize_t _pd_read(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    void* buf,
    size_t count)
{
    ssize_t ret = 0;
    pipe_impl_t* p;
    uint8_t* ptr = buf;
    size_t rem = count;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (pipe->mode == O_WRONLY)
        ERAISE(-EBADF);

    if (count == 0)
        goto done;

    _lock(pipe);
    p = pipe->impl;

    if (!_valid_pipe(pipe))
    {
        /* cannot unlock since mutex is no longer valid */
        _unlock(pipe);
        ERAISE(-EBADF);
    }

    while (rem)
    {
        /* block here while the pipe is empty */
        while (p->nbytes == 0)
        {
            /* Handle non-blocking write */
            if (pipe->flags & O_NONBLOCK)
            {
                _unlock(pipe);

                if (rem < count)
                {
                    /* return short count */
                    ret = count - rem;
                    goto done;
                }

                ERAISE(-EAGAIN);
            }

            /* if there are no writers, then fail */
            if (p->nwriters == 0)
            {
                _unlock(pipe);

                if (rem < count)
                {
                    /* return short count */
                    ret = count - rem;
                    goto done;
                }

                /* broken pipe */
                ERAISE(-EPIPE);
            }

            /* If write operation is finished */
            if (p->wrsize == 0 && rem < count)
            {
                _unlock(pipe);
                /* return short count */
                ret = count - rem;
                goto done;
            }

            /* wait here for another thread to write */
            if (myst_cond_wait(&p->cond, &p->mutex) != 0)
            {
                /* unexpected */
                _unlock(pipe);
                ERAISE(-EPIPE);
            }
        }

        /* copy bytes from pipe to the caller buffer */
        if (p->nbytes <= rem)
        {
            const size_t n = p->nbytes;
            memcpy(ptr, p->data, n);
            p->nbytes = 0;
            myst_cond_signal(&p->cond);
            rem -= n;
            ptr += n;
            p->wrsize -= n;
        }
        else /* p->nbytes > count */
        {
            const size_t n = rem;
            memcpy(ptr, p->data, n);
            memmove(p->data, p->data + n, p->nbytes - rem);
            p->nbytes -= n;
            p->wrsize -= n;
            myst_cond_signal(&p->cond);
            break;
        }
    }

    _unlock(pipe);
    ret = count;

done:

    if (ret > 0)
        myst_tcall_poll_wake();

    return ret;
}

static ssize_t _pd_write(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    const void* buf,
    size_t count)
{
    ssize_t ret = 0;
    pipe_impl_t* p;
    size_t nspace;
    const uint8_t* ptr = buf;
    size_t rem = count;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (pipe->mode == O_RDONLY)
        ERAISE(-EBADF);

    /* if there are no readers, then raise EPIPE */
    if (pipe->impl->nreaders == 0)
    {
        myst_syscall_kill(myst_getpid(), SIGPIPE);
        ERAISE(-EPIPE);
    }

    if (count == 0)
        goto done;

    _lock(pipe);
    p = pipe->impl;

    p->wrsize += count;

    if (!_valid_pipe(pipe))
    {
        /* cannot unlock since mutex is no longer valid */
        _unlock(pipe);
        ERAISE(-EBADF);
    }

    while (rem)
    {
        /* Block here while the pipe is full */
        while (p->nbytes == p->pipesz)
        {
            /* Handle non-blocking read */
            if (pipe->flags & O_NONBLOCK)
            {
                _unlock(pipe);

                if (rem < count)
                {
                    /* return short count */
                    ret = count - rem;
                    goto done;
                }

                ERAISE(-EAGAIN);
            }

            /* if there are no readers, then fail */
            if (p->nreaders == 0)
            {
                _unlock(pipe);

                if (rem < count)
                {
                    /* return short count */
                    ret = count - rem;
                    goto done;
                }

                /* broken pipe */
                ERAISE(-EPIPE);
            }

            /* wait here for another thread to read */
            if (myst_cond_wait(&p->cond, &p->mutex) != 0)
            {
                /* unexpected */
                _unlock(pipe);
                ERAISE(-EPIPE);
            }
        }

        /* calculate the space in the pipe buffer */
        nspace = p->pipesz - p->nbytes;

        /* copy bytes from caller buffer to pipe */
        if (nspace <= rem)
        {
            const size_t n = nspace;
            memcpy(p->data + p->nbytes, ptr, n);
            p->nbytes += n;
            myst_cond_signal(&p->cond);
            rem -= n;
            ptr += n;
        }
        else /* nspace > r */
        {
            const size_t n = rem;
            memcpy(p->data + p->nbytes, ptr, n);
            p->nbytes += n;
            myst_cond_signal(&p->cond);
            break;
        }
    }

    _unlock(pipe);
    ret = count;

done:

    if (ret > 0)
        myst_tcall_poll_wake();

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
    struct stat buf;

    if (!pipedev || !_valid_pipe(pipe) || !statbuf)
        ERAISE(-EINVAL);

    memset(&buf, 0, sizeof(buf));
    buf.st_dev = 12; /* FIFO device */
    buf.st_ino = (ino_t)pipe;
    buf.st_mode = S_IFIFO | O_EXCL | O_NOCTTY;
    buf.st_nlink = 1;
    buf.st_uid = MYST_DEFAULT_UID;
    buf.st_gid = MYST_DEFAULT_GID;
    buf.st_rdev = 0;
    buf.st_size = 0;
    buf.st_blksize = PIPE_BUF;
    buf.st_blocks = 0;
    memset(&buf.st_atim, 0, sizeof(buf.st_atim));
    memset(&buf.st_mtim, 0, sizeof(buf.st_mtim));
    memset(&buf.st_ctim, 0, sizeof(buf.st_ctim));

    *statbuf = buf;

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
    pipe_impl_t* p;
    bool locked = false;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EINVAL);

    _lock(pipe);
    locked = true;
    p = pipe->impl;

    switch (cmd)
    {
        case F_SETFD:
        {
            if (arg != FD_CLOEXEC && arg != 0)
                ERAISE(-EINVAL);

            pipe->fdflags = arg;
            goto done;
        }
        case F_GETFD:
        {
            ret = pipe->fdflags;
            goto done;
        }
        case F_SETPIPE_SZ:
        {
            void* data;
            size_t pipesz;

            if (arg <= 0)
                arg = PIPE_BUF;

            ECHECK(myst_round_up(arg, PIPE_BUF, &pipesz));

            if (!(data = calloc(pipesz, 1)))
                ERAISE(-ENOMEM);

            if (p->data != p->buf)
                free(p->data);

            p->data = data;
            p->pipesz = pipesz;

            ret = (long)pipesz;
            goto done;
        }
        case F_GETPIPE_SZ:
        {
            ret = p->pipesz;
            goto done;
        }
        case F_GETFL:
        {
            ret = pipe->mode | pipe->flags;
            goto done;
        }
        default:
        {
            ERAISE(-ENOTSUP);
        }
    }

    /* unreachable */
    myst_assume(false);

done:

    if (locked)
        _unlock(pipe);

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

    /* file descriptor flags are not propagated */
    new_pipe->fdflags = 0;

    _lock((myst_pipe_t*)new_pipe);

    if (new_pipe->mode == O_RDONLY)
        new_pipe->impl->nreaders++;
    else
        new_pipe->impl->nwriters++;

    _unlock((myst_pipe_t*)new_pipe);

    *pipe_out = new_pipe;
    new_pipe = NULL;

done:

    if (new_pipe)
        free(new_pipe);

    return ret;
}

static int _pd_interrupt(myst_pipedev_t* pipedev, myst_pipe_t* pipe)
{
    int ret = 0;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    _lock(pipe);

    /* signal any threads blocked on read or write */
    myst_cond_signal(&pipe->impl->cond);

    _unlock(pipe);

done:
    return ret;
}

static int _pd_close(myst_pipedev_t* pipedev, myst_pipe_t* pipe)
{
    int ret = 0;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    _lock(pipe);

    if (!pipe->impl->nreaders && !pipe->impl->nwriters)
    {
        _unlock(pipe);
        ERAISE(-EBADF);
    }
    if (pipe->mode == O_RDONLY)
        pipe->impl->nreaders--;
    else if (pipe->mode == O_WRONLY)
        pipe->impl->nwriters--;

    /* signal any threads blocked on read or write */
    myst_cond_signal(&pipe->impl->cond);

    /* Release the pipe if no more readers or writers */
    if (pipe->impl->nreaders == 0 && pipe->impl->nwriters == 0)
    {
        _unlock(pipe);

        if (pipe->impl->data != pipe->impl->buf)
            free(pipe->impl->data);

        memset(pipe->impl, 0, sizeof(pipe_impl_t));
        free(pipe->impl);
    }
    else
    {
        _unlock(pipe);
    }

    memset(pipe, 0, sizeof(myst_pipe_t));
    free(pipe);

done:

    return ret;
}

static int _pd_target_fd(myst_pipedev_t* pipedev, myst_pipe_t* pipe)
{
    int ret = 0;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

static int _pd_get_events(myst_pipedev_t* pipedev, myst_pipe_t* pipe)
{
    int ret = 0;
    int events = 0;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EINVAL);

    _lock(pipe);
    {
        if (pipe->mode == O_RDONLY)
        {
            /* if there is anything to read, then set input event */
            if (pipe->impl->nbytes > 0)
                events |= POLLIN;
        }
        else if (pipe->mode == O_WRONLY)
        {
            /* if there is room to write more, then set output event */
            if (pipe->impl->nbytes < pipe->impl->pipesz)
                events |= POLLOUT;
        }
    }
    _unlock(pipe);

    ret = events;

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
