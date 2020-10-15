#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libos/cond.h>
#include <libos/defs.h>
#include <libos/eraise.h>
#include <libos/id.h>
#include <libos/panic.h>
#include <libos/pipedev.h>

#define MAGIC 0x9906acdc

#define SCRATCH_BUF_SIZE 256

typedef struct pipe_impl
{
    libos_cond_t cond;
    libos_mutex_t mutex;
    char buf[PIPE_BUF];
    size_t nbytes;
    size_t nreaders;
    size_t nwriters;
} pipe_impl_t;

struct libos_pipe
{
    uint32_t magic;
    int mode;  /* O_RDONLY or O_WRONLY */
    int flags; /* (O_NONBLOCK | O_CLOEXEC | O_DIRECT) */
    pipe_impl_t* impl;
};

LIBOS_INLINE bool _valid_pipe(const libos_pipe_t* pipe)
{
    return pipe && pipe->magic == MAGIC && pipe->impl;
}

static void _lock(libos_pipe_t* pipe)
{
    libos_assume(_valid_pipe(pipe));
    libos_mutex_lock(&pipe->impl->mutex);
}

static void _unlock(libos_pipe_t* pipe)
{
    libos_assume(_valid_pipe(pipe));
    libos_mutex_unlock(&pipe->impl->mutex);
}

static ssize_t _get_total_iov_size(const struct iovec* iov, int iovcnt)
{
    ssize_t ret = 0;
    ssize_t size = 0;

    for (int i = 0; i < iovcnt; i++)
    {
        const struct iovec* v = &iov[i];

        if (!v->iov_base && v->iov_len)
            ERAISE(-EINVAL);

        size += v->iov_len;
    }

    ret = size;

done:
    return ret;
}

static int _pd_pipe2(libos_pipedev_t* pipedev, libos_pipe_t* pipe[2], int flags)
{
    int ret = 0;
    libos_pipe_t* rdpipe = NULL;
    libos_pipe_t* wrpipe = NULL;
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
    }

    /* Create the read pipe */
    {
        if (!(rdpipe = calloc(1, sizeof(libos_pipe_t))))
            ERAISE(-ENOMEM);

        rdpipe->magic = MAGIC;
        rdpipe->mode = O_RDONLY;
        rdpipe->flags = flags;
        rdpipe->impl = impl;
    }

    /* Create the write pipe */
    {
        if (!(wrpipe = calloc(1, sizeof(libos_pipe_t))))
            ERAISE(-ENOMEM);

        wrpipe->magic = MAGIC;
        wrpipe->mode = O_WRONLY;
        wrpipe->flags = flags;
        wrpipe->impl = impl;
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
    libos_pipedev_t* pipedev,
    libos_pipe_t* pipe,
    void* buf,
    size_t count)
{
    ssize_t ret = 0;
    pipe_impl_t* p;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (count == 0)
        goto done;

    _lock(pipe);
    p = pipe->impl;

    if (!_valid_pipe(pipe))
    {
        /* cannot unlock since mutex is no longer valid */
        ERAISE(-EBADF);
    }

    /* block here while the pipe is empty */
    while (p->nbytes == 0)
    {
        /* Handle non-blocking write */
        if (pipe->flags & O_NONBLOCK)
        {
            _unlock(pipe);
            ERAISE(-EAGAIN);
        }

        /* if there are no writers, then fail */
        if (p->nwriters == 0)
        {
            _unlock(pipe);
            /* broken pipe */
            ERAISE(-EPIPE);
        }

        /* wait here for another thread to write */
        if (libos_cond_wait(&p->cond, &p->mutex) != 0)
        {
            /* unexpected */
            _unlock(pipe);
            ERAISE(-EPIPE);
        }
    }

    /* copy bytes from pipe to the caller buffer */
    if (p->nbytes <= count)
    {
        const size_t n = p->nbytes;
        memcpy(buf, p->buf, n);
        p->nbytes = 0;
        libos_cond_signal(&p->cond);
        _unlock(pipe);
        ret = n;
        goto done;
    }
    else /* p->nbytes > count */
    {
        const size_t n = count;
        memcpy(buf, p->buf, n);
        memmove(p->buf, p->buf + n, p->nbytes - count);
        p->nbytes -= n;
        libos_cond_signal(&p->cond);
        _unlock(pipe);
        ret = n;
        goto done;
    }

done:
    return ret;
}

static ssize_t _pd_write(
    libos_pipedev_t* pipedev,
    libos_pipe_t* pipe,
    const void* buf,
    size_t count)
{
    ssize_t ret = 0;
    pipe_impl_t* p = pipe->impl;
    size_t nspace;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (count == 0)
        goto done;

    _lock(pipe);
    p = pipe->impl;

    if (!_valid_pipe(pipe))
    {
        /* cannot unlock since mutex is no longer valid */
        ERAISE(-EBADF);
    }

    /* Block here while the pipe is full */
    while (p->nbytes == PIPE_BUF)
    {
        /* Handle non-blocking read */
        if (pipe->flags & O_NONBLOCK)
        {
            _unlock(pipe);
            ERAISE(-EAGAIN);
        }

        /* if there are no readers, then fail */
        if (p->nreaders == 0)
        {
            _unlock(pipe);
            /* broken pipe */
            ERAISE(-EPIPE);
        }

        /* wait here for another thread to read */
        if (libos_cond_wait(&p->cond, &p->mutex) != 0)
        {
            /* unexpected */
            _unlock(pipe);
            ERAISE(-EPIPE);
        }
    }

    /* calculate the space in the pipe buffer */
    nspace = PIPE_BUF - p->nbytes;

    /* copy bytes from caller buffer to pipe */
    if (nspace <= count)
    {
        const size_t n = nspace;
        memcpy(p->buf + p->nbytes, buf, n);
        p->nbytes += n;
        libos_cond_signal(&p->cond);
        _unlock(pipe);
        ret = n;
        goto done;
    }
    else /* nspace > count */
    {
        const size_t n = count;
        memcpy(p->buf + p->nbytes, buf, n);
        p->nbytes += n;
        libos_cond_signal(&p->cond);
        _unlock(pipe);
        ret = n;
        goto done;
    }

done:
    return ret;
}

static ssize_t _pd_readv(
    libos_pipedev_t* pipedev,
    libos_pipe_t* pipe,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;
    ssize_t count = 0;
    uint8_t scratch[SCRATCH_BUF_SIZE];
    void* buf;
    size_t r;

    if (!_valid_pipe(pipe) || (!iov && iovcnt) || iovcnt < 0)
        ERAISE(-EINVAL);

    /* Calculate the number of bytes to read */
    ECHECK(count = _get_total_iov_size(iov, iovcnt));

    /* suceed if zero bytes to read */
    if (count == 0)
        goto done;

    /* choose between the scratch buffer and the dynamic buffer */
    if ((size_t)count <= sizeof(scratch))
        buf = scratch;
    else if (!(buf = malloc(count)))
        ERAISE(-ENOMEM);

    /* Peform the read */
    if ((r = _pd_read(pipedev, pipe, buf, count)) < 0)
        ERAISE(r);

    /* Copy the data back to the caller's buffer */
    {
        const uint8_t* ptr = buf;
        size_t rem = r;

        for (int i = 0; i < iovcnt && rem; i++)
        {
            const struct iovec* v = &iov[i];

            if (v->iov_len)
            {
                size_t min = (rem < v->iov_len) ? rem : v->iov_len;
                memcpy(v->iov_base, ptr, min);
                ptr += min;
                rem -= min;
            }
        }
    }

    ret = r;

done:

    if (buf != scratch)
        free(buf);

    return ret;
}

static ssize_t _pd_writev(
    libos_pipedev_t* pipedev,
    libos_pipe_t* pipe,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;
    ssize_t count = 0;
    uint8_t scratch[SCRATCH_BUF_SIZE];
    void* buf;
    size_t r;

    if (!pipedev || !_valid_pipe(pipe) || (!iov && iovcnt) || iovcnt < 0)
        ERAISE(-EINVAL);

    /* Calculate the number of bytes to write */
    ECHECK(count = _get_total_iov_size(iov, iovcnt));

    /* suceed if zero bytes to write */
    if (count == 0)
        goto done;

    /* choose between the scratch buffer and the dynamic buffer */
    if ((size_t)count <= sizeof(scratch))
        buf = scratch;
    else if (!(buf = malloc(count)))
        ERAISE(-ENOMEM);

    /* Copy the caller buffer onto the flat buffer */
    {
        uint8_t* ptr = buf;

        for (int i = 0; i < iovcnt; i++)
        {
            const struct iovec* v = &iov[i];

            if (v->iov_len)
            {
                memcpy(ptr, v->iov_base, v->iov_len);
                ptr += v->iov_len;
            }
        }
    }

    /* Peform the write */
    if ((r = _pd_write(pipedev, pipe, buf, count)) < 0)
        ERAISE(r);

    ret = r;

done:

    if (buf != scratch)
        free(buf);

    return ret;
}

static int _pd_fstat(
    libos_pipedev_t* pipedev,
    libos_pipe_t* pipe,
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
    buf.st_uid = LIBOS_DEFAULT_UID;
    buf.st_gid = LIBOS_DEFAULT_GID;
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
    libos_pipedev_t* pipedev,
    libos_pipe_t* pipe,
    int cmd,
    long arg)
{
    int ret = 0;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EINVAL);

    if (cmd == F_SETFD && arg == FD_CLOEXEC)
    {
        pipe->flags |= O_CLOEXEC;
        goto done;
    }

    if (cmd == F_GETFD)
    {
        ret = pipe->flags;
        goto done;
    }

    ERAISE(-ENOTSUP);

done:
    return ret;
}

static int _pd_close(libos_pipedev_t* pipedev, libos_pipe_t* pipe)
{
    int ret = 0;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    _lock(pipe);

    if (!pipe->impl->nreaders && !pipe->impl->nwriters)
        ERAISE(-EBADF);

    if (pipe->mode == O_RDONLY)
        pipe->impl->nreaders--;
    else if (pipe->mode == O_WRONLY)
        pipe->impl->nwriters--;

    /* signal any threads blocked on read or write */
    libos_cond_signal(&pipe->impl->cond);

    /* Release the pipe if no more readers or writers */
    if (pipe->impl->nreaders == 0 && pipe->impl->nwriters == 0)
    {
        _unlock(pipe);
        memset(pipe->impl, 0, sizeof(pipe_impl_t));
        free(pipe->impl);
    }
    else
    {
        _unlock(pipe);
    }

    memset(pipe, 0, sizeof(libos_pipe_t));
    free(pipe);

done:

    return ret;
}

extern libos_pipedev_t* libos_pipedev_get(void)
{
    // clang-format-off
    static libos_pipedev_t _pipdev = {
        {
            .fd_read = (void*)_pd_read,
            .fd_write = (void*)_pd_write,
            .fd_readv = (void*)_pd_readv,
            .fd_writev = (void*)_pd_writev,
            .fd_fstat = (void*)_pd_fstat,
            .fd_fcntl = (void*)_pd_fcntl,
            .fd_close = (void*)_pd_close,
        },
        .pd_pipe2 = _pd_pipe2,
        .pd_read = _pd_read,
        .pd_write = _pd_write,
        .pd_readv = _pd_readv,
        .pd_writev = _pd_writev,
        .pd_fstat = _pd_fstat,
        .pd_fcntl = _pd_fcntl,
        .pd_close = _pd_close,
    };
    // clang-format-on

    return &_pipdev;
}

int libos_pipedev_clone_pipe(
    libos_pipedev_t* pipedev,
    const libos_pipe_t* pipe,
    libos_pipe_t** pipe_out)
{
    int ret = 0;
    libos_pipe_t* new_pipe = NULL;

    if (pipe_out)
        *pipe_out = NULL;

    if (!pipedev || !_valid_pipe(pipe) || !pipe_out)
        ERAISE(-EINVAL);

    if (!(new_pipe = calloc(1, sizeof(libos_pipe_t))))
        ERAISE(-ENOMEM);

    *new_pipe = *pipe;

    _lock((libos_pipe_t*)new_pipe);

    if (new_pipe->mode == O_RDONLY)
        new_pipe->impl->nreaders++;
    else
        new_pipe->impl->nwriters++;

    _unlock((libos_pipe_t*)new_pipe);

    *pipe_out = new_pipe;
    new_pipe = NULL;

done:

    if (new_pipe)
        free(new_pipe);

    return ret;
}
