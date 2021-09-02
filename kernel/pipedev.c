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
#include <myst/pipedev.h>
#include <myst/printf.h>
#include <myst/process.h>
#include <myst/round.h>
#include <myst/spinlock.h>
#include <myst/syscall.h>

#define MAGIC 0x9906acdc

#define USE_ASYNC_TCALL

#define T(EXPR)

/* Limit the number of pipes to 256 */
#define MAX_PIPES 256

#define HEADER_MAGIC 0x0112013912e54099
#define FOOTER_MAGIC 0x66e69483d7e44981

#define PACKET_SIZE 128

/*
**==============================================================================
**
** wire protocol:
**
**     [header][packets...][footer]
**
**==============================================================================
*/

typedef struct header
{
    /* Must contain HEADER_MAGIC */
    uint64_t magic;

    /* The unpadded size of the data (contained in packets that follow) */
    uint64_t size;

    /* Padding to the PACKET_SIZE boundary */
    uint8_t padding[PACKET_SIZE - sizeof(uint64_t) - sizeof(uint64_t)];
} header_t;

/* A single data packet */
typedef struct packet
{
    uint8_t data[PACKET_SIZE];
} packet_t;

// Footers are needed to keep the pipe read-enabled until the reader has
// consumed all the data between the header and footer.
typedef struct footer
{
    /* FOOTER_MAGIC */
    uint64_t magic;

    /* Padding to the PACKET_SIZE boundary */
    uint8_t padding[PACKET_SIZE - sizeof(uint64_t)];
} footer_t;

MYST_STATIC_ASSERT(sizeof(header_t) == PACKET_SIZE);
MYST_STATIC_ASSERT(sizeof(packet_t) == PACKET_SIZE);
MYST_STATIC_ASSERT(sizeof(footer_t) == PACKET_SIZE);

/* this structure is shared by the pipe */
typedef struct shared
{
    size_t nreaders;
    size_t nwriters;
} shared_t;

struct myst_pipe
{
    uint32_t magic; /* MAGIC */
    int fd;         /* host file descriptor */
    int mode;       /* O_RDONLY or O_WRONLY */
    shared_t* shared;
};

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

MYST_INLINE long _sys_dup(int oldfd)
{
    long params[6] = {oldfd};
    return myst_tcall(SYS_dup, params);
}

MYST_INLINE bool _valid_pipe(const myst_pipe_t* pipe)
{
    return pipe && pipe->magic == MAGIC;
}

static int _pd_pipe2(myst_pipedev_t* pipedev, myst_pipe_t* pipe[2], int flags)
{
    int ret = 0;
    myst_pipe_t* rdpipe = NULL;
    myst_pipe_t* wrpipe = NULL;
    shared_t* shared = NULL;
    int pipefd[2] = {-1, -1};

    if (!pipedev || !pipe || (flags & ~(O_CLOEXEC | O_DIRECT | O_NONBLOCK)))
        ERAISE(-EINVAL);

    /* Create the pipe descriptors on the host */
    ECHECK(_sys_pipe2(pipefd, flags));

    /* Create the shared structure */
    {
        if (!(shared = calloc(1, sizeof(shared_t))))
            ERAISE(-ENOMEM);

        /* initially there is one read and one writer */
        shared->nreaders = 1;
        shared->nwriters = 1;
    }

    /* Create the read pipe */
    {
        if (!(rdpipe = calloc(1, sizeof(myst_pipe_t))))
            ERAISE(-ENOMEM);

        rdpipe->magic = MAGIC;
        rdpipe->fd = pipefd[0];
        rdpipe->mode = O_RDONLY;
        rdpipe->shared = shared;
    }

    /* Create the write pipe */
    {
        if (!(wrpipe = calloc(1, sizeof(myst_pipe_t))))
            ERAISE(-ENOMEM);

        wrpipe->magic = MAGIC;
        wrpipe->fd = pipefd[1];
        wrpipe->mode = O_WRONLY;
        wrpipe->shared = shared;
    }

    T(printf(
          "_pd_pipe2(): pipefd[%d:%d] pid=%d\n",
          pipefd[0],
          pipefd[1],
          myst_getpid());)

    pipe[0] = rdpipe;
    pipe[1] = wrpipe;
    rdpipe = NULL;
    wrpipe = NULL;
    pipefd[0] = -1;
    pipefd[1] = -1;

done:

    if (rdpipe)
        free(rdpipe);

    if (wrpipe)
        free(wrpipe);

    if (pipefd[0] >= 0)
        _sys_close(pipefd[0]);

    if (pipefd[1] >= 0)
        _sys_close(pipefd[1]);

    return ret;
}

static ssize_t _pd_read(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    void* buf,
    size_t count)
{
    ssize_t ret = 0;
    ssize_t nread;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (count == 0)
        goto done;

    if (pipe->mode == O_WRONLY)
        ERAISE(-EBADF);

    /* read from the host pipe */
    T(printf("_pd_read(): fd=%d pid=%d\n", pipe->fd, myst_getpid());)
    nread = _sys_read(pipe->fd, buf, count);
    ECHECK(nread);

    ret = nread;

done:

    T(printf("_pd_read(): done\n");)
    return ret;
}

static ssize_t _pd_write(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    const void* buf,
    size_t count)
{
    ssize_t ret = 0;
    ssize_t nwritten;
    myst_buf_t data = MYST_BUF_INITIALIZER;

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (pipe->mode == O_RDONLY)
        ERAISE(-EBADF);

    if (count == 0)
        goto done;

    /* if there are no readers, then raise EPIPE */
    if (pipe->shared->nreaders == 0)
    {
        myst_syscall_kill(myst_getpid(), SIGPIPE);
        ERAISE(-EPIPE);
    }

    /* Format the data for the wire */
#if 0
    {
        header_t header = { HEADER_MAGIC, count };
        footer_t footer = { FOOTER_MAGIC };
        size_t padded_count;
        size_t size;

        ECHECK(myst_round_up(count, PACKET_SIZE, &padded_count));
        size = sizeof(header) + padded_count + sizeof(footer);
        ECHECK(myst_buf_reserve(&data, size));
        ECHECK(myst_buf_append(&data, &header, sizeof(header)));
        ECHECK(myst_buf_append(&data, buf, count));
        ECHECK(myst_buf_resize(&data, sizeof(header) + padded_count));
        ECHECK(myst_buf_append(&data, &footer, sizeof(footer)));
        assert(data.size == size);
    }
#endif

    /* write the packet for this data to the host pipe */
#if 1
    ECHECK(nwritten = _sys_write(pipe->fd, buf, count));
    assert((size_t)nwritten == count);
#else
    ECHECK(nwritten = _sys_write(pipe->fd, data.data, data.size));
#endif

    ret = nwritten;

done:

    if (data.data)
        free(data.data);

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

    ECHECK((r = _sys_fcntl(pipe->fd, cmd, arg)));
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
