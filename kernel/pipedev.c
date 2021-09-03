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

#define MAGIC 0x9906acdc

#define USE_ASYNC_TCALL

#if 0
#define T(EXPR) EXPR
#else
#define T(EXPR)
#endif

/* Limit the number of pipes */
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

static _Atomic(size_t) _num_pipes;

/* this structure is shared by the pipe */
typedef struct shared
{
    _Atomic(size_t) nreaders;
    _Atomic(size_t) nwriters;
    _Atomic(size_t) npackets; /* number of packets currently in the pipe */
    _Atomic(size_t) pipesz;   /* capacity of pipe (F_SETPIPE_SZ/F_GETPIPE_SZ) */
    _Atomic(bool) nonblock;   /* true if non-blocking socket */
    myst_mutex_t lock;
} shared_t;

struct myst_pipe
{
    uint32_t magic; /* MAGIC */
    int fd;         /* host file descriptor */
    int mode;       /* O_RDONLY or O_WRONLY */
    shared_t* shared;
    myst_buf_t inbuf; /* data read from wire */
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

MYST_INLINE bool _valid_pipe(const myst_pipe_t* pipe)
{
    return pipe && pipe->magic == MAGIC;
}

static int _get_nonblock(int fd, bool* flag)
{
    int ret = 0;
    int flags;

    ECHECK(flags = _sys_fcntl(fd, F_GETFL, 0));
    *flag = (flags & O_NONBLOCK);

done:
    return ret;
}

static int _pd_pipe2(myst_pipedev_t* pipedev, myst_pipe_t* pipe[2], int flags)
{
    int ret = 0;
    myst_pipe_t* rdpipe = NULL;
    myst_pipe_t* wrpipe = NULL;
    shared_t* shared = NULL;
    int pipefd[2] = {-1, -1};
    int pipesz;
    bool nonblock;

    if (!pipedev || !pipe || (flags & ~(O_CLOEXEC | O_DIRECT | O_NONBLOCK)))
        ERAISE(-EINVAL);

    if (++_num_pipes == MAX_PIPES)
    {
        _num_pipes--;
        ERAISE(-EMFILE);
    }

    /* Create the pipe descriptors on the host */
    ECHECK(_sys_pipe2(pipefd, flags));

    /* Get the size of the pipe buffer */
    ECHECK(pipesz = _sys_fcntl(pipefd[1], F_GETPIPE_SZ, 0));

#if 0
    /* Double the pipe buffer size */
    ECHECK(_sys_fcntl(pipefd[1], F_SETPIPE_SZ, pipesz * 2));
#endif

    /* Get the non-block flag */
    ECHECK(_get_nonblock(pipefd[1], &nonblock));

    /* Create the shared structure */
    {
        if (!(shared = calloc(1, sizeof(shared_t))))
            ERAISE(-ENOMEM);

        /* initially there is one reader and one writer */
        shared->nreaders = 1;
        shared->nwriters = 1;

        /* Set initial pipe capacity; may be updated by fcntl(F_SETPIPE_SZ) */
        shared->pipesz = (size_t)pipesz;

        /* Set the non-blocking flag */
        shared->nonblock = (size_t)nonblock;
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstack-usage="
static ssize_t _pd_read(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    void* buf,
    size_t count)
{
    ssize_t ret = 0;
    ssize_t nread = 0;

    T(printf("=== _pd_read(): count=%zu\n", count));

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (count == 0)
        goto done;

    if (pipe->mode == O_WRONLY)
        ERAISE(-EBADF);

    /* perform the read operation */
    {
        uint8_t* ptr = buf;
        size_t rem = count;

        while (rem > 0)
        {
            const void* data = pipe->inbuf.data;
            const size_t size = pipe->inbuf.size;

            /* first read from the buffer */
            if (size > 0)
            {
                size_t min = _min(rem, size);
                memcpy(ptr, data, min);
                nread += min;
                ptr += min;
                rem -= min;
                myst_buf_remove(&pipe->inbuf, 0, min);

                /* if the buffer is exhausted, then consume the footer */
                if (pipe->inbuf.size == 0)
                {
                    footer_t footer;
                    ssize_t n = _sys_read(pipe->fd, &footer, sizeof(footer));
                    ECHECK(n);

                    /* handle end-of-file */
                    if (n == 0)
                    {
                        ret = nread;
                        goto done;
                    }

                    assert(n == sizeof(footer));
                    assert(footer.magic == FOOTER_MAGIC);
                    pipe->shared->npackets--;
                }
            }

            /* if caller's buffer is full */
            if (rem == 0)
                break;

            if (pipe->shared->npackets == 0 && nread > 0)
                break;

            /* now read from the pipe */
            {
                ssize_t n;
                size_t size;

                /* read the header */
                {
                    header_t header;
                    n = _sys_read(pipe->fd, &header, sizeof(header));
                    ECHECK(n);

                    /* handle end-of-file */
                    if (n == 0)
                    {
                        ret = nread;
                        goto done;
                    }

                    assert(n == sizeof(header));
                    assert(header.magic == HEADER_MAGIC);
                    pipe->shared->npackets--;
                    size = header.size;
                }

                /* calculate the number of data packets */
                size_t padded_count;
                ECHECK(myst_round_up(size, PACKET_SIZE, &padded_count));
                size_t npackets = padded_count / PACKET_SIZE;

                /* read the data packets */
                for (size_t i = 0; i < npackets; i++)
                {
                    packet_t packet;

                    n = _sys_read(pipe->fd, &packet, sizeof(packet));
                    ECHECK(n);

                    /* handle end-of-file */
                    if (n == 0)
                    {
                        ret = nread;
                        goto done;
                    }

                    assert(n == sizeof(packet));
                    pipe->shared->npackets--;

                    size_t min = _min(size, PACKET_SIZE);
                    assert(min != 0);

                    ECHECK(myst_buf_append(&pipe->inbuf, packet.data, min));

                    size -= min;
                }
            }
        }
    }

    ret = nread;

done:

    T(printf("_pd_read(): ret=%zd\n", ret));

    return ret;
}
#pragma GCC diagnostic pop

MYST_UNUSED
static ssize_t _get_available_space(int fd)
{
    ssize_t ret = 0;
    size_t nread = 0;
    size_t pipesz;

    if (fd < 0)
        goto done;

    ECHECK(_sys_ioctl(fd, FIONREAD, (long)&nread));
    ECHECK(pipesz = _sys_fcntl(fd, F_GETPIPE_SZ, 0));
    assert(pipesz >= nread);
    ret = pipesz - nread;

done:
    return ret;
}

static int _format_payload(myst_buf_t* out, const void* buf, size_t count)
{
    int ret = 0;
    header_t header = {HEADER_MAGIC, count};
    footer_t footer = {FOOTER_MAGIC};
    size_t padded_count;
    size_t size;

    ECHECK(myst_buf_clear(out));
    ECHECK(myst_round_up(count, PACKET_SIZE, &padded_count));
    size = sizeof(header) + padded_count + sizeof(footer);
    ECHECK(myst_buf_reserve(out, size));
    ECHECK(myst_buf_append(out, &header, sizeof(header)));
    ECHECK(myst_buf_append(out, buf, count));
    ECHECK(myst_buf_resize(out, sizeof(header) + padded_count));
    ECHECK(myst_buf_append(out, &footer, sizeof(footer)));

    assert(out->size == size);
    assert((out->size % PACKET_SIZE) == 0);

done:
    return ret;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstack-usage="
static ssize_t _pd_write(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    const void* buf,
    size_t count)
{
    ssize_t ret = 0;
    ssize_t nwritten = 0;
    myst_buf_t out = MYST_BUF_INITIALIZER;
    bool locked = false;

    T(printf("=== _pd_write(): count=%zu\n", count));

    if (!pipedev || !_valid_pipe(pipe))
        ERAISE(-EBADF);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (pipe->mode == O_RDONLY)
        ERAISE(-EBADF);

    if (count == 0)
        goto done;

    myst_mutex_lock(&pipe->shared->lock);
    locked = true;

    /* if there are no readers, then raise EPIPE */
    if (pipe->shared->nreaders == 0)
    {
        myst_syscall_kill(myst_getpid(), SIGPIPE);
        ERAISE(-EPIPE);
    }

    /* If non-blocking, then adjust the count for the available space */
    if (pipe->shared->nonblock)
    {
        const size_t nused = pipe->shared->npackets * PACKET_SIZE;
        const size_t pipesz = pipe->shared->pipesz;
        assert(nused <= pipesz);
        assert((nused % PACKET_SIZE) == 0);
        const size_t navail = pipesz - nused;
        assert((navail % PACKET_SIZE) == 0);

        /* If not enough room for header, one-packet, and footer */
        if (navail < (3 * PACKET_SIZE))
            ERAISE(-EAGAIN);

        /* Adjust the count for the amount of available data space */
        {
            const size_t n = navail - (2 * PACKET_SIZE);

            if (count > n)
                count = n;
        }
    }

#if 0
    /* reduce count so that total bytes written will be less than PIPE_BUF */
    count = _min(count, PIPE_BUF - (2 * PACKET_SIZE));
#endif

    /* write in chunks that are <= PIPE_BUF */
    {
        const uint8_t* ptr = buf;
        size_t rem = count;

        while (rem > 0)
        {
            size_t chunk_size = _min(rem, PIPE_BUF - (2 * PACKET_SIZE));
            ssize_t n;

            ECHECK(_format_payload(&out, ptr, chunk_size));
            ECHECK(n = _sys_write(pipe->fd, out.data, out.size));
            assert((size_t)n == out.size);

#if 0
            printf("_pd_write(): %zu packets\n", (out.size / PACKET_SIZE));
            pipe->shared->npackets += (out.size / PACKET_SIZE);

            printf("_pd_write(): wrote %zu of %zu\n", n, out.size);
            printf("_pd_write(): space=%zu\n", _get_available_space(pipe->fd));
#endif

            nwritten += chunk_size;
            ptr += chunk_size;
            rem -= chunk_size;
        }
    }

    ret = nwritten;

done:

    if (locked)
        myst_mutex_unlock(&pipe->shared->lock);

    if (out.data)
        free(out.data);

    T(printf("_pd_write(): ret=%ld\n", ret));

    return ret;
}
#pragma GCC diagnostic pop

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

    switch (cmd)
    {
        case F_SETPIPE_SZ:
        {
            pipe->shared->pipesz = arg;
            break;
        }
        case F_SETFL:
        {
            pipe->shared->nonblock = (arg & O_NONBLOCK);
            break;
        }
        default:
        {
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
