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

#include <myst/defs.h>
#include <myst/eraise.h>
#include <myst/id.h>
#include <myst/listener.h>
#include <myst/process.h>
#include <myst/proxypipedev.h>

#define PIPEDEV_MAGIC 0x95fe781f54f24bad

#define PIPE_MAGIC 0x2be05eeda328407f

typedef struct proxypipedev
{
    myst_pipedev_t base;
    uint64_t magic;
    uint64_t cookie;
} proxypipedev_t;

MYST_INLINE bool _proxypipedev_valid(const proxypipedev_t* dev)
{
    return dev && dev->magic == PIPEDEV_MAGIC;
}

struct myst_pipe
{
    uint64_t magic;
    uint64_t cookie;
};

MYST_INLINE bool _pipe_valid(const myst_pipe_t* pipe)
{
    return pipe && pipe->magic == PIPE_MAGIC;
}

static off_t _pipeop(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    myst_pipeop_args_t* args,
    const void* inbuf,
    size_t inbufsize,
    void* outbuf,
    size_t outbufsize,
    myst_message_type_t mt)
{
    ssize_t ret = 0;
    proxypipedev_t* proxypipedev = (proxypipedev_t*)pipedev;
    myst_pipeop_request_t* req = NULL;
    size_t req_size = sizeof(*req) + inbufsize;
    myst_pipeop_response_t* rsp = NULL;
    size_t rsp_size;

    if (!_proxypipedev_valid(proxypipedev) || !_pipe_valid(pipe))
        ERAISE(-EINVAL);

    if (!(req = calloc(1, req_size)))
        ERAISE(-ENOMEM);

    /* initialize the req structure */
    req->pipedev_cookie = proxypipedev->cookie;
    req->pipe_cookie = pipe->cookie;
    req->args = *args;
    req->inbufsize = inbufsize;
    req->outbufsize = outbufsize;

    if (inbuf && inbufsize)
        memcpy(req->buf, inbuf, inbufsize);

    /* call into the listener */
    ECHECK(myst_call_listener_helper(
        mt, req, req_size, sizeof(*rsp), (void**)&rsp, &rsp_size));

    if (outbuf && outbufsize)
    {
        size_t rem = rsp_size - sizeof(*rsp);

        if (rem)
            memcpy(outbuf, rsp->buf, rem);
    }

    ECHECK(rsp->retval);

    ret = rsp->retval;

done:

    if (req)
        free(req);

    if (rsp)
        free(rsp);

    return ret;
}

static int _pd_pipe2(myst_pipedev_t* pipedev, myst_pipe_t* pipe[2], int flags)
{
    int ret = 0;
    proxypipedev_t* dev = (proxypipedev_t*)pipedev;
    myst_pipe_t* rdpipe = NULL;
    myst_pipe_t* wrpipe = NULL;

    if (!_proxypipedev_valid(dev) || !pipe)
        ERAISE(-EINVAL);

    (void)flags;

    /* Create the read pipe */
    {
        if (!(rdpipe = calloc(1, sizeof(myst_pipe_t))))
            ERAISE(-ENOMEM);

        rdpipe->magic = PIPE_MAGIC;
    }

    /* Create the write pipe */
    {
        if (!(wrpipe = calloc(1, sizeof(myst_pipe_t))))
            ERAISE(-ENOMEM);

        wrpipe->magic = PIPE_MAGIC;
    }

    /* ATTN: */

    pipe[0] = rdpipe;
    rdpipe = NULL;
    pipe[1] = wrpipe;
    wrpipe = NULL;

done:

    if (rdpipe)
        free(rdpipe);

    if (wrpipe)
        free(wrpipe);

    return ret;
}

static ssize_t _pd_read(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    void* buf,
    size_t count)
{
    ssize_t ret = 0;
    proxypipedev_t* dev = (proxypipedev_t*)pipedev;

    if (!_proxypipedev_valid(dev) || !_pipe_valid(pipe))
        ERAISE(-EINVAL);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (count == 0)
        goto done;

    /* delegate to listener */
    {
        const myst_message_type_t mt = MYST_MESSAGE_READ_PIPE;
        myst_pipeop_args_t args;
        memset(&args, 0, sizeof(args));
        ret = _pipeop(pipedev, pipe, &args, NULL, 0, buf, count, mt);
        ECHECK(ret);
    }

done:

    return ret;
}

static ssize_t _pd_write(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    const void* buf,
    size_t count)
{
    ssize_t ret = 0;
    proxypipedev_t* dev = (proxypipedev_t*)pipedev;

    if (!_proxypipedev_valid(dev) || !_pipe_valid(pipe))
        ERAISE(-EINVAL);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (count == 0)
        goto done;

    /* delegate to listener */
    {
        const myst_message_type_t mt = MYST_MESSAGE_WRITE_PIPE;
        myst_pipeop_args_t args;
        memset(&args, 0, sizeof(args));
        ret = _pipeop(pipedev, pipe, &args, buf, count, NULL, 0, mt);
        ECHECK(ret);
    }

done:

    return ret;
}

static ssize_t _pd_readv(
    myst_pipedev_t* pipedev,
    myst_pipe_t* pipe,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;
    proxypipedev_t* dev = (proxypipedev_t*)pipedev;

    if (!_proxypipedev_valid(dev) || !_pipe_valid(pipe))
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
    proxypipedev_t* dev = (proxypipedev_t*)pipedev;

    if (!_proxypipedev_valid(dev) || !_pipe_valid(pipe))
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
    proxypipedev_t* dev = (proxypipedev_t*)pipedev;
    struct stat buf;

    if (!_proxypipedev_valid(dev) || !_pipe_valid(pipe) || !statbuf)
        ERAISE(-EINVAL);

    /* delegate to listener */
    {
        const myst_message_type_t mt = MYST_MESSAGE_FSTAT_PIPE;
        myst_pipeop_args_t args;
        memset(&args, 0, sizeof(args));
        ECHECK(_pipeop(pipedev, pipe, &args, NULL, 0, &buf, sizeof(buf), mt));
    }

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
    proxypipedev_t* dev = (proxypipedev_t*)pipedev;

    if (!_proxypipedev_valid(dev) || !_pipe_valid(pipe))
        ERAISE(-EINVAL);

    /* delegate to listener */
    {
        const myst_message_type_t mt = MYST_MESSAGE_FCNTL_PIPE;
        myst_pipeop_args_t args;
        memset(&args, 0, sizeof(args));
        args.fcntl.cmd = cmd;
        args.fcntl.arg = arg;
        ret = _pipeop(pipedev, pipe, &args, NULL, 0, NULL, 0, mt);
        ECHECK(ret);
    }

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
    proxypipedev_t* dev = (proxypipedev_t*)pipedev;

    if (!_proxypipedev_valid(dev) || !_pipe_valid(pipe))
        ERAISE(-EINVAL);

    if (request == TIOCGWINSZ)
        ERAISE(-EINVAL);

    ERAISE(-ENOTSUP);

    (void)request;
    (void)arg;

done:

    return ret;
}

static int _pd_dup(
    myst_pipedev_t* pipedev,
    const myst_pipe_t* pipe,
    myst_pipe_t** pipe_out)
{
    int ret = 0;
    proxypipedev_t* dev = (proxypipedev_t*)pipedev;
    myst_pipe_t* new_pipe = NULL;

    if (pipe_out)
        *pipe_out = NULL;

    if (!_proxypipedev_valid(dev) || !_pipe_valid(pipe) || !pipe_out)
        ERAISE(-EINVAL);

    /* delegate to listener */
    {
        const myst_message_type_t mt = MYST_MESSAGE_DUP_PIPE;
        myst_pipeop_args_t args;
        uint64_t cookie = 0xffffffffffffffff;

        memset(&args, 0, sizeof(args));
        ECHECK(_pipeop(
            pipedev,
            (myst_pipe_t*)pipe,
            &args,
            NULL,
            0,
            &cookie,
            sizeof(cookie),
            mt));
        ECHECK(myst_proxypipe_wrap(cookie, &new_pipe));
    }

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
    proxypipedev_t* dev = (proxypipedev_t*)pipedev;

    if (!_proxypipedev_valid(dev) || !_pipe_valid(pipe))
        ERAISE(-EINVAL);

    /* ATTN: */

done:
    return ret;
}

static int _pd_close(myst_pipedev_t* pipedev, myst_pipe_t* pipe)
{
    int ret = 0;
    proxypipedev_t* dev = (proxypipedev_t*)pipedev;

    if (!_proxypipedev_valid(dev) || !_pipe_valid(pipe))
        ERAISE(-EINVAL);

    /* delegate to listener */
    {
        const myst_message_type_t mt = MYST_MESSAGE_CLOSE_PIPE;
        myst_pipeop_args_t args;
        memset(&args, 0, sizeof(args));
        ret = _pipeop(pipedev, pipe, &args, NULL, 0, NULL, 0, mt);
        ECHECK(ret);
    }

done:
    return ret;
}

static int _pd_target_fd(myst_pipedev_t* pipedev, myst_pipe_t* pipe)
{
    int ret = 0;

    if (!pipedev || !_pipe_valid(pipe))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

static int _pd_get_events(myst_pipedev_t* pipedev, myst_pipe_t* pipe)
{
    int ret = 0;

    if (!pipedev || !_pipe_valid(pipe))
        ERAISE(-EINVAL);

    /* ATTN: */

done:
    return ret;
}

int myst_proxypipe_wrap(uint64_t pipe_cookie, myst_pipe_t** pipe_out)
{
    int ret = 0;
    myst_pipe_t* pipe = NULL;

    if (pipe_out)
        *pipe_out = NULL;

    if (!pipe_cookie || !pipe_out)
        ERAISE(-EINVAL);

    if (!(pipe = calloc(1, sizeof(myst_pipe_t))))
        ERAISE(-ENOMEM);

    pipe->magic = PIPE_MAGIC;
    pipe->cookie = pipe_cookie;

    *pipe_out = pipe;
    pipe = NULL;

done:

    if (pipe)
        free(pipe);

    return ret;
}

int myst_proxypipedev_wrap(
    uint64_t pipedev_cookie,
    myst_pipedev_t** pipedev_out)
{
    int ret = 0;
    // clang-format-off
    static myst_pipedev_t _base = {
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
    proxypipedev_t* dev = NULL;

    if (pipedev_out)
        *pipedev_out = NULL;

    if (!pipedev_cookie || !pipedev_out)
        ERAISE(-EINVAL);

    if (!(dev = calloc(1, sizeof(proxypipedev_t))))
        ERAISE(-ENOMEM);

    dev->base = _base;
    dev->magic = PIPEDEV_MAGIC;
    dev->cookie = pipedev_cookie;

    *pipedev_out = &dev->base;
    dev = NULL;

done:

    if (dev)
        free(dev);

    return ret;
}

bool myst_is_proxypipedev(const myst_pipedev_t* pipedev)
{
    return _proxypipedev_valid((const proxypipedev_t*)pipedev);
}
