// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <sys/ioctl.h>

#include <myst/asynctcall.h>
#include <myst/eraise.h>
#include <myst/eventfddev.h>
#include <myst/syscall.h>

#define MAGIC 0x9906acdc

struct myst_eventfd
{
    uint32_t magic;
    int fd;
};

MYST_INLINE long _sys_eventfd(unsigned int initval, int flags)
{
    long params[6] = {(long)initval, (long)flags};
    return myst_tcall(SYS_eventfd, params);
}

MYST_INLINE long _sys_read(int fd, void* buf, size_t count)
{
#ifdef USE_ASYNC_TCALL
    int poll_flags = POLLIN | POLLHUP;
    return myst_async_tcall(SYS_read, poll_flags, fd, buf, count);
#else
    long params[6] = {(long)fd, (long)buf, (long)count};
    return myst_tcall(SYS_read, params);
#endif
}

MYST_INLINE long _sys_write(int fd, const void* buf, size_t count)
{
#ifdef USE_ASYNC_TCALL
    int poll_flags = POLLOUT;
    return myst_async_tcall(SYS_write, poll_flags, fd, buf, count);
#else
    long params[6] = {(long)fd, (long)buf, (long)count};
    return myst_tcall(SYS_write, params);
#endif
}

MYST_INLINE long _sys_fcntl(int fd, int cmd, long arg)
{
    long params[6] = {fd, cmd, arg};
    return myst_tcall(SYS_fcntl, params);
}

MYST_INLINE bool _valid_eventfd(const myst_eventfd_t* eventfd)
{
    return eventfd && eventfd->magic == MAGIC;
}

MYST_INLINE long _sys_dup(int oldfd)
{
    long params[6] = {oldfd};
    return myst_tcall(SYS_dup, params);
}

MYST_INLINE long _sys_close(int fd)
{
    long params[6] = {fd};
    return myst_tcall(SYS_close, params);
}

MYST_INLINE long _sys_fstat(int fd, struct stat* statbuf)
{
    long params[6] = {fd, (long)statbuf};
    return myst_tcall(SYS_fstat, params);
}

static int _eventfd_eventfd(
    myst_eventfddev_t* eventfddev,
    unsigned int initval,
    int flags,
    myst_eventfd_t** eventfd_out)
{
    int ret = 0;
    myst_eventfd_t* eventfd = NULL;

    if (!eventfddev || !eventfd_out)
        ERAISE(-EINVAL);

    /* Allocate the read eventfd struct. */
    {
        if (!(eventfd = calloc(1, sizeof(myst_eventfd_t))))
            ERAISE(-ENOMEM);

        eventfd->magic = MAGIC;
    }

    /* Create the eventfd file descriptor */
    ECHECK(eventfd->fd = _sys_eventfd(initval, flags));

    *eventfd_out = eventfd;
    eventfd = NULL;

done:

    if (eventfd)
        free(eventfd);

    return ret;
}

static ssize_t _eventfd_read(
    myst_eventfddev_t* eventfddev,
    myst_eventfd_t* eventfd,
    void* buf,
    size_t count)
{
    ssize_t ret = 0;

    if (!eventfddev || !_valid_eventfd(eventfd))
        ERAISE(-EBADF);

    if (!buf || count < sizeof(uint64_t))
        ERAISE(-EINVAL);

    ssize_t nread;
    ECHECK(nread = _sys_read(eventfd->fd, buf, count));

    ret = nread;

done:
    return ret;
}

static ssize_t _eventfd_write(
    myst_eventfddev_t* eventfddev,
    myst_eventfd_t* eventfd,
    const void* buf,
    size_t count)
{
    ssize_t ret = 0;

    if (!eventfddev || !_valid_eventfd(eventfd))
        ERAISE(-EBADF);

    if (!buf || count < sizeof(uint64_t))
        ERAISE(-EINVAL);

    ssize_t nwritten;
    ECHECK(nwritten = _sys_write(eventfd->fd, buf, count));

    ret = nwritten;

done:
    return ret;
}

static ssize_t _eventfd_readv(
    myst_eventfddev_t* eventfddev,
    myst_eventfd_t* eventfd,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    if (!eventfddev || !_valid_eventfd(eventfd))
        ERAISE(-EINVAL);

    ret = myst_fdops_readv(&eventfddev->fdops, eventfd, iov, iovcnt);
    ECHECK(ret);

done:

    return ret;
}

static ssize_t _eventfd_writev(
    myst_eventfddev_t* eventfddev,
    myst_eventfd_t* eventfd,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    if (!eventfddev || !_valid_eventfd(eventfd))
        ERAISE(-EINVAL);

    ret = myst_fdops_writev(&eventfddev->fdops, eventfd, iov, iovcnt);
    ECHECK(ret);

done:

    return ret;
}

static int _eventfd_fstat(
    myst_eventfddev_t* eventfddev,
    myst_eventfd_t* eventfd,
    struct stat* statbuf)
{
    int ret = 0;

    if (!eventfddev || !_valid_eventfd(eventfd) || !statbuf)
        ERAISE(-EINVAL);

    ECHECK(_sys_fstat(eventfd->fd, statbuf));

done:
    return ret;
}

static int _eventfd_fcntl(
    myst_eventfddev_t* eventfddev,
    myst_eventfd_t* eventfd,
    int cmd,
    long arg)
{
    int ret = 0;
    long r;

    if (!eventfddev || !_valid_eventfd(eventfd))
        ERAISE(-EINVAL);

    ECHECK((r = _sys_fcntl(eventfd->fd, cmd, arg)));
    ret = r;

done:

    return ret;
}

static int _eventfd_ioctl(
    myst_eventfddev_t* eventfddev,
    myst_eventfd_t* eventfd,
    unsigned long request,
    long arg)
{
    int ret = 0;

    (void)arg;

    if (!eventfddev || !_valid_eventfd(eventfd))
        ERAISE(-EBADF);

    if (request == TIOCGWINSZ)
        ERAISE(-EINVAL);

    ERAISE(-ENOTSUP);

done:

    return ret;
}

static int _eventfd_dup(
    myst_eventfddev_t* eventfddev,
    const myst_eventfd_t* eventfd,
    myst_eventfd_t** eventfd_out)
{
    int ret = 0;
    myst_eventfd_t* new_eventfd = NULL;

    if (eventfd_out)
        *eventfd_out = NULL;

    if (!eventfddev || !_valid_eventfd(eventfd) || !eventfd_out)
        ERAISE(-EINVAL);

    if (!(new_eventfd = calloc(1, sizeof(myst_eventfd_t))))
        ERAISE(-ENOMEM);

    ECHECK(new_eventfd->fd = _sys_dup(eventfd->fd));
    new_eventfd->magic = MAGIC;

    *eventfd_out = new_eventfd;
    new_eventfd = NULL;

done:

    if (new_eventfd)
        free(new_eventfd);

    return ret;
}

static int _eventfd_close(
    myst_eventfddev_t* eventfddev,
    myst_eventfd_t* eventfd)
{
    int ret = 0;

    if (!eventfddev || !_valid_eventfd(eventfd))
        ERAISE(-EBADF);

    ECHECK(_sys_close(eventfd->fd));

    memset(eventfd, 0, sizeof(myst_eventfd_t));
    free(eventfd);

done:
    return ret;
}

static int _eventfd_target_fd(
    myst_eventfddev_t* eventfddev,
    myst_eventfd_t* eventfd)
{
    int ret = 0;

    if (!eventfddev || !_valid_eventfd(eventfd))
        ERAISE(-EINVAL);

    ret = eventfd->fd;

done:
    return ret;
}

static int _eventfd_get_events(
    myst_eventfddev_t* eventfddev,
    myst_eventfd_t* eventfd)
{
    int ret = 0;

    if (!eventfddev || !_valid_eventfd(eventfd))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

extern myst_eventfddev_t* myst_eventfddev_get(void)
{
    // clang-format off
    static myst_eventfddev_t _pipdev =
    {
        {
            .fd_read = (void*)_eventfd_read,
            .fd_write = (void*)_eventfd_write,
            .fd_readv = (void*)_eventfd_readv,
            .fd_writev = (void*)_eventfd_writev,
            .fd_fstat = (void*)_eventfd_fstat,
            .fd_fcntl = (void*)_eventfd_fcntl,
            .fd_ioctl = (void*)_eventfd_ioctl,
            .fd_dup = (void*)_eventfd_dup,
            .fd_close = (void*)_eventfd_close,
            .fd_target_fd = (void*)_eventfd_target_fd,
            .fd_get_events = (void*)_eventfd_get_events,
        },
        .eventfd = _eventfd_eventfd,
        .read = _eventfd_read,
        .write = _eventfd_write,
        .readv = _eventfd_readv,
        .writev = _eventfd_writev,
        .fstat = _eventfd_fstat,
        .fcntl = _eventfd_fcntl,
        .ioctl = _eventfd_ioctl,
        .dup = _eventfd_dup,
        .close = _eventfd_close,
        .target_fd = _eventfd_target_fd,
        .get_events = _eventfd_get_events,
    };
    // clang-format on

    return &_pipdev;
}
