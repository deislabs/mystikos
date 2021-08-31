// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <myst/assume.h>
#include <myst/bufalloc.h>
#include <myst/epolldev.h>
#include <myst/eraise.h>
#include <myst/fdtable.h>
#include <myst/id.h>
#include <myst/list.h>
#include <myst/spinlock.h>
#include <myst/syscall.h>
#include <myst/tcall.h>

#define MAGIC 0xc436d7e6

typedef struct epoll_entry epoll_entry_t;

struct myst_epoll
{
    uint32_t magic; /* MAGIC */
    int epfd;
};

MYST_INLINE long _sys_close(int fd)
{
    long params[6] = {fd};
    return myst_tcall(SYS_close, params);
}

MYST_INLINE long _sys_epoll_create1(int flags)
{
    long params[6] = {flags};
    return myst_tcall(SYS_epoll_create1, params);
}

MYST_INLINE long _sys_epoll_ctl(
    int epfd,
    int op,
    int fd,
    struct epoll_event* event)
{
    long params[6] = {epfd, op, fd, (long)event};
    return myst_tcall(SYS_epoll_ctl, params);
}

MYST_INLINE long _sys_epoll_wait(
    int epfd,
    struct epoll_event* events,
    size_t maxevents,
    int timeout)
{
    long params[6] = {epfd, (long)events, (long)maxevents, timeout};
    return myst_tcall(SYS_epoll_wait, params);
}

MYST_INLINE long _sys_fcntl(int fd, int cmd, long arg)
{
    long params[6] = {fd, cmd, arg};
    return myst_tcall(SYS_fcntl, params);
}

MYST_INLINE long _sys_fstat(int fd, struct stat* statbuf)
{
    long params[6] = {fd, (long)statbuf};
    return myst_tcall(SYS_fstat, params);
}

static bool _valid_epoll(const myst_epoll_t* epoll)
{
    return epoll && epoll->magic == MAGIC;
}

static int _ed_epoll_create1(
    myst_epolldev_t* epolldev,
    int flags,
    myst_epoll_t** epoll_out)
{
    int ret = 0;
    myst_epoll_t* epoll = NULL;
    int epfd;

    if (epoll_out)
        *epoll_out = NULL;

    if (!epolldev || !epoll_out)
        ERAISE(-EINVAL);

    /* Create the epoll implementation structure */
    {
        if (!(epoll = calloc(1, sizeof(myst_epoll_t))))
            ERAISE(-ENOMEM);

        epoll->magic = MAGIC;
    }

    /* delegate the operation */
    ECHECK(epfd = _sys_epoll_create1(flags));
    epoll->epfd = epfd;

    *epoll_out = epoll;
    epoll = NULL;

done:

    if (epoll)
        free(epoll);

    return ret;
}

static int _ed_epoll_ctl(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    int op,
    int fd,
    struct epoll_event* event)
{
    ssize_t ret = 0;
    int target_fd;

    if (!epolldev || !_valid_epoll(epoll) || !event)
        ERAISE(-EBADF);

    if (!myst_valid_fd(fd))
        ERAISE(-EBADF);

    /* get the target file descriptor for this file descriptor */
    {
        myst_fdtable_t* fdtable = myst_fdtable_current();
        myst_fdtable_type_t type;
        myst_fdops_t* fdops;
        void* object;

        ECHECK(myst_fdtable_get_any(
            fdtable, fd, &type, (void**)&fdops, (void**)&object));

        if (type == MYST_FDTABLE_TYPE_FILE)
            ERAISE(-EPERM);

        if ((target_fd = (*fdops->fd_target_fd)(fdops, object)) < 0)
            ERAISE(-EBADF);
    }

    /* delegate the request to the target */
    ECHECK(_sys_epoll_ctl(epoll->epfd, op, target_fd, event));

done:

    return ret;
}

static int _ed_epoll_wait(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    struct epoll_event* events,
    int maxevents,
    int timeout) /* milliseconds */
{
    int ret = 0;
    int n;

    if (!epolldev || !_valid_epoll(epoll) || !events || maxevents < 0)
        ERAISE(-EINVAL);

    ECHECK(n = _sys_epoll_wait(epoll->epfd, events, maxevents, timeout));
    ret = n;

done:

    return ret;
}

static ssize_t _ed_read(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    void* buf,
    size_t count)
{
    ssize_t ret = 0;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EBADF);

    if (!buf && count)
        ERAISE(-EINVAL);

    ERAISE(-ENOTSUP);

done:
    return ret;
}

static ssize_t _ed_write(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    const void* buf,
    size_t count)
{
    ssize_t ret = 0;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EBADF);

    if (!buf && count)
        ERAISE(-EINVAL);

    ERAISE(-ENOTSUP);

done:
    return ret;
}

static ssize_t _ed_readv(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    (void)iov;
    (void)iovcnt;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EINVAL);

    ERAISE(-ENOTSUP);

done:

    return ret;
}

static ssize_t _ed_writev(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    (void)iov;
    (void)iovcnt;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EINVAL);

    ERAISE(-ENOTSUP);

done:

    return ret;
}

static int _ed_fstat(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    struct stat* statbuf)
{
    int ret = 0;

    if (!epolldev || !_valid_epoll(epoll) || !statbuf)
        ERAISE(-EINVAL);

    ECHECK(_sys_fstat(epoll->epfd, statbuf));

done:
    return ret;
}

static int _ed_fcntl(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    int cmd,
    long arg)
{
    int ret = 0;
    long r;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EINVAL);

    ECHECK((r = _sys_fcntl(epoll->epfd, cmd, arg)));
    ret = r;

done:
    return ret;
}

static int _ed_ioctl(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    unsigned long request,
    long arg)
{
    int ret = 0;

    (void)request;
    (void)arg;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EBADF);

    ERAISE(-ENOTSUP);

done:

    return ret;
}

static int _ed_dup(
    myst_epolldev_t* epolldev,
    const myst_epoll_t* epoll,
    myst_epoll_t** epoll_out)
{
    int ret = 0;

    if (epoll_out)
        *epoll_out = NULL;

    if (!epolldev || !_valid_epoll(epoll) || !epoll_out)
        ERAISE(-EINVAL);

    /* ATTN: dup() not supported for epoll objects */
    ERAISE(-ENOTSUP);

done:

    return ret;
}

static int _ed_close(myst_epolldev_t* epolldev, myst_epoll_t* epoll)
{
    int ret = 0;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EBADF);

    ECHECK(_sys_close(epoll->epfd));
    memset(epoll, 0, sizeof(myst_epoll_t));
    free(epoll);

done:

    return ret;
}

static int _ed_target_fd(myst_epolldev_t* epolldev, myst_epoll_t* epoll)
{
    int ret = 0;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

static int _ed_get_events(myst_epolldev_t* epolldev, myst_epoll_t* epoll)
{
    int ret = 0;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

extern myst_epolldev_t* myst_epolldev_get(void)
{
    // clang-format-off
    static myst_epolldev_t _epolldev = {
        {
            .fd_read = (void*)_ed_read,
            .fd_write = (void*)_ed_write,
            .fd_readv = (void*)_ed_readv,
            .fd_writev = (void*)_ed_writev,
            .fd_fstat = (void*)_ed_fstat,
            .fd_fcntl = (void*)_ed_fcntl,
            .fd_ioctl = (void*)_ed_ioctl,
            .fd_dup = (void*)_ed_dup,
            .fd_close = (void*)_ed_close,
            .fd_target_fd = (void*)_ed_target_fd,
            .fd_get_events = (void*)_ed_get_events,
        },
        .ed_epoll_create1 = _ed_epoll_create1,
        .ed_epoll_ctl = _ed_epoll_ctl,
        .ed_epoll_wait = _ed_epoll_wait,
        .ed_read = _ed_read,
        .ed_write = _ed_write,
        .ed_readv = _ed_readv,
        .ed_writev = _ed_writev,
        .ed_fstat = _ed_fstat,
        .ed_fcntl = _ed_fcntl,
        .ed_ioctl = _ed_ioctl,
        .ed_dup = _ed_dup,
        .ed_close = _ed_close,
        .ed_target_fd = _ed_target_fd,
        .ed_get_events = _ed_get_events,
    };
    // clang-format-on

    return &_epolldev;
}
