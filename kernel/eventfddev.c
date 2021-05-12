// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <myst/cond.h>
#include <myst/defs.h>
#include <myst/eraise.h>
#include <myst/eventfddev.h>
#include <myst/id.h>
#include <myst/panic.h>
#include <myst/process.h>
#include <myst/round.h>
#include <myst/syscall.h>

#define MAGIC 0x9906acdc

#define MAX_COUNTER_VALUE ((uint64_t)0xfffffffffffffffe)

struct myst_eventfd
{
    uint32_t magic;
    int flags;
    int fdflags;
    uint64_t counter;
    myst_mutex_t mutex;
    myst_cond_t cond;
};

MYST_INLINE bool _valid_eventfd(const myst_eventfd_t* eventfd)
{
    return eventfd && eventfd->magic == MAGIC;
}

static void _lock(myst_eventfd_t* eventfd)
{
    myst_assume(_valid_eventfd(eventfd));
    myst_mutex_lock(&eventfd->mutex);
}

static void _unlock(myst_eventfd_t* eventfd)
{
    myst_assume(_valid_eventfd(eventfd));
    myst_mutex_unlock(&eventfd->mutex);
}

static int _eventfd(
    myst_eventfddev_t* eventfddev,
    unsigned int initval,
    int flags,
    myst_eventfd_t** eventfd_out)
{
    int ret = 0;
    myst_eventfd_t* eventfd = NULL;

    if (!eventfddev || !eventfd_out)
        ERAISE(-EINVAL);

    if ((flags & ~(EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE)))
        ERAISE(-EINVAL);

    /* Create the read eventfd */
    {
        if (!(eventfd = calloc(1, sizeof(myst_eventfd_t))))
            ERAISE(-ENOMEM);

        eventfd->magic = MAGIC;
        eventfd->counter = initval;

        if (flags & EFD_CLOEXEC)
            eventfd->fdflags = FD_CLOEXEC;

        eventfd->flags = flags;
    }

    *eventfd_out = eventfd;
    eventfd = NULL;

done:

    if (eventfd)
        free(eventfd);

    return ret;
}

static ssize_t _read(
    myst_eventfddev_t* eventfddev,
    myst_eventfd_t* eventfd,
    void* buf,
    size_t count)
{
    ssize_t ret = 0;
    bool locked = false;

    if (!eventfddev || !_valid_eventfd(eventfd))
        ERAISE(-EBADF);

    if (!buf)
        ERAISE(-EINVAL);

    if (count < sizeof(uint64_t))
        ERAISE(-EINVAL);

    _lock(eventfd);
    locked = true;

    /* check validitiy of eventfd a second time (now that lock is obtained) */
    if (!_valid_eventfd(eventfd))
    {
        /* cannot unlock since mutex is no longer valid */
        locked = false;
        ERAISE(-EBADF);
    }

    /* if the counter is readable (non-zero) */
    if (eventfd->counter != 0)
    {
        memcpy(buf, &eventfd->counter, sizeof(uint64_t));

        if ((eventfd->flags & EFD_SEMAPHORE))
            eventfd->counter--;
        else
            eventfd->counter = 0;

        myst_cond_signal(&eventfd->cond);
        ret = sizeof(uint64_t);
        goto done;
    }

    /* handle non-blocking read */
    if (eventfd->flags & EFD_NONBLOCK)
    {
        ERAISE(-EAGAIN);
    }

    /* wait here for another thread to write to the counter */
    for (;;)
    {
        if (myst_cond_wait(&eventfd->cond, &eventfd->mutex) != 0)
        {
            /* unexpected */
            ERAISE(-EPIPE);
        }

        if (eventfd->counter != 0)
        {
            memcpy(buf, &eventfd->counter, sizeof(uint64_t));

            if (eventfd->flags & EFD_SEMAPHORE)
                eventfd->counter--;
            else
                eventfd->counter = 0;

            myst_cond_signal(&eventfd->cond);
            ret = sizeof(uint64_t);
            goto done;
        }
    }

    /* unreachable */

done:

    if (locked)
        _unlock(eventfd);

    if (ret > 0)
        myst_tcall_poll_wake();

    return ret;
}

static ssize_t _write(
    myst_eventfddev_t* eventfddev,
    myst_eventfd_t* eventfd,
    const void* buf,
    size_t count)
{
    ssize_t ret = 0;
    uint64_t value;
    bool locked = false;

    if (!eventfddev || !_valid_eventfd(eventfd))
        ERAISE(-EBADF);

    if (!buf)
        ERAISE(-EINVAL);

    if (count < sizeof(uint64_t))
        ERAISE(-EINVAL);

    if (value == UINT64_MAX)
        ERAISE(-EINVAL);

    memcpy(&value, buf, sizeof(uint64_t));

    _lock(eventfd);
    locked = true;

    /* check validitiy of eventfd a second time (now that lock is obtained) */
    if (!_valid_eventfd(eventfd))
    {
        /* cannot unlock since mutex is no longer valid */
        ERAISE(-EBADF);
    }

    /* if able to write the the counter */
    if (eventfd->counter < MAX_COUNTER_VALUE - value)
    {
        eventfd->counter += value;
        myst_cond_signal(&eventfd->cond);
        ret = sizeof(uint64_t);
        goto done;
    }

    /* handle non-blocking case */
    if (eventfd->flags & EFD_NONBLOCK)
    {
        ERAISE(-EAGAIN);
    }

    /* wait here for another thread to read the counter */
    for (;;)
    {
        if (myst_cond_wait(&eventfd->cond, &eventfd->mutex) != 0)
        {
            /* unexpected */
            ERAISE(-EPIPE);
        }

        if (eventfd->counter < MAX_COUNTER_VALUE - value)
        {
            eventfd->counter += value;
            myst_cond_signal(&eventfd->cond);
            ret = sizeof(uint64_t);
            goto done;
        }
    }

    ret = count;

done:

    if (locked)
        _unlock(eventfd);

    if (ret > 0)
        myst_tcall_poll_wake();

    return ret;
}

static ssize_t _readv(
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

static ssize_t _writev(
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

static int _fstat(
    myst_eventfddev_t* eventfddev,
    myst_eventfd_t* eventfd,
    struct stat* statbuf)
{
    int ret = 0;
    struct stat buf;

    if (!eventfddev || !_valid_eventfd(eventfd) || !statbuf)
        ERAISE(-EINVAL);

    memset(&buf, 0, sizeof(buf));
    buf.st_dev = 13; /* event fd */
    buf.st_ino = (ino_t)eventfd;
    buf.st_mode = 0600;
    buf.st_nlink = 1;
    buf.st_uid = 0;
    buf.st_gid = 0;
    buf.st_rdev = 0;
    buf.st_size = 0;
    buf.st_blksize = 4096;
    buf.st_blocks = 0;
    memset(&buf.st_atim, 0, sizeof(buf.st_atim));
    memset(&buf.st_mtim, 0, sizeof(buf.st_mtim));
    memset(&buf.st_ctim, 0, sizeof(buf.st_ctim));

    *statbuf = buf;

done:
    return ret;
}

static int _fcntl(
    myst_eventfddev_t* eventfddev,
    myst_eventfd_t* eventfd,
    int cmd,
    long arg)
{
    int ret = 0;
    bool locked = false;

    if (!eventfddev || !_valid_eventfd(eventfd))
        ERAISE(-EINVAL);

    _lock(eventfd);
    locked = true;

    switch (cmd)
    {
        case F_SETFD:
        {
            if (arg != FD_CLOEXEC && arg != 0)
                ERAISE(-EINVAL);

            eventfd->fdflags = arg;
            goto done;
        }
        case F_GETFD:
        {
            ret = eventfd->fdflags;
            goto done;
        }
        case F_GETFL:
        {
            ret = eventfd->flags;
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
        _unlock(eventfd);

    return ret;
}

static int _ioctl(
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

static int _dup(
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

    /* do not dup fdflags, cond, and mutex */
    _lock((myst_eventfd_t*)eventfd);
    new_eventfd->magic = eventfd->magic;
    new_eventfd->flags = eventfd->flags;
    new_eventfd->counter = eventfd->counter;
    _unlock((myst_eventfd_t*)eventfd);

    *eventfd_out = new_eventfd;
    new_eventfd = NULL;

done:

    if (new_eventfd)
        free(new_eventfd);

    return ret;
}

static int _close(myst_eventfddev_t* eventfddev, myst_eventfd_t* eventfd)
{
    int ret = 0;

    if (!eventfddev || !_valid_eventfd(eventfd))
        ERAISE(-EBADF);

    /* signal any threads blocked on read or write */
    _lock(eventfd);
    myst_cond_signal(&eventfd->cond);
    _unlock(eventfd);

    memset(eventfd, 0, sizeof(myst_eventfd_t));
    free(eventfd);

done:

    return ret;
}

static int _target_fd(myst_eventfddev_t* eventfddev, myst_eventfd_t* eventfd)
{
    int ret = 0;

    if (!eventfddev || !_valid_eventfd(eventfd))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

static int _get_events(myst_eventfddev_t* eventfddev, myst_eventfd_t* eventfd)
{
    int ret = 0;
    int events = 0;

    if (!eventfddev || !_valid_eventfd(eventfd))
        ERAISE(-EINVAL);

    _lock(eventfd);
    {
        if (eventfd->counter != 0)
            events |= POLLIN;

        if (eventfd->counter != MAX_COUNTER_VALUE)
            events |= POLLOUT;
    }
    _unlock(eventfd);

    ret = events;

done:
    return ret;
}

extern myst_eventfddev_t* myst_eventfddev_get(void)
{
    // clang-format-off
    static myst_eventfddev_t _pipdev = {
        {
            .fd_read = (void*)_read,
            .fd_write = (void*)_write,
            .fd_readv = (void*)_readv,
            .fd_writev = (void*)_writev,
            .fd_fstat = (void*)_fstat,
            .fd_fcntl = (void*)_fcntl,
            .fd_ioctl = (void*)_ioctl,
            .fd_dup = (void*)_dup,
            .fd_close = (void*)_close,
            .fd_target_fd = (void*)_target_fd,
            .fd_get_events = (void*)_get_events,
        },
        .eventfd = _eventfd,
        .read = _read,
        .write = _write,
        .readv = _readv,
        .writev = _writev,
        .fstat = _fstat,
        .fcntl = _fcntl,
        .ioctl = _ioctl,
        .dup = _dup,
        .close = _close,
        .target_fd = _target_fd,
        .get_events = _get_events,
    };
    // clang-format-on

    return &_pipdev;
}
